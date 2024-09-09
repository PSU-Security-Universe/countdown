// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"math/rand"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer          *Fuzzer
	pid             int
	env             *ipc.Env
	rnd             *rand.Rand
	execOpts        *ipc.ExecOpts
	execOptsCollide *ipc.ExecOpts
	execOptsCover   *ipc.ExecOpts
	execOptsComps   *ipc.ExecOpts

	cd_exec_num int

	op_refcntchange_exist_found_crossVM_d map[cd_op]map[int32]int // map[int]int: refcnt change->1 means exists. will be updated by data from other vms.

	op_refcntchange_exist_verified_inVM_d map[cd_op]map[int32]int
	hash_syscall_map                      map[uint32]map[int32]bool
	pairing_map                           map[cd_syzidx_pair]map[cd_type_for_counting]bool
	cd_choiceTable                       *prog.ChoiceTable

	cd_write_log_time_total int64
	cd_start_time           time.Time
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsCollide := *fuzzer.execOpts
	execOptsCollide.Flags &= ^ipc.FlagCollectSignal
	execOptsCover := *fuzzer.execOpts
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := *fuzzer.execOpts
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:          fuzzer,
		pid:             pid,
		env:             env,
		rnd:             rnd,
		execOpts:        fuzzer.execOpts,
		execOptsCollide: &execOptsCollide,
		execOptsCover:   &execOptsCover,
		execOptsComps:   &execOptsComps,
	}
	return proc, nil
}

// BytesToString
func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func (proc *Proc) loop() {

	// CountDown init maps
	if proc.op_refcntchange_exist_found_crossVM_d == nil {
		proc.op_refcntchange_exist_found_crossVM_d = make(map[cd_op]map[int32]int)
	}

	if proc.op_refcntchange_exist_verified_inVM_d == nil {
		proc.op_refcntchange_exist_verified_inVM_d = make(map[cd_op]map[int32]int)
	}
	if proc.pairing_map == nil {
		proc.pairing_map = make(map[cd_syzidx_pair]map[cd_type_for_counting]bool)
	}

	if proc.hash_syscall_map == nil {
		proc.hash_syscall_map = make(map[uint32]map[int32]bool)
	}

	if proc.cd_choiceTable == nil {
		proc.cd_choiceTable = proc.fuzzer.choiceTable.CD_CopyChoiceTable()
	}

	proc.cd_start_time = time.Now()


	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				log.Fatalf("unknown work type: %#v", item)
			}
			continue
		}

		ct := proc.cd_choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := fuzzerSnapshot.chooseProgram(proc.rnd).Clone()
			PrepareRefcountCallCandidate(proc, p) // need to set p.CD_one_turn_findings before.
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	rawCover := []uint32{}
	for i := 0; i < signalRuns; i++ {
		item.p.CD_exec_source = 2
		info := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		item.p.CD_exec_source = 0

		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				return // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		if len(rawCover) == 0 && proc.fuzzer.fetchRawCover {
			rawCover = append([]uint32{}, thisCover...)
		}
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			return
		}
		inputCover.Merge(thisCover)
	}
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				for i := 0; i < minimizeAttempts; i++ {
					info := proc.execute(proc.execOpts, p1, ProgNormal, StatMinimize)
					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						return true
					}
				}
				return false
			})
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.Input{
		Call:     callName,
		CallID:   item.call,
		Prog:     data,
		Signal:   inputSignal.Serialize(),
		Cover:    inputCover.Serialize(),
		RawCover: rawCover,
	})

	proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.cd_choiceTable, proc.fuzzer.noMutate, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.executeAndCollide(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 1; nth <= 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		newProg := p.Clone()
		newProg.Calls[call].Props.FailNth = nth
		info := proc.executeRaw(proc.execOpts, newProg, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

// if we use task-based refcount tracking, we do not need to run again to comfirm the record.
func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) *ipc.ProgInfo {

	if p.CD_COMMENT == "duplicated program" {
		// if duplicated prog, do not need to record and analyze again.
		info := proc.executeRaw(execOpts, p, stat)
		return info
	}

	if stat == StatMinimize {
		p.CD_exec_source = 2
		info := proc.executeRaw(execOpts, p, stat)
		p.CD_exec_source = 0
		return info
	}

	proc.cd_exec_num += 1

	if proc.cd_exec_num%200 == 0 { // CountDown check frequency.
		cd_write_log_and_update_knowledge(proc)
		fmt.Printf("CountDown proc.cd_exec_num=%v", proc.cd_exec_num)
	}

	p.CD_exec_source = 1
	info := proc.executeRaw(execOpts, p, stat)
	p.CD_exec_source = 0

	defer func() {
		if info != nil {
			calls, extra := proc.fuzzer.checkNewSignal(p, info)
			for _, callIndex := range calls {
				proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
			}
			if extra {
				proc.enqueueCallTriage(p, flags, -1, info.Extra)
			}
		}
	}()

	if info == nil {
		return nil
	}


	this_turn_res := prog.One_turn_res{
		One_turn_findings: info.CD_one_turn_findings,
	}


	new_pair_map := add_and_return_new_pair_one_prog(proc, this_turn_res)
	new_op_map := add_and_return_new_op_one_prog(proc, info.CD_one_turn_findings)

	for op, _ := range new_op_map {
		// only deplicate when refcnt change < 0
		if op.refcnt_change < 0 {
			hash_idx_in_prog_map := get_hash_idx_in_prog_map(info.CD_one_turn_findings)
			after_refcnt_value := new_op_map[op]
			dup_program(proc, p, op, int(after_refcnt_value), hash_idx_in_prog_map[op.refcnt_hash]) // we only dup when sum refcnt change < 0.
		}
	}


	if len(new_pair_map)+len(new_op_map) == 0 {
		return info
	}

	p.CD_COMMENT = ""

	return info
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeAndCollide(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes, stat Stat) {
	proc.execute(execOpts, p, flags, stat)

	if proc.execOptsCollide.Flags&ipc.FlagThreaded == 0 {
		// We cannot collide syscalls without being in the threaded mode.
		return
	}
	const collideIterations = 2
	for i := 0; i < collideIterations; i++ {
		proc.executeRaw(proc.execOptsCollide, proc.randomCollide(p), StatCollide)
	}
}

func (proc *Proc) randomCollide(origP *prog.Prog) *prog.Prog {
	if proc.rnd.Intn(5) == 0 {
		// Old-style collide with a 20% probability.
		p, err := prog.DoubleExecCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	if proc.rnd.Intn(4) == 0 {
		// Duplicate random calls with a 20% probability (25% * 80%).
		p, err := prog.DupCallCollide(origP, proc.rnd)
		if err == nil {
			return p
		}
	}
	p := prog.AssignRandomAsync(origP, proc.rnd)
	if proc.rnd.Intn(2) != 0 {
		prog.AssignRandomRerun(p, proc.rnd)
	}
	return p
}


type cd_op struct {
	syscall_idx_syz int32
	hash            uint32
}

func get_hash_idx_in_prog_map(one_turn_findings map[prog.CD_sum_op]prog.CD_sum_res) map[uint32][]int {

	hash_idx_in_prog_map := make(map[uint32][]int)

	for tmp_op, _ := range one_turn_findings {
		// one_str := fmt.Sprintf("%s_%d_%d_%d_%d_%d", "suc", , , , , tmp_res.after_value)

		refcnt_hash := tmp_op.Hash
		call_idx_in_prog := tmp_op.Call_idx_in_prog

		if _, hash_found := hash_idx_in_prog_map[refcnt_hash]; !hash_found {
			hash_idx_in_prog_map[refcnt_hash] = make([]int, 0)
		}
		hash_idx_in_prog_map[refcnt_hash] = append(hash_idx_in_prog_map[refcnt_hash], int(call_idx_in_prog))
	}
	return hash_idx_in_prog_map
}

func add_and_return_new_op_one_prog(proc *Proc, one_turn_findings map[prog.CD_sum_op]prog.CD_sum_res) map[one_refcnt_change_record]int32 {
	new_op_map := make(map[one_refcnt_change_record]int32)

	for tmp_op, tmp_res := range one_turn_findings {
		call_idx_in_syz := tmp_res.Call_idx_in_syz
		refcnt_hash := tmp_op.Hash
		refcnt_change := tmp_res.Refcnt_delta_sum
		call_idx_in_prog := tmp_op.Call_idx_in_prog
		after_refcnt_value := tmp_res.After_value

		if !check_op_exists(proc, call_idx_in_syz, refcnt_hash, refcnt_change) {
			one_record := one_refcnt_change_record{
				call_idx_in_prog: call_idx_in_prog,
				call_idx_in_syz:  call_idx_in_syz,
				refcnt_hash:      refcnt_hash,
				refcnt_change:    refcnt_change,
			}
			new_op_map[one_record] = after_refcnt_value
		}

		// new op confirmed
		add_change(proc, call_idx_in_syz, refcnt_hash, refcnt_change, true)
	}
	return new_op_map
}

func add_and_return_new_pair_one_prog(proc *Proc, one_turn_res prog.One_turn_res) map[cd_pairing_for_sorting]map[cd_type_for_counting]bool {

	// newcov_signal_map := one_turn_res.One_turn_newcov_signal_map
	pair_set := cd_get_pair_set(one_turn_res.One_turn_findings)
	new_pair_set := make(map[cd_pairing_for_sorting]map[cd_type_for_counting]bool)

	for pairing, _ := range pair_set {

		key_cd_syzidx_pair := cd_syzidx_pair{
			call_idx_in_syz_1: pairing.call_idx_in_syz_1,
			call_idx_in_syz_2: pairing.call_idx_in_syz_2,
		}

		interesting_branch_l := make([]int, 0)
		interesting_branch_l = append(interesting_branch_l, 0)

		for i := 0; i < len(interesting_branch_l); i++ {
			counting_key := cd_type_for_counting{
				refcnt_hash: pairing.refcnt_hash,
				new_branch:  interesting_branch_l[i],
			}

			if _, pair_found_in_global := proc.pairing_map[key_cd_syzidx_pair]; !pair_found_in_global {
				proc.pairing_map[key_cd_syzidx_pair] = make(map[cd_type_for_counting]bool)
			}
			proc.pairing_map[key_cd_syzidx_pair][counting_key] = true
		}
	}
	return new_pair_set
}

func check_op_exists(proc *Proc, call_idx_in_syz int32, refcnt_hash uint32, refcnt_change int32) bool {
	op := cd_op{hash: refcnt_hash, syscall_idx_syz: call_idx_in_syz}
	if _, op_found := proc.op_refcntchange_exist_found_crossVM_d[op]; op_found {
		if _, change_found := proc.op_refcntchange_exist_found_crossVM_d[op][refcnt_change]; change_found {
			return true
		}
	}
	return false
}

func add_change(proc *Proc, call_idx_in_syz int32, refcnt_hash uint32, refcnt_change int32, verified_by_this_vm bool) {
	op := cd_op{hash: refcnt_hash, syscall_idx_syz: call_idx_in_syz}
	if _, op_found := proc.op_refcntchange_exist_found_crossVM_d[op]; !op_found {
		proc.op_refcntchange_exist_found_crossVM_d[op] = make(map[int32]int)
	}
	proc.op_refcntchange_exist_found_crossVM_d[op][refcnt_change] = 1

	if verified_by_this_vm {
		if _, op_found := proc.op_refcntchange_exist_verified_inVM_d[op]; !op_found {
			proc.op_refcntchange_exist_verified_inVM_d[op] = make(map[int32]int)
		}
		proc.op_refcntchange_exist_verified_inVM_d[op][refcnt_change] = 1
	}

	if _, hash_found := proc.hash_syscall_map[refcnt_hash]; !hash_found {
		proc.hash_syscall_map[refcnt_hash] = make(map[int32]bool)
	}
	proc.hash_syscall_map[refcnt_hash][call_idx_in_syz] = true
}

func PrepareRefcountCallCandidate(proc *Proc, p *prog.Prog) {

	one_turn_findings := p.CD_one_turn_findings
	// choose a refcount object.
	// the refcount objects operated by more syscalls gets higher possibility.
	hash_l := make([]uint32, 0)
	tmp_hash_syscall_map := make(map[uint32]map[int32]bool)
	for tmp_op, tmp_res := range one_turn_findings {
		refcnt_hash := tmp_op.Hash
		syscall_idx_in_syz := tmp_res.Call_idx_in_syz
		hash_l = append(hash_l, refcnt_hash)

		if _, hash_found := tmp_hash_syscall_map[refcnt_hash]; !hash_found {
			tmp_hash_syscall_map[refcnt_hash] = make(map[int32]bool)
		}

		tmp_hash_syscall_map[refcnt_hash][syscall_idx_in_syz] = true
	}

	if len(hash_l) == 0 {
		p.RefcountCallCandidate = make([]int32, 0)
		return
	}
	chosen_hash_pos := proc.rnd.Int31n(int32(len(hash_l)))
	chosen_hash := hash_l[chosen_hash_pos]

	tmp_used_map := make(map[int32]bool)

	for _, c := range p.Calls {
		tmp_used_map[int32(c.Meta.ID)] = true
	}

	call_idx_in_syz_l := make([]int32, 0)
	for call_idx_in_syz, _ := range proc.hash_syscall_map[chosen_hash] {
		call_idx_in_syz_l = append(call_idx_in_syz_l, call_idx_in_syz)
		if _, idx_found := tmp_used_map[call_idx_in_syz]; !idx_found {
			for i := 0; i < 10; i++ {
				call_idx_in_syz_l = append(call_idx_in_syz_l, call_idx_in_syz)
			}
		}
	}

	p.RefcountCallCandidate = call_idx_in_syz_l
}

func dup_program(proc *Proc, p *prog.Prog, one_record one_refcnt_change_record, after_refcnt_value int, matched_hash_idx_in_prog []int) {
	var newP *prog.Prog
	change := false

	if after_refcnt_value > 0 { //if a refcnt is not freed, we will duplicate it
		newP = p.DuplicateCall(int(one_record.call_idx_in_prog), int(after_refcnt_value), -1) //duplicate at the ori pos
		change = true

	} else { //if a refcnt is freed, we will add all the operations using the same hash at the end
		newP = p
		for idx_in_prog := range matched_hash_idx_in_prog {
			newP = newP.DuplicateCall(int(idx_in_prog), 1, 1)
			change = true
		}
	}

	if change {
		newP.CD_COMMENT = "duplicated program"
		newP.Dup.CD_dup_target_hash = one_record.refcnt_hash
		newP.Dup.CD_dup_syscall_nr = one_record.call_idx_in_syz
		newP.Dup.CD_dup_original_refcnt_change = one_record.refcnt_change
		proc.fuzzer.workQueue.enqueue(&WorkCandidate{p: newP, flags: ProgTypes(newP.CD_flags)})
	}
}

type one_refcnt_change_record struct {
	call_idx_in_prog int32
	call_idx_in_syz  int32
	refcnt_hash      uint32
	refcnt_change    int32
}

type cd_type_for_sorting struct {
	call_idx_in_prog int32
	call_idx_in_syz  int32
}

type cd_pairing_for_sorting struct {
	refcnt_hash        uint32
	call_idx_in_prog_1 int32
	call_idx_in_prog_2 int32
	call_idx_in_syz_1  int32
	call_idx_in_syz_2  int32
}

type cd_syzidx_pair struct {
	call_idx_in_syz_1 int32
	call_idx_in_syz_2 int32
}

type cd_type_for_counting struct {
	refcnt_hash uint32
	new_branch  int
}

func CheckFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}


var update_times int32 = 0

// UpdateRunTable CountDown
func UpdateRunTable(proc *Proc, ct *prog.ChoiceTable, cd_exec_num int) bool {

	if !CheckFileIsExist("/kref/") {
		err := os.MkdirAll("/kref/", 0666)
		if err != nil {
			fmt.Println(err)
		}
	}

	update_times += 1
	merge_ratio := update_times

	fmt.Printf("CountDown update times = %v\n", update_times)

	len_limit := len(ct.Prios)
	tmp_prios := make([][]int32, len_limit)

	var prios [][]int32

	prios = ct.LogPrios


	for i := range prios {
		tmp_prios[i] = make([]int32, len_limit)
		copy(tmp_prios[i], prios[i])
	}

	var oldKrefFilepath string = "/kref/kref-relation-cross-history"
	if !CheckFileIsExist(oldKrefFilepath) {
		fmt.Println("CountDown no kref-relation-cross-history!")
		return false
	}

	content, err := ioutil.ReadFile(oldKrefFilepath)
	if err != nil {
		panic(err)
	}

	fileText := BytesToString(content)
	pairL := strings.Split(fileText, "\n")

	for i := 0; i < len(pairL); i++ {
		if !strings.Contains(pairL[i], " ") {
			continue
		}

		aPair := strings.Split(pairL[i], " ")
		if len(aPair) < 3 {
			continue
		}
		idx1, _ := strconv.Atoi(aPair[0])
		idx2, _ := strconv.Atoi(aPair[1])

		key_cd_syzidx_pair := cd_syzidx_pair{
			call_idx_in_syz_1: int32(idx1),
			call_idx_in_syz_2: int32(idx2),
		}

		if _, syzidx_pair_found := proc.pairing_map[key_cd_syzidx_pair]; !syzidx_pair_found {
			proc.pairing_map[key_cd_syzidx_pair] = make(map[cd_type_for_counting]bool)
		}

		times := 0

		for j := 2; j < len(aPair); j++ {
			a_key := aPair[j]
			if a_key == "" {
				continue
			}

			tmp_data_l := strings.Split(a_key, ":")
			hash, _ := strconv.Atoi(tmp_data_l[0])
			counting_key := cd_type_for_counting{
				refcnt_hash: uint32(hash),
				new_branch:  0,
			}

			proc.pairing_map[key_cd_syzidx_pair][counting_key] = true

			times++
		}

		if idx1 >= len_limit || idx2 >= len_limit {
			fmt.Println("CountDown error prio file! idx out of range!")
			return false
		}

		TimeMaxLimit := 100 // CountDown limit the max refcount object number tp avoid too large number.
		if times > TimeMaxLimit {
			times = TimeMaxLimit
		}

		this_add_prio := int32(times)
		this_add_prio = int32(math.Log2(float64(this_add_prio) + 1))

		tmp_prios[idx1][idx2] += this_add_prio * merge_ratio

	}

	ct.CD_update_runs_from_prio(tmp_prios)

	return true
}

func cd_get_pair_set(one_turn_findings map[prog.CD_sum_op]prog.CD_sum_res) map[cd_pairing_for_sorting]bool {

	pair_set := make(map[cd_pairing_for_sorting]bool)

	hash_idxs_map := make(map[uint32][]cd_type_for_sorting)
	for tmp_op, tmp_res := range one_turn_findings {
		call_idx_in_syz := tmp_res.Call_idx_in_syz
		refcnt_hash := tmp_op.Hash
		call_idx_in_prog := tmp_op.Call_idx_in_prog

		if _, hash_found := hash_idxs_map[refcnt_hash]; !hash_found {
			hash_idxs_map[refcnt_hash] = make([]cd_type_for_sorting, 0)
		}
		hash_idxs_map[refcnt_hash] = append(hash_idxs_map[refcnt_hash], cd_type_for_sorting{call_idx_in_prog: call_idx_in_prog, call_idx_in_syz: call_idx_in_syz})
	}

	for refcnt_hash, cd_idx_l := range hash_idxs_map {

		sort.Slice(cd_idx_l, func(i, j int) bool {
			return cd_idx_l[i].call_idx_in_prog < cd_idx_l[j].call_idx_in_prog
		})

		for i := 0; i < len(cd_idx_l)-1; i++ {
			for j := i + 1; j < len(cd_idx_l); j++ {
				pairing := cd_pairing_for_sorting{
					refcnt_hash:        refcnt_hash,
					call_idx_in_prog_1: cd_idx_l[i].call_idx_in_prog,
					call_idx_in_prog_2: cd_idx_l[j].call_idx_in_prog,
					call_idx_in_syz_1:  cd_idx_l[i].call_idx_in_syz,
					call_idx_in_syz_2:  cd_idx_l[j].call_idx_in_syz,
				}

				pair_set[pairing] = true
			}
		}
	}

	return pair_set
}

func update_refcnt_change_table(proc *Proc) {

	refcnt_change_path := "/kref/kref-refcnt-change-cross-history"

	if !CheckFileIsExist(refcnt_change_path) {
		fmt.Println("CountDown no kref-refcnt-change-cross-history!")
		return
	}

	content, err := ioutil.ReadFile(refcnt_change_path)
	if err != nil {
		panic(err)
	}

	fileText := BytesToString(content)
	opstrL := strings.Split(fileText, "\n")

	for i := 0; i < len(opstrL); i++ {
		if !strings.Contains(opstrL[i], " ") {
			continue
		}

		elements := strings.Split(opstrL[i], " ")
		if len(opstrL) <= 3 {
			continue
		}

		call_idx_in_syz, _ := strconv.Atoi(elements[0])
		refcnt_hash, _ := strconv.Atoi(elements[1])

		for j := 2; j < len(elements); j++ {
			refcnt_change, _ := strconv.Atoi(elements[j])
			add_change(proc, int32(call_idx_in_syz), uint32(refcnt_hash), int32(refcnt_change), false)
		}
	}
}

func cd_write_log_and_update_knowledge(proc *Proc) {

	fmt.Printf("CountDown start writing\n")

	startTime := time.Now()

	executor_id_nr := proc.env.CD_env_nr

	op_file_name := "this-vm-finding-" + strconv.Itoa(executor_id_nr)
	f_op, _ := os.Create(op_file_name)

	for op, refcnt_change_map := range proc.op_refcntchange_exist_verified_inVM_d {
		tmp_vm_op := fmt.Sprintf("%d_%d", op.syscall_idx_syz, op.hash)
		f_op.WriteString(tmp_vm_op)

		for refcnt_change, _ := range refcnt_change_map {
			tmp_vm_op = fmt.Sprintf("_%d:%d", refcnt_change, 0)
			f_op.WriteString(tmp_vm_op)
		}

		f_op.WriteString("\n")
	}
	f_op.Close()

	pair_file_name := "this-vm-pair-" + strconv.Itoa(executor_id_nr)
	f_pair, _ := os.Create(pair_file_name)

	for pairing, counting_map := range proc.pairing_map {
		this_prio_str := ""

		for counting_key, _ := range counting_map {
			if counting_key.refcnt_hash == 0 {
				panic("CountDown hash == 0!\n")
			}
			this_prio_str += fmt.Sprintf("%d:%d ", counting_key.refcnt_hash, counting_key.new_branch)
		}
		tmp_vm_pair := fmt.Sprintf("%d %d %s\n", pairing.call_idx_in_syz_1, pairing.call_idx_in_syz_2, this_prio_str)
		f_pair.WriteString(tmp_vm_pair)
	}
	f_pair.Close()

	UpdateRunTable(proc, proc.cd_choiceTable, proc.cd_exec_num)
	update_refcnt_change_table(proc)

	this_time_diff_sec := time.Now().Unix() - startTime.Unix()

	proc.cd_write_log_time_total += this_time_diff_sec
}


func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) *ipc.ProgInfo {
	proc.fuzzer.checkDisabledCalls(p)

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than counting this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				atomic.AddUint64(&proc.fuzzer.stats[StatBufferTooSmall], 1)
				return nil
			}
			if try > 10 {
				log.Fatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
