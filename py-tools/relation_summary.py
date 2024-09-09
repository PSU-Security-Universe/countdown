import os

realation_path_cross_history = 'kref-relation-cross-history'
refcnt_change_path_cross_history = 'kref-refcnt-change-cross-history'

kref_name_one_history = 'this-vm-finding'

relation_name_one_history = 'this-vm-pair'


MAX_SYS_NR = 5000

def get_ref_change_record(info_s):

    # op is (syscall_nr, ref_hash)

    op_refchange_D = {}

    for l in info_s:
        items = l.split('_')
        if len(items) < 3:
            print('item num wrong!')
            continue
        try:
            call_nr = items[0] # use string nr here
            ref_hash = items[1]

            if int(call_nr) >= MAX_SYS_NR:
                print('Error: Wrong call num')
                continue

            for change_time in items[2:]:
                ref_change = int(change_time.split(':')[0])

            if ref_change > 200:
                ref_change = 200
            if ref_change < -200:
                ref_change = -200

            op = (call_nr, ref_hash)
            if op not in op_refchange_D:
                op_refchange_D[op] = set()
            op_refchange_D[op].add(ref_change)

        except:
            continue

    
    return op_refchange_D



def write_ref_change_record_to_file(op_refchange_D, refcnt_change_path):
    outstr = ""
    
    for op in op_refchange_D:
        (call_nr, ref_hash) = op
        outstr += call_nr + ' ' + ref_hash + ' '

        refcnt_change_s = op_refchange_D[op]
        for refcnt_change in refcnt_change_s:
            outstr += str(refcnt_change) + ' '
        
        outstr = outstr[:-1] + '\n'

    with open(refcnt_change_path, 'w') as f:
        f.write(outstr)

def get_relation_table_cross_program(info_s):

    hash_syscall_D = {}

    for l in info_s:
        items = l.split('_')
        if len(items) != 3:
            print(l)
            print('item num wrong!')
            continue
        try:
            call_nr = items[0] # use string nr here
            ref_hash = items[1]
        except:
            continue
        
        if int(call_nr) >= MAX_SYS_NR:
            continue

        if ref_hash not in hash_syscall_D:
            hash_syscall_D[ref_hash] = set()
        hash_syscall_D[ref_hash].add(call_nr)
    
    syscallp_rel_D = {}

    for ref_hash in hash_syscall_D:
        call_l = list(hash_syscall_D[ref_hash])
        for i in range(len(call_l)):
            for j in range(i + 1, len(call_l)):
                syscallp = (call_l[i], call_l[j])
                if syscallp not in syscallp_rel_D:
                    syscallp_rel_D[syscallp] = 0
                syscallp_rel_D[syscallp] += 1

    return syscallp_rel_D


def write_relation_table_to_file(syscallp_rel_D, realation_path):
    outstr = ""
    for syscallp in syscallp_rel_D:
        (sys1_str, sys2_str) = syscallp
        all_counting_key_str = ''
        for counting_key in syscallp_rel_D[syscallp]:
            if counting_key[-2:] == ':0':
                all_counting_key_str += counting_key + ' '
        outstr += sys1_str + ' ' + sys2_str + ' ' + all_counting_key_str + '\n'

    with open(realation_path, 'w') as f:
        f.write(outstr)
    

def relation_summary_func():
    info_s = set()

    relation_D = {}

    for root, dirs, files in os.walk("./refcnt_records", topdown=False):
        for name in files:
            try:
                f_name = os.path.join(root, name)
                if kref_name_one_history in name:
                    f = open(f_name)
                    for l in f.readlines():
                        info_s.add(l[:-1])
                        
                if relation_name_one_history in name:
                    f = open(f_name)
                    for l in f.readlines():
                        items = l.split(' ')
                        if len(items) < 3:
                            print('wrong number')
                            continue
                        len_correct = True
                        for i in items:
                            if len(i) > len('4265573642:0'):
                                len_correct = False
                        if not len_correct:
                            print('len not correct')
                            continue

                        sys1_str = items[0]
                        sys2_str = items[1]
                        if int(sys1_str) > MAX_SYS_NR and int(sys2_str) > MAX_SYS_NR:
                            print('error syscall num')
                            continue
                        

                        prio_strs = set(items[2:-1])
                        apair = (sys1_str, sys2_str)
                        if apair not in relation_D:
                            relation_D[apair] = set()
                        relation_D[apair] = relation_D[apair].union(prio_strs)
            except:
                print('file error')
                pass

    write_relation_table_to_file(relation_D, realation_path_cross_history)

    op_refchange_D = get_ref_change_record(info_s)
    write_ref_change_record_to_file(op_refchange_D, refcnt_change_path_cross_history)
    

if __name__ == "__main__":
    relation_summary_func()
