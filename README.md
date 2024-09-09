# CountDown: Refcount-guided Fuzzing for Exposing Temporal Memory Errors in Linux Kernel

## Introduction

CountDown is a novel refcount-guided kernel fuzzer, targeting kernel use-after-free bugs. Different from coverage-guided fuzzers, CountDown reshapes syscall relations through shared refcounts among different syscalls and generates test cases based on refcount-based relations. 


## Publication
[**CountDown: Refcount-guided Fuzzing for Exposing Temporal Memory Errors in Linux Kernel**](https://shuangpengbai.github.io/papers/bai-countdown.pdf)

Shuangpeng Bai, Zhechang Zhang, and Hong Hu.

In Proceedings of the 31st ACM Conference on Computer and Communications Security (CCS 2024)


## Setup


### Dependencies

```
sudo apt-get update
sudo apt-get install -y make git gcc flex bison libelf-dev libssl-dev bc qemu-system-x86 build-essential debootstrap
```

Install Go language support before compiling CountDown.

```
wget https://dl.google.com/go/go1.22.1.linux-amd64.tar.gz
tar -xf go1.22.1.linux-amd64.tar.gz
export GOROOT=`pwd`/go
export PATH=$GOROOT/bin:$PATH
``` 

Also, CountDown requires [**KVM**](https://help.ubuntu.com/community/KVM/Installation)  enabled.

### Prepare Kernel (v6.6)

Instrument kernel (v6.6) to record kernel refcount operations. 

```
cd countdown
git clone https://github.com/torvalds/linux
cd linux
git checkout v6.6
git apply ../kernel_compile/kernel.patch
```

Compile kernel with configuration file `.config`. We provide the Syzbot config used in experiments. The latested configs can be found at [**Syzbot**](https://syzkaller.appspot.com/upstream).

```
cp ../kernel_compile/.config ./
make
```

### Build Image

Generate a minimal Debian Linux image suitable for fuzzing. 

```
cd countdown/image
chmod +x ./create-image.sh
./create-image.sh
```

### Build Fuzzer

Compile the fuzzer. Make sure Go is installed.

```
cd countdown/countdown_fuzzer
make
```

### Start Fuzzing

Start fuzzer with the config. We used `cd_cfg` in experiments. 

```
cd countdown/countdown_fuzzer
./bin/syz-manager -config ./cd_cfg 
```

Start relation collection in another terminal.

```
cd py-tools
python3 relation_collect.py
```

The fuzzer is correctly configured if the files `kref-relation-cross-history` and `kref-refcnt-change-cross-history` are generated in the `py-tools` folder and contain data.


## Acknowledgment

We thank National Science Foundation (NSF) for supporting our work. This research is supported by NSF under grants CNS-2247652 and CNS-2339848. 
