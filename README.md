# "Noisy Neighbor" graph

This application displays a graph of latency and preemptions per cgroup using eBPF.

It consists of two parts:
1. eBPF program which collects data from kernel functions (`sched_wakeup` and `sched_switch`)
2. Userspace program which runs eBPF, process data and displays as graph.

![Image](https://github.com/user-attachments/assets/5c5e437d-ea35-4c19-879a-3724ee0dcdeb)

## Compiling

0. Requirements: [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf), pkg-config, [raylib](https://github.com/raysan5/raylib) (v5), make

1. Building eBPF:
    ```console
    $ cd ebpf
    $ ecc latency.bpf.c latency.h
    ```

2. Building application:
    ```console
    $ make
    ```

3. Running (**requires root**):
    ```console
    $ ./build/graph
    ```

## Sample workloads

Requirements: cgroups v2, stress, netcat

Running (**requires root**):
```console
$ ./workloads/latency_only.sh
$ ./workloads/preempts_only.sh
$ ./workloads/noisy.sh
```

## References

[Noisy Neighbor Detection with eBPF](https://netflixtechblog.com/noisy-neighbor-detection-with-ebpf-64b1f4b3bbdd)
