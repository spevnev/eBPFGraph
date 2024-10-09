#ifndef LATENCY_H
#define LATENCY_H

#include <vmlinux.h>

struct runq_event {
    __u64 prev_cgroup_id;
    __u64 cgroup_id;
    __u64 runq_latency;
    __u64 ktime;
};

#endif  // LATENCY_H
