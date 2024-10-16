// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#ifndef LATENCY_H
#define LATENCY_H

#include <vmlinux.h>

struct runq_event {
    u8 did_preempt;
    u64 cgroup_id;
    u64 runq_latency;
    u64 ktime;
};

#endif  // LATENCY_H
