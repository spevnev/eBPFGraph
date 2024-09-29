/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#include <vmlinux.h>
// Don't reorder
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define RATE_LIMIT_NS 10
#define MAX_ENTRIES 8192
#define RINGBUF_SIZE_BYTES 65535

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u64);
} runq_enqueued SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_id_to_last_event_ts SEC(".maps");

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

__u64 get_task_cgroup_id(struct task_struct *task) {
    struct css_set *cgroups;
    __u64 cgroup_id;
    bpf_rcu_read_lock();
    cgroups = task->cgroups;
    cgroup_id = cgroups->dfl_cgrp->kn->id;
    bpf_rcu_read_unlock();
    return cgroup_id;
}

SEC("tp_btf/sched_wakeup")
int tp_sched_wakeup(__u64 *ctx) {
    struct task_struct *task = (void *) ctx[0];
    __u32 pid = task->pid;
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&runq_enqueued, &pid, &ts, BPF_NOEXIST);

    return 0;
}

SEC("tp_btf/sched_switch")
int tp_sched_switch(__u64 *ctx) {
    struct task_struct *prev = (struct task_struct *) ctx[1];
    struct task_struct *next = (struct task_struct *) ctx[2];
    __u32 prev_pid = prev->pid;
    __u32 next_pid = next->pid;

    // fetch timestamp of when the next task was enqueued
    __u64 *tsp = bpf_map_lookup_elem(&runq_enqueued, &next_pid);
    if (tsp == NULL) {
        return 0;  // missed enqueue
    }

    // calculate runq latency before deleting the stored timestamp
    __u64 now = bpf_ktime_get_ns();
    __u64 runq_latency = now - *tsp;

    // delete pid from enqueued map
    bpf_map_delete_elem(&runq_enqueued, &next_pid);

    __u64 prev_cgroup_id = get_task_cgroup_id(prev);
    __u64 cgroup_id = get_task_cgroup_id(next);

    // per-cgroup-id-per-CPU rate-limiting
    // to balance observability with performance overhead
    __u64 *last_ts = bpf_map_lookup_elem(&cgroup_id_to_last_event_ts, &cgroup_id);
    __u64 last_ts_val = last_ts == NULL ? 0 : *last_ts;

    // check the rate limit for the cgroup_id in consideration
    // before doing more work
    if (now - last_ts_val < RATE_LIMIT_NS) {
        // Rate limit exceeded, drop the event
        return 0;
    }

    struct runq_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);

    if (event) {
        event->prev_cgroup_id = prev_cgroup_id;
        event->cgroup_id = cgroup_id;
        event->runq_latency = runq_latency;
        event->ts = now;
        bpf_ringbuf_submit(event, 0);
        // Update the last event timestamp for the current cgroup_id
        bpf_map_update_elem(&cgroup_id_to_last_event_ts, &cgroup_id, &now, BPF_ANY);
    }

    return 0;
}
