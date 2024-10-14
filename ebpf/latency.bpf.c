// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <vmlinux.h>
// Don't reorder
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_RUNQ_ENTRIES 8192
#define MAX_EVENT_ENTRIES 262144

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RUNQ_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} runq_enqueued SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, MAX_EVENT_ENTRIES);
} events SEC(".maps");

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

u64 get_task_cgroup_id(struct task_struct *task) {
    bpf_rcu_read_lock();
    u64 cgroup_id = task->cgroups->dfl_cgrp->kn->id;
    bpf_rcu_read_unlock();
    return cgroup_id;
}

SEC("tp_btf/sched_wakeup")
int tp_sched_wakeup(u64 *ctx) {
    struct task_struct *task = (void *) ctx[0];
    u32 pid = task->pid;
    u64 ktime = bpf_ktime_get_ns();

    bpf_map_update_elem(&runq_enqueued, &pid, &ktime, BPF_NOEXIST);

    return 0;
}

SEC("tp_btf/sched_switch")
int tp_sched_switch(u64 *ctx) {
    struct task_struct *prev = (struct task_struct *) ctx[1];
    struct task_struct *next = (struct task_struct *) ctx[2];
    u32 prev_pid = prev->pid;
    u32 next_pid = next->pid;

    // fetch timestamp of when the next task was enqueued
    u64 *tsp = bpf_map_lookup_elem(&runq_enqueued, &next_pid);
    if (tsp == NULL) return 0;  // missed enqueue

    // calculate runq latency before deleting the stored timestamp
    u64 now = bpf_ktime_get_ns();
    u64 runq_latency = now - *tsp;

    // delete pid from enqueued map
    bpf_map_delete_elem(&runq_enqueued, &next_pid);

    // PID 0 belongs to an idle process, called swapper.
    // Previous cgroup is used to track preemptions, so we skip cases when
    // idle process gets preempted by recording a special value instead.
    u64 prev_cgroup_id = prev_pid == 0 ? __UINT64_MAX__ : get_task_cgroup_id(prev);
    u64 cgroup_id = get_task_cgroup_id(next);

    struct runq_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event) {
        event->prev_cgroup_id = prev_cgroup_id;
        event->cgroup_id = cgroup_id;
        event->runq_latency = runq_latency;
        event->ktime = now;
        bpf_ringbuf_submit(event, 0);
    }

    return 0;
}
