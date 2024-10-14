// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include <vmlinux.h>
// Don't reorder
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "latency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define RATE_LIMIT_NS 500000  // 500us

#define MAX_RUNQ_ENTRIES 16384
#define MAX_CGROUP_ENTRIES 8192
#define MAX_EVENT_ENTRIES 131072

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_RUNQ_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} runq_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, MAX_CGROUP_ENTRIES);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
} cgroup_last_ts SEC(".maps");

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
    struct task_struct *task = (struct task_struct *) ctx[0];
    u32 pid = task->pid;
    u64 ktime = bpf_ktime_get_ns();

    bpf_map_update_elem(&runq_tasks, &pid, &ktime, BPF_NOEXIST);

    return 0;
}

SEC("tp_btf/sched_switch")
int tp_sched_switch(u64 *ctx) {
    struct task_struct *prev = (struct task_struct *) ctx[1];
    struct task_struct *next = (struct task_struct *) ctx[2];
    u32 prev_pid = prev->pid;
    u32 next_pid = next->pid;

    // Get previous timestamp
    u64 *task_ts = bpf_map_lookup_elem(&runq_tasks, &next_pid);
    if (task_ts == NULL) return 0;

    u64 now = bpf_ktime_get_ns();
    u64 latency = now - *task_ts;

    bpf_map_delete_elem(&runq_tasks, &next_pid);

    u64 cgroup_id = get_task_cgroup_id(next);

    // Rate limiting
    u64 *group_ts = bpf_map_lookup_elem(&cgroup_last_ts, &cgroup_id);
    if (group_ts != NULL && now - *group_ts < RATE_LIMIT_NS) return 0;
    bpf_map_update_elem(&cgroup_last_ts, &cgroup_id, &now, BPF_ANY);

    // Submitting event
    struct runq_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (event == NULL) return 0;

    // PID 0 belongs to an idle process, called swapper.
    // Previous cgroup is used to track preemptions, so we skip cases when
    // idle process gets preempted by recording a special value instead.
    event->prev_cgroup_id = prev_pid == 0 ? __UINT64_MAX__ : get_task_cgroup_id(prev);
    event->cgroup_id = cgroup_id;
    event->runq_latency = latency;
    event->ktime = now;
    bpf_ringbuf_submit(event, 0);

    return 0;
}
