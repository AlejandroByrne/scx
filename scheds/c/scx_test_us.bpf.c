/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>
#include "scx_test_ks.h"

char _license[] SEC("license") = "GPL";

volatile s32 usertask_pid;

volatile s32 user_task_needed;
volatile u64 nr_returned;
volatile u64 nr_sent;
volatile u64 nr_missed;
volatile u64 nr_queues;
volatile u64 nr_errors;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} returned SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} finalized SEC(".maps");

static bool is_user_task(const struct task_struct *p)
{
	return p->pid == usertask_pid;
}


s32 BPF_STRUCT_OPS(test_us_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (user_task_needed && is_user_task(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(test_us_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_user_task(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
	// Send data
	struct struct_data data = {.pid = p->pid, .data = p->recent_used_cpu, .time_start = bpf_ktime_get_ns()};
	if (bpf_map_push_elem(&sent, &data, 0) == 0) {
		__sync_fetch_and_add(&nr_sent, 1);
	} else {
		__sync_fetch_and_add(&nr_errors, 1);
	}
	__sync_fetch_and_or(&user_task_needed, 1);
}

void BPF_STRUCT_OPS(test_us_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_consume(SHARED_DSQ) == false) {
		
	} else {
		__sync_fetch_and_add(&nr_queues, 1);
	}
	bpf_repeat(256) {
		// no ready tasks available to consume, poll for results from user space
		struct struct_data data;
		if (bpf_map_pop_elem(&returned, &data) == 0) {
			struct struct_data final = {.time_end = bpf_ktime_get_ns(), .data=data.data, .time_start=data.time_start, .pid = data.pid};
			final.elapsed_ns = final.time_end - final.time_start;
			struct task_struct * p = bpf_task_from_pid(final.pid);
			if (p) {
				scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
				bpf_task_release(p);
				__sync_fetch_and_add(&nr_returned, 1);
				bpf_map_push_elem(&finalized, &final, 0);
			} else {
				__sync_fetch_and_add(&nr_missed, 1);
			}
		} else {
			break;
		}
	}
}

void BPF_STRUCT_OPS(test_us_running, struct task_struct *p)
{
	if (nr_sent == nr_returned) {
		__sync_fetch_and_or(&user_task_needed, 0);
	}
	return;
}

void BPF_STRUCT_OPS(test_us_stopping, struct task_struct *p, bool runnable)
{
	return;
}

void BPF_STRUCT_OPS(test_us_enable, struct task_struct *p)
{
	return;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(test_us_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(test_us_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(test_us_ops,
	       .select_cpu		= (void *)test_us_select_cpu,
	       .enqueue			= (void *)test_us_enqueue,
	       .dispatch		= (void *)test_us_dispatch,
	       .running			= (void *)test_us_running,
	       .stopping		= (void *)test_us_stopping,
	       .enable			= (void *)test_us_enable,
	       .init			= (void *)test_us_init,
	       .exit			= (void *)test_us_exit,
	       .name			= "test_us");
