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

const volatile s32 usertask_pid;

static volatile s32 user_task_needed;
volatile u64 nr_returned;
volatile u64 nr_sent;
static u64 time_prev;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 16);
	__type(value, u64);
} sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 16);
	__type(value, u64);
} returned SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 256);
	__type(value, struct time_datum);
} time_data SEC(".maps");

// static struct task_struct *usersched_task(void)
// {
// 	struct task_struct *p;

// 	p = bpf_task_from_pid(usertask_pid);
// 	/*
// 	 * Should never happen -- the usersched task should always be managed
// 	 * by sched_ext.
// 	 */
// 	if (!p)
// 		scx_bpf_error("Failed to find usersched task %d", usertask_pid);

// 	return p;
// }

static bool is_user_task(const struct task_struct *p)
{
	return p->pid == usertask_pid;
}

// static void dispatch_user_scheduler(void)
// {
// 	struct task_struct *p;

// 	p = usersched_task();
// 	if (p) {
// 		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
// 		bpf_task_release(p);
// 	}
// }

s32 BPF_STRUCT_OPS(test_us_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !is_user_task(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(test_us_enqueue, struct task_struct *p, u64 enq_flags)
{
	// Only dispatch the userspace task if it is needed
	if (is_user_task(p)) {
		if (user_task_needed) {
			scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		} else {
			return;
		}
	} else {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	}
	
}

void BPF_STRUCT_OPS(test_us_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(test_us_running, struct task_struct *p)
{
	// Check the inbox!
	u64 returned_value;
	bpf_repeat(16) { // parameter indicates the maximum loop iterations, since it breaks if there is nothing to poll
		if (bpf_map_pop_elem(&returned, &returned_value) < 0) {
			break;
		}
		struct time_datum td;
		bpf_map_pop_elem(&time_data, &td);
		u64 time_done = bpf_ktime_get_ns();
		__sync_fetch_and_add(&nr_returned, 1);
	}
	__sync_fetch_and_or(&user_task_needed, 0);
	/* TODO
	Find a more efficient way of calculating if approximately 1 second has passed
	Use bit manipulation for the check.
	*/
	if (bpf_ktime_get_ns() - time_prev >= 1000000000) { // have 1000000000 nanoseconds passed?
		// Fill the ringbuffer with some input for the user-space task to poll (just a number to indicate that a second has passed)
		u64 time_now = bpf_ktime_get_ns();
		u64 input1 = 10;
		if (bpf_map_push_elem(&sent, &input1, 0) == 0) {
			__sync_fetch_and_add(&nr_sent, 1);
			__sync_fetch_and_or(&user_task_needed, 1);
		}
		time_prev = bpf_ktime_get_ns();
	}

	//if (user_task_needed) dispatch_user_scheduler();
	return;
}

void BPF_STRUCT_OPS(test_us_stopping, struct task_struct *p, bool runnable)
{
	if (nr_sent > nr_returned) {
		__sync_fetch_and_or(&user_task_needed, 1);
	} else {
		__sync_fetch_and_or(&user_task_needed, 0);
	}
	return;
}

void BPF_STRUCT_OPS(test_us_enable, struct task_struct *p)
{

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
