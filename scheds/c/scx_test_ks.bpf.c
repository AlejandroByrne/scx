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

volatile u64 nr_enqueued;

volatile u64 nr_sent;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} finalized SEC(".maps");

static u64 test_operation(u64 num) {
	// time start
	u64 result = (num / 2) + 1;
	// time end
	return result;
}

s32 BPF_STRUCT_OPS(test_ks_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	return cpu;
}

void BPF_STRUCT_OPS(test_ks_enqueue, struct task_struct *p, u64 enq_flags)
{
	// Send data
	struct struct_data data = {.data = p->recent_used_cpu, .time_start = bpf_ktime_get_ns()};
	// Wait for response
	u64 result = test_operation(data.data);
	data.time_end = bpf_ktime_get_ns();
	data.elapsed_ns = data.time_end - data.time_start;
	bpf_map_push_elem(&finalized, &data, 0);
	__sync_fetch_and_add(&nr_sent, 1);
	// Dispatch
	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
}

void BPF_STRUCT_OPS(test_ks_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(test_ks_running, struct task_struct *p)
{
	return;
}

void BPF_STRUCT_OPS(test_ks_stopping, struct task_struct *p, bool runnable)
{
	return;
}

void BPF_STRUCT_OPS(test_ks_enable, struct task_struct *p)
{
	return;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(test_ks_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(test_ks_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(test_ks_ops,
	       .select_cpu		= (void *)test_ks_select_cpu,
	       .enqueue			= (void *)test_ks_enqueue,
	       .dispatch		= (void *)test_ks_dispatch,
	       .running			= (void *)test_ks_running,
	       .stopping		= (void *)test_ks_stopping,
	       .enable			= (void *)test_ks_enable,
	       .init			= (void *)test_ks_init,
	       .exit			= (void *)test_ks_exit,
	       .name			= "test_ks");
