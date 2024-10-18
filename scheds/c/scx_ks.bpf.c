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
#include "bpf/bpf_helpers.h"
#include "scx_test_ks.h"

char _license[] SEC("license") = "GPL";

volatile u64 start_time;
volatile u64 end_time;
volatile u64 running_start;
volatile u64 total_time;
volatile u64 total_running_time;

volatile s32 usertask_pid;

volatile u64 nr_returned;
volatile u64 nr_sent;
volatile u64 nr_missed;
volatile u64 nr_queues;
volatile u64 nr_errors;
volatile u64 num_running;
volatile u64 num_stopping;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} finalized SEC(".maps");

static bool is_user_task(const struct task_struct *p)
{
	return p->pid == usertask_pid;
}


s32 BPF_STRUCT_OPS(ks_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	//if (is_user_task(p)) { // user space task isolated to cpu 4
	 //	return 4;
	//}
	bool is_idle = false;
	s32 cpu;
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	// if (cpu == 4) { // ensure no other tasks get set to cpu 4
	// 	return cpu - 1;
	// }
	return cpu;
}

static u64 test_operation(u64 num) {
	return (num / 2) + 1;
}

void BPF_STRUCT_OPS(ks_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (is_user_task(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
		return;
	}
	// Send data
	struct struct_data data = {.pid = p->pid, .data = p->recent_used_cpu, .time_start = bpf_ktime_get_ns()};

	data.data = test_operation(data.data);

	data.time_end = bpf_ktime_get_ns();

	data.elapsed_ns = data.time_end - data.time_start;

	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);

	bpf_map_push_elem(&finalized, &data, 0);
}

void BPF_STRUCT_OPS(ks_dispatch, s32 cpu, struct task_struct *prev)
{
	if (scx_bpf_consume(SHARED_DSQ) == false) {
		
	} else {
		__sync_fetch_and_add(&nr_queues, 1);
	}
}

void BPF_STRUCT_OPS(ks_running, struct task_struct *p)
{
	if (is_user_task(p)) {
		running_start = bpf_ktime_get_ns();
		bpf_printk("Start: %llu\n", running_start);
		__sync_fetch_and_add(&num_running, 1);
	}
	return;
}

void BPF_STRUCT_OPS(ks_stopping, struct task_struct *p, bool runnable)
{
	if (is_user_task(p)) {
		if (num_stopping == 0) {
			total_running_time = 0;
			bpf_printk("First time setting total_running_time: %llu\n", total_running_time);
			__sync_fetch_and_add(&num_stopping, 1);
			return;
		}
		total_time = bpf_ktime_get_ns();
		bpf_printk("Time:%llu\n", total_time);
		u64 elapsed_time = (total_time - running_start); // time in milliseconds
		// bpf_printk("Stop: %llu\n", time);
		bpf_printk("TOT RUN: %llu\n", total_running_time);
		bpf_printk("Elapsed: %llu\n", elapsed_time);
		total_running_time += elapsed_time;
		bpf_printk("Total running time: %llu\n", total_running_time);
		// This is almost always 20 milliseconds
		__sync_fetch_and_add(&num_stopping, 1);
	}
	return;
}

void BPF_STRUCT_OPS(ks_enable, struct task_struct *p)
{
	return;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ks_init)
{
	total_running_time = 0;
	running_start = 0;

	start_time = bpf_ktime_get_ns();
	bpf_printk("Start time: %llu\n", start_time);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(ks_exit, struct scx_exit_info *ei)
{
	end_time = bpf_ktime_get_ns();
	total_time = end_time - start_time;
	bpf_printk("End time: %llu\n", end_time);
	bpf_printk("Total time: %llu\n", total_time);
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(ks_ops,
	       .select_cpu		= (void *)ks_select_cpu,
	       .enqueue			= (void *)ks_enqueue,
	       .dispatch		= (void *)ks_dispatch,
	       .running			= (void *)ks_running,
	       .stopping		= (void *)ks_stopping,
	       .enable			= (void *)ks_enable,
	       .init			= (void *)ks_init,
	       .exit			= (void *)ks_exit,
	       .name			= "ks");
