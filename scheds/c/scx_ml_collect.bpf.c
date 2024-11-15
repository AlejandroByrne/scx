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
#include "task_sched_data.h"
#include <sched.h>

#define EXIT_ZOMBIE 0x00000020
#define EXIT_DEAD 0x00000010

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dispatch_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could
 * just use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2);			/* [local, global] */
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(pid_t));
	__uint(value_size, sizeof(struct task_sched_data));
	__uint(max_entries, 256);
} task_data SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

s32 BPF_STRUCT_OPS(ml_collect_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		stat_inc(0);	/* count local queueing */
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(ml_collect_enqueue, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid;
	struct task_sched_data * tsk_ptr = bpf_map_lookup_elem(&task_data, &pid);
    if (tsk_ptr != NULL) { // already aware of this task (pid)
		bpf_printk("Found a pid that is already accounted for\n");
		// update data
		tsk_ptr->nr_migrations = p->se.nr_migrations;
		tsk_ptr->vruntime = p->se.vruntime;
		tsk_ptr->min_flt = p->min_flt;
		tsk_ptr->maj_flt = p->maj_flt;
		tsk_ptr->total_vm = p->mm->total_vm;
		tsk_ptr->hiwater_rss = p->mm->hiwater_rss;
		tsk_ptr->map_count = p->mm->map_count;
	} else { // new task, create and insert new data struct for it
		struct task_sched_data tsk_data = {.pid = p->pid, .start_time = p->start_time};
		//strncpy(tsk_data.name, p->comm, TASK_COMM_LEN);
		__builtin_memcpy(tsk_data.name, p->comm, sizeof(tsk_data.name));
		if (bpf_map_update_elem(&task_data, &pid, &tsk_data, BPF_NOEXIST) == 0) {
			bpf_printk("Successfully added a struct to the task_data hash map\n");
		} else {
			bpf_printk("Adding a struct to the task_data hash map failed\n");
		}
	}

	stat_inc(1);	/* count global queueing */

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

void BPF_STRUCT_OPS(ml_collect_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(ml_collect_running, struct task_struct *p)
{
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (vtime_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(ml_collect_stopping, struct task_struct *p, bool runnable)
{
	// is the task finished? If so, collect exit stats
	if (p->exit_state == EXIT_ZOMBIE || p->__state == EXIT_DEAD) {
		// there is useful exit data to collect, find the task_sched_data struct and update it
		pid_t pid = p->pid;
	    struct task_sched_data * tsk_ptr = bpf_map_lookup_elem(&task_data, &pid);
		if (tsk_ptr != NULL) {
			
		} else {
			// this should be an issue. The task should not be finishing before we have even become aware of it.
		}
	}

	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(ml_collect_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(ml_collect_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(ml_collect_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(ml_collect_ops,
	       .select_cpu		= (void *)ml_collect_select_cpu,
	       .enqueue			= (void *)ml_collect_enqueue,
	       .dispatch		= (void *)ml_collect_dispatch,
	       .running			= (void *)ml_collect_running,
	       .stopping		= (void *)ml_collect_stopping,
	       .enable			= (void *)ml_collect_enable,
	       .init			= (void *)ml_collect_init,
	       .exit			= (void *)ml_collect_exit,
	       .name			= "ml_collect");
