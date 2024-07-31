/* SPDX-License-Identifier: GPL-2.0 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

#define SHARED_DSQ 0

s32 BPF_STRUCT_OPS(test_fifo_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(test_fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	
}

void BPF_STRUCT_OPS(test_fifo_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(test_fifo_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(test_fifo_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(test_fifo_ops,
	       .select_cpu		= (void *)test_fifo_select_cpu,
	       .enqueue			= (void *)test_fifo_enqueue,
	       .dispatch		= (void *)test_fifo_dispatch,
	       .init			= (void *)test_fifo_init,
	       .exit			= (void *)test_fifo_exit,
	       .name			= "test_fifo");