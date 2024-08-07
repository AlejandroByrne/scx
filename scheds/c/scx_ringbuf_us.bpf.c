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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 16);
} sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 256);
	__type(value, struct struct_data);
} returned SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 16);
} time_data SEC(".maps");

static bool is_user_task(const struct task_struct *p)
{
	return p->pid == usertask_pid;
}

s32 BPF_STRUCT_OPS(ringbuf_us_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !is_user_task(p)) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(ringbuf_us_enqueue, struct task_struct *p, u64 enq_flags)
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

void BPF_STRUCT_OPS(ringbuf_us_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(ringbuf_us_running, struct task_struct *p)
{
	// Check the inbox!
	struct struct_data returned_value;
	bpf_repeat(16) { // parameter indicates the maximum loop iterations, since it breaks if there is nothing to poll
		if (bpf_map_pop_elem(&returned, &returned_value) < 0) {
			break;
		}
		u64 time_done = bpf_ktime_get_ns();
		returned_value.time_end = time_done;
		returned_value.elapsed_ns = time_done - returned_value.time_start;
		u64 * time;
		time = bpf_ringbuf_reserve(&time_data, sizeof(*time), 0);
		if (!time) return;
		*time = returned_value.elapsed_ns;
		bpf_ringbuf_submit(time, 0);
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
		struct struct_data *d;
		d = bpf_ringbuf_reserve(&sent, sizeof(*d), 0);
		if (!d) return;
		d->time_start = time_now;
		d->data = 10;
		bpf_ringbuf_submit(d, 0);
		__sync_fetch_and_add(&nr_sent, 1);
		__sync_fetch_and_or(&user_task_needed, 1);
		time_prev = bpf_ktime_get_ns();
	}

	//if (user_task_needed) dispatch_user_scheduler();
	return;
}

void BPF_STRUCT_OPS(ringbuf_us_stopping, struct task_struct *p, bool runnable)
{
	if (nr_sent > nr_returned) {
		__sync_fetch_and_or(&user_task_needed, 1);
	} else {
		__sync_fetch_and_or(&user_task_needed, 0);
	}
	return;
}

void BPF_STRUCT_OPS(ringbuf_us_enable, struct task_struct *p)
{

}

s32 BPF_STRUCT_OPS_SLEEPABLE(ringbuf_us_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(ringbuf_us_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(ringbuf_us_ops,
	       .select_cpu		= (void *)ringbuf_us_select_cpu,
	       .enqueue			= (void *)ringbuf_us_enqueue,
	       .dispatch		= (void *)ringbuf_us_dispatch,
	       .running			= (void *)ringbuf_us_running,
	       .stopping		= (void *)ringbuf_us_stopping,
	       .enable			= (void *)ringbuf_us_enable,
	       .init			= (void *)ringbuf_us_init,
	       .exit			= (void *)ringbuf_us_exit,
	       .name			= "ringbuf_us");