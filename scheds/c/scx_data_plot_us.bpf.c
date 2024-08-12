#include <scx/common.bpf.h>
#include "scx_test_ks.h"

char _license[] SEC("license") = "GPL";

volatile s32 usertask_pid;
volatile u32 other_task;
volatile u64 nr_enqueued;
volatile u64 nr_tasks;
volatile u64 nr_sent;
volatile u64 nr_returned;
volatile u64 time_start;
volatile u32 user_task_needed;

static u64 time_prev;

UEI_DEFINE(uei);

#define SHARED_DSQ 0

#define EXIT_ZOMBIE 0x00000020
#define EXIT_DEAD 0x00000010
#define TASK_DEAD 0x00000080

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, u64);
} sent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, u64);
} returned SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 1024);
	__type(value, struct struct_data);
} finalized SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 1024);
        __type(key, pid_t);
        __type(value, u64);
} tasks_hm SEC(".maps");

static bool is_user_task(const struct task_struct *p)
{
	return p->pid == usertask_pid;
}

s32 BPF_STRUCT_OPS(data_plot_us_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}

	return cpu;
}

void BPF_STRUCT_OPS(data_plot_us_enqueue, struct task_struct *p, u64 enq_flags)
{
	__sync_fetch_and_add(&nr_enqueued, 1);
	// Check if this specific task has been seen before, if not, increment counter and add to HM
	pid_t pid = p->pid;
	u64 start_time = p->start_time;
	u64 * value = bpf_map_lookup_elem(&tasks_hm, &pid);
	if (value != NULL) {
		if (*value != start_time) {
			bpf_map_update_elem(&tasks_hm, &pid, &start_time, BPF_NOEXIST);
			__sync_fetch_and_add(&nr_tasks, 1);
		}
	} else {
		bpf_map_update_elem(&tasks_hm, &pid, &start_time, BPF_NOEXIST);
		__sync_fetch_and_add(&nr_tasks, 1);
	}

	if (is_user_task(p) && user_task_needed) {
		// user-space task skips the line
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
	} else {
		__sync_fetch_and_or(&other_task, 1);
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	}
	
}

void BPF_STRUCT_OPS(data_plot_us_dispatch, s32 cpu, struct task_struct *prev)
{
    __sync_fetch_and_add(&nr_enqueued, 1);
	scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(data_plot_us_running, struct task_struct *p)
{
	// Check the inbox!
	struct struct_data returned_value;
	bpf_repeat(16) { // parameter indicates the maximum loop iterations, since it breaks if there is nothing to poll
		if (bpf_map_pop_elem(&returned, &returned_value) < 0) {
			break;
		}
		returned_value.time_end = bpf_ktime_get_ns();
		returned_value.elapsed_ns = returned_value.time_end - returned_value.time_start;
		bpf_map_push_elem(&finalized, &returned_value, 0);
		__sync_fetch_and_add(&nr_returned, 1);
	}
	__sync_fetch_and_or(&user_task_needed, 0);

	struct struct_data data = {.time_start = bpf_ktime_get_ns(), .data = 10};
	
	if (bpf_map_push_elem(&sent, &data, 0) == 0) {
		__sync_fetch_and_add(&nr_sent, 1);
		__sync_fetch_and_or(&user_task_needed, 1);
	}
	time_prev = bpf_ktime_get_ns();

	//if (user_task_needed) dispatch_user_scheduler();
	return;
}

void BPF_STRUCT_OPS(data_plot_us_stopping, struct task_struct *p, bool runnable)
{
	pid_t pid = p->pid;
	if (p->exit_state == EXIT_ZOMBIE || p->exit_state == EXIT_DEAD || p->__state == TASK_DEAD) {
		bpf_map_delete_elem(&tasks_hm, &pid);
		__sync_fetch_and_sub(&nr_tasks, 1);
	}
	return;
}

void BPF_STRUCT_OPS(data_plot_us_enable, struct task_struct *p)
{
	return;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(data_plot_us_init)
{
	__sync_fetch_and_or(&other_task, 0);
	__sync_fetch_and_or(&user_task_needed, 0);
    time_start = bpf_ktime_get_ns();
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(data_plot_us_exit, struct scx_exit_info *ei)
{
	scx_bpf_destroy_dsq(SHARED_DSQ);
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(data_plot_us_ops,
	       .select_cpu		= (void *)data_plot_us_select_cpu,
	       .enqueue			= (void *)data_plot_us_enqueue,
	       .dispatch		= (void *)data_plot_us_dispatch,
	       .running			= (void *)data_plot_us_running,
	       .stopping		= (void *)data_plot_us_stopping,
	       .enable			= (void *)data_plot_us_enable,
	       .init			= (void *)data_plot_us_init,
	       .exit			= (void *)data_plot_us_exit,
	       .name			= "data_plot_us");