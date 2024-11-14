#include <scx/common.bpf.h>
#include <linux/sched.h>
#include "scx_ml.h"

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
  __uint(max_entries, 2); /* [dead, revived] */
} stats SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH); 
  __uint(key_size, sizeof(pid_t));
  __uint(value_size, sizeof(struct task_sched_data));
  __uint(max_entries, 256);
} tasks SEC(".maps");

static void stat_inc(u32 idx) {
  u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
  if (cnt_p)
    (*cnt_p)++;
}

static inline bool vtime_before(u64 a, u64 b) { return (s64)(a - b) < 0; }

s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu,
                   u64 wake_flags) {
  bool is_idle = false;
  s32 cpu;

  cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
  if (is_idle) {
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
  }

  return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags) {
	// Collect process data
	

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

    scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
  }
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev) {
  scx_bpf_consume(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p) {
  // Collect data about process

// Look up the task in the map
  struct task_sched_data *tsk_ptr = bpf_map_lookup_elem(&tasks, &p->pid);

  if (tsk_ptr == NULL) {  // If no entry exists, create a new task_data entry
    struct task_sched_data tsk = {};

    // Populate the task data
    bpf_get_current_comm(tsk.name, sizeof(tsk.name));  // Get the task name (comm)
    tsk.start_time = bpf_ktime_get_ns();

    // Copy the task data into the map
    bpf_map_update_elem(&tasks, &p->pid, &tsk, BPF_ANY);  // Insert the data
  }

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

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable) {

  // Extract data from task struct
  if (p->exit_state == EXIT_DEAD || p->exit_state == EXIT_ZOMBIE) {
    stat_inc(0); // task died, complete its execution time
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

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p) {
  p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init) {
  return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei) {
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_ops, .select_cpu = (void *)simple_select_cpu,
               .enqueue = (void *)simple_enqueue,
               .dispatch = (void *)simple_dispatch,
               .running = (void *)simple_running,
               .stopping = (void *)simple_stopping,
               .enable = (void *)simple_enable, .init = (void *)simple_init,
               .exit = (void *)simple_exit, .name = "simple");
