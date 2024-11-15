// #include <sched.h>

#define TASK_COMM_LEN 16

struct task_sched_data {
    // Task attributes
    // Identification
    char name[TASK_COMM_LEN]; // Ale down
    int pid;
    int rq_idx;
    u64 last_sum_exec_runtime;
    u64 total_numa_faults;
    u64 blkio_start; // Deadline attribtues, anthony down
	u64 blkio_delay; // Anthony, and down
	u64 swapin_delay;
	u32 blkio_count;
	u32 swapin_count;
	u64 freepages_start;
	u64 freepages_delay;
	u64 thrashing_start;
	u64 thrashing_delay;
	u32 freepages_count;
	u32 thrashing_count;
    int stack_refcount;

    // Sched entity counters
    long unsigned int weight; // ale, and down
    u32 inv_weight;
    //u64 deadline;
    u64 vruntime;
    u64 sum_exec_runtime;
    u64 prev_sum_exec_runtime;
    u64 nr_migrations;

    // Sched stats counters
    u64 wait_start; // Anthony down
    u64 wait_max;
    u64 wait_count;
    u64 wait_sum;
    u64 iowait_count;
    u64 iowait_sum;
    u64 sleep_start;
    u64 sleep_max;
    u64 sum_sleep_runtime;
    u64 block_start;
    u64 block_max;
    u64 start_time; // added by Ale
    u64 end_time; // added by Ale
    u64 execution_time; // added by Ale

    u64 run_delay; // Anthony down
    u64 last_arrival;
    u64 last_queued;

    // Memory counters
    u32 min_flt; // ale and down
    u32 maj_flt;
    u32 total_vm;
    u32 hiwater_rss;
    int map_count;

};
