/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <linux/sysinfo.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "task_sched_data.h"
#include "scx_ml_collect.bpf.skel.h"

#define PRINT_DEBUG

const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct scx_ml_collect *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

static void print_task_stats (struct task_sched_data * tsk_ptr) {
	printf("------------------>>>>>     TASK: %-20s  <<<<<-----------------------\n", tsk_ptr->name);
	printf("---------------------------------------------\n");
	printf("PID: %d, DONE YET? %s, EXEC_TIME: %lu\n", tsk_ptr->pid, tsk_ptr->execution_time == 0 ? "false" : "true", tsk_ptr->execution_time);
	printf("-----------------------       Memory Stats      ---------------------\n");
	printf("MIN_FLT: %u, MAJ_FLT: %u, TOTAL_VM: %u, MAP_COUNT: %u, HIWATER_RSS: %u\n", tsk_ptr->min_flt, tsk_ptr->maj_flt, tsk_ptr->total_vm, tsk_ptr->map_count, tsk_ptr->hiwater_rss);
	printf("-----------------------       CPU Stats         ---------------------\n");
	printf("NUMA_FLTS: %lu, \n", tsk_ptr->total_numa_faults);
	printf("STACK_REF_CNT: %d\n", tsk_ptr->stack_refcount);
	printf("-----------------------     Timing Stats        ---------------------\n");
	printf("WEIGHT: %lu, INV_WEIGHT: %u\n", tsk_ptr->weight, tsk_ptr->inv_weight);
	printf("VRUNTIME: %lu, NR_MIGRATIONS: %lu, PREV_SUM_EXEC_RTIME: %lu, CUR_SUM_EXEC_RTIME: %lu\n", tsk_ptr->vruntime, tsk_ptr->nr_migrations, tsk_ptr->prev_sum_exec_runtime, tsk_ptr->sum_exec_runtime);
	printf("-----------------------   Deadline Attributes   ---------------------\n");
	printf("BLKIO_START: %lu, BLKIO_DELAY: %lu, SWAPIN_DELAY: %lu, BLKIO_CNT: %u\n", tsk_ptr->blkio_start, tsk_ptr->blkio_delay, tsk_ptr->swapin_delay, tsk_ptr->blkio_count);
	printf("SWAPIN_CNT: %u, FREEPAGES_START: %lu, FREEPAGES_DELAY: %lu\n", tsk_ptr->swapin_count, tsk_ptr->freepages_start, tsk_ptr->freepages_delay);
	printf("THRASHING_CNT: %lu, THRASHING_DELAY: %lu\n", tsk_ptr->thrashing_start, tsk_ptr->thrashing_delay);
	printf("FREEPAGES_CNT: %u, THRASHING_CNT: %u\n", tsk_ptr->freepages_count, tsk_ptr->thrashing_count);
	printf("-----------------------   Scheduler Statistics Counters   ---------------------\n");
	printf("WAIT_START: %lu, WAIT_MAX: %lu, WAIT_CNT: %lu, WAIT_SUM: %lu\n", tsk_ptr->wait_start, tsk_ptr->wait_max, tsk_ptr->wait_count, tsk_ptr->wait_sum);
	printf("IOWAIT_CNT: %lu, IOWAIT_SUM: %lu\n", tsk_ptr->iowait_count, tsk_ptr->iowait_sum);
	printf("SLEEP_START: %lu, SLEEP_MAX: %lu, SUM_SLEEP_RUNTIME: %lu\n", tsk_ptr->sleep_start, tsk_ptr->sleep_max, tsk_ptr->sum_sleep_runtime);
	printf("BLOCK_START: %lu, BLOCK_MAX: %lu\n", tsk_ptr->block_start, tsk_ptr->block_max);
	printf("RUN_DELAY: %lu, LAST_ARRIVAL: %lu, LAST_QUEUED: %lu\n", tsk_ptr->run_delay, tsk_ptr->last_arrival, tsk_ptr->last_queued);
	printf("---------------------------------------------\n\n");
}

static void print_sysinfo_stats(struct sysinfo *info) {
	printf("********************** SYSTEM STATS **********************\n");
	printf("UPTIME: %ld\n", info->uptime);
	printf("TOTAL_RAM: %lu, FREE_RAM: %lu, SHARED_RAM: %lu, BUFFER_RAM: %lu\n", info->totalram, info->freeram, info->sharedram, info->bufferram);
	printf("TOTAL_SWAP: %lu, FREE_SWAP: %lu\n", info->totalswap, info->freeswap);
	printf("# PROCESSES: %hu\n", info->procs);
	printf("TOTAL_HIGH: %lu\n", info->totalhigh);
	printf("FREE_HIGH: %lu\n", info->freehigh);
	printf("**********************************************************\n\n");
}

static void print_stats(struct scx_ml_collect * skel) {
	#ifdef PRINT_DEBUG
	print_sysinfo_stats(&skel->bss->system_information);
	#endif
	pid_t * cur_pid = NULL;
	pid_t next_pid;
	int err = bpf_map_get_next_key(bpf_map__fd(skel->maps.task_data), cur_pid, &next_pid);
	struct task_sched_data tsk_ptr;
	while (!err) {
		//printf("err value: %d\n", err);
		int result = bpf_map_lookup_elem(bpf_map__fd(skel->maps.task_data), &next_pid, &tsk_ptr);
		//printf("result value: %d\n", result);
		if (result) {
			break;
		}
		#ifdef PRINT_DEBUG
		print_task_stats(&tsk_ptr);
		#endif
		cur_pid = &next_pid;
		err = bpf_map_get_next_key(bpf_map__fd(skel->maps.task_data), cur_pid, &next_pid);
	}
}

static void update_system_wide_data(struct scx_ml_collect *skel) {
	// Try putting the system information in a temporary struct then copying
	// it to the system_information struct in the skeleton (worried about
	// issues with mmapped data being passed into a system call)

	// TODO: See if this copying is even necessary
	struct sysinfo gathered_sysinfo;
	if (sysinfo(&gathered_sysinfo) == 0) {
		skel->bss->system_information = gathered_sysinfo;
	}
}

int main(int argc, char **argv)
{
	struct scx_ml_collect *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(ml_collect_ops, scx_ml_collect);

	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, ml_collect_ops, scx_ml_collect, uei);
	link = SCX_OPS_ATTACH(skel, ml_collect_ops, scx_ml_collect);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		update_system_wide_data(skel);
		// __u64 stats[2];
		#ifdef PRINT_DEBUG
		print_stats(skel);
		#endif
		// read_stats(skel, stats);
		// printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_ml_collect__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
