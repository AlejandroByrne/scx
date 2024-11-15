/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <scx/common.h>
#include "task_sched_data.h"
#include "scx_ml_collect.bpf.skel.h"

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

static void print_stats(struct scx_ml_collect * skel) {
	pid_t * cur_pid = NULL;
	pid_t next_pid;
	int err = bpf_map_get_next_key(bpf_map__fd(skel->maps.task_data), cur_pid, &next_pid);
	struct task_sched_data tsk_ptr;
	while (!err) {
		printf("err value: %d\n", err);
		int result = bpf_map_lookup_elem(bpf_map__fd(skel->maps.task_data), &next_pid, &tsk_ptr);
		printf("result value: %d\n", result);
		printf("NAME: %s, PID: %d, MIN_FLT: %u\n", tsk_ptr.name, tsk_ptr.pid, tsk_ptr.min_flt);
		cur_pid = &next_pid;
		err = bpf_map_get_next_key(bpf_map__fd(skel->maps.task_data), cur_pid, &next_pid);
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
		// __u64 stats[2];
		print_stats(skel);
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