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
#include <scx/common.h>
#include <sched.h>
#include "scx_test.bpf.skel.h"

const char help_fmt[] =
"A simple scheduler used for user-space function calls and overhead measurement.\n"
"The purpose is to figure out the feasibility of implementing an ML interface that\n"
"invokes user-space functions for inferences.\n"
"\n"
"The scheduling policy behind the testing purpose is simple weighted vtime.\n"
"\n"
"Usage: %s [-f] [-v] [-p]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -p			 Run the scheduler in partial mode\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int test)
{
	exit_req = 1;
}

static void read_stats(struct scx_test *skel, __u64 *stats)
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

int handle_event(void *ctx, void *data, size_t data_sz) {
	const u32 * input = data;
	printf("The value polled from the ring buffer is %d", *input);
	return input;
}

int main(int argc, char **argv)
{
	struct ring_buffer * rb = NULL;
	struct scx_test *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	// Schedule this user-space task with SCHED_EXT
	struct sched_param sched_param;
	sched_param.sched_priority = sched_get_priority_max(SCHED_EXT);
	int err = syscall(__NR_sched_setscheduler, getpid(), SCHED_EXT, &sched_param);
	SCX_BUG_ON(err, "Failed to set scheduler to SCHED_EXT");

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(test_ops, scx_test);

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "Failed to create ring buffer \n");
		goto cleanup;
	}

	while ((opt = getopt(argc, argv, "fvhp")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
		case 'p':
			skel->struct_ops.test_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, test_ops, scx_test, uei);
	link = SCX_OPS_ATTACH(skel, test_ops, scx_test);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		/* This is the code that gets run every time this task gets scheduled */
		// __u64 stats[2];

		// read_stats(skel, stats);
		// printf("local=%llu global=%llu\n", stats[0], stats[1]);

		/* Consume data from BPF ringbuffer when it becomes available */
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}

		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_test__destroy(skel);

cleanup:
	ring_buffer__free(rb);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
