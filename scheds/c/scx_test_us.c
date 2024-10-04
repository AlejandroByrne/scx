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
#include <assert.h>
#include <sched.h>
#include <time.h>
#include "scx_test_us.bpf.skel.h"
#include "scx_test_ks.h"

#define SCHED_EXT 7

const char help_fmt[] =
"A test sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
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

static u64 test_operation(u64 num) {
	return (num / 2) + 1;
}

int main(int argc, char **argv)
{
	struct scx_test_us *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	struct sched_param param;
    param.sched_priority = 0; // SCHED_EXT may not use priority, but setting it to 0
    if (sched_setscheduler(0, SCHED_EXT, &param) == -1) {
        // fprintf(stderr, "Error setting scheduler for process %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
restart:
	skel = SCX_OPS_OPEN(test_us_ops, scx_test_us);
	
	SCX_OPS_LOAD(skel, test_us_ops, scx_test_us, uei);
	link = SCX_OPS_ATTACH(skel, test_us_ops, scx_test_us);

	skel->bss->usertask_pid = getpid();
	assert(skel->bss->usertask_pid > 0);
	
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	skel->bss->start_time = ((u64) ts.tv_sec * 1000000000ULL) + ts.tv_nsec;

	while ((opt = getopt(argc, argv, "vhp")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'p':
			skel->struct_ops.test_us_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t time_prev = ts.tv_sec;
    float sum_elapsed_time = 0;
    u32 num_data_points = 0;
    time_t interval_ns = 1;
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		//printf("Working\n");
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            // printf("%ld, %ld\n", time_prev, ts_n.tv_nsec);
            // printf("%ld - %ld = %ld\n", ts.tv_sec, time_prev, ts.tv_sec - time_prev);
            if ((ts.tv_sec - time_prev) >= interval_ns) {
                float average_elapsed_ns = sum_elapsed_time / num_data_points;
                printf("%ld, %d, %.2f\n", ts.tv_sec, num_data_points, average_elapsed_ns);
                // printf("%ld, %d", ts.tv_nsec);
                sum_elapsed_time = 0;
                num_data_points = 0;
                time_prev += interval_ns;
            }
        }
        struct struct_data input;
		while (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.sent), NULL, &input) == 0) {
			// printf("Value polled: %ld | ", input);
			input.data = test_operation(input.data);
			if (bpf_map_update_elem(bpf_map__fd(skel->maps.returned), NULL, &input, 0) == 0) {
				// printf("Value sent back: %ld | ", result);
			} else {
				printf("Task failed to be sent back\n");
			}
		}
		while (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.finalized), NULL, &input) == 0) {
			num_data_points++;
			// printf("%ld\n", input.elapsed_ns);
            sum_elapsed_time += (float) input.elapsed_ns / 100000; // convert to milliseconds
		}

		fflush(stdout);
		//sleep(1);
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	skel->bss->end_time = ((u64) ts.tv_sec * 1000000000ULL) + ts.tv_nsec;
	skel->bss->total_time = skel->bss->end_time - skel->bss->start_time;
	double running_ratio = skel->bss->total_running_time / skel->bss->total_time;
	printf("User space task running time ratio: %f\n", running_ratio);
	printf("Sent: %ld Returned: %ld Missed: %ld\n", skel->bss->nr_sent, skel->bss->nr_returned, skel->bss->nr_missed);
	printf("Number of enqueues: %ld\n", skel->bss->nr_queues);
	printf("Number of errors: %ld\n", skel->bss->nr_errors);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_test_us__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}