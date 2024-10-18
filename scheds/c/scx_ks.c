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
#include "scx_ks.bpf.skel.h"
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

static time_t time_prev = 0;
static float sum_elapsed_time = 0;
static u32 num_data_points = 0;
static time_t interval_ns = 1000000000;
static u32 time_counter = 0;

static u64 old_total_time = 0;
static u64 old_userspace_time = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static time_t ts_to_ns (struct timespec * ts) {
	return ts->tv_sec * 1000000000 + ts->tv_nsec;
}

static void sigint_handler(int test)
{
	exit_req = 1;
}

static void live_stats(struct scx_ks * skel, struct timespec * ts) {
	// Collecting statistics and printing to STDOUT
	if (clock_gettime(CLOCK_MONOTONIC, ts) == 0) {
		// printf("%ld, %ld\n", time_prev, ts_n.tv_nsec);
		// printf("%ld - %ld = %ld\n", ts.tv_sec, time_prev, ts.tv_sec - time_prev);
		time_t time_now = ts_to_ns(ts);
		if ((time_now - time_prev) >= interval_ns) {
			float average_elapsed_ns = sum_elapsed_time / num_data_points;
			u64 userspace_time = skel->bss->total_running_time - old_userspace_time;
			u64 total_time = skel->bss->total_time - old_total_time;
			// printf("%ld, %ld\n", userspace_time, total_time);
			double running_ratio_interval = (double) userspace_time / total_time;
			printf("%d, %d, %.2f, %.4f\n", time_counter, num_data_points, average_elapsed_ns, running_ratio_interval);
			// printf("%ld, %d", ts.tv_nsec);
			old_userspace_time = skel->bss->total_running_time;
			old_total_time = skel->bss->total_time;

			sum_elapsed_time = 0;
			num_data_points = 0;
			time_prev += interval_ns;
			++time_counter;
		}
	}
}

static void final_stats(struct scx_ks * skel) {
	printf("Sent: %ld Returned: %ld Missed: %ld\n", skel->bss->nr_sent, skel->bss->nr_returned, skel->bss->nr_missed);
	printf("Number of enqueues: %ld\n", skel->bss->nr_queues);
	printf("Number of errors: %ld\n", skel->bss->nr_errors);

	double running_ratio = (double) skel->bss->total_running_time / (skel->bss->total_time);
	// change the 208 number later to reflect the real-time average for user-space timeslice
	// the SCX_SLICE_DFL is 20000000ULL, so it makes sense that the average run time is around that

	printf("Num running: %lu, Num stopping: %lu\n", skel->bss->num_running, skel->bss->num_stopping);
	printf("Total running time (ns): %lu, Total time (ns): %lu\n", skel->bss->total_running_time, skel->bss->total_time);
	printf("User space task running time ratio: %f\n", running_ratio);
}

int main(int argc, char **argv)
{
	struct scx_ks *skel;
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
	// printf("PID: %d\nPlease press enter to continue", getpid());
	// getchar();
restart:
	skel = SCX_OPS_OPEN(ks_ops, scx_ks);
	
	SCX_OPS_LOAD(skel, ks_ops, scx_ks, uei);
	link = SCX_OPS_ATTACH(skel, ks_ops, scx_ks);

	skel->bss->usertask_pid = getpid();
	assert(skel->bss->usertask_pid > 0);

	old_total_time = skel->bss->start_time;
	

	while ((opt = getopt(argc, argv, "vhp")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'p':
			skel->struct_ops.ks_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	struct timespec ts;
	
    clock_gettime(CLOCK_MONOTONIC, &ts);
	time_prev = ts_to_ns(&ts);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		// Telemetry data collection and printing
		live_stats(skel, &ts);
		
		// Collect data, process it, and send it back to kernel space
        struct struct_data input;
		while (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.finalized), NULL, &input) == 0) {
			num_data_points++;
			// printf("%ld\n", input.elapsed_ns);
			sum_elapsed_time += (float) input.elapsed_ns; // convert to milliseconds
			printf("%ld\n", input.elapsed_ns);
		}

		fflush(stdout);
		//sleep(1);
	}

	// This funtion has to execute for 'exit' callback to be invoked from kernel space scheduler
	// Final computations on telemetry data are made in the 'exit' callback, so let this run first
	bpf_link__destroy(link);

	// final_stats(skel);


	ecode = UEI_REPORT(skel, uei);
	scx_ks__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
