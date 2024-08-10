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
#include <sys/resource.h>
#include <assert.h>
#include <sched.h>
#include "scx_ringbuf_us.bpf.skel.h"
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

static struct ring_buffer *sent;
static int returned_fd;

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

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static u64 test_operation(u64 num) {
	return (num / 2) + 1;
}

int handle_time_data(void * ctx, void * data, size_t data_size) {
	u64 * time = data;
	// printf("%ld\n", *time);
	return 0;
}

int handle_sent(void * ctx, void * data, size_t data_size) {
	struct struct_data *d_in = data;
    struct struct_data d_out = {.data = d_in->data, .time_start = d_in->time_start};
    if (verbose) printf("Received: %d ", d_out.data);
    d_out.data = test_operation(d_out.data);
    if (verbose) printf("Returned: %d\n", d_out.data);
    bpf_map_update_elem(returned_fd, NULL, &d_out, 0);
    return 0;
}

int main(int argc, char **argv)
{
	struct scx_ringbuf_us *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	struct sched_param param;
    param.sched_priority = 0; // SCHED_EXT may not use priority, but setting it to 0
    if (sched_setscheduler(0, SCHED_EXT, &param) == -1) {
        // fprintf(stderr, "Error setting scheduler for process %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
restart:
	skel = SCX_OPS_OPEN(ringbuf_us_ops, scx_ringbuf_us);

	skel->rodata->usertask_pid = getpid();
	assert(skel->rodata->usertask_pid > 0);

	while ((opt = getopt(argc, argv, "vhp")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'p':
			skel->struct_ops.ringbuf_us_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, ringbuf_us_ops, scx_ringbuf_us, uei);
	link = SCX_OPS_ATTACH(skel, ringbuf_us_ops, scx_ringbuf_us);

	struct ring_buffer * time_data;
	time_data = ring_buffer__new(bpf_map__fd(skel->maps.sent), handle_time_data, NULL, NULL);

    sent = ring_buffer__new(bpf_map__fd(skel->maps.sent), handle_sent, NULL, NULL);
    returned_fd = bpf_map__fd(skel->maps.returned);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		if (verbose) printf("Working\n");
		while (ring_buffer__poll(sent, 100 /*timeout threshold, ms*/) > 0) {
			
		}
		while(ring_buffer__poll(time_data, 100) > 0) {

		}
		printf("Sent: %ld Returned: %ld\n", skel->bss->nr_sent, skel->bss->nr_returned);
		fflush(stdout);
		sleep(1);
	}

    ring_buffer__free(sent);
	ring_buffer__free(time_data);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_ringbuf_us__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}