/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_fifo.bpf.skel.h"

#define SCHED_EXT 7

static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int test)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_fifo *skel;
	struct bpf_link *link;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	
restart:
	skel = SCX_OPS_OPEN(test_fifo_ops, scx_fifo);

	SCX_OPS_LOAD(skel, test_fifo_ops, scx_fifo, uei);
	link = SCX_OPS_ATTACH(skel, test_fifo_ops, scx_fifo);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		printf("Working\n");
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_fifo__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}