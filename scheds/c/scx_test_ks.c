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
#include "scx_test_ks.bpf.skel.h"
#include "scx_test_ks.h"

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
	struct scx_test_ks *skel;
	struct bpf_link *link;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	
restart:
	skel = SCX_OPS_OPEN(test_ks_ops, scx_test_ks);

	SCX_OPS_LOAD(skel, test_ks_ops, scx_test_ks, uei);
	link = SCX_OPS_ATTACH(skel, test_ks_ops, scx_test_ks);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
<<<<<<< HEAD
		printf("Working\n");
=======
		//printf("Working\n");
		u64 input;
		while (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.results), NULL, &input) == 0) {
			//printf("Value polled: %ld | ", input);
			struct time_datum td;
			if (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.time_data), NULL, &td) == 0) {
				//printf("Time taken: %ld ns| ", td.elapsed_ns);
				printf("%ld\n", td.elapsed_ns);
			}
		}
		//printf("Sent: %ld\n", skel->bss->nr_sent);
>>>>>>> main
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_test_ks__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
