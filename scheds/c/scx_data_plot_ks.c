#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include <assert.h>
#include <sched.h>
#include <time.h>
#include "scx_data_plot_ks.bpf.skel.h"
#include "scx_test_ks.h"

#define SCHED_EXT 7

static bool verbose;
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
	struct scx_data_plot_ks *skel;
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
	skel = SCX_OPS_OPEN(data_plot_ks_ops, scx_data_plot_ks);

	SCX_OPS_LOAD(skel, data_plot_ks_ops, scx_data_plot_ks, uei);
	link = SCX_OPS_ATTACH(skel, data_plot_ks_ops, scx_data_plot_ks);

	skel->bss->usertask_pid = getpid();
	assert(skel->bss->usertask_pid > 0);

	while ((opt = getopt(argc, argv, "vhp")) != -1) {
		switch (opt) {
		case 'v':
			verbose = true;
			break;
		case 'p':
			skel->struct_ops.data_plot_ks_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
			break;
		default:
			return opt != 'h';
		}
	}

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    time_t time_prev = ts.tv_sec;
    u32 num_tasks_prev = 0;
    u32 num_tasks = 0;
    float sum_elapsed_time = 0;
    u32 num_data_points = 0;
    time_t interval_ns = 1;
	while (!exit_req && !UEI_EXITED(skel, uei)) {
		//printf("Working\n");
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            // printf("%ld, %ld\n", time_prev, ts_n.tv_nsec);
            // printf("%ld - %ld = %ld\n", ts.tv_sec, time_prev, ts.tv_sec - time_prev);
            if ((ts.tv_sec - time_prev) >= interval_ns) { // has 0.1 seconds passed?
                num_tasks = skel->bss->nr_tasks;
                float average_elapsed_ns = sum_elapsed_time / num_data_points;
                int tasks = num_tasks - num_tasks_prev;
                printf("%ld, %d, %.2f, %d\n", ts.tv_sec, num_data_points, average_elapsed_ns, num_tasks);
                // printf("%ld, %d", ts.tv_nsec);
                num_tasks_prev = num_tasks;
                sum_elapsed_time = 0;
                num_data_points = 0;
                time_prev += interval_ns;
            }
        }
        struct struct_data input;
		while (bpf_map_lookup_and_delete_elem(bpf_map__fd(skel->maps.finalized), NULL, &input) == 0) {
			num_data_points++;
            sum_elapsed_time += (float) input.elapsed_ns / 1000; // convert to microseconds
		}

		fflush(stdout);
		//sleep(1);
	}
	printf("Sent: %ld\n", skel->bss->nr_sent);
	bool other_task = skel->bss->other_task == 1;
	printf(other_task ? "Other tasks? Yes" : "Other tasks? No");
	printf("Number of enqueues: %ld\n", skel->bss->nr_enqueued);
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_data_plot_ks__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}