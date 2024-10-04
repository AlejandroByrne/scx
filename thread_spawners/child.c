#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/*
compile this file with:
gcc -o child child.c
*/

void simulate_work() {
    time_t start_time = time(NULL);
    while (difftime(time(NULL), start_time) < 60) {
        // Simulate some work by sleeping for a bit
        // printf("Child process %d is working...\n", getpid());
        sleep(1);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        // fprintf(stderr, "Usage: %s <process_num>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int process_num = atoi(argv[1]);
    // printf("Child process %d started with process_num %d.\n", getpid(), process_num);

    simulate_work();

    // printf("Child process %d finished work.\n", getpid());
    return EXIT_SUCCESS;
}