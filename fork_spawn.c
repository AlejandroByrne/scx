#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

/*
compile this file with:
gcc -o fork_spawn fork_spawn.c
*/

#define NUM_PROCESSES 60
#define SCHED_EXT 7 // Replace this with the actual value for SCHED_EXT if it's defined differently

void countdown(int seconds)
{
    for (int i = seconds; i > 0; i--)
    {
        // if (i == 10 || i <= 5) {
        //     printf("%d...\n", i);
        // }
        sleep(1);
    }
}

int main()
{
    pid_t pids[NUM_PROCESSES];
    int process_args[NUM_PROCESSES];

    // printf("Countdown before creating processes:\n");
    countdown(12);

    // Set the scheduling policy to SCHED_EXT if required
    struct sched_param param;
    param.sched_priority = 0; // SCHED_EXT may not use priority, but setting it to 0
    if (sched_setscheduler(0, SCHED_EXT, &param) == -1)
    {
        // fprintf(stderr, "Error setting scheduler for process %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < NUM_PROCESSES; ++i)
    {
        process_args[i] = i;
        pids[i] = fork();
        if (pids[i] < 0)
        {
            // Fork failed
            // fprintf(stderr, "Error forking process %d: %s\n", i, strerror(errno));
            exit(EXIT_FAILURE);
        }
        else if (pids[i] == 0)
        {
            // Child process
            char process_num_str[10];
            snprintf(process_num_str, sizeof(process_num_str), "%d", process_args[i]);
            char *args[] = {"./child", process_num_str, NULL};
            execv(args[0], args);

            // If execv returns, there was an error
            // fprintf(stderr, "Error executing child process %d: %s\n", i, strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    // Parent process waits for all child processes to finish
    for (int i = 0; i < NUM_PROCESSES; ++i)
    {
        int status;
        waitpid(pids[i], &status, 0);
        if (WIFEXITED(status))
        {
            // printf("Process %d exited with status %d.\n", i, WEXITSTATUS(status));
        }
        else
        {
            // printf("Process %d did not exit normally.\n", i);
        }
    }

    printf("All processes have finished.\n");
    return EXIT_SUCCESS;
}