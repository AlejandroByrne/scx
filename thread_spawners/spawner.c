#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

#define NUM_CHILDREN 3
#define SCHED_EXT 7 //

int main() {
    struct sched_param param;
    param.sched_priority = 0;

    // Set scheduler for parent process
    if (sched_setscheduler(0, SCHED_EXT, &param) == -1) {
        perror("sched_setscheduler");
        exit(1);
    }
    for (int i = 1; i < NUM_CHILDREN; i++) {
        pid_t pid = fork();

        if (pid == 0) { // Child process
            char child_name[10];
            sprintf(child_name, "child_%d", i);

            char *args[] = {child_name, NULL};
            execv(child_name, args);
            perror("execv");
            exit(1);
        } else if (pid > 0) { // Parent process
            // Optionally, wait for children to finish
            // wait(NULL); 
        } else {
            perror("fork");
            exit(1);
        }
    }

    return 0;
}