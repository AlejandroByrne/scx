#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Child 1: Simulating I/O intensive task...\n");
    for (int i = 0; i < 100000; i++) {
        // Simulate I/O (e.g., read/write to a file)
        FILE *fp = fopen("/dev/null", "w");
        fprintf(fp, "Some data\n");
        fclose(fp);
    }
    printf("Child 1: Done.\n");
    return 0;
}