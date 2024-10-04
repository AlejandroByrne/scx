#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Child 2: Simulating CPU intensive task...\n");
    for (long long i = 0; i < 10000000000; i++) {
        // Busy loop (CPU intensive)
    }
    printf("Child 2: Done.\n");
    return 0;
}