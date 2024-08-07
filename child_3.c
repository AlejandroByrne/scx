#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    printf("Child 3: Simulating memory intensive task...\n");
    for (int i = 0; i < 10000; i++) {
        // Allocate and deallocate memory (memory intensive)
        int *data = malloc(1024 * 1024); // Allocate 1MB
        free(data);
    }
    printf("Child 3: Done.\n");
    return 0;
}