#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[]) {
    printf("CyberShield Test Suite - Clean Utility Benchmark\n");
    printf("Computing standard arithmetic calculations...\n");
    int sum = 0;
    for (int i = 0; i < 100; ++i) {
        sum += (i * 2) - 1;
    }
    printf("Calculated checksum: %d\n", sum);
    return 0;
}

