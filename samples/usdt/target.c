#include <sys/sdt.h>
#include <stdio.h>
#include <unistd.h>

// A minimal userspace program with a single, hand-placed USDT probe. It has
// no purpose besides existing as a target to attach eBPF to: myapp:order_processed
// fires once per "processed order", carrying the order id as its only argument.
//
// Build with: gcc -O0 -g -o target target.c
int main(void) {
    for (int order_id = 1; order_id <= 5; order_id++) {
        printf("Processing order %d\n", order_id);
        DTRACE_PROBE1(myapp, order_processed, order_id);
        sleep(1);
    }

    return 0;
}
