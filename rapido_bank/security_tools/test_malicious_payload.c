#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig) {
    keep_running = 0;  // Set the flag to false to break the loop
}

void add_payload_to_stack() {
    // Local variable on the stack
    unsigned char stack_payload[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE, 0xBA, 0xAD, 0xF0, 0x0D, 0xCA, 0xFE, 0xBA, 0xBE};
    printf("Malicious stack payload is at %p\n", (void*)stack_payload);
}

int main() {
    // Register the signal handler for SIGINT
    signal(SIGINT, handle_sigint);

    // Allocate memory on the heap and add payload
    unsigned char *heap_payload = (unsigned char*) malloc(16);  // Ensure there's enough space
    if (heap_payload == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    memcpy(heap_payload, (unsigned char[]){0xBA, 0xAD, 0xF0, 0x0D, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xFA, 0xCE, 0xBA, 0xAD, 0xCA, 0xFE}, 16);
    printf("Malicious heap payload is at %p\n", (void*)heap_payload);

    // Add payload to the stack
    add_payload_to_stack();

    printf("Running indefinitely, press Ctrl+C to exit...\n");

    // Infinite loop until SIGINT is received
    while (keep_running) {
        sleep(1);  // Sleep to reduce CPU usage
    }

    printf("Signal received, cleaning up and exiting...\n");

    // Clean up and exit
    free(heap_payload);
    return 0;
}

