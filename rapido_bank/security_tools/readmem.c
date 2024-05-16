#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <string.h>

void print_verbose(const char *message, int verbose) {
    if (verbose) {
        fprintf(stderr, "%s\n", message);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s [--verbose] <pid> <address1> <size1> <address2> <size2> ... \n", argv[0]);
        return 1;
    }

    int verbose = 0;
    int arg_offset = 0;
    if (strcmp(argv[1], "--verbose") == 0) {
        verbose = 1;
        arg_offset = 1;
    }

    int pid = atoi(argv[1 + arg_offset]);
    char message[256];
    sprintf(message, "Attempting to attach to process PID %d.", pid);
    print_verbose(message, verbose);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
        perror("Failed to attach to the target process");
        return 1;
    }

    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process did not stop as expected.\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    sprintf(message, "Process %d successfully stopped. Reading memory regions.", pid);
    print_verbose(message, verbose);

    for (int i = 2 + arg_offset; i < argc; i += 2) {
        unsigned long address = strtoul(argv[i], NULL, 16);
        size_t size = (size_t)atoi(argv[i + 1]);
        sprintf(message, "Reading memory at address %lx with size %zu.", address, size);
        print_verbose(message, verbose);

        char memPath[256];
        sprintf(memPath, "/proc/%d/mem", pid);
        int fd = open(memPath, O_RDONLY);
        if (fd < 0) {
            perror("Failed to open memory file");
            continue;
        }

        lseek(fd, address, SEEK_SET);
        unsigned char *buffer = malloc(size);
        if (buffer && read(fd, buffer, size) == size) {
            write(STDOUT_FILENO, buffer, size);
        } else {
            perror("Failed to read memory");
        }

        free(buffer);
        close(fd);
    }

    sprintf(message, "Detaching from process %d.", pid);
    print_verbose(message, verbose);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

