#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <pid> <address1> <size1> <address2> <size2> ... \n", argv[0]);
        return 1;
    }

    int pid = atoi(argv[1]);
    fprintf(stderr, "Attempting to attach to process PID %d.\n", pid);

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

    fprintf(stderr, "Process %d successfully stopped. Reading memory regions.\n", pid);
    for (int i = 2; i < argc; i += 2) {
        unsigned long address = strtoul(argv[i], NULL, 16);
        size_t size = (size_t)atoi(argv[i + 1]);
        fprintf(stderr, "Reading memory at address %lx with size %zu.\n", address, size);

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

    fprintf(stderr, "Detaching from process %d.\n", pid);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}

