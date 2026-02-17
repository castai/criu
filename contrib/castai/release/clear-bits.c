#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        fprintf(stderr, "Writes '4' to /proc/<pid>/clear_refs to clear soft-dirty bits\n");
        return 1;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/clear_refs", argv[1]);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 1;
    }

    const char *val = "4\n";
    ssize_t written = write(fd, val, 2);
    if (written < 0) {
        fprintf(stderr, "Failed to write to %s: %s\n", path, strerror(errno));
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}

