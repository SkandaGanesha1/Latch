/* QNX test-image helper: exercise separate proposal writer sessions and read
 * generated virtual policy files without relying on their reported size. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (strcmp(argv[1], "dump") == 0) {
        char buf[1024]; ssize_t n;
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) { perror("dump open"); return 1; }
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t written = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
                if (written <= 0) { perror("dump write"); close(fd); return 1; }
                off += written;
            }
        }
        if (n < 0) { perror("dump read"); close(fd); return 1; }
        close(fd); return 0;
    }
    if (strcmp(argv[1], "hold") == 0 || strcmp(argv[1], "try") == 0) {
        int fd = open(argv[2], O_WRONLY);
        if (fd < 0) {
            int error = errno;
            printf("PROBE_OPEN errno=%d\n", error); return error == EBUSY ? 3 : 1;
        }
        puts("PROBE_OPEN success"); fflush(stdout);
        if (strcmp(argv[1], "hold") == 0) sleep(15);
        if (close(fd) != 0) { perror("close"); return 1; }
        puts("PROBE_CLOSED"); return 0;
    }
    return 2;
}
