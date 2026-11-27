/* Test-only launcher. Started by the image script as latch_verify_t, this
 * waits for a local trigger after the QEMU guest and ingest have stopped.
 * It never changes security type or grants the operator a type transition. */
#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    const struct timespec pause_time = {0, 50000000L};
    const char *trigger = "/dev/shmem/latch_verify_trigger";
    for (unsigned int i = 0; i < 12000u; ++i) {
        if (access(trigger, F_OK) == 0) {
            puts("LATCH_TEST_VERIFY_LAUNCH");
            fflush(stdout);
            execl("/proc/boot/latch_verify", "latch_verify", "--print-rc", "-m",
                  "/proc/boot/latch.manifest", (char *)NULL);
            perror("latch_verify_trigger: exec");
            return 1;
        }
        if (errno != ENOENT) {
            perror("latch_verify_trigger: access");
            return 1;
        }
        (void)nanosleep(&pause_time, NULL);
    }
    fputs("latch_verify_trigger: timeout\n", stderr);
    return 1;
}
