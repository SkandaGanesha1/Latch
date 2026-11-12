/*
 * qnx/latchlog.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * On-Target Continuous Evidence Tape Logger:
 *   - Attaches to /dev/latch/actuator via devctl(DCMD_LATCH_DUMP_TAPE).
 *   - Periodically queries the in-memory .bss ring buffer.
 *   - Persists evidence records to /dev/shmem/latch_tape.csv or specified file.
 *   - Ensures continuous auditability across target reboots.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "latch_protocol.h"
#include "latch_manifest.h"

static volatile sig_atomic_t g_log_running = 1;

static void latch_log_sig_handler(int signo) {
    (void)signo;
    g_log_running = 0;
}

static const char *mode_str(uint16_t mode) {
    switch (mode) {
        case LATCH_MODE_HP:   return "HP";
        case LATCH_MODE_HOLD: return "HOLD";
        case LATCH_MODE_HOME: return "HOME";
        default:              return "UNK";
    }
}

int main(int argc, char *argv[]) {
    const char *dev_path    = LATCH_DEV_ACTUATOR;
    const char *output_file = NULL;
    const char *manifest_path = "latch.manifest";
    uint32_t    interval_ms = 100u;
    bool        output_file_set = false;
    bool        dev_path_set     = false;
    bool        manifest_explicit = false;

    int opt;
    while ((opt = getopt(argc, argv, "d:o:i:m:")) != -1) {
        switch (opt) {
            case 'd': dev_path = optarg; dev_path_set = true; break;
            case 'o': output_file = optarg; output_file_set = true; break;
            case 'i': interval_ms = (uint32_t)strtoul(optarg, NULL, 10); break;
            case 'm': manifest_path = optarg; manifest_explicit = true; break;
            default:
                fprintf(stderr, "Usage: %s [-m latch.manifest] [-d /dev/latch/actuator] "
                                "[-o /dev/shmem/latch_tape.csv] [-i interval_ms]\n",
                        argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Resolve the manifest the same way latch-ingest and latchd do: the
     * target's CWD is "/", so a bare "latch.manifest" is not findable there.
     * Without this the evidence logger would fail closed and never start. */
    if (!manifest_explicit && access(manifest_path, F_OK) != 0) {
        if (access("qnx/latch.manifest", F_OK) == 0) {
            manifest_path = "qnx/latch.manifest";
        } else if (access("/proc/boot/latch.manifest", F_OK) == 0) {
            manifest_path = "/proc/boot/latch.manifest";
        }
    }

    /*
     * Every path in this project comes from the signed manifest, not from a
     * hardcoded string: `paths.actuator` for the device node and
     * `tape.log_path` for where the evidence tape is persisted. The `-d`/`-o`
     * flags remain as operator overrides, but the default is the manifest.
     */
    latch_manifest_t manifest;
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latchlog: FATAL: Failed to load manifest '%s': %s (Fail-Closed)\n",
                manifest_path, err_buf);
        return EXIT_FAILURE;
    }    if (!dev_path_set && manifest.paths.actuator[0] != '\0') {
        dev_path = manifest.paths.actuator;
    }
    if (!output_file_set && manifest.tape.log_path[0] != '\0') {
        output_file = manifest.tape.log_path;
    }
    if (output_file == NULL) {
        output_file = "/dev/shmem/latch_tape.csv";
    }

    signal(SIGINT, latch_log_sig_handler);
    signal(SIGTERM, latch_log_sig_handler);

    int fd = open(dev_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "latchlog: Cannot open '%s': %s\n", dev_path, strerror(errno));
        return EXIT_FAILURE;
    }

    FILE *fp = fopen(output_file, "a+");
    if (!fp) {
        fprintf(stderr, "latchlog: Cannot open output '%s': %s (trying local ./latch_tape.csv)\n",
                output_file, strerror(errno));
        output_file = "latch_tape.csv";
        fp = fopen(output_file, "a+");
        if (!fp) {
            fprintf(stderr, "latchlog: Failed to open '%s': %s\n", output_file, strerror(errno));
            close(fd);
            return EXIT_FAILURE;
        }
    }

    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,mode_name,fault_bits\n");
        fflush(fp);
    }

    printf("latchlog: Streaming evidence tape from '%s' to '%s' (interval=%u ms)...\n",
           dev_path, output_file, interval_ms);

    uint64_t last_persisted_tick = 0;
    uint32_t next_read_index = 0u;
    bool initial_query = true;

    struct timespec sleep_ts = {
        .tv_sec  = (time_t)(interval_ms / 1000u),
        .tv_nsec = (long)((interval_ms % 1000u) * 1000000L)
    };

    while (g_log_running) {
        (void)nanosleep(&sleep_ts, NULL);
        if (!g_log_running) break;

        bool drain_more = false;
        do {
            latch_tape_dump_t dump;
            memset(&dump, 0, sizeof(dump));
            dump.start_index = initial_query ? UINT32_MAX : next_read_index;
            dump.count       = LATCH_DUMP_MAX_ENTRIES;

            int rc = devctl(fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL);
            if (rc != EOK) {
                if (rc == EPERM) {
                    fprintf(stderr, "latchlog: EPERM error (missing 'latch/actuator' ability)\n");
                }
                break;
            }

            if (initial_query) {
                next_read_index = dump.start_index;
                initial_query = false;
            } else if (dump.start_index != next_read_index) {
                uint32_t missed = (dump.start_index >= next_read_index)
                                      ? (dump.start_index - next_read_index)
                                      : 0u;
                fprintf(stderr, "latchlog: WARNING: tape wrapped across %u slots (#%u -> #%u)\n",
                        missed, next_read_index, dump.start_index);
                fprintf(fp, "# GAP missed_slots=%u expected=%u actual=%u\n",
                        missed, next_read_index, dump.start_index);
                fflush(fp);
            }

            uint32_t written_count = 0;
            for (uint32_t i = 0; i < dump.count; ++i) {
                const latch_tape_entry_t *e = &dump.entries[i];
                if (e->tick <= last_persisted_tick) {
                    continue;
                }
                uint64_t lat = (e->cycles_out >= e->cycles_in) ? (e->cycles_out - e->cycles_in) : 0;
                fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%u,%s,0x%04X\n",
                        e->tick, e->cycles_in, e->cycles_out, lat,
                        e->seq, e->u_proposed, e->theta_applied,
                        (unsigned int)e->mode, mode_str(e->mode),
                        (unsigned int)e->fault_bits);
                last_persisted_tick = e->tick;
                written_count++;
            }

            next_read_index = dump.start_index + dump.count;

            if (written_count > 0) {
                fflush(fp);
            }

            /* Drain back-to-back if a full batch was returned so high-rate bursts are lossless */
            drain_more = (dump.count == LATCH_DUMP_MAX_ENTRIES);
        } while (drain_more && g_log_running);
    }

    printf("latchlog: Terminating cleanly. Last tick persisted: %" PRIu64 "\n", last_persisted_tick);
    fclose(fp);
    close(fd);
    return EXIT_SUCCESS;
}

