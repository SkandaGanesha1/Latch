/*
 * qnx/latch_ingest.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Unprivileged virtio-console byte parser and ingest bridge:
 *   - Pinned to _cpu-1 via ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT).
 *   - Holds NO "latch/actuator" ability and NO I2C file descriptor.
 *   - Reads 32-byte packed little-endian latch_wire_frame_t packets from stdin
 *     (bound by qvm `vdev virtio-console` `hostdev >"|/proc/boot/latch-ingest"`).
 *   - Checks magic (0x4C415448 'LATH'), version (1), joint (0), reserved[12]==0,
 *     IEEE 802.3 CRC32 over bytes [0..16), and INT32_MIN NaN sentinel.
 *   - Discards the proposed `u_mrad` payload on magic, CRC, or reserved failure
 *     (never forwards a half-parsed or corrupted `u` to `latchd`).
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __QNXNTO__
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/syspage.h>
#endif

#include "latch_protocol.h"
#include "latch_manifest.h"

#define LATCH_INGEST_PREFILL_FRAMES 32u

static volatile sig_atomic_t g_ingest_running = 1;

static void latch_ingest_sig_handler(int signo) {
    (void)signo;
    g_ingest_running = 0;
}

static inline uint64_t latch_ingest_cycles(void) {
#ifdef __QNXNTO__
    return ClockCycles();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

static int latch_ingest_pin_cpu(unsigned int target_cpu) {
#ifdef __QNXNTO__
    unsigned int num_cpu = _syspage_ptr->num_cpu;
    if (target_cpu >= num_cpu) {
        target_cpu = (num_cpu > 1u) ? 1u : 0u;
    }

    int rsize = RMSK_SIZE(num_cpu);
    size_t buf_len = sizeof(unsigned int) + (size_t)(2 * rsize) * sizeof(uint32_t);
    uint8_t *buf = (uint8_t *)calloc(1u, buf_len);
    if (buf == NULL) {
        return -ENOMEM;
    }

    unsigned int *rmaskp = (unsigned int *)buf;
    *rmaskp = (unsigned int)rsize;

    uint32_t *runmask     = (uint32_t *)(rmaskp + 1);
    uint32_t *inheritmask = runmask + rsize;

    RMSK_SET(target_cpu, runmask);
    RMSK_SET(target_cpu, inheritmask);

    int rc = ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT, buf);
    int saved_errno = errno;
    free(buf);

    return (rc == -1) ? -saved_errno : 0;
#else
    (void)target_cpu;
    return 0;
#endif
}

static int latch_read_exact(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0u;

    while (total < len && g_ingest_running) {
        ssize_t n = read(fd, p + total, len - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n == 0) {
            return (total == 0u) ? 0 : -1;
        } else {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
    }
    return (total == len) ? 1 : -1;
}

static int latch_write_exact(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t total = 0u;

    while (total < len && g_ingest_running) {
        ssize_t n = write(fd, p + total, len - total);
        if (n > 0) {
            total += (size_t)n;
        } else if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        } else {
            return -1;
        }
    }
    return (total == len) ? 0 : -1;
}

static void latch_parse_wire_frame(const latch_wire_frame_t *frame,
                                   latch_ipc_proposal_t *out_prop) {
    uint16_t faults = LATCH_FAULT_NONE;

    if (frame->magic != LATCH_WIRE_MAGIC ||
        frame->version != LATCH_WIRE_VERSION ||
        frame->joint != LATCH_WIRE_JOINT_DEFAULT) {
        faults |= LATCH_FAULT_MAGIC;
    }

    if (!latch_wire_reserved_is_zero(frame)) {
        faults |= LATCH_FAULT_RESERVED;
    }

    uint32_t expected_crc = latch_crc32_ieee(frame, LATCH_CRC_COVERED_BYTES);
    if (expected_crc != frame->crc32) {
        faults |= LATCH_FAULT_CRC;
    }

    if (frame->u_mrad == LATCH_NAN_MRAD) {
        faults |= LATCH_FAULT_NAN;
    }

    memset(out_prop, 0, sizeof(*out_prop));
    out_prop->ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC;
    out_prop->wire_flags     = frame->flags;
    out_prop->pre_fault_bits = faults;
    out_prop->ingest_cycles  = latch_ingest_cycles();

    /*
     * Section 4.1 Rule (Corrected for E-5):
     * Discard sequence and payload only on wire framing integrity failures
     * (magic, CRC, or non-zero reserved bytes).
     * For semantic payload faults (such as NaN), preserve seq and u_mrad so
     * latchd can evaluate the exact sequence number without spurious sequence drops.
     */
    if ((faults & (LATCH_FAULT_MAGIC | LATCH_FAULT_CRC | LATCH_FAULT_RESERVED)) != 0u) {
        out_prop->seq    = 0u;
        out_prop->u_mrad = 0;
    } else {
        out_prop->seq    = frame->seq;
        out_prop->u_mrad = frame->u_mrad;
    }
}

int main(int argc, char *argv[]) {
    const char *input_path    = NULL;
    const char *proposal_path = LATCH_DEV_PROPOSAL;
    const char *manifest_path = "latch.manifest";
    unsigned int target_cpu   = 1u;
    bool verbose              = false;

    int opt;
    while ((opt = getopt(argc, argv, "i:o:m:c:v")) != -1) {
        switch (opt) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                proposal_path = optarg;
                break;
            case 'm':
                manifest_path = optarg;
                break;
            case 'c':
                target_cpu = (unsigned int)strtoul(optarg, NULL, 10);
                break;
            case 'v':
                verbose = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input_dev] [-o /dev/latch/proposal|-] [-m latch.manifest] [-c cpu] [-v]\n",
                        argv[0]);
                return EXIT_FAILURE;
        }
    }

    /* Try to read manifest if present to auto-configure paths/CPU */
    latch_manifest_t manifest;
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &manifest, err_buf, sizeof(err_buf)) == 0) {
        target_cpu = manifest.ingest.cpu;
        if (strcmp(proposal_path, LATCH_DEV_PROPOSAL) == 0 && manifest.paths.proposal[0] != '\0') {
            proposal_path = manifest.paths.proposal;
        }
    }

    signal(SIGINT, latch_ingest_sig_handler);
    signal(SIGTERM, latch_ingest_sig_handler);
    signal(SIGPIPE, SIG_IGN);

    (void)latch_ingest_pin_cpu(target_cpu);

    int in_fd = STDIN_FILENO;
    if (input_path != NULL && strcmp(input_path, "-") != 0) {
        in_fd = open(input_path, O_RDONLY);
        if (in_fd < 0) {
            perror("latch-ingest: open input");
            return EXIT_FAILURE;
        }
    }

    int out_fd = STDOUT_FILENO;
    if (strcmp(proposal_path, "-") != 0) {
        out_fd = open(proposal_path, O_WRONLY);
        if (out_fd < 0) {
            perror("latch-ingest: open /dev/latch/proposal");
            if (in_fd != STDIN_FILENO) {
                close(in_fd);
            }
            return EXIT_FAILURE;
        }
    }

#ifdef __QNXNTO__
    /* Drop and lock all abilities: latch-ingest only parses wire frames and writes to proposal pipe */
    (void)procmgr_ability(0,
                          PROCMGR_ADN_ROOT | PROCMGR_ADN_NONROOT |
                          PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK,
                          PROCMGR_AID_EOL);
#endif

    latch_wire_frame_t   wire_frame;
    latch_ipc_proposal_t ipc_prop;
    uint32_t total_frames   = 0u;
    uint32_t wire_faults    = 0u;
    uint32_t silence_ticks  = 0u;

    while (g_ingest_running) {
        int r = latch_read_exact(in_fd, &wire_frame, sizeof(wire_frame));
        if (r <= 0) {
            break;
        }

        latch_parse_wire_frame(&wire_frame, &ipc_prop);
        total_frames++;
        if (ipc_prop.pre_fault_bits != 0u) {
            wire_faults++;
        }
        if ((wire_frame.flags & LATCH_WIRE_FLAG_SILENCE) != 0u) {
            silence_ticks++;
        }

        if (verbose) {
            if (ipc_prop.pre_fault_bits == 0u) {
                fprintf(stderr, "[latch-ingest] Frame #%-3u: seq=%-3u u=%+5d mrad -> FORWARDED\n",
                        total_frames, ipc_prop.seq, ipc_prop.u_mrad);
            } else {
                fprintf(stderr, "[latch-ingest] Frame #%-3u: seq=%-3u u=%+5d mrad -> WIRE FAULT 0x%04X (sanitized)\n",
                        total_frames, ipc_prop.seq, ipc_prop.u_mrad, ipc_prop.pre_fault_bits);
            }
        }

        if (latch_write_exact(out_fd, &ipc_prop, sizeof(ipc_prop)) != 0) {
            break;
        }

        /* 32-frame burst prefill followed by 1 ms pacing when writing to device node */
        if (out_fd != STDOUT_FILENO && total_frames > LATCH_INGEST_PREFILL_FRAMES) {
            uint32_t pace_us = (manifest.timing.period_us > 0) ? manifest.timing.period_us : 1000u;
            usleep(pace_us);
        }
    }

    /* Wait for latchd to drain queued proposals before closing channel */
    if (out_fd != STDOUT_FILENO) {
        usleep(15000); /* 15 ms drain wait */
    }

    uint32_t nominal_forwarded = (total_frames >= wire_faults + silence_ticks)
                                     ? (total_frames - wire_faults - silence_ticks)
                                     : 0u;
    if (verbose || out_fd != STDOUT_FILENO) {
        fprintf(stderr, "[latch-ingest] Completed: %u frames processed (%u nominal forwarded, %u silence ticks, %u wire faults sanitized) -> %s\n",
                total_frames, nominal_forwarded, silence_ticks, wire_faults, proposal_path);
    }

    if (out_fd != STDOUT_FILENO) {
        close(out_fd);
    }
    if (in_fd != STDIN_FILENO) {
        close(in_fd);
    }
    return EXIT_SUCCESS;
}
