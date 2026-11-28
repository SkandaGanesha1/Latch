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
#include <getopt.h>
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
#include "governor_wire.h"
#include "latch_ingest_start.h"

/*
 * There is deliberately no prefill constant here any more. A previous
 * revision used a compile-time 32-frame burst prefill followed by a sleep
 * between deliveries; both are gone. The supervisor's ring, bounded by the
 * manifest's `ingest.queue_depth`, is the only buffer in the path, and the
 * guest is required to keep that burst within `ingest.queue_depth` (the
 * invariant is asserted across files by tools/consistency_check.py).
 */

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
    if (!latch_ingest_cpu_in_range(target_cpu, num_cpu)) {
        /*
         * THE SIGNED CONTRACT NAMES A CPU THIS PLATFORM DOES NOT HAVE.
         *
         * The old code silently moved the bridge to CPU 1 -- or to CPU 0
         * on a single-CPU platform -- and reported SUCCESS.  That is a
         * silent substitution of a compiled-in default for SIGNED data,
         * and the fallback is the CPU THE SAFETY SUPERVISOR RUNS ON.  So
         * the bridge refuses to be placed rather than being placed
         * somewhere else, and the caller is told why.
         */
        return -EINVAL;
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

static void latch_parse_wire_v2_frame(const uint8_t frame[32],
                                      latch_ipc_proposal_v2_t *out_prop) {
    governor_wire_message_t message;
    uint16_t faults = governor_wire_v2_parse(frame, 32u, &message);
    memset(out_prop, 0, sizeof(*out_prop));
    out_prop->ipc_magic = LATCH_IPC_PROPOSAL_V2_MAGIC;
    out_prop->ipc_version = 2u;
    out_prop->wire_version = 2u;
    out_prop->ingest_cycles = latch_ingest_cycles();
    out_prop->pre_fault_bits = (uint16_t)(faults & LATCH_FAULT_WIRE_MASK);
    if (faults == LATCH_FAULT_NONE) {
        out_prop->seq = message.seq;
        out_prop->u_mrad = message.u_mrad;
        out_prop->wire_flags = (uint16_t)message.kind;
        out_prop->kind = (uint8_t)message.kind;
        out_prop->confidence_q8 = message.confidence_q8;
        out_prop->agent_state = message.agent_state;
        out_prop->coherence_ctr = message.coherence_ctr;
        out_prop->shrink_v = message.shrink_v;
        out_prop->shrink_scale_q8 = message.shrink_scale_q8;
        out_prop->unit_id = message.unit_id;
    }
}

int main(int argc, char *argv[]) {
    const char *input_path    = NULL;
    const char *proposal_path = LATCH_DEV_PROPOSAL;
    const char *manifest_path = "latch.manifest";
    bool explicit_manifest    = false;
    /*
     * THE CPU, AS AN ASSERTION.
     *
     * `-c` is NOT an override: the SIGNED manifest is the authority for
     * where the bridge runs, and `-c` says "I expect the bridge on CPU
     * N".  A disagreement with the signed contract is a REFUSAL, not a
     * substitution -- see `qnx/latch_ingest_start.h` for why an override
     * would be wrong on this target.  The option used to be parsed and
     * then overwritten by the manifest's value, which made it a lie.
     */
    bool cpu_asserted          = false;
    unsigned int cpu_assertion = 0u;
    bool verbose              = false;
    /*
     * Producer identity (L-2).
     *
     * The supervisor's dead-man lease is scoped to the producer that
     * established the session. This bridge stamps every forwarded v2 frame
     * with its producer tag; a frame whose tag differs from the session
     * owner's is lease-inert and cannot move the plant while the owner's
     * lease is live.
     *
     * The default is 1 -- the single production guest bridge. A second
     * producer (the A8 adversarial rig, or a second bridge) passes a
     * DIFFERENT tag, and the supervisor treats it as a foreign producer
     * rather than as the owner.
     */
    uint16_t producer_tag     = 1u;
    /*
     * Session epoch (RT-02).
     *
     * The producer chooses the epoch of the session it opens, and stamps it
     * on every frame it forwards.  The supervisor binds the epoch of the
     * session it is running and rejects any frame carrying a different one,
     * so a frame captured in an earlier session cannot be replayed into a
     * later one (the supervisor's sequence baseline is re-based on every
     * session open, so without the epoch a stale frame with a high sequence
     * number would be accepted as the new session's first frame).
     *
     * The DEFAULT is a FRESH epoch for every process: two bridge instances
     * that start at the same moment must not collide, and a restarted bridge
     * must not silently resume the previous session's identity.  The value
     * is derived from the monotonic clock, the wall clock and the pid, so it
     * is unique per process in practice -- it is an IDENTIFIER, not a
     * secret, and it is not an authentication mechanism.
     *
     * `-e N` / `--session-epoch N` pins it, which is what the regression
     * tests use to prove that a REUSED epoch is rejected.
     */
    uint32_t session_epoch   = 0u;
    bool session_epoch_pinned = false;

    int opt;
    static const struct option long_options[] = {
        { "session-epoch", required_argument, NULL, 'e' },
        { "producer-tag",  required_argument, NULL, 't' },
        { NULL, 0, NULL, 0 }
    };
    while ((opt = getopt_long(argc, argv, "i:o:m:c:t:e:v", long_options, NULL)) != -1) {
        switch (opt) {
            case 'i':
                input_path = optarg;
                break;
            case 'o':
                proposal_path = optarg;
                break;
            case 'm':
                manifest_path = optarg;
                explicit_manifest = true;
                break;
            case 'c':
                cpu_assertion = (unsigned int)strtoul(optarg, NULL, 10);
                cpu_asserted = true;
                break;
            case 't':
                producer_tag = (uint16_t)strtoul(optarg, NULL, 10);
                break;
            case 'e':
                session_epoch = (uint32_t)strtoul(optarg, NULL, 0);
                session_epoch_pinned = true;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                fprintf(stderr, "Usage: %s [-i input_dev] [-o /dev/latch/proposal|-] "
                                "[-m latch.manifest] [-c cpu] [-t producer_tag] "
                                "[-e session_epoch] [-v]\n"
                                "       %s --session-epoch N --producer-tag N\n"
                                "       (-c ASSERTS the signed contract's ingest.cpu; a "
                                "disagreement refuses to start)\n",
                        argv[0], argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (producer_tag == LATCH_PRODUCER_TAG_NONE) {
        fprintf(stderr, "latch-ingest: FATAL: producer tag 0 is reserved (a v2 frame "
                        "must name its producer); refusing to start (Fail-Closed)\n");
        return EXIT_FAILURE;
    }

    if (!session_epoch_pinned) {
        /*
         * Derive a FRESH epoch for this process.
         *
         * The epoch is an IDENTIFIER, not a secret and not an authentication
         * mechanism: it says "this frame belongs to the session I opened",
         * and the supervisor checks it against the session it is running.
         * It therefore only has to be UNIQUE per session and not REUSABLE,
         * which is why it is derived from three independent sources -- the
         * monotonic clock (never repeats), the wall clock (never repeats
         * across a reboot) and the pid (never repeats among live peers).
         *
         * The mixing is a bijective scramble of the low bits so that two
         * processes starting in the same nanosecond still differ.
         */
        struct timespec mono;
        struct timespec wall;
        (void)clock_gettime(CLOCK_MONOTONIC, &mono);
        (void)clock_gettime(CLOCK_REALTIME, &wall);
        uint64_t mixed = (uint64_t)mono.tv_nsec;
        mixed ^= (uint64_t)mono.tv_sec * 0x9E3779B97F4A7C15ULL;
        mixed ^= (uint64_t)wall.tv_nsec * 0xC2B2AE3D27D4EB4FULL;
        mixed ^= (uint64_t)wall.tv_sec * 0x165667B19E3779F9ULL;
        mixed ^= (uint64_t)(unsigned)getpid() * 0x27D4EB2F165667C5ULL;
        mixed ^= (mixed >> 29);
        session_epoch = (uint32_t)(mixed & 0xFFFFFFFFULL);
        if (session_epoch == LATCH_SESSION_EPOCH_NONE) {
            /* 0 is RESERVED: it means "this frame names no session". */
            session_epoch = 1u;
        }
    }

    if (session_epoch == LATCH_SESSION_EPOCH_NONE) {
        fprintf(stderr, "latch-ingest: FATAL: session epoch 0 is reserved (a v2 frame "
                        "must name its session); refusing to start (Fail-Closed)\n");
        return EXIT_FAILURE;
    }

    if (verbose) {
        fprintf(stderr, "[latch-ingest] producer_tag=%u session_epoch=0x%08X%s\n",
                (unsigned int)producer_tag, (unsigned int)session_epoch,
                session_epoch_pinned ? " (pinned)" : " (fresh)");
    }

    if (!explicit_manifest && access(manifest_path, F_OK) != 0) {
        if (access("qnx/latch.manifest", F_OK) == 0) {
            manifest_path = "qnx/latch.manifest";
        } else if (access("/proc/boot/latch.manifest", F_OK) == 0) {
            manifest_path = "/proc/boot/latch.manifest";
        }
    }

    /* Fail-Closed Manifest Enforcement */
    latch_manifest_t manifest;
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latch-ingest: FATAL: Failed to load manifest '%s': %s (Fail-Closed)\n",
                manifest_path, err_buf);
        return EXIT_FAILURE;
    }
    /*
     * THE CPU IS THE SIGNED CONTRACT'S TO DECIDE.
     *
     * The manifest is loaded before the CPU is chosen, because the
     * manifest is the authority.  `-c` may ASSERT the CPU the bridge
     * expects; it may not CHANGE it.  A contradiction is a refusal.
     */
    const latch_ingest_cpu_choice_t cpu_choice =
        latch_ingest_cpu_choose(cpu_asserted, cpu_assertion, manifest.ingest.cpu);
    if (!latch_ingest_start_allowed(cpu_choice.decision)) {
        fprintf(stderr, "latch-ingest: FATAL: the requested CPU (%u) contradicts the signed "
                        "contract's ingest.cpu (%u); refusing to start (Fail-Closed)\n",
                cpu_assertion, manifest.ingest.cpu);
        return EXIT_FAILURE;
    }
    const unsigned int target_cpu = cpu_choice.cpu;
    if (verbose) {
        fprintf(stderr, "[latch-ingest] cpu=%u (%s)\n", target_cpu,
                cpu_choice.asserted ? (cpu_choice.agrees ? "asserted, agrees with the signed contract"
                                                        : "asserted, DISAGREES with the signed contract")
                                     : "from the signed contract");
    }
    if (strcmp(proposal_path, LATCH_DEV_PROPOSAL) == 0 && manifest.paths.proposal[0] != '\0') {
        proposal_path = manifest.paths.proposal;
    }

    signal(SIGINT, latch_ingest_sig_handler);
    signal(SIGTERM, latch_ingest_sig_handler);
    signal(SIGPIPE, SIG_IGN);

    /*
     * THE PIN IS FATAL.
     *
     * The bridge's whole reason for being on `_cpu-1` is that it is not
     * on `_cpu-0`, where the safety supervisor runs.  A bridge that could
     * not be placed used to carry on anyway -- UNPINNED, on whatever CPU
     * the scheduler chose -- because the pin's return value was
     * discarded.  So the result is checked, and a failure stops the
     * bridge.
     */
    const int pin_rc = latch_ingest_pin_cpu(target_cpu);
    const latch_ingest_start_decision_t pin_decision = latch_ingest_pin_decide(pin_rc);
    if (!latch_ingest_start_allowed(pin_decision)) {
        const int pin_errno = (pin_rc < 0) ? (-pin_rc) : EINVAL;
        fprintf(stderr, "latch-ingest: FATAL: could not pin to CPU %u (%s); refusing to start "
                        "UNPINNED (Fail-Closed)\n", target_cpu, strerror(pin_errno));
        return EXIT_FAILURE;
    }

    int in_fd = STDIN_FILENO;
    if (input_path != NULL && strcmp(input_path, "-") != 0) {
        in_fd = open(input_path, O_RDONLY);
        if (in_fd < 0) {
            perror("latch-ingest: open input");
            return EXIT_FAILURE;
        }
    }

    bool is_stdout = (strcmp(proposal_path, "-") == 0);
    int out_fd = is_stdout ? STDOUT_FILENO : -1;

#ifdef __QNXNTO__
    /* Drop and lock concrete abilities: latch-ingest only parses wire frames and writes to proposal pipe */
    const unsigned drop_flags = PROCMGR_ADN_ROOT | PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK;
    int ab_rc = procmgr_ability(0,
                                drop_flags | PROCMGR_AID_ABLE_CREATE,
                                drop_flags | PROCMGR_AID_SETUID,
                                drop_flags | PROCMGR_AID_SETGID,
                                drop_flags | PROCMGR_AID_FORK,
                                drop_flags | PROCMGR_AID_SPAWN,
                                drop_flags | PROCMGR_AID_MEM_PHYS,
                                drop_flags | PROCMGR_AID_IO,
                                drop_flags | PROCMGR_AID_CLOCKSET,
                                drop_flags | PROCMGR_AID_PUBLIC_CHANNEL,
                                drop_flags | PROCMGR_AID_XPROCESS_ABLE,
                                PROCMGR_AID_EOL);
    if (ab_rc != EOK) {
        int err = (ab_rc > 0) ? ab_rc : errno;
        fprintf(stderr, "latch-ingest: FATAL: procmgr_ability() failed (%s) (Fail-Closed)\n", strerror(err));
        if (in_fd != STDIN_FILENO) {
            close(in_fd);
        }
        return EXIT_FAILURE;
    }
    if (manifest.paths.ability[0] != '\0') {
        /*
         * THE ABILITY LOOKUP IS FATAL.
         *
         * The manifest names the custom ability the bridge must
         * surrender -- `latch/actuator` in every shipped contract.  A
         * FAILED lookup means the bridge cannot prove it has surrendered
         * it, and carrying on would leave the guest's bridge HOLDING the
         * ability to move the plant: the failure mode of the old code
         * was an ESCALATION, not a crash.  So the lookup's result is
         * checked, and a failure stops the bridge.
         *
         * There is no start-up race here: `latchd` creates the ability
         * BEFORE it attaches the actuator node, and every shipped
         * buildfile waits for that node before it starts the guest.
         */
        const int custom_aid = procmgr_ability_lookup(manifest.paths.ability);
        const latch_ingest_start_decision_t ability_decision =
            latch_ingest_ability_decide(custom_aid);
        if (!latch_ingest_start_allowed(ability_decision)) {
            fprintf(stderr, "latch-ingest: FATAL: could not resolve the custom ability '%s' "
                            "(lookup returned %d); refusing to start while it may still be held "
                            "(Fail-Closed)\n", manifest.paths.ability, custom_aid);
            if (in_fd != STDIN_FILENO) {
                close(in_fd);
            }
            return EXIT_FAILURE;
        }
        int custom_rc = procmgr_ability(0, drop_flags | (unsigned)custom_aid, PROCMGR_AID_EOL);
        if (custom_rc != EOK) {
            int err = (custom_rc > 0) ? custom_rc : errno;
            fprintf(stderr, "latch-ingest: FATAL: procmgr_ability(%s) failed (%s) (Fail-Closed)\n",
                    manifest.paths.ability, strerror(err));
            if (in_fd != STDIN_FILENO) {
                close(in_fd);
            }
            return EXIT_FAILURE;
        }
    }
#endif

    uint8_t              wire_bytes[32];
    latch_ipc_proposal_t ipc_prop;
    latch_ipc_proposal_v2_t ipc_prop_v2;
    uint32_t total_frames   = 0u;
    uint32_t wire_faults    = 0u;
    uint32_t silence_ticks  = 0u;

    while (g_ingest_running) {
        int r = latch_read_exact(in_fd, wire_bytes, sizeof(wire_bytes));
        if (r <= 0) {
            break;
        }

        uint16_t wire_version = (uint16_t)((uint16_t)wire_bytes[4] |
                                           ((uint16_t)wire_bytes[5] << 8u));
        bool contract_v2 = (manifest.schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION &&
                            manifest.protocol.version == 2u && manifest.governor.enabled != 0u);
        const void *ipc_data = &ipc_prop;
        size_t ipc_size = sizeof(ipc_prop);
        if (contract_v2) {
            if (wire_version == 2u) {
                latch_parse_wire_v2_frame(wire_bytes, &ipc_prop_v2);
            } else {
                /* Active v2 contract: never fall back to 24B LPRP on v1/unknown
                 * wire frames. Emit a sanitized 56B LPR2 fault frame instead. */
                memset(&ipc_prop_v2, 0, sizeof(ipc_prop_v2));
                ipc_prop_v2.ipc_magic = LATCH_IPC_PROPOSAL_V2_MAGIC;
                ipc_prop_v2.ipc_version = 2u;
                ipc_prop_v2.wire_version = 2u;
                ipc_prop_v2.kind = GOVERNOR_WIRE_CMD;
                ipc_prop_v2.wire_flags = (uint16_t)GOVERNOR_WIRE_CMD;
                ipc_prop_v2.pre_fault_bits = LATCH_FAULT_MAGIC;
                ipc_prop_v2.ingest_cycles = latch_ingest_cycles();
            }
            ipc_data = &ipc_prop_v2;
            ipc_size = sizeof(ipc_prop_v2);
            /* Stamp the producer identity (L-2): the supervisor's lease is
             * scoped to the producer that established the session. */
            ipc_prop_v2.producer_tag = producer_tag;
            /* Stamp the session epoch (RT-02): every frame this bridge
             * forwards belongs to the session the bridge opened. The
             * supervisor binds that epoch and rejects any frame carrying a
             * different one, so a frame captured in an earlier session
             * cannot be replayed into this one. */
            ipc_prop_v2.session_epoch = session_epoch;
            ipc_prop_v2.reserved1 = 0u;
            if (ipc_prop_v2.pre_fault_bits != 0u) wire_faults++;
        } else {
            latch_wire_frame_t wire_frame;
            memcpy(&wire_frame, wire_bytes, sizeof(wire_frame));
            latch_parse_wire_frame(&wire_frame, &ipc_prop);
            if (ipc_prop.pre_fault_bits != 0u) wire_faults++;
            if (wire_version == 1u && (wire_frame.flags & LATCH_WIRE_FLAG_SILENCE) != 0u) {
                silence_ticks++;
            }
        }
        total_frames++;

        /* Deferred open: open proposal node only when first wire frame is ready */
        if (out_fd < 0) {
            out_fd = open(proposal_path, O_WRONLY);
            if (out_fd < 0) {
                perror("latch-ingest: open /dev/latch/proposal");
                if (in_fd != STDIN_FILENO) {
                    close(in_fd);
                }
                return EXIT_FAILURE;
            }
        }

        if (verbose) {
            if (ipc_size == sizeof(ipc_prop_v2)) {
                fprintf(stderr, "[latch-ingest] v2 frame #%-3u kind=%u seq=%u faults=0x%04X\n",
                        total_frames, (unsigned int)ipc_prop_v2.kind,
                        ipc_prop_v2.seq, ipc_prop_v2.pre_fault_bits);
            } else if (ipc_prop.pre_fault_bits == 0u) {
                fprintf(stderr, "[latch-ingest] Frame #%-3u: seq=%-3u u=%+5d mrad -> FORWARDED\n",
                        total_frames, ipc_prop.seq, ipc_prop.u_mrad);
            } else {
                fprintf(stderr, "[latch-ingest] Frame #%-3u: seq=%-3u u=%+5d mrad -> WIRE FAULT 0x%04X (sanitized)\n",
                        total_frames, ipc_prop.seq, ipc_prop.u_mrad, ipc_prop.pre_fault_bits);
            }
        }

        if (latch_write_exact(out_fd, ipc_data, ipc_size) != 0) {
            break;
        }

        /*
         * NO ARTIFICIAL PACING HERE -- the supervisor's queue IS the buffer.
         *
         * This process validates the wire frame and hands it to the supervisor
         * as fast as the transport delivers it. The supervisor drains exactly
         * one proposal per 1 ms tick from a ring bounded by
         * `ingest.queue_depth`, so the ring -- not a sleep in the ingest -- is
         * what decouples the producer's burst from the consumer's tick.
         *
         * Why there must be no sleep here: the supervisor's watchdog is
         * `watchdog_ticks` (2 by default, i.e. 2 ms). Any stretch where the
         * supervisor finds no proposal makes it fail closed into HA-HOLD and
         * then retract to HA-HOME, which moves `theta` away from the value the
         * next proposal carries and turns every later frame into a spurious
         * RATE veto. Measured on QEMU AArch64 virt, a half-period sleep here
         * produced 16- and 28-tick stalls in the guest->host delivery (the
         * virtio-console vdev's forwarding pulse is priority-driven; see the
         * `sched 60` on that vdev) and 48 envelope vetoes where 7 are
         * correct. The safety story is the ORDER of the frames, and order is
         * preserved by the ring.
         *
         * The guest likewise does not pace itself: it emits one continuous
         * byte stream and lets the host's ring absorb the burst.
         */
    }

    /* Wait for latchd to drain queued proposals before closing channel */
    if (!is_stdout && out_fd >= 0) {
        uint32_t drain_wait_us = (manifest.ingest.queue_depth + 10u) * manifest.timing.period_us;
        if (drain_wait_us < 75000u) drain_wait_us = 75000u;
        usleep(drain_wait_us);
    }

    uint32_t nominal_forwarded = (total_frames >= wire_faults + silence_ticks)
                                     ? (total_frames - wire_faults - silence_ticks)
                                     : 0u;
    if (verbose || !is_stdout) {
        fprintf(stderr, "[latch-ingest] Completed: %u frames processed (%u nominal forwarded, %u silence ticks, %u wire faults sanitized) -> %s\n",
                total_frames, nominal_forwarded, silence_ticks, wire_faults, proposal_path);
    }

    if (!is_stdout && out_fd >= 0) {
        close(out_fd);
    }
    if (in_fd != STDIN_FILENO) {
        close(in_fd);
    }
    return EXIT_SUCCESS;
}
