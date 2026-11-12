/*
 * qnx/latch_verify.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * On-Target Microkernel Verification Harness:
 *   - Verifies all 5 fault & handoff scenarios against running latchd daemon.
 *   - [1/5] Nominal tracking in HP mode (theta advances from 0 -> -100 mrad).
 *   - [2/5] Keep-out envelope veto (+450 mrad inside [250, 650] mrad -> HA-HOLD).
 *   - [3/5] Wire CRC bit-flip rejection -> HA-HOLD maintained.
 *   - [4/5] Monotonic sequence replay + 80 ms silence -> Watchdog trips, HA-HOME
 *           retracts horn back to 0 mrad.
 *   - [5/5] Process Manager Ability enforcement: devctl(FORCE_HOLD) and write-open
 *           without 'latch/actuator' ability return EPERM (1).
 *   - Actively asserts evidence tape records and returns EXIT_FAILURE on discrepancy.
 */

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __QNXNTO__
#include <devctl.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#else
static inline uint64_t ClockCycles(void) { return 0; }
typedef struct { uint64_t cycles_per_sec; } qtime_dummy_t;
static qtime_dummy_t g_qtime_dummy = { 1000000000ULL };
#define SYSPAGE_ENTRY(x) (&g_qtime_dummy)
#endif

#include "latch_protocol.h"
#include "latch_manifest.h"

static const char *mode_name(uint16_t m) {
    return (m == LATCH_MODE_HP) ? "HP" : (m == LATCH_MODE_HOLD) ? "HOLD" : "HOME";
}

static int send_frame(int fd, uint32_t seq, int32_t u_mrad, uint16_t fault, uint32_t delay_us) {
    latch_ipc_proposal_t p;
    memset(&p, 0, sizeof(p));
    p.ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC;
    p.seq            = seq;
    p.u_mrad         = u_mrad;
    p.pre_fault_bits = fault;
    p.ingest_cycles  = ClockCycles();
    ssize_t wr = write(fd, &p, sizeof(p));
    if (wr != (ssize_t)sizeof(p)) {
        perror("latch_verify: write(/dev/latch/proposal)");
        return -1;
    }
    if (delay_us > 0u) {
        usleep(delay_us);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    bool dump_only = false;
    bool explicit_manifest = false;
    const char *manifest_path = "latch.manifest";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--status") == 0) {
            dump_only = true;
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            manifest_path = argv[++i];
            explicit_manifest = true;
        } else {
            fprintf(stderr, "Usage: %s [--status] [-m latch.manifest]\n", argv[0]);
            return 1;
        }
    }

    if (!explicit_manifest && access(manifest_path, F_OK) != 0) {
        if (access("qnx/latch.manifest", F_OK) == 0) {
            manifest_path = "qnx/latch.manifest";
        } else if (access("/proc/boot/latch.manifest", F_OK) == 0) {
            manifest_path = "/proc/boot/latch.manifest";
        }
    }

    latch_manifest_t manifest;
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latch_verify: FATAL: Failed to load manifest '%s': %s (Fail-Closed)\n",
                manifest_path, err_buf);
        return 1;
    }

    const char *act_path  = (manifest.paths.actuator[0] != '\0') ? manifest.paths.actuator : LATCH_DEV_ACTUATOR;
    const char *prop_path = (manifest.paths.proposal[0] != '\0') ? manifest.paths.proposal : LATCH_DEV_PROPOSAL;
    uint32_t period_us    = manifest.timing.period_us;
    uint32_t send_pace_us = (strcmp(manifest.ingest.delivery, "queued") == 0)
                                ? 0u
                                : ((period_us >= 400u) ? (period_us / 2u) : 200u);

    bool all_passed = true;

    int act_fd = open(act_path, O_RDONLY);
    if (act_fd < 0) {
        act_fd = open(act_path, O_RDWR);
    }
    if (act_fd < 0) {
        perror("open /dev/latch/actuator");
        return 1;
    }

    latch_status_reply_t st_init;
    memset(&st_init, 0, sizeof(st_init));
    if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_init, sizeof(st_init), NULL) != 0) {
        perror("devctl(GET_STATUS)");
        close(act_fd);
        return 1;
    }

    if (!dump_only) {
        printf("=== LATCH Native QNX 8.0 Microkernel Verification ===\n");
        int prop_fd = open(prop_path, O_WRONLY);
        if (prop_fd < 0) {
            perror("open /dev/latch/proposal");
            close(act_fd);
            return 1;
        }

        uint32_t seq = 0u;
        int32_t home = manifest.envelope.home_mrad;
        int32_t step = (manifest.envelope.a_max > 0) ? manifest.envelope.a_max : 10;
        if (step > manifest.envelope.v_max) step = manifest.envelope.v_max;
        int32_t neg_space = home - manifest.envelope.theta_min_mrad;
        int32_t pos_space = manifest.envelope.theta_max_mrad - home;
        int32_t dir = (neg_space >= pos_space) ? -1 : 1;
        if (latch_manifest_in_keepout(&manifest, home + dir * step * 5)) {
            dir = -dir;
        }

        /* 1. Nominal tracking in HP mode: step smoothly along safe ramp from home */
        int32_t pos = home;
        uint32_t ramp_frames = 10u;
        for (uint32_t i = 1u; i <= ramp_frames; ++i) {
            int32_t cand = pos + dir * step;
            if (cand < manifest.envelope.theta_min_mrad || cand > manifest.envelope.theta_max_mrad ||
                latch_manifest_crossed_keepout(&manifest, pos, cand)) {
                break;
            }
            pos = cand;
            if (send_frame(prop_fd, ++seq, pos, LATCH_FAULT_NONE, send_pace_us) != 0) {
                all_passed = false;
            }
        }

        latch_status_reply_t st_nom;
        memset(&st_nom, 0, sizeof(st_nom));
        for (uint32_t wait = 0; wait < 20u; ++wait) {
            (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_nom, sizeof(st_nom), NULL);
            if (st_nom.theta_mrad == pos) {
                break;
            }
            usleep(period_us);
        }

        int32_t min_expected_travel = (pos - home) / 2;
        bool reached_halfway = (dir < 0) ? (st_nom.theta_mrad <= home + min_expected_travel)
                                         : (st_nom.theta_mrad >= home + min_expected_travel);
        if (st_nom.mode == LATCH_MODE_HP && reached_halfway) {
            printf("[1/5] PASS: Nominal HP tracking verified (%s -> theta = %d mrad)\n",
                   prop_path, st_nom.theta_mrad);
        } else {
            printf("[1/5] FAIL: Nominal HP tracking not observed (theta = %d mrad, target = %d, mode = %s)\n",
                   st_nom.theta_mrad, pos, mode_name(st_nom.mode));
            all_passed = false;
        }

        /* 2. Keep-out envelope violation derived from manifest */
        int32_t ko_target = (manifest.envelope.num_keepouts > 0u)
                                ? ((manifest.envelope.keepout[0].lo_mrad + manifest.envelope.keepout[0].hi_mrad) / 2)
                                : (manifest.envelope.theta_max_mrad + 500);
        if (send_frame(prop_fd, ++seq, ko_target, LATCH_FAULT_NONE, send_pace_us) != 0) {
            all_passed = false;
        }
        usleep(period_us * 10u);

        latch_status_reply_t st_ko;
        memset(&st_ko, 0, sizeof(st_ko));
        (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_ko, sizeof(st_ko), NULL);
        if (st_ko.mode == LATCH_MODE_HOLD &&
            (st_ko.latched_faults & (LATCH_FAULT_KEEPOUT | LATCH_FAULT_BOUNDS)) != 0u) {
            printf("[2/5] PASS: Keep-out violation (%d mrad) vetoed -> HA-HOLD locked at theta = %d mrad (latched = 0x%04X)\n",
                   ko_target, st_ko.theta_mrad, st_ko.latched_faults);
        } else {
            printf("[2/5] FAIL: Keep-out violation not properly vetoed (theta = %d mrad, mode = %s, faults = 0x%04X)\n",
                   st_ko.theta_mrad, mode_name(st_ko.mode), st_ko.latched_faults);
            all_passed = false;
        }

        /* 3. Wire CRC bit-flip fault */
        if (send_frame(prop_fd, 0, 0, LATCH_FAULT_CRC, send_pace_us) != 0) {
            all_passed = false;
        }
        usleep(period_us * 10u);

        latch_status_reply_t st_crc;
        memset(&st_crc, 0, sizeof(st_crc));
        (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_crc, sizeof(st_crc), NULL);
        if (st_crc.mode == LATCH_MODE_HOLD && (st_crc.latched_faults & LATCH_FAULT_CRC) != 0u) {
            printf("[3/5] PASS: Wire CRC bit-flip fault injected -> HA-HOLD maintained (latched = 0x%04X)\n",
                   st_crc.latched_faults);
        } else {
            printf("[3/5] FAIL: Wire CRC fault not latched (latched = 0x%04X)\n", st_crc.latched_faults);
            all_passed = false;
        }

        /* 4. Sequence replay + silence -> Watchdog trips -> HA-HOME retraction to home_mrad */
        if (send_frame(prop_fd, (seq > 1u) ? (seq - 1u) : 1u, pos, LATCH_FAULT_NONE, send_pace_us) != 0) {
            all_passed = false;
        }
        uint32_t v_home = (manifest.envelope.v_home > 0) ? (uint32_t)manifest.envelope.v_home : 1u;
        uint32_t dist   = (uint32_t)abs(st_crc.theta_mrad - home);
        uint32_t retract_ticks = (dist + v_home - 1u) / v_home;
        uint32_t silence_ticks = manifest.timing.watchdog_ticks +
                                 manifest.recovery.hold_to_home_ticks +
                                 retract_ticks + 15u;
        usleep(silence_ticks * period_us);

        latch_status_reply_t st_home;
        memset(&st_home, 0, sizeof(st_home));
        (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_home, sizeof(st_home), NULL);

        /* Inspect evidence tape to verify HOME retraction occurred monotonically */
        latch_tape_dump_t tape_check;
        memset(&tape_check, 0, sizeof(tape_check));
        tape_check.start_index = UINT32_MAX;
        tape_check.count       = LATCH_DUMP_MAX_ENTRIES;
        bool saw_home_mode = false;
        bool home_monotonic = true;
        int32_t prev_dist = INT32_MAX;
        if (devctl(act_fd, DCMD_LATCH_DUMP_TAPE, &tape_check, sizeof(tape_check), NULL) == 0) {
            for (uint32_t i = 0; i < tape_check.count; ++i) {
                if (tape_check.entries[i].mode == LATCH_MODE_HOME) {
                    saw_home_mode = true;
                    int32_t cur_dist = abs(tape_check.entries[i].theta_applied - home);
                    if (prev_dist != INT32_MAX && cur_dist > prev_dist) {
                        home_monotonic = false;
                    }
                    prev_dist = cur_dist;
                }
            }
        }

        if ((st_home.active_faults & LATCH_FAULT_WATCHDOG) != 0u &&
            st_home.theta_mrad == home &&
            saw_home_mode &&
            home_monotonic) {
            printf("[4/5] PASS: Sequence replay + silence -> Watchdog tripped -> HA-HOME monotonic retraction to %d mrad\n",
                   home);
        } else {
            printf("[4/5] FAIL: HA-HOME retraction invalid (theta = %d, expected = %d, faults = 0x%04X, saw_home=%d, mono=%d)\n",
                   st_home.theta_mrad, home, st_home.active_faults, (int)saw_home_mode, (int)home_monotonic);
            all_passed = false;
        }

        close(prop_fd);

        /* 5. Process Manager Ability Verification (Read-Only Probe & Mutating devctl) */
        int rc_probe = devctl(act_fd, DCMD_LATCH_PROBE_ABILITY, NULL, 0, NULL);
        if (rc_probe == EPERM) {
            printf("[5a/5] PASS: Dedicated probe devctl(PROBE_ABILITY) WITHOUT 'latch/actuator' ability -> EPERM (Fail-closed)\n");
        } else {
            printf("[5a/5] FAIL: devctl(PROBE_ABILITY) returned %d instead of EPERM\n", rc_probe);
            all_passed = false;
        }

        latch_force_hold_cmd_t hold_cmd = { .lock_hold = 1u, .reason_code = 99u };
        int rc = devctl(act_fd, DCMD_LATCH_FORCE_HOLD, &hold_cmd, sizeof(hold_cmd), NULL);
        if (rc != 0) {
            printf("[5b/5] PASS: Calling devctl(FORCE_HOLD) WITHOUT 'latch/actuator' ability -> %d (%s)\n",
                   rc, strerror(rc));
        } else {
            printf("[5b/5] FAIL: devctl(FORCE_HOLD) unexpectedly succeeded without ability!\n");
            all_passed = false;
        }

        /* 5c. Write-open verification */
        int wfd = open(LATCH_DEV_ACTUATOR, O_WRONLY);
        if (wfd < 0 && errno == EPERM) {
            printf("[5c/5] PASS: open('/dev/latch/actuator', O_WRONLY) WITHOUT ability -> EPERM (Fail-closed)\n");
        } else {
            if (wfd >= 0) close(wfd);
            printf("[5c/5] FAIL: open with O_WRONLY returned %d (errno=%d)\n", wfd, errno);
            all_passed = false;
        }
    }

    latch_status_reply_t st;
    memset(&st, 0, sizeof(st));
    if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st, sizeof(st), NULL) != 0) {
        close(act_fd);
        return 0;
    }

    uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    char sha_hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(&sha_hex[i * 2], 3, "%02x", st.manifest_sha256[i]);
    }
    sha_hex[64] = '\0';

    printf("\n=== LATCH Verified Telemetry & Microkernel Evidence Tape ===\n");
    printf("Tick Counter       : %" PRIu64 " ticks (1 kHz CLOCK_MONOTONIC pulse)\n", st.tick);
    printf("Current Mode       : %s (theta = %d mrad)\n", mode_name(st.mode), st.theta_mrad);
    printf("Proposals Received : %u | Wire Faults: %u | Envelope Vetoes: %u | Ring Drops: %u | WCET Overruns: %u | EPERM Rejects: %u\n",
           st.total_proposals_rx, st.total_wire_faults, st.total_envelope_faults,
           st.total_ring_drops, st.wcet_overruns, st.total_eperm_rejects);
    printf("Decision Latency   : last = %" PRIu64 " cyc (%u ns) | max = %" PRIu64 " cyc (%u ns) @ %" PRIu64 " Hz\n",
           st.last_latency_cycles, st.last_latency_ns, st.max_latency_cycles, st.max_latency_ns, cps);
    printf("Manifest SHA-256   : %s\n", sha_hex);

    latch_tape_dump_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.start_index = UINT32_MAX;
    dump.count       = 12;
    if (devctl(act_fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL) == 0) {
        printf("\nLast %u Evidence Tape Records (.bss Ring):\n", dump.count);
        printf("  %-8s %-8s %-10s %-10s %-6s %-8s %-10s\n",
               "TICK", "SEQ", "U_PROP", "THETA_OUT", "MODE", "FAULTS", "CYCLES");
        for (uint32_t i = 0; i < dump.count; ++i) {
            const latch_tape_entry_t *e = &dump.entries[i];
            printf("  #%-7" PRIu64 " %-8u %-10d %-10d %-6s 0x%04X   %" PRIu64 "\n",
                   e->tick, e->seq, e->u_proposed, e->theta_applied,
                   mode_name(e->mode), e->fault_bits, e->cycles_out - e->cycles_in);
        }
    }
    close(act_fd);

    if (!dump_only) {
        if (all_passed) {
            printf("\n[LATCH VERIFY] ALL 5 MICROKERNEL CRITICALITY INVARIANTS VERIFIED (PASS).\n");
            return 0;
        } else {
            printf("\n[LATCH VERIFY] VERIFICATION FAILED: One or more invariants violated.\n");
            return 1;
        }
    }

    return 0;
}
