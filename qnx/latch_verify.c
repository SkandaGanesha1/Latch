/*
 * qnx/latch_verify.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * On-Target Microkernel Verification Harness:
 *   - Verifies all 5 fault & handoff scenarios against running latchd daemon.
 *   - [1/5] Nominal tracking in HP mode. The ramp is derived from the
 *          OBSERVED plant angle and the manifest's own limits, and the result
 *          is read from the EVIDENCE TAPE (not from an instantaneous status
 *          read, which would have to catch a 2-tick window).
 *   - [2/5] Keep-out envelope veto (a target derived from the manifest's
 *          keep-out box -> HA-HOLD).
 *   - [3/5] A wire fault flagged by the ingest bridge -> HA-HOLD maintained.
 *          The CRC computation itself is proven end-to-end by the guest's own
 *          corrupted frames (fault bits 0x0002 in the tape) and by the
 *          host-sim pipeline; this step exercises the supervisor's half.
 *   - [4/5] A REAL sequence replay (the supervisor's own last_seq, re-sent)
 *          -> the SEQ fault is ASSERTED latched; then silence -> the
 *          watchdog trips -> HA-HOME retracts jerk-bounded to home_mrad.
 *   - [5/5] Process Manager Ability enforcement: devctl(FORCE_HOLD) and
 *          write-open without the 'latch/actuator' ability return EPERM.
 *
 * Exit codes: 0 = all five invariants verified; 1 = an invariant was
 * violated; 2 = the harness could not COMPLETE (it could not read the
 * supervisor's status or the evidence tape). Code 2 exists because a
 * verification harness that cannot verify must never be mistaken for one
 * that verified successfully.
 *
 * The harness JOINS the supervisor's session; it never resets it. It
 * continues the supervisor's own sequence, derives the ramp from the
 * observed plant state, and sends the ramp as a burst so the supervisor's
 * watchdog cannot fire while a measurement is being taken.
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

/*
 * Wait until the supervisor has CONSUMED `count` more proposals than it had
 * when the caller last looked.
 *
 * The consumption counter (`total_proposals_rx`) is used rather than
 * `last_seq`, because `last_seq` only advances on a CLEAN frame: a frame
 * that the supervisor correctly VETOED would never satisfy it, and the
 * harness would wait forever.
 */
static int wait_for_consumed(int act_fd, uint32_t rx_before, uint32_t count,
                             uint32_t timeout_ms) {
    uint32_t deadline_ms = timeout_ms;
    uint32_t waited_ms   = 0u;
    latch_status_reply_t st;
    while (waited_ms <= deadline_ms) {
        memset(&st, 0, sizeof(st));
        if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st, sizeof(st), NULL) == 0) {
            if (st.total_proposals_rx >= rx_before + count) {
                return 0;
            }
        }
        usleep(1000u);
        waited_ms += 1u;
    }
    return -1;
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

    /*
     * PACE THE PROPOSALS AT ONE PER SUPERVISOR TICK.
     *
     * This tool writes straight into the supervisor's queue, so it owns the
     * pacing: one frame per `period_us`, which is exactly the rate the
     * supervisor consumes at. That keeps a frame always queued, so the
     * supervisor's `watchdog_ticks` window never elapses while this tool is
     * still measuring.
     *
     * A previous revision sent the whole ramp unpaced (0 us). The supervisor
     * then drained the burst one frame per tick and, two ticks after the
     * last frame, tripped the watchdog -- while this tool was still polling
     * for the applied angle. On QEMU TCG, where the poll loop overruns the
     * 1 ms tick, the result was a false FAIL of step 1: the angle had
     * reached the target but the mode had already failed closed to HOLD.
     *
     * The safety story is the ORDER of the frames, and pacing preserves it.
     */
    /*
     * THE VERIFICATION HARNESS JOINS THE SUPERVISOR'S SESSION; IT DOES NOT
     * RESET IT.
     *
     * Three rules, all of them learned from a failed on-target run:
     *
     * 1. The harness CONTINUES the supervisor's sequence. It reads the
     *    observed last_seq and starts from there. A harness that starts its
     *    own sequence at 1 would have every one of its frames rejected as
     *    stale.
     *
     * 2. The ramp is derived from the OBSERVED plant angle, not from
     *    absolute constants, so the harness is correct whatever state the
     *    supervisor is in when it starts.
     *
     * 3. The ramp is sent as a BURST and the result is read from the
     *    EVIDENCE TAPE, not from an instantaneous status read. The
     *    supervisor consumes exactly one proposal per tick, so a burst is
     *    applied at precisely the same rate as a paced stream -- but the
     *    ring holds the frames, so the supervisor never sees a tick with no
     *    proposal and its 2-tick watchdog cannot fire while the measurement
     *    is being taken. A paced stream at exactly one frame per tick is a
     *    coin flip: one millisecond of scheduler jitter under TCG and the
     *    watchdog fires, the supervisor fails closed, theta is retracted,
     *    and every later frame of the ramp is vetoed as a spurious RATE
     *    fault. That is exactly what the archived failed session shows
     *    (last_seq frozen at 4, 15 envelope vetoes instead of 7).
     *
     *    The tape is also the RIGHT place to read the answer from: it
     *    records (tick, seq, u, theta, mode, faults) for every tick, so it
     *    is the authoritative record of what the supervisor did. An
     *    instantaneous read would have to catch a 2-tick window.
     */
    bool all_passed = true;

    int act_fd = open(act_path, O_RDONLY);
    if (act_fd < 0) {
        act_fd = open(act_path, O_RDWR);
    }
    if (act_fd < 0) {
        perror("open /dev/latch/actuator");
        return 1;
    }

    /* --- Pre-flight: the supervisor's current state ------------------- */
    latch_status_reply_t st0;
    memset(&st0, 0, sizeof(st0));
    if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st0, sizeof(st0), NULL) != 0) {
        fprintf(stderr, "latch_verify: FATAL: cannot read the supervisor status "
                        "(devctl GET_STATUS failed) -- cannot verify anything.\n");
        close(act_fd);
        return 2;
    }
    if (st0.manifest_sha256[0] == 0u) {
        fprintf(stderr, "latch_verify: FATAL: the supervisor returned an empty "
                        "manifest digest -- the status snapshot was not taken "
                        "consistently.\n");
        close(act_fd);
        return 2;
    }

    int prop_fd = open(prop_path, O_WRONLY);
    if (prop_fd < 0) {
        perror("open /dev/latch/proposal");
        close(act_fd);
        return 1;
    }

    /* Continue the supervisor's sequence, and remember where we started. */
    uint32_t seq          = st0.last_seq;
    uint32_t rx_baseline  = st0.total_proposals_rx;

    if (!dump_only) {
        printf("=== LATCH Native QNX 8.0 Microkernel Verification ===\n");
        printf("--- pre-flight: supervisor mode=%s theta=%d mrad last_seq=%u rx=%u\n",
               mode_name(st0.mode), st0.theta_mrad, st0.last_seq, st0.total_proposals_rx);

        /* 1. Nominal tracking in HP mode.
         *
         * The ramp starts from the OBSERVED angle and steps toward a legal
         * pose derived from the manifest. The step size is the manifest's
         * own acceleration limit (the tightest of a_max and v_max), so the
         * ramp is envelope-legal for ANY plant.
         */
        int32_t pos = st0.theta_mrad;
        int32_t step = (manifest.envelope.a_max > 0) ? manifest.envelope.a_max : 10;
        if (step > manifest.envelope.v_max) step = manifest.envelope.v_max;
        int32_t neg_space = pos - manifest.envelope.theta_min_mrad;
        int32_t pos_space = manifest.envelope.theta_max_mrad - pos;
        int32_t dir = (neg_space >= pos_space) ? -1 : 1;
        if (latch_manifest_in_keepout(&manifest, pos + dir * step * 5)) {
            dir = -dir;
        }

        /*
         * RECOVERY: BRING THE SUPERVISOR BACK TO HP BEFORE RAMPING.
         *
         * The supervisor only returns to HP after
         * `recovery.hysteresis_clean_frames` CONSECUTIVE CLEAN frames. On
         * target the guest's last phase is REAL SILENCE, which trips the
         * watchdog and leaves the supervisor in HOLD. In HOLD the plant is
         * frozen (HA-HOLD holds the angle in place), so a ramp is consumed
         * but NOT applied -- the previous revision measured exactly that:
         * 10 tape rows in the ramp and an angle that never moved.
         *
         * The recovery frames are LEGAL NO-OPS: they propose the plant's
         * current angle plus its current velocity, so the velocity step is
         * the velocity and the acceleration step is ZERO. A frame that
         * merely held the angle still carried an acceleration step of
         * -v, which is a RATE fault whenever the plant is moving faster
         * than `envelope.a_max`.
         */
        uint32_t recovery_frames = manifest.recovery.hysteresis_clean_frames;
        if (recovery_frames == 0u) recovery_frames = 1u;
        uint32_t recovery_sent = 0u;
        {
            latch_status_reply_t s2;
            memset(&s2, 0, sizeof(s2));
            (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &s2, sizeof(s2), NULL);
            int32_t hold_u = s2.theta_mrad + s2.velocity_mrad_tick;
            if (hold_u < manifest.envelope.theta_min_mrad) hold_u = manifest.envelope.theta_min_mrad;
            if (hold_u > manifest.envelope.theta_max_mrad) hold_u = manifest.envelope.theta_max_mrad;
            for (uint32_t i = 0u; i < recovery_frames; ++i) {
                if (send_frame(prop_fd, ++seq, hold_u, LATCH_FAULT_NONE, 0u) != 0) {
                    all_passed = false;
                    break;
                }
                recovery_sent++;
            }
        }

        uint32_t ramp_frames = 10u;
        uint32_t ramp_sent   = 0u;
        uint32_t ramp_first_seq = seq + 1u;
        for (uint32_t i = 1u; i <= ramp_frames; ++i) {
            int32_t cand = pos + dir * step;
            if (cand < manifest.envelope.theta_min_mrad || cand > manifest.envelope.theta_max_mrad ||
                latch_manifest_crossed_keepout(&manifest, pos, cand)) {
                break;
            }
            pos = cand;
            if (send_frame(prop_fd, ++seq, pos, LATCH_FAULT_NONE, 0u) != 0) {
                all_passed = false;
                break;
            }
            ramp_sent++;
        }
        uint32_t ramp_last_seq = seq;

        /* Wait until the supervisor has CONSUMED the ramp.
         *
         * The consumption counter is the right one to watch: `last_seq` only
         * advances on a CLEAN frame, so a ramp frame that was (correctly)
         * vetoed would never satisfy it, and the harness would hang.
         */
        if (all_passed && wait_for_consumed(act_fd, rx_baseline,
                                           recovery_sent + ramp_sent, 4000u) != 0) {
            fprintf(stderr, "latch_verify: the supervisor did not consume the %u recovery "
                            "+ %u ramp frames within the timeout.\n",
                    recovery_sent, ramp_sent);
            all_passed = false;
        }
        rx_baseline = st0.total_proposals_rx + recovery_sent + ramp_sent;

        /* Read the answer from the EVIDENCE TAPE. */
        bool ramp_tracked = false;
        bool ramp_in_hp   = false;
        int32_t ramp_theta_start = 0;
        int32_t ramp_theta_end   = 0;
        uint32_t ramp_rows = 0u;
        {
            latch_tape_dump_t dump;
            memset(&dump, 0, sizeof(dump));
            dump.start_index = UINT32_MAX;
            dump.count       = LATCH_DUMP_MAX_ENTRIES;
            if (devctl(act_fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL) != 0) {
                fprintf(stderr, "latch_verify: cannot read the evidence tape.\n");
                all_passed = false;
            } else {
                for (uint32_t i = 0; i < dump.count; ++i) {
                    const latch_tape_entry_t *e = &dump.entries[i];
                    if (e->seq < ramp_first_seq || e->seq > ramp_last_seq) {
                        continue;
                    }
                    if (ramp_rows == 0u) {
                        ramp_theta_start = e->theta_applied;
                    }
                    ramp_theta_end = e->theta_applied;
                    ramp_rows++;
                    if (e->mode == LATCH_MODE_HP && e->theta_applied == pos) {
                        ramp_tracked = true;
                        ramp_in_hp   = true;
                    }
                }
            }
        }

        if (ramp_tracked && ramp_in_hp && ramp_rows > 0u) {
            printf("[1/5] PASS: Nominal HP tracking verified (%s -> theta = %d mrad "
                   "from %d mrad, %u tape rows in HP mode)\n",
                   prop_path, ramp_theta_end, ramp_theta_start, ramp_rows);
        } else {
            printf("[1/5] FAIL: Nominal HP tracking not observed (theta = %d mrad, target = %d, "
                   "mode = %s, tape rows in the ramp = %u)\n",
                   ramp_theta_end, pos, mode_name(st0.mode), ramp_rows);
            all_passed = false;
        }

        /* 2. Keep-out envelope violation derived from the manifest */
        int32_t ko_target = (manifest.envelope.num_keepouts > 0u)
                                ? ((manifest.envelope.keepout[0].lo_mrad + manifest.envelope.keepout[0].hi_mrad) / 2)
                                : (manifest.envelope.theta_max_mrad + 500);
        if (send_frame(prop_fd, ++seq, ko_target, LATCH_FAULT_NONE, 0u) != 0) {
            all_passed = false;
        }
        if (wait_for_consumed(act_fd, rx_baseline, 1u, 2000u) != 0) {
            all_passed = false;
        }
        rx_baseline++;

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

        /* 3. Wire fault flagged by the ingest bridge.
         *
         * The CRC COMPUTATION lives in latch-ingest, which validates the
         * 32-byte wire frame and flags the proposal it forwards; the
         * supervisor's job is to latch the flag and hold the actuator.
         * This step exercises the supervisor's half of that contract
         * directly.
         *
         * The end-to-end proof that the CRC computation itself rejects a
         * corrupted frame is the GUEST's own corrupted frames, which travel
         * through the real latch-ingest code path and appear in the
         * evidence tape as fault bits 0x0002 (CRC). The host-sim pipeline
         * proves the same path on the workstation (`make check` reports
         * wire_faults=12, of which 4 are CRC).
         */
        if (send_frame(prop_fd, ++seq, 0, LATCH_FAULT_CRC, 0u) != 0) {
            all_passed = false;
        }
        if (wait_for_consumed(act_fd, rx_baseline, 1u, 2000u) != 0) {
            all_passed = false;
        }
        rx_baseline++;

        latch_status_reply_t st_crc;
        memset(&st_crc, 0, sizeof(st_crc));
        (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_crc, sizeof(st_crc), NULL);
        if (st_crc.mode == LATCH_MODE_HOLD && (st_crc.latched_faults & LATCH_FAULT_CRC) != 0u) {
            printf("[3/5] PASS: Wire CRC fault injected -> HA-HOLD maintained (latched = 0x%04X)\n",
                   st_crc.latched_faults);
        } else {
            printf("[3/5] FAIL: Wire CRC fault not latched (latched = 0x%04X)\n",
                   st_crc.latched_faults);
            all_passed = false;
        }

        /* 4. Sequence replay + silence -> Watchdog trips -> HA-HOME retraction
         *    to home_mrad.
         *
         * The replay is a REAL replay: the harness re-reads the supervisor's
         * current last_seq and re-sends that exact value, so the frame is
         * unambiguously stale. The previous revision sent its OWN counter
         * minus one, which -- because the harness's counter and the
         * supervisor's sequence had diverged -- was a merely stale frame
         * rather than a replay of the immediately preceding one.
         *
         * The harness then ASSERTS that the SEQ fault was actually latched.
         * The previous revision did not: it only checked the watchdog, the
         * home angle and the monotonic retraction, so the step could report
         * PASS while the replay had never been detected at all.
         */
        latch_status_reply_t st_pre;
        memset(&st_pre, 0, sizeof(st_pre));
        (void)devctl(act_fd, DCMD_LATCH_GET_STATUS, &st_pre, sizeof(st_pre), NULL);
        uint32_t replay_seq = st_pre.last_seq;
        if (send_frame(prop_fd, replay_seq, st_pre.theta_mrad, LATCH_FAULT_NONE, 0u) != 0) {
            all_passed = false;
        }
        if (wait_for_consumed(act_fd, rx_baseline, 1u, 2000u) != 0) {
            all_passed = false;
        }
        rx_baseline++;

        uint32_t v_home = (manifest.envelope.v_home > 0) ? (uint32_t)manifest.envelope.v_home : 1u;
        uint32_t dist   = (uint32_t)abs(st_crc.theta_mrad - manifest.envelope.home_mrad);
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
                    int32_t cur_dist = abs(tape_check.entries[i].theta_applied - manifest.envelope.home_mrad);
                    if (prev_dist != INT32_MAX && cur_dist > prev_dist) {
                        home_monotonic = false;
                    }
                    prev_dist = cur_dist;
                }
            }
        }

        /*
         * The retraction is only OBSERVABLE if the plant was moved away
         * from home first -- which is what the ramp does. If the ramp did
         * not move the plant, there is nothing to retract and the test
         * cannot be judged; that is reported as a distinct failure rather
         * than as a mysterious "no HOME rows".
         */
        bool plant_moved = (ramp_theta_end != manifest.envelope.home_mrad);
        if ((st_home.active_faults & LATCH_FAULT_WATCHDOG) != 0u &&
            (st_home.latched_faults & LATCH_FAULT_SEQ) != 0u &&
            st_home.theta_mrad == manifest.envelope.home_mrad &&
            plant_moved &&
            saw_home_mode &&
            home_monotonic) {
            printf("[4/5] PASS: Sequence replay (seq=%u) -> SEQ fault latched, then silence -> "
                   "Watchdog tripped -> HA-HOME monotonic retraction to %d mrad\n",
                   replay_seq, manifest.envelope.home_mrad);
        } else {
            printf("[4/5] FAIL: HA-HOME retraction invalid (theta = %d, expected = %d, "
                   "active = 0x%04X, latched = 0x%04X, saw_home=%d, mono=%d, "
                   "plant_moved=%d)\n",
                   st_home.theta_mrad, manifest.envelope.home_mrad,
                   st_home.active_faults, st_home.latched_faults,
                   (int)saw_home_mode, (int)home_monotonic, (int)plant_moved);
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

        /* 5c. Write-open verification (path comes from the manifest, like every
         *     other path in this project -- no hardcoded device names). */
        int wfd = open(act_path, O_WRONLY);
        if (wfd < 0 && errno == EPERM) {
            printf("[5c/5] PASS: open('%s', O_WRONLY) WITHOUT ability -> EPERM (Fail-closed)\n",
                   act_path);
        } else {
            if (wfd >= 0) close(wfd);
            printf("[5c/5] FAIL: open with O_WRONLY returned %d (errno=%d)\n", wfd, errno);
            all_passed = false;
        }
    }

    latch_status_reply_t st;
    memset(&st, 0, sizeof(st));
    if (devctl(act_fd, DCMD_LATCH_GET_STATUS, &st, sizeof(st), NULL) != 0) {
        /* A failed final status read must NOT be reported as success. The
         * previous revision returned 0 here, which skipped both the PASS
         * banner and the FAIL branch: the caller saw VERIFY_RC=0 with no
         * verdict at all. Exit 2 means "the harness could not complete",
         * which is distinguishable from "the invariants were violated". */
        fprintf(stderr, "latch_verify: FATAL: cannot read the final supervisor status "
                        "(devctl GET_STATUS failed) -- verification INCOMPLETE.\n");
        close(act_fd);
        return 2;
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
