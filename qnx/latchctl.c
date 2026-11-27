/*
 * qnx/latchctl.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Administrative & Verification CLI Utility:
 *   - Interacts with /dev/latch/actuator via devctl().
 *   - Verifies whether caller holds custom "latch/actuator" ability.
 *   - Commands emergency operator HA-HOLD lock.
 *   - Queries live status, nanosecond latency telemetry, and manifest hash.
 *   - Dumps .bss evidence tape to CSV format.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>

#include "latch_protocol.h"
#include "latch_manifest.h"

static const char *mode_name(uint16_t m) {
    switch (m) {
        case LATCH_MODE_HP:   return "HP (High Performance)";
        case LATCH_MODE_HOLD: return "HOLD (High Assurance 1)";
        case LATCH_MODE_HOME: return "HOME (High Assurance 2)";
        default:              return "UNKNOWN";
    }
}

static void format_fault_bits(uint16_t bits, char *buf, size_t buflen) {
    if (bits == 0u) {
        snprintf(buf, buflen, "0x0000 (NONE)");
        return;
    }
    char names[128] = "";
    if (bits & LATCH_FAULT_MAGIC)    strcat(names, "MAGIC|");
    if (bits & LATCH_FAULT_CRC)      strcat(names, "CRC|");
    if (bits & LATCH_FAULT_SEQ)      strcat(names, "SEQ|");
    if (bits & LATCH_FAULT_NAN)      strcat(names, "NAN|");
    if (bits & LATCH_FAULT_RESERVED) strcat(names, "RESERVED|");
    if (bits & LATCH_FAULT_KEEPOUT)  strcat(names, "KEEPOUT|");
    if (bits & LATCH_FAULT_BOUNDS)   strcat(names, "BOUNDS|");
    if (bits & LATCH_FAULT_RATE)     strcat(names, "RATE|");
    if (bits & LATCH_FAULT_WATCHDOG) strcat(names, "WATCHDOG|");
    if (bits & LATCH_FAULT_I2C)      strcat(names, "I2C|");
    if (bits & LATCH_FAULT_OPERATOR) strcat(names, "OPERATOR|");
    if (bits & LATCH_FAULT_EPERM)    strcat(names, "EPERM|");
    if (bits & LATCH_FAULT_UNIT)     strcat(names, "UNIT|");
    if (bits & LATCH_FAULT_HEARTBEAT) strcat(names, "HEARTBEAT|");
    if (bits & LATCH_FAULT_WIDEN)    strcat(names, "WIDEN|");
    if (bits & LATCH_FAULT_DOSE)     strcat(names, "DOSE|");

    size_t len = strlen(names);
    if (len > 0 && names[len - 1] == '|') {
        names[len - 1] = '\0';
    }
    snprintf(buf, buflen, "0x%04X (%s)", bits, names);
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-d /dev/latch/actuator] <command> [args...]\n\n"
            "Commands:\n"
            "  status                             Query live Simplex supervisor state & telemetry\n"
            "  latency                            Report the decision-latency DISTRIBUTION\n"
            "                                      (U-4): sample count, p50/p99, max\n"
            "  session-status                     Report the writer-session state (L-2 handoff)\n"
            "  grant-check                        Verify whether caller holds 'latch/actuator' ability\n"
            "  hold <1|0> [reason]                Set (1) or release (0) operator emergency HA-HOLD\n"
            "  dump <output.csv>                  Dump evidence tape records to CSV\n"
            "  events [-n count] [-s start]       Dump GOVERNOR circular event ring\n"
            "         [--json] [--csv]\n"
            "  manifest-verify <path> [sha256]    Verify manifest integrity, admissibility & sidecar\n"
            "  console [path] [-f]                Mirror the guest kernel console (default\n"
            "                                      /dev/shmem/guest_console.log); -f follows\n"
            "  guest-status                       Report the guest VM lifecycle state\n"
            "  guest-restart [--timeout <sec>]    Stop the guest VM, OBSERVE the writer-session\n"
            "                                      handoff, then start it again\n",
            prog);
}

/*
 * Mirror the QNX-hosted guest kernel console to stdout.
 *
 * The guest's PL011 is a VIRTUAL device inside qvm; its output is captured by
 * `hostdev >/dev/shmem/guest_console.log`. The minimal IFS ships no `cat`,
 * `tail` or `grep`, so this is the supported way for an operator (or a judge)
 * to read what the guest kernel printed.
 */
static int do_console(const char *path, bool follow) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "latchctl: cannot open '%s': %s\n", path, strerror(errno));
        return 1;
    }
    printf("=== LATCH guest console: %s ===\n", path);
    fflush(stdout);

    char line[512];
    while (fgets(line, sizeof(line), fp) != NULL) {
        fputs(line, stdout);
        fflush(stdout);
    }

    if (!follow) {
        fclose(fp);
        return 0;
    }

    /* Follow mode: poll the file for appended bytes. */
    for (;;) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 200000000L };
        (void)nanosleep(&ts, NULL);
        clearerr(fp);
        while (fgets(line, sizeof(line), fp) != NULL) {
            fputs(line, stdout);
            fflush(stdout);
        }
    }
    /* NOTREACHED */
}

static int do_status(int fd) {
    latch_status_reply_t rep;
    memset(&rep, 0, sizeof(rep));

    latch_governor_status_reply_t gov;
    memset(&gov, 0, sizeof(gov));
    bool has_governor_status = false;
    int rc = devctl(fd, DCMD_LATCH_GET_GOV_STATUS, &gov, sizeof(gov), NULL);
    if (rc == EOK && gov.extension_version >= 1u) {
        rep = gov.latch;
        has_governor_status = true;
    } else {
        rc = devctl(fd, DCMD_LATCH_GET_STATUS, &rep, sizeof(rep), NULL);
    }
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(GET_STATUS) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    char active_str[160];
    char latched_str[160];
    format_fault_bits(rep.active_faults, active_str, sizeof(active_str));
    format_fault_bits(rep.latched_faults, latched_str, sizeof(latched_str));

    printf("=== LATCH Simplex Supervisor Status ===\n");
    printf("Tick Counter         : %" PRIu64 " ticks\n", rep.tick);
    printf("Current Mode         : %s\n", mode_name(rep.mode));
    printf("Actuator Angle       : %d mrad\n", rep.theta_mrad);
    printf("Velocity / Omega     : %d mrad/tick | %d mrad/s\n",
           rep.velocity_mrad_tick, rep.omega_mrad_s);
    printf("Last Proposed Angle  : %d mrad (seq=%u)\n",
           rep.last_u_proposed_mrad, rep.last_seq);
    printf("Decision Latency     : last = %" PRIu64 " cyc (%u ns) | max = %" PRIu64 " cyc (%u ns)\n",
           rep.last_latency_cycles, rep.last_latency_ns,
           rep.max_latency_cycles, rep.max_latency_ns);
    printf("Proposals Received   : %u\n", rep.total_proposals_rx);
    printf("Wire Faults Caught   : %u\n", rep.total_wire_faults);
    printf("Envelope Vetoes      : %u\n", rep.total_envelope_faults);
    printf("Ring Drops / WCET    : %u drops | %u overruns\n",
           rep.total_ring_drops, rep.wcet_overruns);
    printf("Proposal Backlog     : peak %u frames | %u over limit\n",
           rep.max_backlog_seen, rep.backlog_overruns);
    printf("EPERM Rejections     : %u\n", rep.total_eperm_rejects);
    printf("Operator Hold Locked : %s\n", rep.operator_hold_locked ? "YES" : "NO");
    printf("Active Fault Bits    : %s\n", active_str);
    printf("Latched Fault Bits   : %s\n", latched_str);
    printf("Clean Streak         : %u frames\n", rep.clean_streak);
    if (has_governor_status) {
        static const char *const rung_names[] = {
            "HP", "ADVISE", "CLAMP", "SLOW", "SAFE_STOP", "LATCH"
        };
        const char *rung_name = gov.rung < (sizeof(rung_names) / sizeof(rung_names[0]))
                                    ? rung_names[gov.rung] : "INVALID";
        printf("GOVERNOR             : %s | rung=%s (%u)\n",
               gov.enabled ? "enabled" : "disabled", rung_name, gov.rung);
        printf("V2 Session / Lease   : %s | %u ticks left | lease age %u ticks\n",
               gov.v2_session ? "active" : "inactive", gov.lease_ticks_remaining,
               gov.lease_age_ticks);
        printf("Warm-up / Agent      : %u heartbeats | state %u\n",
               gov.warmup_heartbeats_seen, gov.agent_state);
        if (gov.extension_version >= 2u) {
            printf("Recovery Clean       : %u accepted commands\n", gov.clean_command_streak);
        }
        if (gov.extension_version >= 3u) {
            printf("Deadline Misses      : %u overruns\n", gov.deadline_misses);
        }
        if (gov.extension_version >= 4u) {
            printf("HOMEOSTAT            : %s | scale_q8=%u (256=unity) | v_max ceiling=%u | stress epochs=%u\n",
                   gov.homeostat_enabled ? "enabled" : "disabled",
                   gov.homeostat_scale_q8, gov.homeostat_v_max,
                   gov.homeostat_stress_epochs);
        }
        if (gov.extension_version >= 5u) {
            printf("Lease Owner          : %s | producer tag %u | session dead %s\n",
                   gov.lease_owner_valid ? "valid" : "unset", gov.lease_owner_tag,
                   gov.session_dead ? "YES" : "NO");
            printf("Foreign / Takeovers  : %u frames | %u takeovers\n",
                   gov.foreign_frames, gov.producer_takeovers);
        }
        if (gov.extension_version >= 6u) {
            /* The epoch is the session's IDENTITY (RT-02): two sessions can
             * both start at sequence 1, but they cannot share an epoch. */
            printf("Session Epoch        : %s | 0x%08X\n",
                   gov.session_epoch_valid ? "bound" : "unbound",
                   (unsigned int)gov.session_epoch);
        }
        printf("Rate / Shrink        : %u tokens | active=%u v_max=%u scale_q8=%u\n",
               gov.rate_tokens_remaining, gov.shrink_active,
               gov.shrink_v_max, gov.shrink_scale_q8);
        printf("Coherence            : %s | counter=%u\n",
               gov.coherence_valid ? "valid" : "unset", gov.coherence_ctr);
    }

    char sha_hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(&sha_hex[i * 2], 3, "%02x", rep.manifest_sha256[i]);
    }
    sha_hex[64] = '\0';
    printf("Manifest SHA-256     : %s\n", sha_hex);

    return 0;
}

/*
 * THE DECISION-LATENCY DISTRIBUTION (U-4).
 *
 * This is the READOUT of the measurement that replaces the withdrawn
 * "61 microsecond WCET" claim.  It reports a DISTRIBUTION over a sample of
 * ticks, with the sample count, and it reports each percentile as the
 * BUCKET RANGE the sample fell into -- never as a point estimate the
 * histogram cannot support.
 *
 * It is deliberately NOT called a worst-case execution time: the project
 * claims no WCET, and a tool that printed one would be the first place the
 * withdrawn claim came back.
 */

/* The nearest-rank percentile: the smallest bucket whose cumulative count
 * reaches ceil(num/den * samples).  Integer arithmetic only -- a floating
 * point rank could put a sample in the wrong bucket. */
static int latency_percentile(const uint64_t *hist, uint64_t samples,
                               unsigned num_buckets, uint64_t num, uint64_t den,
                               uint64_t *lo, uint64_t *hi) {
    if (samples == 0u || hist == NULL) return -1;
    uint64_t rank = (num * samples + den - 1u) / den;
    if (rank == 0u) rank = 1u;
    uint64_t cumulative = 0u;
    for (unsigned b = 0u; b < num_buckets; ++b) {
        cumulative += hist[b];
        if (cumulative >= rank) {
            latch_latency_bucket_range(b, lo, hi);
            return 0;
        }
    }
    return -1;
}

/* Cycles to nanoseconds, without the overflow the naive form has.  The
 * supervisor uses the same quotient/remainder shape, so the two agree. */
static uint64_t latency_cycles_to_ns(uint64_t cycles, uint64_t cps) {
    if (cps == 0u) return 0u;
    uint64_t whole = cycles / cps;
    uint64_t rem   = cycles % cps;
    if (whole > (UINT64_MAX / 1000000000ULL) - 1u) return UINT64_MAX;
    return whole * 1000000000ULL + (rem * 1000000000ULL) / cps;
}

static void latency_print_distribution(const char *label,
                                       const uint64_t *hist, uint64_t samples,
                                       uint64_t cps) {
    uint64_t p50_lo = 0u, p50_hi = 0u, p99_lo = 0u, p99_hi = 0u;
    int have50 = latency_percentile(hist, samples, LATCH_LATENCY_BUCKETS,
                                    50u, 100u, &p50_lo, &p50_hi);
    int have99 = latency_percentile(hist, samples, LATCH_LATENCY_BUCKETS,
                                    99u, 100u, &p99_lo, &p99_hi);
    /* latency_percentile() returns 0 on SUCCESS and -1 on failure, so the
     * test is `!= 0`, NOT `!`.  The inverted test printed "no samples" for
     * every populated histogram -- the readout said the distribution was
     * empty when the distribution was right there in the payload. */
    if (have50 != 0 || have99 != 0) {
        printf("%-22s: no samples\n", label);
        return;
    }
    printf("%-22s: p50 = [%" PRIu64 ", %" PRIu64 ") cyc ([%" PRIu64 ", %" PRIu64 ") ns)"
           " | p99 = [%" PRIu64 ", %" PRIu64 ") cyc ([%" PRIu64 ", %" PRIu64 ") ns)\n",
           label,
           p50_lo, p50_hi, latency_cycles_to_ns(p50_lo, cps), latency_cycles_to_ns(p50_hi, cps),
           p99_lo, p99_hi, latency_cycles_to_ns(p99_lo, cps), latency_cycles_to_ns(p99_hi, cps));
}

static int do_latency(int fd) {
    latch_latency_stats_t st;
    memset(&st, 0, sizeof(st));

    int rc = devctl(fd, DCMD_LATCH_GET_LATENCY_STATS, &st, sizeof(st), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(GET_LATENCY_STATS) failed: %s (%d)\n",
                strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }
    if (st.struct_size != (uint32_t)sizeof(st)) {
        fprintf(stderr, "latchctl: the supervisor returned a latency payload of a "
                        "different size (%u vs %u) -- refuse to interpret it\n",
                st.struct_size, (unsigned int)sizeof(st));
        return 1;
    }

    printf("=== LATCH Supervisor Decision-Latency Distribution ===\n");
    printf("Samples (ticks)       : %" PRIu64 "\n", st.samples_total);
    printf("Decision-path samples : %" PRIu64 " (a proposal was dequeued)\n", st.samples_decision);
    printf("Idle-path samples     : %" PRIu64 " (the proposal queue was empty)\n", st.samples_idle);
    printf("Motion evaluations    : %" PRIu64 " (of the decision-path samples)\n", st.samples_motion);
    printf("Cycle rate            : %" PRIu64 " Hz\n", st.cycles_per_sec);
    printf("First / last tick     : %" PRIu64 " / %" PRIu64 "\n",
           st.first_tick, st.last_tick);
    if (st.samples_decision > 0u) {
        printf("Min / Max (decision)  : %" PRIu64 " / %" PRIu64 " cyc"
               " (%" PRIu64 " / %" PRIu64 " ns)\n",
               st.min_decision_cycles, st.max_decision_cycles,
               latency_cycles_to_ns(st.min_decision_cycles, st.cycles_per_sec),
               latency_cycles_to_ns(st.max_decision_cycles, st.cycles_per_sec));
        /* The mean is over the DECISION-path samples only, so it describes
         * the decision path.  Dividing the ALL-sample sum by the all-sample
         * count under a "Mean (decision)" label reported a number that
         * described neither path. */
        printf("Mean (decision)       : %.3f cyc\n",
               (double)st.sum_decision_cycles / (double)st.samples_decision);
    }
    if (st.samples_total > 0u) {
        printf("Min / Max (all ticks) : %" PRIu64 " / %" PRIu64 " cyc"
               " (%" PRIu64 " / %" PRIu64 " ns)\n",
               st.min_cycles, st.max_cycles,
               latency_cycles_to_ns(st.min_cycles, st.cycles_per_sec),
               latency_cycles_to_ns(st.max_cycles, st.cycles_per_sec));
        printf("Mean (all ticks)      : %.3f cyc\n",
               (double)st.sum_cycles / (double)st.samples_total);
    }
    latency_print_distribution("Decision path", st.hist_decision,
                               st.samples_decision, st.cycles_per_sec);
    latency_print_distribution("Idle path", st.hist_idle,
                               st.samples_idle, st.cycles_per_sec);
    printf("Histogram shape      : decision path %u non-empty buckets"
           " | idle path %u non-empty buckets (of %u)\n",
           latch_latency_nonzero_buckets(st.hist_decision, LATCH_LATENCY_BUCKETS),
           latch_latency_nonzero_buckets(st.hist_idle, LATCH_LATENCY_BUCKETS),
           LATCH_LATENCY_BUCKETS);
    printf("Over budget           : %" PRIu64 " samples (over the manifest's "
           "timing.wcet_budget_us)\n", st.over_budget);
    printf("Over tick period      : %" PRIu64 " samples (over the decision period)\n",
           st.over_period);
    {
        char modes[256];
        size_t at = 0u;
        modes[0] = '\0';
        for (unsigned m = 0u; m < LATCH_LATENCY_MODES; ++m) {
            if (st.mode_ticks[m] == 0u) continue;
            int n = snprintf(modes + at, sizeof(modes) - at, "%s%s=%u",
                             (at == 0u) ? "" : " ",
                             mode_name((uint16_t)m), st.mode_ticks[m]);
            if (n < 0 || (size_t)n >= sizeof(modes) - at) break;
            at += (size_t)n;
        }
        printf("Mode ticks            : %s\n", (modes[0] == '\0') ? "(none)" : modes);
    }
    return 0;
}

static int do_grant_check(int fd) {
    int rc = devctl(fd, DCMD_LATCH_PROBE_ABILITY, NULL, 0, NULL);
    if (rc == EOK) {
        printf("[AUTH] GRANTED: Process holds 'latch/actuator' ability. Actuation permitted.\n");
        return 0;
    }
    if (rc == EPERM) {
        printf("[AUTH] DENIED: Process lacks 'latch/actuator' ability (EPERM). Fail-closed.\n");
        return 2;
    }
    fprintf(stderr, "[AUTH] ERROR: Unexpected devctl failure: %s (%d)\n", strerror(rc), rc);
    return 1;
}

static int do_manifest_verify(const char *manifest_path, const char *expected_arg) {
    if (manifest_path == NULL) {
        fprintf(stderr, "Usage: latchctl manifest-verify <path> [expected_sha256]\n");
        return 1;
    }
    latch_manifest_t m;
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &m, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "[MANIFEST] REJECTED: Could not load or validate '%s': %s\n", manifest_path, err_buf);
        return 1;
    }
    if (expected_arg != NULL) {
        if (strncasecmp(m.sha256_hex, expected_arg, 64) != 0) {
            fprintf(stderr, "[MANIFEST] MISMATCH: Computed %s != Expected %s\n", m.sha256_hex, expected_arg);
            return 1;
        }
    }
    printf("[MANIFEST] VERIFIED: Manifest '%s' SHA-256=%s (admissibility SATISFIED)\n",
           manifest_path, m.sha256_hex);
    return 0;
}

static int do_hold(int fd, int argc, char *argv[]) {
    if (argc < 1) {
        fprintf(stderr, "Usage: latchctl hold <1|0> [reason_code]\n");
        return 1;
    }

    uint32_t lock_val = (uint32_t)strtoul(argv[0], NULL, 10);
    uint32_t reason   = (argc >= 2) ? (uint32_t)strtoul(argv[1], NULL, 10) : 1u;

    latch_force_hold_cmd_t cmd = {
        .lock_hold   = lock_val ? 1u : 0u,
        .reason_code = reason
    };

    int rc = devctl(fd, DCMD_LATCH_FORCE_HOLD, &cmd, sizeof(cmd), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(FORCE_HOLD) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    printf("latchctl: Operator HA-HOLD %s (reason=%u)\n",
           lock_val ? "LOCKED" : "RELEASED", reason);

    /*
     * Report what ACTUALLY happened to a release (L-5).
     *
     * The operator release is only effective while the ladder is at LATCH,
     * the rung from which the fail-closed interlock can only be left with
     * an explicit acknowledgement.  A release issued at any other rung used
     * to be consumed silently, so the operator believed it "took" when it had
     * done nothing at all.  The supervisor now RETAINS such a request and
     * reports its state, and this prints the settled outcome.
     */
    if (!lock_val) {
        latch_hold_status_t st;
        memset(&st, 0, sizeof(st));
        int src = devctl(fd, DCMD_LATCH_GET_HOLD_STATUS, &st, sizeof(st), NULL);
        if (src != EOK) {
            fprintf(stderr, "latchctl: WARNING: could not read the release state "
                            "(%s (%d)) -- the request was accepted but its effect "
                            "is UNKNOWN.\n", strerror(src), src);
            return 1;
        }
        switch (st.release_state) {
            case LATCH_RELEASE_ARMED:
                printf("latchctl: Release ARMED at rung LATCH: the fail-closed interlock "
                       "may leave LATCH after the manifest's configured clean-frame hysteresis.\n");
                break;
            case LATCH_RELEASE_DEFERRED:
                printf("latchctl: Release RECORDED but DEFERRED: the ladder is at rung %u, "
                       "where a release has no effect (it is armed only at rung LATCH).\n",
                       st.rung);
                printf("latchctl: The request is RETAINED (waiting %u tick(s)); it is "
                       "invalidated if the rung changes. Re-issue 'latchctl hold 0' "
                       "once the status shows rung LATCH.\n",
                       st.release_deferred_ticks);
                break;
            default:
                printf("latchctl: Release NOT armed: the ladder is at rung %u.\n", st.rung);
                break;
        }
    }
    return 0;
}

/*
 * Report the writer-session state (L-2 handoff).
 *
 * `writer_held` is the OBSERVABLE handoff point between two writer sessions:
 * a harness waits for it to read 0 before it opens the proposal node itself,
 * instead of sleeping and hoping the resource manager has processed the
 * previous writer's disconnect.  `session_generation` counts the writer
 * sessions the supervisor has seen, so a caller can also prove it is in a
 * DIFFERENT session from the previous one.
 *
 * This is a read-only query: it grants no ability and changes nothing.
 */
static int do_session_status(int fd) {
    latch_session_status_t st;
    memset(&st, 0, sizeof(st));

    int rc = devctl(fd, DCMD_LATCH_GET_SESSION_STATUS, &st, sizeof(st), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(GET_SESSION_STATUS) failed: %s (%d)\n",
                strerror(rc), rc);
        return (rc == EPERM || rc == EACCES) ? 2 : 1;
    }

    printf("=== LATCH Session Status ===\n");
    /* The numeric value comes FIRST so a machine can parse it without
     * having to understand the human-readable suffix. */
    printf("Writer Held      : %u (%s)\n", st.writer_held,
           st.writer_held ? "exclusive writer OCB is OPEN" : "no writer OCB is open");
    printf("Session Gen      : %u\n", st.session_generation);
    return 0;
}

/* ==========================================================================
 * Guest lifecycle control (U-1)
 * ==========================================================================
 *
 * The guest VM is owned by `latch_guestd`, a narrowly-typed process that
 * serves exactly one control channel (`/dev/latch/guestctl`, channel type
 * `guest_ctl_t`).  This client is the ONLY thing that talks to it.
 *
 * The restart is deliberately split into an OBSERVED sequence rather than a
 * single server-side "restart":
 *
 *     1. STOP   -- latch_guestd kills the guest VM child and waits for it
 *                  to be reaped.
 *     2. OBSERVE -- poll the SUPERVISOR's session status until it reports
 *                  that the exclusive proposal writer has been released.
 *                  The handoff is a supervisor fact, so the supervisor is
 *                  what reports it; a sleep would only guess.
 *     3. START  -- latch_guestd spawns a new guest VM child.
 *
 * If step 2 does not complete inside the timeout, the guest is NOT started
 * again.  Starting a guest while the previous writer still holds the
 * proposal node would produce a guest whose ingest is refused with EBUSY
 * and which therefore never streams -- a silent failure that looks like a
 * working system.  Leaving the guest down is the safe direction: the
 * supervisor is in LATCH, the plant is frozen, and the operator is told.
 */
static int guest_open_ctl(void) {
    int fd = open(LATCH_DEV_GUESTCTL, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "latchctl: Cannot open '%s': %s\n",
                LATCH_DEV_GUESTCTL, strerror(errno));
        fprintf(stderr, "latchctl: (the guest-lifecycle daemon is present only on "
                        "profiles that run a guest VM)\n");
        return -1;
    }
    return fd;
}

static int guest_devctl(int fd, unsigned int dcmd, latch_guest_status_t *rep) {
    latch_guest_status_t tmp;
    if (rep == NULL) {
        rep = &tmp;
    }
    memset(rep, 0, sizeof(*rep));
    int rc = devctl(fd, dcmd, rep, sizeof(*rep), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(0x%02X) failed: %s (%d)\n",
                dcmd, strerror(rc), rc);
        return rc;
    }
    return EOK;
}

static int do_guest_status(void) {
    int fd = guest_open_ctl();
    if (fd < 0) {
        return 1;
    }
    latch_guest_status_t st;
    int rc = guest_devctl(fd, (unsigned int)DCMD_LATCH_GET_GUEST_STATUS, &st);
    close(fd);
    if (rc != EOK) {
        return (rc == EPERM || rc == EACCES) ? 2 : 1;
    }

    printf("=== LATCH Guest VM Status ===\n");
    printf("Guest Running    : %s\n", st.running ? "YES" : "NO");
    printf("Guest PID        : %d\n", (int)st.pid);
    printf("Launch Generation: %u\n", st.generation);
    printf("Last Exit Status : 0x%X\n", (unsigned int)st.last_exit_status);
    return 0;
}

/* Read the supervisor's writer-session state.  Returns 1 if a writer is
 * still held, 0 if it is released, and -1 if the state could not be read. */
static int writer_is_held(int actuator_fd) {
    latch_session_status_t st;
    memset(&st, 0, sizeof(st));
    int rc = devctl(actuator_fd, DCMD_LATCH_GET_SESSION_STATUS, &st, sizeof(st), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(GET_SESSION_STATUS) failed: %s (%d)\n",
                strerror(rc), rc);
        return -1;
    }
    return (st.writer_held != 0u) ? 1 : 0;
}

static int do_guest_restart(int argc, char *argv[]) {
    unsigned int timeout_s = 30u;
    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            long v = strtol(argv[++i], NULL, 10);
            if (v < 0) {
                v = 0;
            }
            timeout_s = (unsigned int)v;
        } else {
            fprintf(stderr, "latchctl: guest-restart: unknown argument '%s'\n", argv[i]);
            print_usage("latchctl");
            return 1;
        }
    }

    int ctl_fd = guest_open_ctl();
    if (ctl_fd < 0) {
        return 1;
    }
    int act_fd = open(LATCH_DEV_ACTUATOR, O_RDONLY);
    if (act_fd < 0) {
        fprintf(stderr, "latchctl: Cannot open '%s': %s\n",
                LATCH_DEV_ACTUATOR, strerror(errno));
        close(ctl_fd);
        return 1;
    }

    latch_guest_status_t st;

    /* --- 1. STOP ------------------------------------------------------- */
    if (guest_devctl(ctl_fd, (unsigned int)DCMD_LATCH_GUEST_STOP, &st) != EOK) {
        close(act_fd);
        close(ctl_fd);
        return 1;
    }
    printf("latchctl: guest VM stopped (generation %u, running=%s)\n",
           st.generation, st.running ? "YES" : "NO");

    /* --- 2. OBSERVE the writer-session handoff ------------------------ */
    /*
     * The writer is released when the ingest that held it exits, which
     * happens when the guest VM's virtio-console endpoint closes.  That is
     * a supervisor-side fact and only the supervisor can report it, so the
     * poll reads the supervisor's session status.  It is deliberately NOT
     * a sleep: a fixed delay is exactly the assumption that made the
     * legacy verifier fail with an unrelated EBUSY.
     */
    bool handoff = false;
    const unsigned int poll_ms = 50u;
    for (unsigned int waited = 0u; waited <= timeout_s * 1000u; waited += poll_ms) {
        int held = writer_is_held(act_fd);
        if (held < 0) {
            close(act_fd);
            close(ctl_fd);
            return 1;
        }
        if (held == 0) {
            handoff = true;
            break;
        }
        struct timespec ts = { 0, (long)poll_ms * 1000000L };
        (void)nanosleep(&ts, NULL);
    }
    if (!handoff) {
        fprintf(stderr,
                "latchctl: guest-restart ABORTED: the proposal writer was still held "
                "after %u s. The guest has NOT been restarted.\n"
                "latchctl: Leaving the guest down is the safe direction: the "
                "supervisor stays in LATCH and the plant is frozen.\n",
                timeout_s);
        close(act_fd);
        close(ctl_fd);
        return 1;
    }
    printf("latchctl: writer-session handoff OBSERVED (no writer OCB is open)\n");

    /* --- 3. START ------------------------------------------------------ */
    if (guest_devctl(ctl_fd, (unsigned int)DCMD_LATCH_GUEST_START, &st) != EOK) {
        close(act_fd);
        close(ctl_fd);
        return 1;
    }
    printf("latchctl: guest VM started (pid %d, generation %u)\n",
           (int)st.pid, st.generation);
    printf("latchctl: The guest must boot and re-establish its session before it "
           "streams again; the supervisor stays in LATCH until then.\n");

    close(act_fd);
    close(ctl_fd);
    return 0;
}

static int do_dump(int fd, const char *out_csv) {    latch_tape_dump_t dump;    memset(&dump, 0, sizeof(dump));
    dump.start_index = UINT64_MAX;
    dump.count       = LATCH_DUMP_MAX_ENTRIES;

    int rc = devctl(fd, DCMD_LATCH_DUMP_TAPE, &dump, sizeof(dump), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(DUMP_TAPE) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    FILE *fp = stdout;
    if (out_csv != NULL && strcmp(out_csv, "-") != 0) {
        fp = fopen(out_csv, "w");
        if (!fp) {
            fprintf(stderr, "latchctl: Cannot open output '%s': %s\n", out_csv, strerror(errno));
            return 1;
        }
    }

    fprintf(fp, "# LATCH Evidence Tape Dump | Records: %u | Latest Tick: %" PRIu64 "\n",
            dump.count, dump.latest_tick);
    fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,fault_bits\n");

    for (uint32_t i = 0; i < dump.count; ++i) {
        const latch_tape_entry_t *e = &dump.entries[i];
        uint64_t lat = (e->cycles_out >= e->cycles_in) ? (e->cycles_out - e->cycles_in) : 0;
        fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%u,0x%04X\n",
                e->tick, e->cycles_in, e->cycles_out, lat,
                e->seq, e->u_proposed, e->theta_applied,
                (unsigned int)e->mode, (unsigned int)e->fault_bits);
    }

    if (fp != stdout) {
        fclose(fp);
        printf("latchctl: Exported %u tape records to '%s'\n", dump.count, out_csv);
    }
    return 0;
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; ++i) {
        sprintf(&hex_out[i * 2], "%02x", bytes[i]);
    }
    hex_out[len * 2] = '\0';
}

static const char *rung_str(uint8_t r) {
    switch (r) {
        case 0: return "HP";
        case 1: return "ADVISE";
        case 2: return "CLAMP";
        case 3: return "SLOW";
        case 4: return "SAFE_STOP";
        case 5: return "LATCH";
        default: return "UNK";
    }
}

static const char *kind_str(uint8_t k) {
    switch (k) {
        case 0: return "CMD";
        case 1: return "HEARTBEAT";
        case 2: return "CMD_V2";
        case 3: return "SHRINK_REQ";
        default: return "UNK";
    }
}

static const char *verdict_str(uint8_t v) {
    switch (v) {
        case 0: return "NONE";
        case 1: return "ACCEPT";
        case 2: return "HEARTBEAT";
        case 3: return "SHRINK";
        case 4: return "REJECT";
        default: return "UNK";
    }
}

static const char *mode_short_name(uint8_t m) {
    switch (m) {
        case LATCH_MODE_HP:   return "HP";
        case LATCH_MODE_HOLD: return "HOLD";
        case LATCH_MODE_HOME: return "HOME";
        default:              return "UNK";
    }
}

static int do_events(int fd, int argc, char *argv[]) {
    uint32_t count = LATCH_GOV_EVENT_DUMP_MAX;
    uint64_t start_index = UINT64_MAX;
    bool json_out = false;
    bool csv_out = false;

    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            count = (uint32_t)strtoul(argv[++i], NULL, 10);
            if (count == 0u || count > LATCH_GOV_EVENT_DUMP_MAX) {
                count = LATCH_GOV_EVENT_DUMP_MAX;
            }
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            start_index = (uint64_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--json") == 0) {
            json_out = true;
        } else if (strcmp(argv[i], "--csv") == 0) {
            csv_out = true;
        }
    }

    latch_gov_event_dump_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.start_index = start_index;
    dump.count = count;

    int rc = devctl(fd, DCMD_LATCH_DUMP_GOV_EVENTS, &dump, sizeof(dump), NULL);
    if (rc != EOK) {
        fprintf(stderr, "latchctl: devctl(DUMP_GOV_EVENTS) failed: %s (%d)\n", strerror(rc), rc);
        return (rc == EPERM) ? 2 : 1;
    }

    char sha_hex[65];
    bytes_to_hex(dump.manifest_sha256, 32, sha_hex);

    if (json_out) {
        printf("{\n");
        printf("  \"start_index\": %" PRIu64 ",\n", dump.start_index);
        printf("  \"latest_index\": %" PRIu64 ",\n", dump.latest_index);
        printf("  \"count\": %u,\n", dump.count);
        printf("  \"dropped\": %u,\n", dump.dropped);
        printf("  \"overflow\": %u,\n", dump.overflow);
        printf("  \"record_version\": %u,\n", dump.record_version);
        printf("  \"manifest_sha256\": \"%s\",\n", sha_hex);
        printf("  \"events\": [\n");
        for (uint32_t i = 0; i < dump.count; ++i) {
            const latch_gov_event_t *e = &dump.entries[i];
            char fault_str[160];
            format_fault_bits(e->fault_bits, fault_str, sizeof(fault_str));
            char ev_hex[125];
            bytes_to_hex((const uint8_t *)e, sizeof(*e), ev_hex);

            printf("    {\n");
            printf("      \"event_index\": %" PRIu64 ",\n", e->event_index);
            printf("      \"tick\": %" PRIu64 ",\n", e->tick);
            printf("      \"cycles\": %" PRIu64 ",\n", e->cycles);
            printf("      \"seq\": %u,\n", e->seq);
            printf("      \"raw_u_mrad\": %d,\n", e->raw_u_mrad);
            printf("      \"normalized_u_mrad\": %d,\n", e->normalized_u_mrad);
            printf("      \"theta_applied_mrad\": %d,\n", e->theta_applied_mrad);
            printf("      \"unit_id\": %u,\n", e->unit_id);
            printf("      \"coherence_ctr\": %u,\n", e->coherence_ctr);
            printf("      \"lease_remaining\": %u,\n", e->lease_remaining);
            printf("      \"fault_bits\": %u,\n", (unsigned int)e->fault_bits);
            printf("      \"fault_names\": \"%s\",\n", fault_str);
            printf("      \"mode\": %u,\n", (unsigned int)e->mode);
            printf("      \"mode_name\": \"%s\",\n", mode_short_name(e->mode));
            printf("      \"rung_before\": %u,\n", (unsigned int)e->rung_before);
            printf("      \"rung_after\": %u,\n", (unsigned int)e->rung_after);
            printf("      \"rung_before_name\": \"%s\",\n", rung_str(e->rung_before));
            printf("      \"rung_after_name\": \"%s\",\n", rung_str(e->rung_after));
            printf("      \"kind\": %u,\n", (unsigned int)e->kind);
            printf("      \"kind_name\": \"%s\",\n", kind_str(e->kind));
            printf("      \"verdict\": %u,\n", (unsigned int)e->verdict);
            printf("      \"verdict_name\": \"%s\",\n", verdict_str(e->verdict));
            printf("      \"agent_state\": %u,\n", (unsigned int)e->agent_state);
            printf("      \"confidence_q8\": %u,\n", (unsigned int)e->confidence_q8);
            printf("      \"coherence_valid\": %u,\n", (unsigned int)e->coherence_valid);
            printf("      \"bytes_hex\": \"%s\"\n", ev_hex);
            printf("    }%s\n", (i + 1 < dump.count) ? "," : "");
        }
        printf("  ]\n");
        printf("}\n");
        return 0;
    }

    if (csv_out) {
        printf("event_index,tick,cycles,seq,raw_u,norm_u,theta_applied,unit_id,coherence_ctr,lease_rem,fault_bits,rung_before,rung_after,kind,verdict,agent_state,confidence,coh_valid\n");
        for (uint32_t i = 0; i < dump.count; ++i) {
            const latch_gov_event_t *e = &dump.entries[i];
            printf("%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%d,%u,%u,%u,0x%04X,%u,%u,%u,%u,%u,%u,%u\n",
                   e->event_index, e->tick, e->cycles, e->seq,
                   e->raw_u_mrad, e->normalized_u_mrad, e->theta_applied_mrad,
                   e->unit_id, e->coherence_ctr, e->lease_remaining,
                   e->fault_bits, e->rung_before, e->rung_after,
                   e->kind, e->verdict, e->agent_state, e->confidence_q8, e->coherence_valid);
        }
        return 0;
    }

    /* Human-readable text format */
    printf("=== LATCH Governor Event Ring Dump ===\n");
    printf("Events Returned  : %u (requested start=%" PRIu64 ")\n", dump.count, dump.start_index);
    printf("Latest Write Idx : %" PRIu64 "\n", dump.latest_index);
    printf("Overflow / Drops : %s | %u dropped\n", dump.overflow ? "YES" : "NO", dump.dropped);
    printf("Manifest SHA-256 : %s\n\n", sha_hex);

    for (uint32_t i = 0; i < dump.count; ++i) {
        const latch_gov_event_t *e = &dump.entries[i];
        char fault_str[160];
        format_fault_bits(e->fault_bits, fault_str, sizeof(fault_str));
        printf("#%04" PRIu64 ": tick=%" PRIu64 " seq=%u u=%d->%d->%d unit=%u coh=%u(%s) lease=%u faults=%s rung=%s->%s kind=%s verdict=%s state=%u conf=%u\n",
               e->event_index, e->tick, e->seq,
               e->raw_u_mrad, e->normalized_u_mrad, e->theta_applied_mrad,
               e->unit_id, e->coherence_ctr, e->coherence_valid ? "valid" : "invalid",
               e->lease_remaining, fault_str,
               rung_str(e->rung_before), rung_str(e->rung_after),
               kind_str(e->kind), verdict_str(e->verdict),
               e->agent_state, e->confidence_q8);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    const char *dev_path = LATCH_DEV_ACTUATOR;
    int opt;

    while ((opt = getopt(argc, argv, "d:")) != -1) {
        switch (opt) {
            case 'd':
                dev_path = optarg;
                break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *cmd = argv[optind++];

    if (strcmp(cmd, "manifest-verify") == 0) {
        const char *mpath = (optind < argc) ? argv[optind++] : NULL;
        const char *exp_sha = (optind < argc) ? argv[optind++] : NULL;
        return do_manifest_verify(mpath, exp_sha);
    }

    if (strcmp(cmd, "console") == 0) {
        const char *cpath = "/dev/shmem/guest_console.log";
        bool follow = false;
        for (int i = optind; i < argc; ++i) {
            if (strcmp(argv[i], "-f") == 0) {
                follow = true;
            } else {
                cpath = argv[i];
            }
        }
        return do_console(cpath, follow);
    }

    /* The guest-lifecycle commands talk to latch_guestd on their OWN node,
     * not to the supervisor's actuator node, so they are dispatched before
     * the generic device open below. */
    if (strcmp(cmd, "guest-status") == 0) {
        return do_guest_status();
    }
    if (strcmp(cmd, "guest-restart") == 0) {
        return do_guest_restart(argc - optind, &argv[optind]);
    }

    int oflag = (strcmp(cmd, "hold") == 0) ? O_RDWR : O_RDONLY;
    int fd = open(dev_path, oflag);
    if (fd < 0) {
        if (strcmp(cmd, "grant-check") == 0 && (errno == EPERM || errno == EACCES)) {
            printf("[AUTH] DENIED: Process lacks 'latch/actuator' ability (EPERM). Fail-closed.\n");
            return 2;
        }
        fprintf(stderr, "latchctl: Cannot open '%s': %s\n", dev_path, strerror(errno));
        return (errno == EACCES || errno == EPERM) ? 2 : 1;
    }

    int ret = 0;
    if (strcmp(cmd, "status") == 0) {
        ret = do_status(fd);
    } else if (strcmp(cmd, "latency") == 0) {
        ret = do_latency(fd);
    } else if (strcmp(cmd, "session-status") == 0) {
        ret = do_session_status(fd);
    } else if (strcmp(cmd, "grant-check") == 0) {
        ret = do_grant_check(fd);
    } else if (strcmp(cmd, "hold") == 0) {
        ret = do_hold(fd, argc - optind, &argv[optind]);
    } else if (strcmp(cmd, "dump") == 0) {
        const char *csv_file = (optind < argc) ? argv[optind] : "-";
        ret = do_dump(fd, csv_file);
    } else if (strcmp(cmd, "events") == 0) {
        ret = do_events(fd, argc - optind, &argv[optind]);
    } else {
        fprintf(stderr, "latchctl: Unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }

    close(fd);
    return ret;
}
