/*
 * qnx/latchd.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Host-Side Mixed-Criticality Simplex Supervisor & Dual-Node Resource Manager:
 *   - Attaches /dev/latch/proposal (write-only IPC ingest endpoint).
 *   - Attaches /dev/latch/actuator (devctl-only actuator & evidence endpoint).
 *   - Governed by custom ability "latch/actuator" (created with flags 0:
 *     neither root nor non-root has it by default; checked via
 *     iofunc_client_info_able()).
 *   - Drives PCA9685 16-channel PWM controller at I2C address 0x40 on /dev/i2c1.
 *   - Runs 1.000 ms SCHED_FIFO priority 63 decision tick pinned to _cpu-0.
 *   - Enforces zero-hardcoding metadata architecture via `latch.manifest`.
 *   - Concurrency: Lockless 256-slot ring buffer with Seqlock snapshot guard for concurrent multi-core reads.
 *   - Calibrates ClockCycles() to truthful nanoseconds via QNX qtime syspage.
 *   - Fully testable via POSIX host-simulation (gcc -DLATCH_HOST_SIM).
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef __QNXNTO__
#include <devctl.h>
#include <hw/i2c.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/iomsg.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/resmgr.h>
#include <sys/syspage.h>
/* THE RESOURCE MANAGER'S ATTRIBUTE LOCK.  Every iofunc entry point this
 * resource manager calls goes through the wrappers in this header, so
 * the iofunc call is made while the device's SHARED attribute (the
 * file-use count, the reader and writer counts) is locked.  The iofunc
 * library updates those counters with a NON-ATOMIC 16-bit
 * read-modify-write, so two concurrent opens of the same node can lose
 * an increment -- and the dispatch channel is created with
 * `DISPATCH_FLAG_NOLOCK`, which is exactly what allows two messages to
 * be in flight at the same time. */
#include "latch_rm_attr.h"
#else
#ifndef LATCH_HOST_SIM
#define LATCH_HOST_SIM 1
#endif
#include <pthread.h>
#endif /* __QNXNTO__ */

#include "latch_protocol.h"
#include "latch_manifest.h"
#include "latch_ipc.h"
#include "latch_hold.h"
#include "governor_policy.h"
#include "gov_gate_precheck.h"
#include "gov_homeostat.h"

#include "latch_feedback.h"
#include "latch_feedback_pub.h"

/* ==========================================================================
 * 1. PCA9685 Register Map & Pulse Codes
 * ========================================================================== */

#ifndef _PULSE_CODE_MINAVAIL
#define _PULSE_CODE_MINAVAIL     0
#endif

#define LATCH_PULSE_CODE_TICK    (_PULSE_CODE_MINAVAIL + 1)
#define LATCH_PULSE_CODE_QUIT    (_PULSE_CODE_MINAVAIL + 2)
#define LATCH_PULSE_CODE_ACTUATE (_PULSE_CODE_MINAVAIL + 3)

#define PCA9685_REG_MODE1        0x00u
#define PCA9685_REG_LED0_ON_L    0x06u
#define PCA9685_REG_PRESCALE     0xFEu
#define PCA9685_MODE1_SLEEP      0x10u
#define PCA9685_MODE1_AI         0x20u
#define PCA9685_MODE1_RESTART    0x80u

/* ==========================================================================
 * 2. Lock-Free Atomic Seqlock 256-Slot Publish Ring Buffer
 * ========================================================================== */

#define LATCH_PUB_RING_SIZE 256u

typedef struct latch_seqlock_slot {
    _Atomic uint32_t     gen;
    latch_proposal_t proposal;
} latch_seqlock_slot_t;

typedef struct latch_publish_buffer {
    latch_seqlock_slot_t slots[LATCH_PUB_RING_SIZE];
    _Atomic uint32_t     write_head;
    _Atomic uint32_t     read_tail;
    _Atomic uint32_t     active_idx;
    _Atomic uint32_t     total_publishes;
    _Atomic uint32_t     dropped_full;
    /*
     * Bumped by the session flush (the first-writer open).  A consumer that
     * copied a slot across the bump is holding a PREVIOUS session's frame and
     * must refuse it rather than judge it against the new session's fresh
     * sequence baseline.
     *
     * This is the L-3 fix.  The previous revision flushed the ring from the
     * dispatch thread (write_tail = write_head) while the tick thread could
     * be mid-consume holding a stale tail `t`; the consumer then stored
     * `read_tail = t + 1`, moving the tail BACKWARDS, so a pre-reset frame
     * was delivered into the new session -- where `seq_valid == false`
     * accepts any seq != 0.  One tick wide, but a stale frame judged with a
     * fresh baseline is exactly the hole the session reset exists to close.
     */
    _Atomic uint32_t     flush_epoch;
} latch_publish_buffer_t;

/* ==========================================================================
 * 3. Host-Owned Plant & Simplex State (Only latchd Writes This)
 * ========================================================================== */

typedef struct latch_actuator_target_slot {
    _Atomic uint32_t gen;
    _Atomic uint64_t seq_num;
    int32_t          theta_mrad;
    _Atomic uint32_t io_fault_pending;
} latch_actuator_target_slot_t;

typedef struct latch_simplex_state {
    uint64_t       tick;
    uint64_t       last_latency_cycles;
    uint64_t       max_latency_cycles;
    uint32_t       last_latency_ns;
    uint32_t       max_latency_ns;

    int32_t        theta_mrad;           /* Last angle written to PCA9685     */
    int32_t        omega_mrad_s;         /* (theta - theta_prev) * ticks/sec  */
    int32_t        velocity_mrad_tick;   /* theta - theta_prev per tick       */
    int32_t        accel_mrad_tick2;     /* vel - vel_prev per tick^2         */
    int32_t        last_u_proposed_mrad; /* Last proposed u for telemetry     */
    bool           reconnect_retracting; /* Do not resume HP until home at rest. */

    uint32_t       last_seq;             /* Last accepted sequence number       */
    bool           seq_valid;            /* true once a frame has been accepted  */
    uint64_t       last_rx_cycles;       /* 0 means never                     */
    uint64_t       last_rx_tick;         /* Tick index of last accepted frame */
    uint32_t       last_consumed_pub;    /* Total publish count consumed      */
    uint32_t       clean_streak;         /* Consecutive clean frames          */
    uint32_t       hold_ticks_elapsed;   /* Ticks spent in LATCH_MODE_HOLD    */
    uint8_t        mode;                 /* LATCH_MODE_HP / HOLD / HOME       */

    governor_ladder_state_t gov_ladder;
    gov_gate_state_t gov_gate;
    gov_homeostat_state_t homeostat;
    uint32_t       gov_lease_remaining;
    uint64_t       gov_last_lease_tick;
    uint32_t       gov_last_coherence;
    uint32_t       gov_warmup_seen;
    uint8_t        gov_agent_state;
    bool           gov_v2_session;
    bool           gov_coherence_valid;
    uint32_t       gov_deadline_misses;

    /*
     * Producer-scoped lease authority (L-2).
     *
     * The dead-man lease used to be per-STREAM: any frame on the proposal
     * node could renew it, so a second unprivileged writer could keep a
     * session alive whose real planner had died -- exactly what a dead-man's
     * switch exists to prevent.
     *
     * The lease is now owned by a PRODUCER.  `gov_lease_owner_tag` is the
     * producer tag of the frame that established the session;
     * `gov_lease_owner_valid` says whether there is an owner at all.  A
     * frame from any other producer is LEASE-INERT while the owner's lease
     * is live: it cannot renew the lease, cannot advance the coherence
     * baseline, cannot earn warm-up credit and cannot move the plant.
     *
     * `gov_session_dead` marks the window after the owner's lease expired:
     * the session is no longer authoritative, so another producer may take
     * it over -- which starts a NEW sequence epoch and re-earns the warm-up
     * heartbeat.  The counters are telemetry, so a foreign writer is
     * visible in the status reply instead of being invisible.
     */
    uint16_t       gov_lease_owner_tag;
    bool           gov_lease_owner_valid;
    bool           gov_session_dead;
    uint32_t       gov_foreign_frames;
    uint32_t       gov_producer_takeovers;

    /*
     * Session epoch (RT-02).
     *
     * The producer chooses a FRESH epoch for every session it opens and
     * stamps it on every frame.  The supervisor binds the epoch of the
     * session it is running and rejects every frame that names a different
     * one.
     *
     * Without it, the sequence baseline alone could not tell a frame
     * captured in an earlier session from a frame belonging to this one: the
     * baseline is re-based on every session open, and the old rule accepted
     * ANY non-zero sequence number as the first frame of a new session -- so
     * a stale frame carrying `seq = 999999` was accepted, became the new
     * baseline, and could move the plant.
     *
     * `gov_epoch_ring` remembers the epochs that have already been used.
     * A producer that restarts and reuses its previous epoch is rejected
     * rather than being allowed to resume the old session's identity.  The
     * ring SURVIVES a session reset on purpose: it is the supervisor's
     * memory of which epochs are spent, not part of the session.
     */
    uint32_t       gov_session_epoch;
    bool           gov_session_epoch_valid;
    uint32_t       gov_epoch_ring[LATCH_SESSION_EPOCH_RING];
    uint32_t       gov_epoch_ring_next;

    bool           session_active;       /* true once proposal stream active */
    bool           retracted_home;       /* true when parked at home pose     */
    bool           tape_frozen;          /* true to prevent post-park overwrite */

    uint16_t       active_faults;
    uint16_t       latched_faults;

    uint32_t       total_proposals_rx;
    uint32_t       total_wire_faults;
    uint32_t       total_envelope_faults;
    uint32_t       wcet_overruns;
    uint32_t       max_backlog_seen;  /* Peak proposal-queue depth observed */
    uint32_t       backlog_overruns;  /* Ticks the queue exceeded timing.max_backlog_ticks */
    _Atomic uint32_t total_ring_drops;
    _Atomic uint32_t total_eperm_rejects;
    _Atomic uint32_t eperm_pending;
    _Atomic uint32_t operator_hold_locked;
    _Atomic uint32_t operator_release_pending;
    /*
     * Operator-release bookkeeping (L-5).
     *
     * The operator release is a ONE-SHOT authorisation to leave the LATCH
     * rung, and the ladder can only ARM it while the rung IS LATCH.  The
     * previous revision consumed the request on EVERY governor tick, so a
     * release issued at SAFE_STOP or ADVISE -- where it has no effect -- was
     * silently thrown away and the operator was told nothing.  The operator
     * believed it "took".
     *
     * The request is now RETAINED until it can actually be armed, and it is
     * INVALIDATED whenever the rung changes, so a stale authorisation can
     * never authorise a later, unrelated LATCH exit.  `release_rung` is the
     * rung the operator was looking at when the request was made.
     */
    _Atomic uint32_t operator_release_rung;
    _Atomic uint32_t operator_release_armed;
    _Atomic uint32_t operator_release_deferred_ticks;
    _Atomic uint32_t snapshot_gen;       /* Seqlock counter for telemetry reads */
    _Atomic uint32_t session_reset_pending; /* Armed by latch_io_open(), consumed by tick */
    _Atomic uint32_t open_writers;          /* Active writer reference count */
    /*
     * Writer-session generation (L-2 handoff).
     *
     * Incremented on every 0 -> 1 transition of `open_writers`, i.e. once
     * per writer session.  It is REPORTED (never consumed) so a harness can
     * tell "the writer handle was free" from "this is a different session
     * than the one the guest used" -- the stronger property.
     */
    _Atomic uint32_t session_generation;
    _Atomic uint32_t writer_closed_eof;     /* Set on last writer close, checked after retract */

    int            i2c_fd;
    uint32_t       period_ns;
    int32_t        ticks_per_sec;
    latch_actuator_target_slot_t actuator_io;

    /*
     * THE DECISION-LATENCY DISTRIBUTION (U-4).
     *
     * One sample per tick, aggregated HERE, on the target, because ten to
     * the six ticks cannot be shipped across the serial console and a
     * host-side sample of a host-side run is not a measurement of the
     * target.  Two histograms, because a tick that consumed a proposal runs
     * the whole decision path and a tick with an empty queue does not, and
     * averaging the two together would describe neither.
     *
     * `min_cycles` and `max_cycles` are EXACT; the histograms carry the
     * distribution.  See latch_protocol.h for the bucket scheme.
     */
    uint64_t       lat_samples;
    uint64_t       lat_decision_samples;
    uint64_t       lat_idle_samples;
    uint64_t       lat_motion_samples;
    uint64_t       lat_min_cycles;
    uint64_t       lat_max_cycles;
    uint64_t       lat_sum_cycles;
    uint64_t       lat_sum_decision_cycles;
    uint64_t       lat_min_decision_cycles;
    uint64_t       lat_max_decision_cycles;
    uint64_t       lat_first_tick;
    uint64_t       lat_last_tick;
    uint64_t       lat_over_budget;
    uint64_t       lat_over_period;
    uint32_t       lat_mode_ticks[LATCH_LATENCY_MODES];
    uint64_t       lat_hist_decision[LATCH_LATENCY_BUCKETS];
    uint64_t       lat_hist_idle[LATCH_LATENCY_BUCKETS];
} latch_simplex_state_t;

/* Global manifest and runtime buffers */
static latch_manifest_t       g_manifest;
static latch_tape_entry_t     g_latch_tape[LATCH_TAPE_CAPACITY];
static _Atomic uint64_t       g_tape_write_idx = 0u;
static latch_gov_event_t      g_gov_events[LATCH_GOV_EVENT_CAPACITY];
static _Atomic uint64_t       g_gov_event_write_idx = 0u;
static _Atomic uint32_t       g_gov_event_overflow = 0u;
static latch_publish_buffer_t g_pub_buf;
static latch_simplex_state_t  g_simplex;
/*
 * The feedback publisher is OPTIONAL and OFF by default.  The flag is a
 * plain read in the tick -- no lock, no function call -- because the
 * publisher is started once before the decision thread and stopped once
 * after it, so the value cannot change while the tick is running.
 */
static bool                   g_feedback_pub_enabled = false;
#ifdef __QNXNTO__
static volatile sig_atomic_t  g_running = 1;
#endif
static uint64_t               g_cycles_per_sec = 0;

/* ==========================================================================
 * 4. High-Resolution Cycle Counter & Nanosecond Converter (Fix E-4)
 * ========================================================================== */

static void latch_time_init(void) {
#ifdef __QNXNTO__
    g_cycles_per_sec = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
#else
    g_cycles_per_sec = 1000000000ULL;
#endif
    if (g_cycles_per_sec == 0) {
        g_cycles_per_sec = 1000000000ULL;
    }
}

static inline uint64_t latch_clock_cycles(void) {
#ifdef __QNXNTO__
    return ClockCycles();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
#endif
}

/*
 * Convert a cycle delta to nanoseconds WITHOUT overflowing, and SATURATE
 * instead of wrapping.
 *
 * The previous form, `(dcycles * 1000000000ULL) / cps`, overflows the uint64
 * intermediate as soon as `dcycles` exceeds UINT64_MAX/1e9 (~1.844e10
 * cycles -- about 295 s at 62.5 MHz), and the quotient was then TRUNCATED to
 * uint32. A long stall was therefore reported as a SMALL latency, which is
 * exactly backwards for a safety measurement: the bigger the stall, the
 * smaller the number on the status reply.
 *
 * The division is split into quotient and remainder, so the largest
 * intermediate is `rem * 1e9` with `rem < cps` (a clock rate), and the final
 * value saturates at the largest nanosecond count the uint32 ABI field can
 * carry.
 */
static inline uint32_t latch_cycles_to_ns(uint64_t dcycles) {
    if (g_cycles_per_sec == 0) return 0;
    const uint64_t cps  = g_cycles_per_sec;
    const uint64_t whole = dcycles / cps;
    const uint64_t rem   = dcycles % cps;

    uint64_t ns = 0;
    if (whole <= (UINT64_MAX / 1000000000ULL)) {
        ns = whole * 1000000000ULL;
        if (rem <= (UINT64_MAX / 1000000000ULL)) {
            ns += (rem * 1000000000ULL) / cps;
        } else {
            ns = UINT64_MAX;
        }
    } else {
        ns = UINT64_MAX;
    }
    return (ns > (uint64_t)UINT32_MAX) ? UINT32_MAX : (uint32_t)ns;
}

static bool latch_governor_enabled(void) {
    return g_manifest.schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION &&
           g_manifest.governor.enabled != 0u;
}

static governor_ladder_config_t latch_governor_ladder_config(void) {
    governor_ladder_config_t config = {
        .enabled = latch_governor_enabled() ? 1u : 0u,
        .advisory_fault_mask = g_manifest.governor.advise_fault_mask,
        .faults_per_demotion = g_manifest.governor.demote_faults_per_rung,
        .clean_frames_per_promotion = g_manifest.governor.promote_clean_frames
    };
    return config;
}

static void latch_governor_init_state(latch_simplex_state_t *state) {
    if (state == NULL) return;
    governor_ladder_init(&state->gov_ladder);
    gov_gate_init(&g_manifest.governor, &state->gov_gate);
    gov_homeostat_init(&state->homeostat);
    state->gov_lease_remaining = 0u;
    state->gov_last_lease_tick = 0u;
    state->gov_last_coherence = 0u;
    state->gov_warmup_seen = 0u;
    state->gov_agent_state = 0u;
    state->gov_v2_session = false;
    state->gov_coherence_valid = false;
    /* A new session has no lease owner (L-2): the next producer to send a
     * valid v2 frame establishes it. */
    state->gov_lease_owner_tag = LATCH_PRODUCER_TAG_NONE;
    state->gov_lease_owner_valid = false;
    state->gov_session_dead = false;
}

/* ==========================================================================
 * HOMEOSTAT outer loop (Ashby ultrastability) -- CONTRACTING ONLY
 * ==========================================================================
 *
 * HOMEOSTAT is an OPTIONAL, DEFAULT-OFF advisor. It is enabled only by an
 * explicit schema-3 `homeostat` section in the signed manifest. When the
 * section is absent, or present with `enabled: 0`, every function below is
 * inert and the supervisor behaves bit-identically to a build without the
 * module -- which is exactly what the frozen host-sim evidence signature
 * asserts.
 *
 * The loop tracks four Essential Variables over a fixed-length epoch:
 *   - rejection ratio      (rejected proposals / proposals seen)
 *   - clamp fraction       (requested motion NOT applied / requested motion)
 *   - latency spread       (max decision latency - min, within the epoch)
 *   - coherence anomalies  (frames whose coherence counter did not advance)
 *
 * If ANY threshold is crossed, the velocity scale contracts by
 * `contraction_q8` (Q8). If the epoch is clean, the scale recovers by
 * `recovery_q8` up to Q8 unity. The scale is bounded below by `floor_q8`, so
 * the loop can never collapse the envelope to zero velocity.
 *
 * The scale is applied as an ADDITIONAL velocity ceiling on top of the signed
 * manifest limit. It is strictly contracting: the effective ceiling is
 * min(manifest v_max, manifest v_max * scale_q8 / 256).
 */

static gov_homeostat_config_t latch_homeostat_config(void) {
    gov_homeostat_config_t config;
    memset(&config, 0, sizeof(config));
    if (!g_manifest.homeostat_present) return config;
    config.enabled                   = g_manifest.homeostat.enabled;
    config.epoch_ticks               = g_manifest.homeostat.epoch_ticks;
    config.reject_threshold_q8       = g_manifest.homeostat.reject_threshold_q8;
    config.latency_spread_threshold_ns = g_manifest.homeostat.latency_spread_threshold_ns;
    config.clamp_threshold_q8        = g_manifest.homeostat.clamp_threshold_q8;
    config.coherence_anomaly_threshold = g_manifest.homeostat.coherence_anomaly_threshold;
    config.contraction_q8            = g_manifest.homeostat.contraction_q8;
    config.recovery_q8               = g_manifest.homeostat.recovery_q8;
    config.floor_q8                  = g_manifest.homeostat.floor_q8;
    return config;
}

/*
 * The HOMEOSTAT velocity ceiling for the CURRENT tick, or 0 when HOMEOSTAT is
 * not applied. 0 means "not applied" to the gate, which reproduces the
 * pre-HOMEOSTAT behaviour exactly.
 */
static int32_t latch_homeostat_vmax(const latch_simplex_state_t *st) {
    if (st == NULL || !g_manifest.homeostat_present ||
        g_manifest.homeostat.enabled == 0u) {
        return 0;
    }
    if (g_manifest.envelope.v_max <= 0) return 0;
    uint32_t vmax = (uint32_t)g_manifest.envelope.v_max;
    uint32_t scaled = gov_homeostat_effective_vmax(vmax, st->homeostat.scale_q8, 256u);
    /* Same 1-unit floor as gov_gate_precheck's q8_scale(): a scale that
     * would underflow to zero velocity is indistinguishable from a bug, so
     * the smallest non-zero step the kinematic model can represent is used. */
    if (scaled == 0u) scaled = 1u;
    return (int32_t)scaled;
}

static void latch_governor_new_session(latch_simplex_state_t *state) {
    if (state == NULL) return;
    state->gov_lease_remaining = 0u;
    state->gov_last_lease_tick = 0u;
    state->gov_last_coherence = 0u;
    state->gov_warmup_seen = 0u;
    state->gov_agent_state = 0u;
    state->gov_v2_session = false;
    state->gov_coherence_valid = false;
    /* A new session has no lease owner (L-2): the next producer to send a
     * valid v2 frame establishes it. */
    state->gov_lease_owner_tag = LATCH_PRODUCER_TAG_NONE;
    state->gov_lease_owner_valid = false;
    state->gov_session_dead = false;
    /* A new session has no bound epoch (RT-02): the next producer binds the
     * epoch of the session it opens.  The ring of SPENT epochs is NOT
     * cleared -- it is the supervisor's memory of which epochs may never be
     * used again, and it must outlive the session. */
    state->gov_session_epoch = LATCH_SESSION_EPOCH_NONE;
    state->gov_session_epoch_valid = false;
    /* Reconnecting a producer must not erase dose already delivered. */
    state->gov_gate.rate_tokens = g_manifest.governor.rate_burst_tokens;
    state->gov_gate.shrink_v = 0u;
    state->gov_gate.shrink_scale_q8 = 255u;
    state->gov_gate.shrink_active = 0u;
}

/*
 * Has this epoch already been used by this supervisor? (RT-02)
 *
 * A producer that restarts and reuses the epoch of its previous session
 * must not be able to resume that session's identity, so a spent epoch can
 * never be bound again.
 */
static bool latch_epoch_already_used(const latch_simplex_state_t *st, uint32_t epoch) {
    if (st == NULL || epoch == LATCH_SESSION_EPOCH_NONE) return false;
    for (uint32_t i = 0u; i < LATCH_SESSION_EPOCH_RING; ++i) {
        if (st->gov_epoch_ring[i] == epoch) return true;
    }
    return false;
}

/* Record an epoch as spent (RT-02). */
static void latch_epoch_mark_used(latch_simplex_state_t *st, uint32_t epoch) {
    if (st == NULL || epoch == LATCH_SESSION_EPOCH_NONE) return;
    st->gov_epoch_ring[st->gov_epoch_ring_next % LATCH_SESSION_EPOCH_RING] = epoch;
    st->gov_epoch_ring_next++;
}

static void latch_record_eperm_fault(void) {
    atomic_fetch_add_explicit(&g_simplex.total_eperm_rejects, 1u, memory_order_relaxed);
    atomic_store_explicit(&g_simplex.eperm_pending, 1u, memory_order_release);
}

/* ==========================================================================
 * 5. Dual Delivery Buffering: 256-Slot Lock-Free Ring Queue & Latest-Wins
 * ========================================================================== */

/*
 * Drop every frame still queued in the ring and start a new session epoch.
 *
 * Returns the number of frames that were discarded (the caller counts them
 * as ring drops so the loss is visible in the telemetry).
 *
 * The tail is advanced with a compare-and-swap, so it can only ever move
 * FORWARD.  The consumer advances it with a CAS as well, so neither side can
 * regress the other: a consumer that was mid-copy when the flush landed
 * fails its CAS and refuses the frame instead of resurrecting it.
 */
static bool latch_claim_writer(_Atomic uint32_t *writers) {
    uint32_t expected = 0u;
    return atomic_compare_exchange_strong_explicit(writers, &expected, 1u,
                                                    memory_order_acq_rel,
                                                    memory_order_acquire);
}

static uint32_t latch_ring_flush_session(latch_publish_buffer_t *buf) {
    atomic_fetch_add_explicit(&buf->flush_epoch, 1u, memory_order_acq_rel);
    uint32_t head = atomic_load_explicit(&buf->write_head, memory_order_relaxed);
    uint32_t tail = atomic_load_explicit(&buf->read_tail, memory_order_acquire);
    uint32_t expected = tail;
    uint32_t stale = 0u;
    while (expected != head && (uint32_t)(head - expected) <= LATCH_PUB_RING_SIZE) {
        uint32_t pending = head - expected;
        if (atomic_compare_exchange_weak_explicit(&buf->read_tail, &expected,
                                                  head,
                                                  memory_order_release,
                                                  memory_order_relaxed)) {
            stale = pending;
            break;
        }
        /* A consumer may have advanced past this head after a concurrent
         * publish. Never move the tail back to the stale snapshot. */
    }
    return stale;
}

static void latch_publish_proposal(latch_publish_buffer_t *buf,
                                   const latch_proposal_t *prop) {
    if (strcmp(g_manifest.ingest.delivery, "queued") == 0) {
        uint32_t depth = g_manifest.ingest.queue_depth;
        if (depth == 0 || depth > LATCH_PUB_RING_SIZE) depth = LATCH_PUB_RING_SIZE;
        uint32_t h = atomic_load_explicit(&buf->write_head, memory_order_relaxed);
        uint32_t t = atomic_load_explicit(&buf->read_tail, memory_order_acquire);
        if (h - t < depth) {
            uint32_t slot_idx = h % LATCH_PUB_RING_SIZE;
            latch_seqlock_slot_t *slot = &buf->slots[slot_idx];
            uint32_t g = atomic_load_explicit(&slot->gen, memory_order_relaxed);
            atomic_store_explicit(&slot->gen, g + 1u, memory_order_release);
            slot->proposal = *prop;
            atomic_store_explicit(&slot->gen, g + 2u, memory_order_release);
            atomic_store_explicit(&buf->write_head, h + 1u, memory_order_release);
            atomic_fetch_add_explicit(&buf->total_publishes, 1u, memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&buf->dropped_full, 1u, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_simplex.total_ring_drops, 1u, memory_order_relaxed);
        }
        return;
    }

    uint32_t cur  = atomic_load_explicit(&buf->active_idx, memory_order_relaxed);
    uint32_t idle = cur ^ 1u;
    latch_seqlock_slot_t *slot = &buf->slots[idle];

    uint32_t g = atomic_load_explicit(&slot->gen, memory_order_relaxed);
    /* Odd generation indicates write in progress */
    atomic_store_explicit(&slot->gen, g + 1u, memory_order_release);

    slot->proposal = *prop;

    /* Even generation indicates stable valid payload */
    atomic_store_explicit(&slot->gen, g + 2u, memory_order_release);
    atomic_store_explicit(&buf->active_idx, idle, memory_order_release);
    atomic_fetch_add_explicit(&buf->total_publishes, 1u, memory_order_release);
}

static bool latch_consume_proposal(latch_publish_buffer_t *buf,
                                   uint32_t *last_pub_inout,
                                   latch_proposal_t *out_prop) {
    if (strcmp(g_manifest.ingest.delivery, "queued") == 0) {
        uint32_t t = atomic_load_explicit(&buf->read_tail, memory_order_relaxed);
        uint32_t h = atomic_load_explicit(&buf->write_head, memory_order_acquire);
        /* Counters wrap modulo 2^32; ordering comparisons lose queued
         * entries when the producer crosses UINT32_MAX. */
        if (t != h) {
            /*
             * Snapshot the session epoch BEFORE the payload is copied.  If a
             * session flush lands while this frame is in flight, the epoch
             * changes and the frame belongs to the previous session.
             */
            uint32_t epoch0 = atomic_load_explicit(&buf->flush_epoch, memory_order_acquire);
            uint32_t slot_idx = t % LATCH_PUB_RING_SIZE;
            const latch_seqlock_slot_t *slot = &buf->slots[slot_idx];
            for (int tries = 0; tries < 4; tries++) {
                uint32_t g1 = atomic_load_explicit(&slot->gen, memory_order_acquire);
                if ((g1 & 1u) != 0u) continue;
                *out_prop = slot->proposal;
                uint32_t g2 = atomic_load_explicit(&slot->gen, memory_order_acquire);
                if (g1 == g2) {
                    /*
                     * Advance the tail with a compare-and-swap, never with an
                     * unconditional store.  An unconditional `read_tail = t+1`
                     * can move the tail BACKWARDS when the session flush has
                     * already pushed it forward to the write head -- which
                     * resurrects the flushed frames.  The CAS only succeeds
                     * while the tail is still exactly the slot this frame was
                     * read from, so the tail is monotonic by construction.
                     */
                    uint32_t epoch1 = atomic_load_explicit(&buf->flush_epoch, memory_order_acquire);
                    if (epoch0 != epoch1) {
                        /* The session was flushed under this frame: refuse it. */
                        return false;
                    }
                    uint32_t expected = t;
                    if (!atomic_compare_exchange_strong_explicit(&buf->read_tail, &expected,
                                                                 t + 1u,
                                                                 memory_order_release,
                                                                 memory_order_relaxed)) {
                        /* The tail moved: a flush discarded this slot. Refuse it. */
                        return false;
                    }
                    return true;
                }
            }
            /*
             * FAIL CLOSED on a torn slot.
             *
             * A previous revision accepted the slot anyway after the
             * generation check failed, which contradicts the documented
             * "100% untorn reads" guarantee: the payload could have been
             * copied mid-write. The correct posture for a safety-critical
             * supervisor is to refuse the frame and retry next tick, not to
             * act on a possibly-torn one.
             *
             * This is unreachable in practice: the publisher seals the slot
             * (even generation) before advancing `write_head`, and the
             * consumer only ever looks at slots below `write_head`. It is
             * kept as a hard guarantee rather than a probability.
             */
            return false;
        }
        return false;
    }

    uint32_t pub_count = atomic_load_explicit(&buf->total_publishes, memory_order_acquire);
    if (pub_count == *last_pub_inout) {
        return false;
    }

    for (int tries = 0; tries < 4; tries++) {
        uint32_t idx = atomic_load_explicit(&buf->active_idx, memory_order_acquire);
        const latch_seqlock_slot_t *slot = &buf->slots[idx];
        uint32_t g1 = atomic_load_explicit(&slot->gen, memory_order_acquire);
        if (g1 & 1u) {
            continue; /* Write currently in progress, retry */
        }

        *out_prop = slot->proposal;

        uint32_t g2 = atomic_load_explicit(&slot->gen, memory_order_acquire);
        if (g1 == g2) {
            *last_pub_inout = pub_count;
            return true;
        }
    }
    return false;
}

/* ==========================================================================
 * 6. Manifest-Driven Envelope Math & Two HA Candidates (Fix G8)
 * ========================================================================== */

static inline int32_t latch_clamp_i32(int32_t val, int32_t lo, int32_t hi) {
    if (val < lo) return lo;
    if (val > hi) return hi;
    return val;
}

static inline int64_t latch_clamp_i64(int64_t val, int64_t lo, int64_t hi) {
    if (val < lo) return lo;
    if (val > hi) return hi;
    return val;
}

/*
 * Magnitude of a signed value, computed in 64 bits.
 *
 * The obvious `val < 0 ? -val : val` on a 32-bit int is undefined
 * behaviour for INT32_MIN: the negation overflows and, in practice,
 * yields INT32_MIN again -- so `abs(INT32_MIN) > v_max` evaluates FALSE
 * and the RATE check is BYPASSED for exactly the one input that must
 * never pass it. A guest can reach that value because only INT32_MIN
 * itself is screened as the NaN sentinel.
 */
static inline int64_t latch_abs_i64(int64_t val) {
    return (val < 0) ? -val : val;
}

/* True when |val| exceeds the limit. 64-bit, so nothing can overflow. */
static inline bool latch_exceeds_i64(int64_t val, int32_t limit) {
    return latch_abs_i64(val) > (int64_t)limit;
}

static uint16_t latch_check_envelope(int32_t theta_cur,
                                     int32_t v_cur,
                                     int32_t a_cur,
                                     int32_t u_mrad) {
    uint16_t faults = LATCH_FAULT_NONE;

    int32_t t_min = g_manifest.envelope.theta_min_mrad;
    int32_t t_max = g_manifest.envelope.theta_max_mrad;
    int32_t v_max = g_manifest.envelope.v_max;
    int32_t a_max = g_manifest.envelope.a_max;
    int32_t j_max = g_manifest.envelope.j_max;
    int32_t horizon = (int32_t)g_manifest.envelope.lookahead_ticks;

    if (u_mrad < t_min || u_mrad > t_max) {
        faults |= LATCH_FAULT_BOUNDS;
    }
    if (latch_manifest_crossed_keepout(&g_manifest, theta_cur, u_mrad)) {
        faults |= LATCH_FAULT_KEEPOUT;
    }

    /*
     * The kinematic differences are computed in 64 bits.
     *
     * In 32 bits `u_mrad - theta_cur` overflows for any u_mrad near
     * INT32_MIN, and a signed overflow is UB: on this target it wraps,
     * which FLIPS THE SIGN OF THE VELOCITY STEP. A proposal that should
     * be a huge negative step is then seen as a huge positive one, and
     * the RATE check passes it.
     */
    int64_t v_step = (int64_t)u_mrad - (int64_t)theta_cur;
    int64_t a_step = v_step - (int64_t)v_cur;
    int64_t j_step = a_step - (int64_t)a_cur;
    if (latch_exceeds_i64(v_step, v_max) ||
        latch_exceeds_i64(a_step, a_max) ||
        (j_max > 0 && latch_exceeds_i64(j_step, j_max))) {
        faults |= LATCH_FAULT_RATE;
    }

    /* Constant-u lookahead rollout */
    int64_t sim_theta = (int64_t)theta_cur;
    for (int h = 0; h < horizon; ++h) {
        int64_t step = latch_clamp_i64((int64_t)u_mrad - sim_theta,
                                        -(int64_t)v_max, (int64_t)v_max);
        int64_t next_theta = sim_theta + step;
        if (next_theta < (int64_t)t_min || next_theta > (int64_t)t_max) {
            faults |= LATCH_FAULT_BOUNDS;
        }
        if (latch_manifest_crossed_keepout(&g_manifest,
                                           (int32_t)latch_clamp_i64(sim_theta, (int64_t)t_min, (int64_t)t_max),
                                           (int32_t)latch_clamp_i64(next_theta, (int64_t)t_min, (int64_t)t_max))) {
            faults |= LATCH_FAULT_KEEPOUT;
        }
        sim_theta = next_theta;
    }

    /* Maximum braking rollout */
    int64_t brake_theta = (int64_t)theta_cur +
                          latch_clamp_i64(v_step, -(int64_t)v_max, (int64_t)v_max);
    int64_t brake_v     = brake_theta - (int64_t)theta_cur;
    for (int h = 0; h < horizon; ++h) {
        if (brake_v > 0) {
            brake_v -= a_max;
            if (brake_v < 0) brake_v = 0;
        } else if (brake_v < 0) {
            brake_v += a_max;
            if (brake_v > 0) brake_v = 0;
        }
        int64_t next_brake = brake_theta + brake_v;
        if (next_brake < (int64_t)t_min || next_brake > (int64_t)t_max) {
            faults |= LATCH_FAULT_BOUNDS;
        }
        if (latch_manifest_crossed_keepout(&g_manifest,
                                           (int32_t)latch_clamp_i64(brake_theta, (int64_t)t_min, (int64_t)t_max),
                                           (int32_t)latch_clamp_i64(next_brake, (int64_t)t_min, (int64_t)t_max))) {
            faults |= LATCH_FAULT_KEEPOUT;
        }
        brake_theta = next_brake;
    }

    return faults;
}

/* HA Candidate 1: Freeze in place */
static int32_t latch_ha_hold(int32_t theta_cur, int32_t *vel_out) {
    *vel_out = 0;
    return latch_clamp_i32(theta_cur,
                           g_manifest.envelope.theta_min_mrad,
                           g_manifest.envelope.theta_max_mrad);
}

/* HA Candidate 2: Retract toward home_mrad along legal boundary */
static bool latch_home_path_is_legal(int32_t theta_cur) {
    if (latch_manifest_in_keepout(&g_manifest, theta_cur)) {
        return false;
    }
    int32_t home = g_manifest.envelope.home_mrad;
    return !latch_manifest_crossed_keepout(&g_manifest, theta_cur, home);
}

static int32_t latch_ha_home(int32_t theta_cur, int32_t *vel_out) {
    if (!latch_home_path_is_legal(theta_cur)) {
        *vel_out = 0;
        return theta_cur;
    }
    int32_t home = g_manifest.envelope.home_mrad;
    int64_t diff = (int64_t)home - (int64_t)theta_cur;
    int32_t step = (int32_t)latch_clamp_i64(diff,
                                             -(int64_t)g_manifest.envelope.v_home,
                                             (int64_t)g_manifest.envelope.v_home);
    int32_t next_theta = (int32_t)latch_clamp_i64((int64_t)theta_cur + step,
                                                   g_manifest.envelope.theta_min_mrad,
                                                   g_manifest.envelope.theta_max_mrad);
    if (latch_manifest_crossed_keepout(&g_manifest, theta_cur, next_theta)) {
        *vel_out = 0;
        return theta_cur;
    }
    *vel_out = (int32_t)latch_clamp_i64((int64_t)next_theta - theta_cur,
                                         INT32_MIN, INT32_MAX);
    return next_theta;
}

/* ==========================================================================
 * 7. PCA9685 I2C Actuator Driver (Symmetric Fixed Calibration, Fix E-8)
 * ========================================================================== */

static uint16_t latch_mrad_to_pca9685_off(int32_t theta_mrad) {
    int32_t safe_theta = latch_clamp_i32(theta_mrad,
                                         g_manifest.envelope.theta_min_mrad,
                                         g_manifest.envelope.theta_max_mrad);
    if (latch_manifest_in_keepout(&g_manifest, safe_theta)) {
        for (uint32_t i = 0; i < g_manifest.envelope.num_keepouts; ++i) {
            int64_t lo = (int64_t)g_manifest.envelope.keepout[i].lo_mrad;
            int64_t hi = (int64_t)g_manifest.envelope.keepout[i].hi_mrad;
            if ((int64_t)safe_theta >= lo && (int64_t)safe_theta <= hi) {
                int64_t mid = (lo + hi) / 2;
                int64_t nudged = ((int64_t)safe_theta < mid) ? (lo - 1) : (hi + 1);
                safe_theta = (int32_t)latch_clamp_i64(
                    nudged,
                    (int64_t)g_manifest.envelope.theta_min_mrad,
                    (int64_t)g_manifest.envelope.theta_max_mrad);
            }
        }
        if (latch_manifest_in_keepout(&g_manifest, safe_theta)) {
            safe_theta = g_manifest.envelope.home_mrad;
        }
    }

    int64_t center = (int64_t)g_manifest.actuator.pwm_center;
    int64_t pmin   = (int64_t)g_manifest.actuator.pwm_min;
    int64_t pmax   = (int64_t)g_manifest.actuator.pwm_max;

    int64_t span_pos = (g_manifest.num_axes > 0 && g_manifest.axes[0].max > 0)
                           ? (int64_t)g_manifest.axes[0].max
                           : (int64_t)g_manifest.envelope.theta_max_mrad;
    int64_t span_neg = (g_manifest.num_axes > 0 && g_manifest.axes[0].min < 0)
                           ? -(int64_t)g_manifest.axes[0].min
                           : -(int64_t)g_manifest.envelope.theta_min_mrad;
    int64_t counts64;
    if (safe_theta >= 0) {
        /* Fail closed: a non-positive span means theta cannot be scaled to
         * PWM counts. Return the neutral centre (no motion) instead of
         * dividing by a magic constant. Reachable only for envelopes whose
         * positive span is invalid; behaviourally identical for every
         * validated manifest. */
        if (span_pos <= 0) return (uint16_t)((uint32_t)center & 0x0FFFu);
        counts64 = center + (((int64_t)safe_theta * (pmax - center)) / span_pos);
    } else {
        if (span_neg <= 0) return (uint16_t)((uint32_t)center & 0x0FFFu);
        counts64 = center + (((int64_t)safe_theta * (center - pmin)) / span_neg);
    }
    int32_t counts = (int32_t)latch_clamp_i64(counts64, pmin, pmax);
    return (uint16_t)((uint32_t)counts & 0x0FFFu);
}

static int latch_pca9685_write_reg(int i2c_fd, uint8_t reg, uint8_t val) {
    if (i2c_fd < 0) {
        return g_manifest.actuator.required ? -ENODEV : 0;
    }
#ifdef __QNXNTO__
    struct __attribute__((packed)) {
        i2c_send_t hdr;
        uint8_t    bytes[2];
    } pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.slave.addr = (uint16_t)g_manifest.actuator.addr;
    pkt.hdr.slave.fmt  = I2C_ADDRFMT_7BIT;
    pkt.hdr.len        = 2u;
    pkt.hdr.stop       = 1;
    pkt.bytes[0]       = reg;
    pkt.bytes[1]       = val;

    int status = devctl(i2c_fd, DCMD_I2C_SEND, &pkt, sizeof(pkt), NULL);
    uint32_t retries = g_manifest.actuator.retries;
    while (status != EOK && retries > 0) {
        retries--;
        status = devctl(i2c_fd, DCMD_I2C_SEND, &pkt, sizeof(pkt), NULL);
    }
    return (status == EOK) ? 0 : -status;
#else
    (void)reg; (void)val; return 0;
#endif
}

static int latch_pca9685_init(int i2c_fd) {
    if (i2c_fd < 0) {
        return g_manifest.actuator.required ? -ENODEV : 0;
    }

    int rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_MODE1, PCA9685_MODE1_SLEEP);
    if (rc != 0) return rc;

    rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_PRESCALE, (uint8_t)g_manifest.actuator.prescale);
    if (rc != 0) return rc;

    rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_MODE1, 0x00u);
    if (rc != 0) return rc;

    struct timespec wait_ts = {
        .tv_sec  = (time_t)(g_manifest.actuator.init_delay_us / 1000000u),
        .tv_nsec = (long)((uint64_t)(g_manifest.actuator.init_delay_us % 1000000u) * 1000ULL)
    };
    (void)nanosleep(&wait_ts, NULL);

    return latch_pca9685_write_reg(
        i2c_fd, PCA9685_REG_MODE1, (uint8_t)(PCA9685_MODE1_RESTART | PCA9685_MODE1_AI));
}

static int latch_pca9685_write_angle(int i2c_fd, int32_t theta_mrad) {
    uint16_t off_counts = latch_mrad_to_pca9685_off(theta_mrad);
    uint16_t pmin = (uint16_t)g_manifest.actuator.pwm_min;
    uint16_t pmax = (uint16_t)g_manifest.actuator.pwm_max;

    if (off_counts < pmin) off_counts = pmin;
    else if (off_counts > pmax) off_counts = pmax;

    if (i2c_fd < 0) {
        return g_manifest.actuator.required ? -ENODEV : 0;
    }

#ifdef __QNXNTO__
    struct __attribute__((packed)) {
        i2c_send_t hdr;
        uint8_t    payload[5];
    } pkt;

    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.slave.addr = (uint16_t)g_manifest.actuator.addr;
    pkt.hdr.slave.fmt  = I2C_ADDRFMT_7BIT;
    pkt.hdr.len        = sizeof(pkt.payload);
    pkt.hdr.stop       = 1;

    pkt.payload[0] = PCA9685_REG_LED0_ON_L;
    pkt.payload[1] = 0x00u;
    pkt.payload[2] = 0x00u;
    pkt.payload[3] = (uint8_t)(off_counts & 0xFFu);
    pkt.payload[4] = (uint8_t)((off_counts >> 8) & 0x0Fu);

    int status = devctl(i2c_fd, DCMD_I2C_SEND, &pkt, sizeof(pkt), NULL);
    uint32_t retries = g_manifest.actuator.retries;
    while (status != EOK && retries > 0) {
        retries--;
        status = devctl(i2c_fd, DCMD_I2C_SEND, &pkt, sizeof(pkt), NULL);
    }
    return (status == EOK) ? 0 : -status;
#else
    (void)off_counts; return 0;
#endif
}

#ifdef __QNXNTO__
static int g_actuator_io_chid = -1;
static int g_actuator_io_coid = -1;
#endif

static void latch_actuator_publish_target(latch_simplex_state_t *st, int32_t theta_mrad) {
    uint32_t g = atomic_load_explicit(&st->actuator_io.gen, memory_order_relaxed);
    atomic_store_explicit(&st->actuator_io.gen, g + 1u, memory_order_release);
    st->actuator_io.theta_mrad = theta_mrad;
    atomic_store_explicit(&st->actuator_io.gen, g + 2u, memory_order_release);
    atomic_fetch_add_explicit(&st->actuator_io.seq_num, 1u, memory_order_release);
#ifdef __QNXNTO__
    if (g_actuator_io_coid != -1 && (st->i2c_fd >= 0 || g_manifest.actuator.required)) {
        (void)MsgSendPulse(g_actuator_io_coid, 20, LATCH_PULSE_CODE_ACTUATE, 0);
    }
#endif
}

static bool latch_actuator_read_target(const latch_actuator_target_slot_t *slot,
                                       uint64_t *last_seq_inout,
                                       int32_t *theta_out) {
    uint64_t cur_seq = atomic_load_explicit(&slot->seq_num, memory_order_acquire);
    if (cur_seq == *last_seq_inout) {
        return false;
    }
    for (int tries = 0; tries < 8; ++tries) {
        uint32_t g1 = atomic_load_explicit(&slot->gen, memory_order_acquire);
        if ((g1 & 1u) != 0u) continue;
        int32_t theta = slot->theta_mrad;
        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&slot->gen, memory_order_acquire);
        if (g1 == g2) {
            *theta_out = theta;
            *last_seq_inout = cur_seq;
            return true;
        }
    }
    return false;
}

/* ==========================================================================
 * 8. Evidence Tape Recorder & 1 kHz Decision Tick (Fix E-3, E-4, E-7)
 * ========================================================================== */

static void latch_record_tape(uint64_t tick,
                              uint64_t cycles_in,
                              uint64_t cycles_out,
                              uint32_t seq,
                              int32_t u_proposed,
                              int32_t theta_applied,
                              uint16_t mode,
                              uint16_t fault_bits) {
    uint32_t cap = g_manifest.tape.capacity;
    if (cap == 0u || cap > LATCH_TAPE_CAPACITY) cap = LATCH_TAPE_CAPACITY;
    uint64_t idx = atomic_load_explicit(&g_tape_write_idx, memory_order_relaxed);
    /* UINT64_MAX is reserved as the latest-page cursor. Stop recording
     * rather than wrap and make old records appear new. */
    if (idx == UINT64_MAX) return;
    latch_tape_entry_t *slot = &g_latch_tape[idx % cap];

    slot->tick          = tick;
    slot->cycles_in     = cycles_in;
    slot->cycles_out    = cycles_out;
    slot->seq           = seq;
    slot->u_proposed    = u_proposed;
    slot->theta_applied = theta_applied;
    slot->mode          = mode;
    slot->fault_bits    = fault_bits;

    atomic_store_explicit(&g_tape_write_idx, idx + 1u, memory_order_release);
}

static void latch_record_governor_event(const latch_proposal_t *proposal,
                                        bool frame_present,
                                        bool frame_accepted,
                                        uint64_t tick,
                                        uint64_t cycles,
                                        int32_t normalized_u,
                                        int32_t theta_applied,
                                        uint16_t fault_bits,
                                        uint8_t mode,
                                        governor_ladder_result_t ladder_result,
                                        uint32_t seq) {
    if (g_manifest.governor.enabled == 0u ||
        (!frame_present && fault_bits == LATCH_FAULT_NONE && ladder_result.changed == 0u)) {
        return;
    }

    uint64_t index = atomic_fetch_add_explicit(&g_gov_event_write_idx, 1u, memory_order_acq_rel);
    if (index >= LATCH_GOV_EVENT_CAPACITY) {
        atomic_store_explicit(&g_gov_event_overflow, 1u, memory_order_release);
    }

    latch_gov_event_t *event = &g_gov_events[index % LATCH_GOV_EVENT_CAPACITY];
    memset(event, 0, sizeof(*event));
    event->event_index = index;
    event->tick = tick;
    event->cycles = cycles;
    event->seq = seq;
    event->raw_u_mrad = frame_present ? proposal->u_mrad : 0;
    event->normalized_u_mrad = normalized_u;
    event->theta_applied_mrad = theta_applied;
    event->unit_id = frame_present ? proposal->unit_id : 0u;
    event->coherence_ctr = frame_present ? proposal->coherence_ctr : g_simplex.gov_last_coherence;
    event->lease_remaining = g_simplex.gov_lease_remaining;
    event->fault_bits = fault_bits;
    event->mode = mode;
    event->rung_before = (uint8_t)ladder_result.rung_before;
    event->rung_after = (uint8_t)ladder_result.rung_after;
    event->kind = frame_present ? proposal->kind : 0u;
    event->verdict = !frame_present ? 0u :
                     (frame_accepted ? 1u :
                      (proposal->kind == GOVERNOR_WIRE_HEARTBEAT ? 2u :
                       (proposal->kind == GOVERNOR_WIRE_SHRINK_REQ ? 3u : 4u)));
    event->agent_state = frame_present ? proposal->agent_state : g_simplex.gov_agent_state;
    event->confidence_q8 = frame_present ? proposal->confidence_q8 : 0u;
    event->coherence_valid = g_simplex.gov_coherence_valid ? 1u : 0u;
}

/*
 * FILE ONE DECISION-LATENCY SAMPLE (U-4).
 *
 * One sample per TICK, taken at the point where that tick's work is
 * finished.  The tick has two exits -- the decision path and the idle path
 * -- and BOTH are sampled, because the supervisor's loop runs whether or
 * not the guest has something to say, and a distribution that quietly
 * omitted the idle ticks would describe a workload that does not exist.
 *
 * The sample is filed under ONE of two histograms:
 *
 *   hist_decision : the tick DEQUEUED A PROPOSAL -- the proposal path.
 *   hist_idle     : the tick's queue was EMPTY -- the supervisor's cost
 *                   when it has nothing to decide.
 *
 * A tick that consumed a proposal but did not evaluate a MOTION one (a
 * heartbeat, a foreign frame, a proposal refused before the envelope) is
 * counted in `lat_motion_samples` only if it really did evaluate a motion
 * proposal, so a reader can tell how much of the decision-path sample was
 * the decision path proper.
 *
 * The mode counter is here for the same reason: a reader has to be able to
 * see whether the sample was taken while the supervisor was FOLLOWING the
 * guest (HP) or had already failed closed, because the two are not the
 * same workload.
 *
 * NOTE WHAT THIS DOES NOT TOUCH.  The legacy "Decision Latency" telemetry
 * (`last_latency_cycles` / `max_latency_cycles`) keeps its own meaning --
 * the latency of the last DECISION-path tick -- and is deliberately NOT
 * updated from the idle path.  The histogram is a new, additive
 * measurement; it does not redefine the field the archived evidence
 * already quotes.
 */
static void latch_latency_sample(latch_simplex_state_t *st, uint64_t latency,
                                 uint32_t lat_ns, bool proposal_consumed,
                                 bool motion_evaluated,
                                 uint32_t period_deadline_ns) {
    const unsigned bucket = latch_latency_bucket(latency);
    st->lat_samples++;
    st->lat_sum_cycles += latency;
    if (st->lat_samples == 1u) {
        st->lat_min_cycles = latency;
        st->lat_first_tick  = st->tick;
    }
    if (latency < st->lat_min_cycles) st->lat_min_cycles = latency;
    if (latency > st->lat_max_cycles) st->lat_max_cycles = latency;
    st->lat_last_tick = st->tick;
    if (proposal_consumed) {
        st->lat_decision_samples++;
        st->lat_sum_decision_cycles += latency;
        /* The decision path gets its OWN exact min/max, so the readout can
         * label the numbers it prints with the path they describe.  A
         * single min/max pair over both paths cannot be labelled with
         * either one honestly. */
        if (st->lat_decision_samples == 1u) {
            st->lat_min_decision_cycles = latency;
        }
        if (latency < st->lat_min_decision_cycles) {
            st->lat_min_decision_cycles = latency;
        }
        if (latency > st->lat_max_decision_cycles) {
            st->lat_max_decision_cycles = latency;
        }
        st->lat_hist_decision[bucket]++;
        if (motion_evaluated) {
            st->lat_motion_samples++;
        }
    } else {
        st->lat_idle_samples++;
        st->lat_hist_idle[bucket]++;
    }
    if ((unsigned)st->mode < LATCH_LATENCY_MODES) {
        st->lat_mode_ticks[(unsigned)st->mode]++;
    }
    if (g_manifest.timing.wcet_budget_us > 0u &&
        lat_ns > (g_manifest.timing.wcet_budget_us * 1000u)) {
        st->lat_over_budget++;
    }
    if (lat_ns > period_deadline_ns) {
        st->lat_over_period++;
    }
}

static void latch_simplex_tick(latch_simplex_state_t *st,
                               latch_publish_buffer_t *pub) {
    /*
     * OPEN THE TELEMETRY GUARD.
     *
     * The guard spans the WHOLE tick, so every status-visible write below
     * is inside it. See latch_snapshot_wait_even() for why the previous
     * narrower window did not support the README's claim.
     */
    atomic_fetch_add_explicit(&st->snapshot_gen, 1u, memory_order_release);
    atomic_thread_fence(memory_order_release);

    uint64_t cycles_in = latch_clock_cycles();
    st->tick++;

    uint16_t tick_faults = LATCH_FAULT_NONE;
    if (atomic_exchange_explicit(&st->eperm_pending, 0u, memory_order_acq_rel) != 0u) {
        tick_faults |= LATCH_FAULT_EPERM;
        st->latched_faults |= LATCH_FAULT_EPERM;
    }
    if (atomic_exchange_explicit(&st->actuator_io.io_fault_pending, 0u, memory_order_acq_rel) != 0u) {
        tick_faults |= LATCH_FAULT_I2C;
        st->latched_faults |= LATCH_FAULT_I2C;
    }

    /* Initialised explicitly: latch_consume_proposal() fills `prop` only on
     * the paths that return true, and the compiler cannot prove that across
     * the call. Zeroing it costs nothing (the field is only read when
     * has_new is true) and removes a spurious maybe-uninitialized report. */
    latch_proposal_t prop;
    memset(&prop, 0, sizeof(prop));
    bool has_new = latch_consume_proposal(pub, &st->last_consumed_pub, &prop);

    /*
     * THE PROPOSAL THIS TICK CONSUMED.
     *
     * Captured before `has_new` is cleared for the message-only and the
     * rejected paths, because the verdict answers the proposal that
     * ARRIVED, not the one that was applied.  A proposal that arrived and
     * was rejected still deserves an answer: "no" is the most useful
     * thing the supervisor can say to a guest that is about to propose
     * the same thing again.
     */
    const bool proposal_consumed = has_new;

    /* Set on the ticks that ran the MOTION-PROPOSAL EVALUATION (the
     * governor gate plus the kinematic envelope).  See the latency
     * histogram at the end of the tick. */
    bool motion_evaluated = false;

    if (has_new) {
        st->total_proposals_rx++;
        if (atomic_exchange_explicit(&st->session_reset_pending, 0u, memory_order_acq_rel) != 0u || !st->session_active) {
            atomic_store_explicit(&st->writer_closed_eof, 0u, memory_order_release);
            st->session_active     = true;
            st->retracted_home     = false;
            st->tape_frozen        = false;
            st->active_faults      = 0u;

            /*
             * A GENUINE NEW SESSION (the FIRST writer opened the node).
             *
             * Two things must NOT happen here, because both are safety
             * defects and both were live:
             *
             * 1. The plant state must not change DISCONTINUOUSLY. A previous
             *    revision unconditionally set theta to home_mrad with zero
             *    velocity. If the plant was anywhere else, that is an
             *    unbounded jump of the actuator -- and the NEXT frame is then
             *    judged against that fictitious state, so it is vetoed as a
             *    spurious RATE fault. The correct posture when the plant is
             *    NOT already at rest at home is the jerk-bounded retraction
             *    (WATCHDOG -> HA-HOLD -> HA-HOME), never an instantaneous
             *    set. When the plant IS already at home and at rest, the
             *    reset is a no-op and the session may start in HP.
             *
             * 2. The sequence baseline must be re-based for the new session
             *    (a new client starts its sequence at 1) -- but ONLY for a
             *    genuine new session. See latch_io_open(): a SECOND writer
             *    joining a live session does not arm this reset at all, so a
             *    legitimate second producer (the verification harness) can
             *    no longer reset the supervisor's sequence baseline and
             *    thereby defeat replay detection.
             */
            bool plant_at_rest = (st->theta_mrad == g_manifest.envelope.home_mrad) &&
                                 (st->velocity_mrad_tick == 0) &&
                                 (st->accel_mrad_tick2 == 0);
            st->last_seq           = 0u;   /* new sequence epoch */
            st->seq_valid          = false;
            st->last_u_proposed_mrad = st->theta_mrad;
            st->reconnect_retracting = !plant_at_rest;
            latch_governor_new_session(st);
            if (plant_at_rest) {
                st->mode               = (atomic_load_explicit(&st->operator_hold_locked, memory_order_acquire) != 0u)
                                             ? (uint8_t)LATCH_MODE_HOLD : (uint8_t)LATCH_MODE_HP;
                st->theta_mrad         = g_manifest.envelope.home_mrad;
                st->velocity_mrad_tick = 0;
                st->accel_mrad_tick2   = 0;
                st->hold_ticks_elapsed = 0u;
                st->clean_streak       = 0u;
            } else {
                /* Not at rest: retract, jerk-bounded. Do NOT teleport.
                 * Start hold_ticks_elapsed at 0 so Section 5 increments it
                 * cleanly to 1 on this first tick (no double-increment). */
                st->mode               = (uint8_t)LATCH_MODE_HOLD;
                st->hold_ticks_elapsed = 0u;
                st->clean_streak       = 0u;
            }
            st->last_rx_tick       = st->tick;
            st->last_rx_cycles     = cycles_in;
        } else {
            st->session_active     = true;
            st->retracted_home     = false;
            st->tape_frozen        = false;
        }
        if ((prop.wire_flags & LATCH_WIRE_FLAG_SILENCE) != 0u) {
            has_new = false;
        }
    } else if (atomic_load_explicit(&st->session_reset_pending, memory_order_acquire) != 0u) {
        /* Writer opened proposal node but Frame #1 has not arrived yet: hold idle without watchdog */
        st->session_active = false;
    }

    if (!st->session_active) {
        /* Idle must preserve the current position and any Governor latch. */
        st->mode = (atomic_load_explicit(&st->operator_hold_locked, memory_order_acquire) != 0u ||
                    (tick_faults & LATCH_FAULT_I2C) != 0u ||
                    (g_manifest.governor.enabled && st->gov_ladder.rung == GOVERNOR_RUNG_LATCH))
                       ? (uint8_t)LATCH_MODE_HOLD : (uint8_t)LATCH_MODE_HP;
        st->active_faults = tick_faults;
        st->clean_streak = 0u;
        st->velocity_mrad_tick = 0;
        st->accel_mrad_tick2 = 0;
        latch_actuator_publish_target(st, st->theta_mrad);
        /* The IDLE PATH IS SAMPLED TOO (U-4).  The supervisor's loop runs
         * whether or not the guest has something to say, so a distribution
         * that omitted the idle ticks would describe a workload that does
         * not exist -- and the pre-session ticks are the ones the guest's
         * boot time produced.  The legacy "Decision Latency" telemetry is
         * deliberately NOT updated here: it keeps its meaning (the last
         * DECISION-path latency), and this measurement is additive. */
        {
            const uint64_t idle_cycles_out = latch_clock_cycles();
            const uint64_t idle_latency    = idle_cycles_out - cycles_in;
            const uint32_t idle_lat_ns     = latch_cycles_to_ns(idle_latency);
            const uint32_t idle_period_ns  = (st->ticks_per_sec > 0)
                                                 ? (1000000000u / (uint32_t)st->ticks_per_sec)
                                                 : 1000000u;
            latch_latency_sample(st, idle_latency, idle_lat_ns, false, false,
                                 idle_period_ns);
        }
        /* CLOSE THE TELEMETRY GUARD on the idle path too. The previous
         * revision returned here with the guard still open (or never
         * opened), so a reader could sample a half-updated idle state
         * with no detection at all. */
        atomic_thread_fence(memory_order_release);
        atomic_fetch_add_explicit(&st->snapshot_gen, 1u, memory_order_release);
        return;
    }

    if (atomic_load_explicit(&st->operator_hold_locked, memory_order_acquire) != 0u) {
        tick_faults |= LATCH_FAULT_OPERATOR;
    }

    bool gov_enabled = latch_governor_enabled();
    bool gov_lease_renewed = false;
    bool gov_lease_expired = false;
    bool gov_frame_accepted = false;
    bool gov_frame_coherent = false;
    bool gov_command_valid = true;
    bool gov_message_only = false;
    /* Silence and message-only traffic must not replay an earlier target.
     * A new movement requires a fresh, independently validated command. */
    int32_t u_candidate = st->theta_mrad;
    int32_t normalized_target = st->theta_mrad;
    bool normalized_target_valid = false;
    bool candidate_approved = false;
    uint32_t seq_observed = st->last_seq;
    /* `has_new` is later cleared for message-only/rejected frames so they
     * cannot move the plant. Preserve physical input presence separately for
     * the recovery ladder's frame accounting.
     *
     * It is NOT const: a frame from a producer that does not hold the lease
     * is not physically present for the recovery ladder either (L-2) --
     * otherwise a foreign writer could reset the clean-frame streak and
     * block the supervisor's recovery by writing frames. */
    bool frame_present = has_new;
    /* L-2: does this frame come from the producer that owns the lease? For
     * a v1 frame (no producer identity) the legacy path has no lease, so
     * the frame is treated as the owner. */
    bool gov_is_owner = true;
    /*
     * Did the proposal's SESSION EPOCH (RT-02) match the one the
     * supervisor has bound?  Hoisted to function scope because the verdict
     * publication below -- which happens at the END of the tick, when the
     * decision is final -- needs it.
     */
    bool gov_epoch_ok = true;

    /*
     * HOMEOSTAT velocity ceiling for this tick.
     *
     * 0 means "not applied" (section absent or disabled) and leaves the
     * pre-HOMEOSTAT behaviour bit-identical. The value is CONSTANT for the
     * whole tick: the loop's epoch closes at the end of the tick, so a scale
     * change takes effect on the NEXT tick, never mid-decision.
     */
    const int32_t homeostat_v_max = latch_homeostat_vmax(st);

    if (has_new) {
        bool gov_v2 = gov_enabled && prop.wire_version == 2u;
        bool gov_heartbeat = gov_v2 && prop.kind == GOVERNOR_WIRE_HEARTBEAT;
        bool gov_shrink = gov_v2 && prop.kind == GOVERNOR_WIRE_SHRINK_REQ;
        /*
         * Does this frame OPEN a session?  Captured BEFORE the lease
         * authority runs, because that block ASSIGNS the lease owner and
         * would otherwise erase the answer.
         *
         * A frame that opens a session is judged against a FRESH sequence
         * baseline, so it is held to the stricter rule that the first frame
         * of a session carries `seq == 1` (RT-02).
         */
        bool gov_opening_session = gov_v2 && !st->gov_lease_owner_valid;
        bool gov_pending_open = false;
        bool gov_pending_takeover = false;

        /* ------------------------------------------------------------------
         * 0. LEASE AUTHORITY (L-2) -- resolved BEFORE the sequence check.
         *
         * All state mutations for opening or taking over a session are
         * DEFERRED until pre_fault_bits, session_epoch, and prop.seq
         * validate below (RT-02). A spent-epoch, seq==0, or corrupted
         * takeover frame must preserve prior owner, epoch, and session.
         * ---------------------------------------------------------------- */
        if (gov_v2) {
            const uint16_t tag = prop.producer_tag;
            const bool can_open_session =
                (prop.kind == GOVERNOR_WIRE_HEARTBEAT ||
                 prop.kind == GOVERNOR_WIRE_CMD_V2);

            if (!st->gov_lease_owner_valid) {
                if (can_open_session) {
                    /* First producer candidate: defer binding until validated. */
                    gov_pending_open = true;
                } else {
                    /* A limit request (or a bare CMD) cannot create a
                     * session or bind session_epoch. */
                    gov_is_owner = true;
                }
            } else if (tag == st->gov_lease_owner_tag) {
                /* The owner. Whether the session is alive again is decided
                 * by whether this frame actually RENEWED the lease -- see
                 * the `gov_lease_renewed` handling below. */
            } else if (st->gov_session_dead && can_open_session) {
                /* TAKEOVER candidate: defer all mutations until validated. */
                gov_pending_takeover = true;
            } else {
                /* FOREIGN producer while the owner's lease is live. */
                st->gov_foreign_frames++;
                gov_is_owner = false;
                gov_command_valid = false;
                frame_present = false;
            }
        }

        /* ------------------------------------------------------------------
         * 0b. SESSION EPOCH (RT-02) -- resolved BEFORE the sequence check.
         * ---------------------------------------------------------------- */
        if (gov_v2 && gov_is_owner) {
            if (!gov_pending_takeover && st->gov_session_epoch_valid) {
                gov_epoch_ok = (prop.session_epoch == st->gov_session_epoch);
            } else {
                /* Not bound yet, or takeover candidate: only a FRESH, non-zero
                 * epoch may open/take over the session. */
                gov_epoch_ok = (prop.session_epoch != LATCH_SESSION_EPOCH_NONE) &&
                               (!gov_pending_takeover || prop.session_epoch != st->gov_session_epoch) &&
                               !latch_epoch_already_used(st, prop.session_epoch);
            }
            if (!gov_epoch_ok) {
                tick_faults |= LATCH_FAULT_SEQ;
                gov_command_valid = false;
                frame_present = false;
            }
        }

        gov_message_only = gov_heartbeat || gov_shrink || !gov_is_owner || !gov_epoch_ok;
        seq_observed = prop.seq;
        if (gov_message_only) {
            u_candidate = st->theta_mrad;
        } else {
            u_candidate = prop.u_mrad;
        }
        bool sequence_ok = false;

        /* 1. Check wire-level pre-faults from ingest (ignore foreign non-owner frames only while owner lease is live) */
        if ((!gov_v2 || gov_is_owner || st->gov_session_dead) && prop.pre_fault_bits != 0u) {
            tick_faults |= (prop.pre_fault_bits & LATCH_FAULT_WIRE_MASK);
        }

        /* 2. Check INT32_MIN NaN sentinel */
        if ((!gov_v2 || gov_is_owner || st->gov_session_dead) && prop.u_mrad == LATCH_NAN_MRAD) {
            tick_faults |= LATCH_FAULT_NAN;
        }

        /* 3. Sequence check */
        if (gov_is_owner && gov_epoch_ok &&
            (tick_faults & (LATCH_FAULT_MAGIC | LATCH_FAULT_CRC | LATCH_FAULT_RESERVED)) == 0u) {
            if (gov_pending_open) {
                if (prop.seq == 1u) {
                    sequence_ok = true;
                } else {
                    tick_faults |= LATCH_FAULT_SEQ;
                }
            } else if (gov_pending_takeover) {
                if (prop.seq != 0u) {
                    sequence_ok = true;
                } else {
                    tick_faults |= LATCH_FAULT_SEQ;
                }
            } else if (!st->seq_valid) {
                if (prop.seq == 0u) {
                    tick_faults |= LATCH_FAULT_SEQ;
                } else if (gov_opening_session && prop.seq != 1u) {
                    tick_faults |= LATCH_FAULT_SEQ;
                } else {
                    sequence_ok = true;
                }
            } else {
                uint32_t delta = prop.seq - st->last_seq;
                if (delta == 0u || delta > 0x7FFFFFFFu) {
                    tick_faults |= LATCH_FAULT_SEQ;
                } else {
                    sequence_ok = true;
                }
            }
        }

        /*
         * RT-02: Commit session open or takeover ONLY after pre_fault_bits,
         * session_epoch, and prop.seq all validate. A bare GOVERNOR_WIRE_CMD
         * never sets gov_pending_open, so it cannot bind gov_session_epoch
         * without gov_lease_owner_valid.
         */
        if (gov_v2 && (gov_pending_open || gov_pending_takeover)) {
            const bool wire_clean = (prop.pre_fault_bits == 0u) &&
                                    ((tick_faults & LATCH_FAULT_WIRE_MASK) == 0u);
            if (wire_clean && gov_epoch_ok && sequence_ok) {
                if (gov_pending_open) {
                    st->gov_lease_owner_tag = prop.producer_tag;
                    st->gov_lease_owner_valid = true;
                    st->gov_session_dead = false;
                    st->gov_session_epoch = prop.session_epoch;
                    st->gov_session_epoch_valid = true;
                    latch_epoch_mark_used(st, prop.session_epoch);
                } else {
                    st->gov_lease_owner_tag = prop.producer_tag;
                    st->gov_lease_owner_valid = true;
                    st->gov_session_dead = false;
                    st->gov_producer_takeovers++;
                    st->last_u_proposed_mrad = st->theta_mrad;
                    st->seq_valid = false;
                    st->last_seq = 0u;
                    st->gov_session_epoch = prop.session_epoch;
                    st->gov_session_epoch_valid = true;
                    latch_epoch_mark_used(st, prop.session_epoch);
                    st->gov_v2_session = false;
                    st->gov_warmup_seen = 0u;
                }
            } else {
                gov_command_valid = false;
                frame_present = false;
                sequence_ok = false;
            }
        }

        if (gov_v2 && gov_is_owner && st->gov_lease_owner_valid &&
            sequence_ok && !st->gov_session_epoch_valid) {
            st->gov_session_epoch = prop.session_epoch;
            st->gov_session_epoch_valid = true;
            latch_epoch_mark_used(st, prop.session_epoch);
        }

        if (gov_v2 && gov_is_owner && sequence_ok &&
            (prop.kind == GOVERNOR_WIRE_HEARTBEAT ||
             prop.kind == GOVERNOR_WIRE_CMD_V2 ||
             prop.kind == GOVERNOR_WIRE_SHRINK_REQ)) {
            if (!st->gov_v2_session) {
                if (prop.kind == GOVERNOR_WIRE_SHRINK_REQ) {
                    /* A limit request cannot create a session or lease. */
                    tick_faults |= LATCH_FAULT_HEARTBEAT;
                    gov_command_valid = false;
                } else {
                    st->gov_v2_session = true;
                    st->gov_coherence_valid = true;
                    st->gov_last_coherence = prop.coherence_ctr;
                    st->gov_lease_remaining = g_manifest.governor.lease_ticks;
                    st->gov_agent_state = prop.agent_state;
                    gov_lease_renewed = true;
                    gov_frame_coherent = true;
                }
            } else {
                uint32_t delta = (prop.coherence_ctr - st->gov_last_coherence) & 0x00FFFFFFu;
                if (delta == 0u || delta > g_manifest.governor.coherence_max_gap) {
                    tick_faults |= LATCH_FAULT_HEARTBEAT;
                    gov_command_valid = false;
                } else {
                    st->gov_last_coherence = prop.coherence_ctr;
                    st->gov_agent_state = prop.agent_state;
                    gov_frame_coherent = true;
                    /* SHRINK_REQ carries telemetry but cannot keep its sender alive. */
                    if (prop.kind == GOVERNOR_WIRE_HEARTBEAT ||
                        prop.kind == GOVERNOR_WIRE_CMD_V2) {
                        st->gov_lease_remaining = g_manifest.governor.lease_ticks;
                        gov_lease_renewed = true;
                    }
                }
            }
            if (gov_frame_coherent && gov_heartbeat) {
                if (st->gov_warmup_seen < UINT32_MAX) st->gov_warmup_seen++;
            }
            if (gov_frame_coherent && prop.kind == GOVERNOR_WIRE_CMD_V2 &&
                st->gov_warmup_seen < g_manifest.governor.warmup_heartbeats) {
                gov_command_valid = false;
            }
        } else if (gov_v2 && gov_is_owner && sequence_ok && prop.kind == GOVERNOR_WIRE_CMD) {
            if (!st->gov_v2_session || st->gov_lease_remaining == 0u ||
                st->gov_warmup_seen < g_manifest.governor.warmup_heartbeats) {
                gov_command_valid = false;
            }
        }

        /* L-2: the session is alive again only when the OWNER's frame
         * actually renewed the lease. A foreign frame can never do this,
         * and an incoherent owner frame must not resurrect the session. */
        if (gov_v2 && gov_is_owner && gov_lease_renewed) {
            st->gov_session_dead = false;
        }

        if (gov_v2 && gov_is_owner && sequence_ok && gov_command_valid &&
            prop.kind == GOVERNOR_WIRE_SHRINK_REQ) {
            gov_gate_input_t gate_input = {
                .rung = st->gov_ladder.rung,
                .kind = prop.kind,
                .confidence_q8 = prop.confidence_q8,
                .unit_id = prop.unit_id,
                .has_v2_metadata = 1u,
                .theta = st->theta_mrad,
                .velocity = st->velocity_mrad_tick,
                .acceleration = st->accel_mrad_tick2,
                .candidate = prop.u_mrad,
                .tick = st->tick,
                .homeostat_v_max = homeostat_v_max
            };
            gov_gate_result_t gate = gov_gate_precheck(&g_manifest,
                                                       &g_manifest.governor,
                                                       &st->gov_gate,
                                                       &gate_input);
            tick_faults |= gate.faults;
            if (gate.command_valid == 0u) gov_command_valid = false;
        }

        if (gov_v2 && gov_message_only) gov_command_valid = false;

        if ((tick_faults & LATCH_FAULT_WIRE_MASK) != 0u) {
            st->total_wire_faults++;
        } else if (gov_command_valid && !gov_message_only) {
            /* THIS TICK EVALUATED A MOTION PROPOSAL.  Recorded for the
             * latency histogram (U-4): a heartbeat or an early refusal did
             * less work than a real command, and a reader has to be able to
             * tell how much of the decision-path sample was the decision
             * path proper. */
            motion_evaluated = true;
            int32_t target_mrad = u_candidate;
            if (gov_v2 && (prop.kind == GOVERNOR_WIRE_CMD ||
                           prop.kind == GOVERNOR_WIRE_CMD_V2)) {
                gov_gate_input_t gate_input = {
                    .rung = st->gov_ladder.rung,
                    .kind = prop.kind,
                    .confidence_q8 = prop.confidence_q8,
                    .unit_id = prop.kind == GOVERNOR_WIRE_CMD_V2
                                   ? prop.unit_id : g_manifest.governor.canonical_unit_id,
                    .has_v2_metadata = gov_v2 ? 1u : 0u,
                    .theta = st->theta_mrad,
                    .velocity = st->velocity_mrad_tick,
                    .acceleration = st->accel_mrad_tick2,
                    .candidate = u_candidate,
                    .tick = st->tick,
                    .homeostat_v_max = homeostat_v_max
                };
                gov_gate_result_t gate = gov_gate_precheck(&g_manifest,
                                                           &g_manifest.governor,
                                                           &st->gov_gate,
                                                           &gate_input);
                tick_faults |= gate.faults;
                u_candidate = gate.candidate;
                target_mrad = gate.normalized_target;
                if (gate.command_valid == 0u) {
                    gov_command_valid = false;
                }
            }

            if (gov_command_valid) {
                normalized_target = target_mrad;
                normalized_target_valid = true;
            }

            if ((tick_faults & LATCH_FAULT_WIRE_MASK) == 0u &&
                gov_command_valid && !gov_message_only) {
                uint16_t env_faults = 0u;
                if (target_mrad < g_manifest.envelope.theta_min_mrad ||
                    target_mrad > g_manifest.envelope.theta_max_mrad) {
                    env_faults |= LATCH_FAULT_BOUNDS;
                }
                if (latch_manifest_crossed_keepout(&g_manifest, st->theta_mrad, target_mrad)) {
                    env_faults |= LATCH_FAULT_KEEPOUT;
                }
                /* 4. Evaluate kinematic envelope and forward lookahead */
                env_faults |= latch_check_envelope(
                    st->theta_mrad, st->velocity_mrad_tick, st->accel_mrad_tick2, u_candidate);
                if (env_faults != LATCH_FAULT_NONE) {
                    tick_faults |= env_faults;
                    st->total_envelope_faults++;
                    /* An advisory RATE classification cannot authorize a
                     * command rejected by the kinematic envelope. */
                    gov_command_valid = false;
                    u_candidate = st->theta_mrad;
                } else if (sequence_ok && tick_faults == LATCH_FAULT_NONE) {
                    candidate_approved = true;
                }
            }
        }

        if (gov_v2 && gov_is_owner && st->gov_lease_owner_valid && sequence_ok &&
            (tick_faults & (LATCH_FAULT_MAGIC | LATCH_FAULT_CRC | LATCH_FAULT_RESERVED |
                            LATCH_FAULT_SEQ)) == 0u) {
            st->last_seq = prop.seq;
            st->seq_valid = true;
        }
        if (gov_is_owner && (!gov_v2 || st->gov_lease_owner_valid) &&
            tick_faults == LATCH_FAULT_NONE) {
            st->last_seq       = prop.seq;
            st->seq_valid      = true;
            st->last_rx_cycles = cycles_in;
            st->last_rx_tick   = st->tick;
        }
        if (gov_v2 && gov_lease_renewed) {
            st->last_rx_cycles = cycles_in;
            st->last_rx_tick = st->tick;
            st->gov_last_lease_tick = st->tick;
        }
        if (gov_v2 && sequence_ok && gov_command_valid && !gov_message_only &&
            tick_faults == LATCH_FAULT_NONE) {
            gov_frame_accepted = true;
        }
        if (gov_v2 && (!gov_command_valid || gov_message_only)) {
            u_candidate = st->theta_mrad;
            has_new = false;
        }
    } else {
        /* Watchdog timer check during active session */
        if (!gov_enabled || !st->gov_v2_session) {
            uint64_t silent_ticks = (st->last_rx_tick == 0u)
                                        ? st->tick
                                        : (st->tick - st->last_rx_tick);
            if (silent_ticks >= (uint64_t)g_manifest.timing.watchdog_ticks) {
                tick_faults |= LATCH_FAULT_WATCHDOG;
            }
        }
    }

    if (gov_enabled && st->gov_v2_session && !gov_lease_renewed) {
        if (st->gov_lease_remaining > 0u) st->gov_lease_remaining--;
        if (st->gov_lease_remaining == 0u) {
            tick_faults |= LATCH_FAULT_HEARTBEAT;
            gov_lease_expired = true;
            st->gov_lease_remaining = g_manifest.governor.lease_ticks;
            /* L-2: the session is no longer authoritative.  The owner may
             * resume it (keeping its sequence epoch), and once it has been
             * declared dead ANOTHER producer may take it over -- with a new
             * sequence epoch and its own warm-up. */
            st->gov_session_dead = true;
        }
    }

    if (gov_enabled && g_manifest.medical_present && has_new && gov_command_valid &&
        !gov_message_only &&
        ((normalized_target_valid &&
          gov_medical_check(&g_manifest, &st->gov_gate, st->tick,
                            st->theta_mrad, normalized_target) != 0u) ||
         gov_medical_check(&g_manifest, &st->gov_gate, st->tick,
                           st->theta_mrad, u_candidate) != 0u)) {
        tick_faults |= LATCH_FAULT_DOSE;
        gov_command_valid = false;
        gov_frame_accepted = false;
        u_candidate = st->theta_mrad;
        has_new = false;
    }

    if (candidate_approved && gov_command_valid && has_new &&
        tick_faults == LATCH_FAULT_NONE && !st->reconnect_retracting) {
        st->last_u_proposed_mrad = normalized_target;
    }

    governor_ladder_result_t gov_ladder_result = {
        .rung_before = st->gov_ladder.rung,
        .rung_after = st->gov_ladder.rung,
        .changed = 0u,
        .hard_fault = 0u
    };
    bool gov_legacy_hard_fault = false;
    /*
     * The operator release is read, NOT consumed, here (L-5).  The ladder
     * arms it only while the rung is LATCH; the request is cleared below
     * once it has been armed, or once the rung moves on and the request no
     * longer refers to the state the operator was looking at.
     */
    uint32_t operator_release_pending = atomic_load_explicit(
        &st->operator_release_pending, memory_order_acquire);
    if (gov_enabled) {
        uint16_t ladder_faults = (uint16_t)(tick_faults &
            (uint16_t)~(LATCH_FAULT_HEARTBEAT | LATCH_FAULT_WIDEN));
        bool demotion_event = gov_lease_expired ||
            (tick_faults & (LATCH_FAULT_HEARTBEAT | LATCH_FAULT_WIDEN)) != 0u;
        governor_ladder_config_t ladder_config = latch_governor_ladder_config();
        governor_ladder_input_t ladder_input = {
            .fault_bits = ladder_faults,
            .frame_accepted = gov_frame_accepted ? 1u : 0u,
            .coherent = gov_frame_coherent ? 1u : 0u,
            .frame_present = frame_present ? 1u : 0u,
            .immediate_demotion = demotion_event ? 1u : 0u,
            .safe_stop_complete =
                (st->velocity_mrad_tick == 0 && st->accel_mrad_tick2 == 0) ? 1u : 0u,
            .operator_release = (uint8_t)(operator_release_pending ? 1u : 0u)
        };
        gov_ladder_result = governor_ladder_step(&ladder_config, &st->gov_ladder, &ladder_input);

        /*
         * Settle the operator-release request (L-5).
         *
         *  - ARMED: the ladder was at LATCH and consumed the request.  Clear
         *    it and record that the release is now effective.
         *  - INVALIDATED: the rung moved since the request was made, so the
         *    request referred to a state that no longer exists.  Clear it.
         *  - DEFERRED: the request is still valid and is simply waiting for
         *    the ladder to reach LATCH.  Keep it, and count the wait so the
         *    operator can see how long it has been waiting.
         */
        if (operator_release_pending != 0u) {
            if (st->gov_ladder.rung == GOVERNOR_RUNG_LATCH) {
                atomic_store_explicit(&st->operator_release_pending, 0u, memory_order_release);
                atomic_store_explicit(&st->operator_release_armed, 1u, memory_order_release);
                atomic_store_explicit(&st->operator_release_deferred_ticks, 0u, memory_order_release);
            } else if (st->gov_ladder.rung !=
                       atomic_load_explicit(&st->operator_release_rung, memory_order_acquire)) {
                /* The rung changed: the request no longer matches the state
                 * the operator acted on. */
                atomic_store_explicit(&st->operator_release_pending, 0u, memory_order_release);
                atomic_store_explicit(&st->operator_release_deferred_ticks, 0u, memory_order_release);
            } else {
                atomic_fetch_add_explicit(&st->operator_release_deferred_ticks, 1u,
                                          memory_order_relaxed);
            }
        }
        if (st->gov_ladder.rung != GOVERNOR_RUNG_LATCH &&
            atomic_load_explicit(&st->operator_release_armed, memory_order_acquire) != 0u) {
            /* The armed release is only meaningful while the ladder is at
             * LATCH; the ladder clears its own arm flag on promotion. */
            atomic_store_explicit(&st->operator_release_armed, 0u, memory_order_release);
        }
        uint16_t non_hard = (uint16_t)(g_manifest.governor.advise_fault_mask |
                                       LATCH_FAULT_HEARTBEAT | LATCH_FAULT_WIDEN);
        gov_legacy_hard_fault = gov_ladder_result.hard_fault != 0u ||
            (tick_faults & (uint16_t)~non_hard) != 0u ||
            st->gov_ladder.rung == GOVERNOR_RUNG_LATCH;
    }

    if (gov_enabled && !st->reconnect_retracting &&
        st->gov_ladder.rung == GOVERNOR_RUNG_SAFE_STOP) {
        int64_t velocity = st->velocity_mrad_tick;
        int64_t decel = g_manifest.governor.safe_stop_decel;
        if (velocity > 0) velocity = velocity > decel ? velocity - decel : 0;
        else if (velocity < 0) velocity = velocity < -decel ? velocity + decel : 0;
        u_candidate = (int32_t)latch_clamp_i64((int64_t)st->theta_mrad + velocity,
                                               INT32_MIN, INT32_MAX);
        if (latch_check_envelope(st->theta_mrad, st->velocity_mrad_tick,
                                 st->accel_mrad_tick2, u_candidate) != LATCH_FAULT_NONE) {
            tick_faults |= LATCH_FAULT_RATE;
            st->gov_ladder.rung = GOVERNOR_RUNG_LATCH;
            gov_legacy_hard_fault = true;
        }
    }

    /* 5. Simplex Mode State Machine */
    uint32_t hys_clean = g_manifest.recovery.hysteresis_clean_frames;
    uint32_t hold_home = g_manifest.recovery.hold_to_home_ticks;
    int32_t home_pos   = g_manifest.envelope.home_mrad;

    if (st->reconnect_retracting && st->theta_mrad == home_pos &&
        st->velocity_mrad_tick == 0 && st->accel_mrad_tick2 == 0) {
        st->reconnect_retracting = false;
    }
    if (st->reconnect_retracting) {
        st->clean_streak = 0u;
        if (st->mode != (uint8_t)LATCH_MODE_HOME) {
            st->mode = (uint8_t)LATCH_MODE_HOLD;
            st->hold_ticks_elapsed++;
            if (st->hold_ticks_elapsed >= hold_home &&
                st->theta_mrad != home_pos && latch_home_path_is_legal(st->theta_mrad)) {
                st->mode = (uint8_t)LATCH_MODE_HOME;
            }
        }
    } else if (gov_enabled) {

        if (gov_legacy_hard_fault) {
            st->clean_streak = 0u;
            st->latched_faults |= tick_faults;
            if (st->mode == (uint8_t)LATCH_MODE_HP) {
                st->mode = (uint8_t)LATCH_MODE_HOLD;
                st->hold_ticks_elapsed = 1u;
            } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
                st->hold_ticks_elapsed++;
                if (st->hold_ticks_elapsed >= hold_home && st->theta_mrad != home_pos &&
                    latch_home_path_is_legal(st->theta_mrad)) {
                    st->mode = (uint8_t)LATCH_MODE_HOME;
                }
            } else if (st->mode == (uint8_t)LATCH_MODE_HOME &&
                       (tick_faults & ~(LATCH_FAULT_WATCHDOG | LATCH_FAULT_HEARTBEAT |
                                        LATCH_FAULT_WIDEN)) != 0u) {
                st->mode = (uint8_t)LATCH_MODE_HOLD;
                st->hold_ticks_elapsed = 1u;
            }
        } else if (st->mode != (uint8_t)LATCH_MODE_HP &&
                   st->mode == (uint8_t)LATCH_MODE_HOLD) {
            st->mode = (uint8_t)LATCH_MODE_HP;
            st->hold_ticks_elapsed = 0u;
        }
    } else if (tick_faults != LATCH_FAULT_NONE) {
        st->clean_streak = 0u;
        st->latched_faults |= tick_faults;

        if (st->mode == (uint8_t)LATCH_MODE_HP) {
            st->mode = (uint8_t)LATCH_MODE_HOLD;
            st->hold_ticks_elapsed = 1u;
        } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
            st->hold_ticks_elapsed++;
            if (st->hold_ticks_elapsed >= hold_home &&
                st->theta_mrad != home_pos &&
                latch_home_path_is_legal(st->theta_mrad)) {
                st->mode = (uint8_t)LATCH_MODE_HOME;
            }
        } else if (st->mode == (uint8_t)LATCH_MODE_HOME) {
            if ((tick_faults & ~LATCH_FAULT_WATCHDOG) != 0u) {
                st->mode = (uint8_t)LATCH_MODE_HOLD;
                st->hold_ticks_elapsed = 1u;
            }
        }
    } else {
        if (has_new) st->clean_streak++;

        if (st->mode != (uint8_t)LATCH_MODE_HP) {
            if (st->clean_streak >= hys_clean) {
                st->mode = (uint8_t)LATCH_MODE_HP;
                st->hold_ticks_elapsed = 0u;
            } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
                st->hold_ticks_elapsed++;
                if (st->hold_ticks_elapsed >= hold_home &&
                    st->theta_mrad != home_pos &&
                    latch_home_path_is_legal(st->theta_mrad)) {
                    st->mode = (uint8_t)LATCH_MODE_HOME;
                }
            }
        }
    }

    /* 6. Command Generation */
    int32_t next_theta = st->theta_mrad;
    int32_t next_vel   = 0;

    if (gov_enabled && !st->reconnect_retracting &&
        st->gov_ladder.rung == GOVERNOR_RUNG_SAFE_STOP) {
        next_theta = u_candidate;
        next_vel = (int32_t)latch_clamp_i64((int64_t)next_theta - st->theta_mrad,
                                            INT32_MIN, INT32_MAX);
    } else if (st->mode == (uint8_t)LATCH_MODE_HP) {
        int32_t step = (int32_t)latch_clamp_i64((int64_t)u_candidate - st->theta_mrad,
                                                -(int64_t)g_manifest.envelope.v_max,
                                                (int64_t)g_manifest.envelope.v_max);
        next_theta = (int32_t)latch_clamp_i64((int64_t)st->theta_mrad + step,
                                              g_manifest.envelope.theta_min_mrad,
                                              g_manifest.envelope.theta_max_mrad);
        next_vel = (int32_t)latch_clamp_i64((int64_t)next_theta - st->theta_mrad,
                                            INT32_MIN, INT32_MAX);
    } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
        next_theta = latch_ha_hold(st->theta_mrad, &next_vel);
    } else {
        next_theta = latch_ha_home(st->theta_mrad, &next_vel);
        if (next_theta == home_pos) {
            st->mode = (uint8_t)LATCH_MODE_HOLD;
            st->hold_ticks_elapsed = 0u;
            st->retracted_home = true;
        }
    }

    /* Also guard supervisor-generated HOME and SAFE_STOP motion. */
    if (gov_enabled && g_manifest.medical_present &&
        gov_medical_check(&g_manifest, &st->gov_gate, st->tick,
                          st->theta_mrad, next_theta) != 0u) {
        tick_faults |= LATCH_FAULT_DOSE;
        st->latched_faults |= LATCH_FAULT_DOSE;
        st->mode = (uint8_t)LATCH_MODE_HOLD;
        next_theta = st->theta_mrad;
        next_vel = 0;
    }

    /* 7. Actuation (offloaded to dedicated actuator I/O worker via 1-slot seqlock) */
    if (gov_enabled && g_manifest.medical_present) {
        /* Failed writes have uncertain physical outcome: count conservatively. */
        gov_medical_commit(&st->gov_gate, st->tick, st->theta_mrad, next_theta);
    }
    latch_actuator_publish_target(st, next_theta);
    if ((tick_faults & LATCH_FAULT_I2C) != 0u) {
        st->clean_streak = 0u;
        st->mode         = (uint8_t)LATCH_MODE_HOLD;
    }

    uint64_t cycles_out = latch_clock_cycles();
    uint64_t latency    = cycles_out - cycles_in;
    uint32_t lat_ns     = latch_cycles_to_ns(latency);

    /*
     * HOMEOSTAT: close the current epoch with THIS tick's outcome.
     *
     * The scale this produces is applied to the NEXT tick (the ceiling for
     * this tick was captured before the frame was evaluated), so a scale
     * change can never alter a decision that is already in flight.
     *
     * The four Essential Variables are measured here, in 64-bit signed
     * arithmetic, so a frame at the edge of the int32 range cannot overflow
     * the motion accounting.
     */
    if (g_manifest.homeostat_present && g_manifest.homeostat.enabled != 0u) {
        /* Only a MOTION proposal counts towards the rejection ratio and the
         * clamp fraction. A heartbeat or a shrink request carries no motion,
         * so counting it as a "rejected proposal" would manufacture stress
         * out of the supervisor's own liveness traffic. The decision LATENCY
         * and the COHERENCE anomaly count are measured on every tick/frame,
         * because they are properties of the pipeline rather than of the
         * proposal. */
        const bool is_motion_proposal = frame_present &&
            (prop.kind == GOVERNOR_WIRE_CMD || prop.kind == GOVERNOR_WIRE_CMD_V2);
        int64_t proposed_delta = is_motion_proposal && normalized_target_valid
                                     ? (int64_t)normalized_target - (int64_t)st->theta_mrad
                                     : 0;
        int64_t applied_delta = (int64_t)next_theta - (int64_t)st->theta_mrad;
        uint64_t proposed_abs = proposed_delta < 0 ? (uint64_t)(-proposed_delta)
                                                   : (uint64_t)proposed_delta;
        uint64_t applied_abs = applied_delta < 0 ? (uint64_t)(-applied_delta)
                                                 : (uint64_t)applied_delta;
        gov_homeostat_sample_t hs_sample = {
            .proposal_present = is_motion_proposal ? 1u : 0u,
            .proposal_accepted = gov_frame_accepted ? 1u : 0u,
            .coherence_anomaly = (frame_present && gov_enabled &&
                                  prop.wire_version == 2u && !gov_frame_coherent) ? 1u : 0u,
            .latency_ns = lat_ns,
            .proposed_motion = proposed_abs > (uint64_t)UINT32_MAX
                                   ? UINT32_MAX : (uint32_t)proposed_abs,
            .applied_motion = applied_abs > (uint64_t)UINT32_MAX
                                  ? UINT32_MAX : (uint32_t)applied_abs
        };
        gov_homeostat_config_t hs_config = latch_homeostat_config();
        (void)gov_homeostat_observe(&hs_config, &st->homeostat, &hs_sample);
    }

    st->accel_mrad_tick2    = (int32_t)latch_clamp_i64(
        (int64_t)next_vel - st->velocity_mrad_tick, INT32_MIN, INT32_MAX);
    st->theta_mrad          = next_theta;
    st->velocity_mrad_tick  = next_vel;
    int64_t omega64         = (int64_t)next_vel * (int64_t)st->ticks_per_sec;
    st->omega_mrad_s        = (int32_t)latch_clamp_i64(omega64, (int64_t)INT32_MIN, (int64_t)INT32_MAX);
    st->active_faults       = tick_faults;
    st->last_latency_cycles = latency;
    st->last_latency_ns     = lat_ns;
    if (latency > st->max_latency_cycles) {
        st->max_latency_cycles = latency;
        st->max_latency_ns     = lat_ns;
    }
    if (g_manifest.timing.wcet_budget_us > 0u &&
        lat_ns > (g_manifest.timing.wcet_budget_us * 1000u)) {
        st->wcet_overruns++;
    }
    uint32_t period_deadline_ns = (st->ticks_per_sec > 0) ? (1000000000u / (uint32_t)st->ticks_per_sec) : 1000000u;
    if (lat_ns > period_deadline_ns) {
        st->gov_deadline_misses++;
    }

    /*
     * THE DECISION-LATENCY DISTRIBUTION (U-4).
     *
     * One sample per tick, taken HERE because this is the only place where
     * the decision path has actually finished: the mode is final, the
     * actuation has been published and the latency is known.
     */
    latch_latency_sample(st, latency, lat_ns, proposal_consumed,
                          motion_evaluated, period_deadline_ns);

    /*
     * BACKLOG HEALTH (the manifest's `timing.max_backlog_ticks`).
     *
     * The guest policy deliberately produces FASTER than the supervisor
     * consumes, so a standing backlog is the NORMAL state, not a fault: it is
     * what keeps the supervisor's watchdog from ever firing spuriously. What
     * matters is that the backlog stays inside the bound the manifest
     * declares, because the bound is what the ring was sized for.
     *
     * A backlog above `max_backlog_ticks` means the transport is falling
     * further behind than the design allows -- a health signal about the
     * pipeline, not a safety violation (the supervisor still processes every
     * frame in order). It is counted and surfaced in `latchctl status` so an
     * operator can see it.
     */
    {
        uint32_t depth = atomic_load_explicit(&g_pub_buf.write_head, memory_order_acquire) -
                         atomic_load_explicit(&g_pub_buf.read_tail, memory_order_acquire);
        if (depth > st->max_backlog_seen) {
            st->max_backlog_seen = depth;
        }
        if (g_manifest.timing.max_backlog_ticks > 0u &&
            depth > g_manifest.timing.max_backlog_ticks) {
            st->backlog_overruns++;
        }
    }

    /* 8. Append to Evidence Tape */
    if (!st->tape_frozen) {
        latch_record_tape(st->tick,
                          cycles_in,
                          cycles_out,
                          seq_observed,
                          u_candidate,
                          next_theta,
                          (uint16_t)st->mode,
                          tick_faults);
    }

    /* GOVERNOR blackbox capture is fixed-size, single-writer, and memory-only.
     * The ring holds raw records only -- the on-target recorder never hashes.
     * Persistence happens when an operator runs `latchctl events --json`, and
     * the rolling SHA-256 chain is computed offline over that dump by
     * tools/gov_replay.py. */
    latch_record_governor_event(&prop, frame_present, gov_frame_accepted,
                                st->tick, cycles_in, u_candidate, next_theta,
                                tick_faults, st->mode, gov_ladder_result,
                                seq_observed);

    /* 9. PUBLISH THE VERDICT (W5).
     *
     * WHAT THIS IS
     * ------------
     * The verdict tells the guest what the supervisor ACTUALLY did with
     * its proposal.  It is ADVISORY: the guest cannot actuate anything, and
     * the supervisor's decision does not depend on the guest believing it.
     * The guest's only power over the plant is to STOP proposing, and that
     * is the fail-closed direction.
     *
     * ONLY MOTION PROPOSALS GET A VERDICT
     * ------------------------------------
     * The wire carries three kinds of governor-v2 frame:
     *
     *     HEARTBEAT   "I am still alive"          -- liveness, not a proposal
     *     CMD_V2      "I want the plant to move"   -- A PROPOSAL
     *     SHRINK_REQ  "please tighten your limits" -- telemetry, not a proposal
     *
     * A heartbeat that came back with "rejected" would be a lie: the
     * supervisor DID renew the lease.  A limit request that came back with
     * "rejected" would be equally meaningless.  So a verdict is published
     * for a CMD_V2 -- for a PROPOSAL -- and for nothing else.  The guest
     * arms its feedback timeout on a proposal and waits for that proposal's
     * answer; it does not wait for an answer to a heartbeat.
     *
     * WHY ONLY THE OWNER'S PROPOSALS GET AN ANSWER
     * --------------------------------------------
     * A verdict is published only for a proposal that belonged to the
     * session the supervisor is running: the owner, with the bound session
     * epoch (RT-02).  A FOREIGN producer's frame, or a frame carrying a
     * spent or mismatched epoch, gets NO verdict.
     *
     * That is deliberate.  The transport keeps ONE verdict, so a verdict
     * published for a foreign frame would OVERWRITE the owner's verdict
     * and delay it.  A foreign producer could then flood the channel and
     * stop the owner from ever seeing an answer -- which would fail
     * closed (the owner times out and stops proposing) but would be a
     * denial of service delivered through an ADVISORY channel, which is
     * not a trade worth making.  Silence is the answer to a frame that
     * does not belong to the session.
     *
     * WHAT THE VERDICT SAYS
     * ---------------------
     * ONE question: "did the plant do what I asked?"  So the verdict is
     * ACCEPT only when the proposal was accepted AND the supervisor is
     * still following the guest (`st->mode == HP`).  A supervisor that has
     * failed closed into HOLD or HOME is not following anybody, and saying
     * "accepted" to a proposal that was silently not applied would be a
     * lie the guest would act on.
     */
    if (g_feedback_pub_enabled && proposal_consumed &&
        gov_is_owner && gov_epoch_ok && st->gov_session_epoch_valid &&
        prop.wire_version == 2u && prop.kind == GOVERNOR_WIRE_CMD_V2) {
        latch_feedback_t verdict;
        memset(&verdict, 0, sizeof(verdict));
        verdict.seq           = seq_observed;
        verdict.session_epoch = st->gov_session_epoch;
        verdict.rung          = (uint8_t)st->gov_ladder.rung;
        verdict.fault_bits    = (uint16_t)tick_faults;
        verdict.fault_bits2   = 0u;
        verdict.flags         = 0u;
        verdict.verdict = (gov_frame_accepted &&
                           st->mode == (uint8_t)LATCH_MODE_HP)
                              ? (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT
                              : (uint8_t)LATCH_FEEDBACK_VERDICT_REJECT;
        (void)latch_feedback_encode(&verdict);
        /* The publish is a MEMCPY and a SIGNAL.  It never touches the
         * transport, so the safety core cannot be delayed by the channel
         * (see latch_feedback_pub.h). */
        (void)latch_feedback_pub_publish(&verdict);
    }

    bool q_empty = (atomic_load_explicit(&pub->read_tail, memory_order_acquire) ==
                    atomic_load_explicit(&pub->write_head, memory_order_acquire));
    if (st->retracted_home &&
        atomic_load_explicit(&st->writer_closed_eof, memory_order_acquire) != 0u &&
        q_empty) {
        st->tape_frozen = true;
        st->session_active = false;
    }

    /* CLOSE THE TELEMETRY GUARD: the tick's state is now consistent. */
    atomic_thread_fence(memory_order_release);
    atomic_fetch_add_explicit(&st->snapshot_gen, 1u, memory_order_release);
}

/* ==========================================================================
 * 9. Status & Tape Snapshot Helpers (Fix E-7)
 * ========================================================================== */

/*
 * TELEMETRY SEQLOCK GUARD.
 *
 * The guard covers the WHOLE decision tick, not just its last few dozen
 * lines.
 *
 * The previous window was opened just before the command-generation step and
 * closed just after it, while ~20 status-visible fields -- tick, last_seq,
 * last_u_proposed_mrad, mode, active_faults, latched_faults, clean_streak,
 * hold_ticks_elapsed, theta_mrad, velocity_mrad_tick, the wire/envelope
 * counters and the rx counter -- were written EARLIER in the same tick and
 * OUTSIDE it. The idle path returned before the window was even opened. A
 * reader could therefore observe `tick = N` together with `last_seq` from
 * tick N+1, and the README's "seqlock snapshot guard eliminates torn reads"
 * claim did not hold.
 *
 * The window is now opened at the top of the tick and closed at the bottom,
 * so a reader can only ever sample BETWEEN ticks. The tick is 1 ms, so a
 * status read that arrives mid-tick waits for that tick to finish -- the
 * correct trade for an operator-facing query.
 */
#define LATCH_SNAPSHOT_SPIN_TRIES 1024

/*
 * Wait until the writer is not inside a tick using a short bounded spin
 * (no nanosleep blocking on resmgr threads), and return the stable
 * generation. Returns false if the writer did not settle in time, so the
 * caller fails loudly with EBUSY instead of blocking or serving a torn snapshot.
 */
static bool latch_snapshot_wait_even(uint32_t *gen_out) {
    for (int i = 0; i < LATCH_SNAPSHOT_SPIN_TRIES; ++i) {
        uint32_t g = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if ((g & 1u) == 0u) {
            *gen_out = g;
            return true;
        }
    }
    return false;
}

static void latch_fill_status_locked(latch_status_reply_t *out) {
    out->tick                  = g_simplex.tick;
    out->last_latency_cycles   = g_simplex.last_latency_cycles;
    out->max_latency_cycles    = g_simplex.max_latency_cycles;
    out->last_rx_cycles        = g_simplex.last_rx_cycles;
    out->last_latency_ns       = g_simplex.last_latency_ns;
    out->max_latency_ns        = g_simplex.max_latency_ns;
    out->last_seq              = g_simplex.last_seq;
    out->theta_mrad            = g_simplex.theta_mrad;
    out->omega_mrad_s          = g_simplex.omega_mrad_s;
    out->velocity_mrad_tick    = g_simplex.velocity_mrad_tick;
    out->last_u_proposed_mrad  = g_simplex.last_u_proposed_mrad;
    out->mode                  = (uint16_t)g_simplex.mode;
    out->active_faults         = g_simplex.active_faults;
    out->latched_faults        = g_simplex.latched_faults;
    out->clean_streak          = (uint16_t)g_simplex.clean_streak;
    out->hold_ticks_elapsed    = g_simplex.hold_ticks_elapsed;
    out->total_proposals_rx    = g_simplex.total_proposals_rx;
    out->total_wire_faults     = g_simplex.total_wire_faults;
    out->total_envelope_faults = g_simplex.total_envelope_faults;
    out->total_eperm_rejects   = atomic_load_explicit(
        &g_simplex.total_eperm_rejects, memory_order_relaxed);
    out->operator_hold_locked  = atomic_load_explicit(
        &g_simplex.operator_hold_locked, memory_order_relaxed);
    out->total_ring_drops      = atomic_load_explicit(
        &g_simplex.total_ring_drops, memory_order_relaxed);
    out->wcet_overruns         = g_simplex.wcet_overruns;
    out->max_backlog_seen      = g_simplex.max_backlog_seen;
    out->backlog_overruns      = g_simplex.backlog_overruns;
    memcpy(out->manifest_sha256, g_manifest.sha256, sizeof(out->manifest_sha256));
}

static bool latch_fill_status(latch_status_reply_t *out) {
    for (int tries = 0; tries < 4; tries++) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) {
            return false;
        }
        atomic_thread_fence(memory_order_acquire);

        latch_fill_status_locked(out);

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) {
            return true;
        }
    }
    /* The writer never settled: the snapshot is not trustworthy. Report the
     * failure rather than serving a torn reply as if it were valid. */
    return false;
}

/*
 * THE LATENCY-DISTRIBUTION SNAPSHOT (U-4).
 *
 * The histogram is written inside the tick, under the same telemetry guard
 * that protects every other status-visible field, so it is read with the
 * SAME seqlock discipline: take the generation, copy, take the generation
 * again, and only accept the copy if the generation did not move.  A torn
 * histogram served as if it were valid would put a fabricated percentile in
 * the evidence archive, which is the one thing this measurement exists to
 * prevent.
 *
 * FAIL LOUDLY: if the writer never settles, the caller gets EBUSY rather
 * than a plausible-looking snapshot.
 */
static void latch_fill_latency_stats_locked(latch_latency_stats_t *out) {
    memset(out, 0, sizeof(*out));
    out->struct_size     = (uint32_t)sizeof(*out);
    out->buckets         = LATCH_LATENCY_BUCKETS;
    out->modes           = LATCH_LATENCY_MODES;
    out->cycles_per_sec  = g_cycles_per_sec;
    out->samples_total   = g_simplex.lat_samples;
    out->samples_decision = g_simplex.lat_decision_samples;
    out->samples_idle    = g_simplex.lat_idle_samples;
    out->samples_motion  = g_simplex.lat_motion_samples;
    out->min_cycles      = g_simplex.lat_min_cycles;
    out->max_cycles      = g_simplex.lat_max_cycles;
    out->sum_cycles      = g_simplex.lat_sum_cycles;
    out->sum_decision_cycles = g_simplex.lat_sum_decision_cycles;
    out->min_decision_cycles = g_simplex.lat_min_decision_cycles;
    out->max_decision_cycles = g_simplex.lat_max_decision_cycles;
    out->first_tick      = g_simplex.lat_first_tick;
    out->last_tick       = g_simplex.lat_last_tick;
    out->over_budget     = g_simplex.lat_over_budget;
    out->over_period     = g_simplex.lat_over_period;
    memcpy(out->mode_ticks, g_simplex.lat_mode_ticks, sizeof(out->mode_ticks));
    memcpy(out->hist_decision, g_simplex.lat_hist_decision,
           sizeof(out->hist_decision));
    memcpy(out->hist_idle, g_simplex.lat_hist_idle, sizeof(out->hist_idle));
}

static bool latch_fill_latency_stats(latch_latency_stats_t *out) {
    if (out == NULL) return false;
    for (int tries = 0; tries < 4; tries++) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) {
            return false;
        }
        atomic_thread_fence(memory_order_acquire);

        latch_fill_latency_stats_locked(out);

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) {
            return true;
        }
    }
    return false;
}

static bool latch_fill_governor_status(latch_governor_status_reply_t *out) {
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    for (int tries = 0; tries < 4; ++tries) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) return false;
        atomic_thread_fence(memory_order_acquire);
        latch_fill_status_locked(&out->latch);

        out->extension_version = 6u;
        out->enabled = g_manifest.governor.enabled;
        out->rung = (uint32_t)g_simplex.gov_ladder.rung;
        out->v2_session = g_simplex.gov_v2_session ? 1u : 0u;
        out->lease_ticks_remaining = g_simplex.gov_lease_remaining;
        uint64_t age = g_simplex.gov_v2_session &&
                       g_simplex.tick >= g_simplex.gov_last_lease_tick
                           ? g_simplex.tick - g_simplex.gov_last_lease_tick : 0u;
        out->lease_age_ticks = age > UINT32_MAX ? UINT32_MAX : (uint32_t)age;
        out->warmup_heartbeats_seen = g_simplex.gov_warmup_seen;
        out->agent_state = g_simplex.gov_agent_state;
        out->rate_tokens_remaining = g_simplex.gov_gate.rate_tokens;
        out->shrink_active = g_simplex.gov_gate.shrink_active;
        out->shrink_v_max = g_simplex.gov_gate.shrink_v;
        out->shrink_scale_q8 = g_simplex.gov_gate.shrink_scale_q8;
        out->coherence_ctr = g_simplex.gov_last_coherence;
        out->coherence_valid = g_simplex.gov_coherence_valid ? 1u : 0u;
        out->clean_command_streak = g_simplex.gov_ladder.clean_frame_streak;
        out->deadline_misses = g_simplex.gov_deadline_misses;
        out->homeostat_enabled = (g_manifest.homeostat_present &&
                                  g_manifest.homeostat.enabled != 0u) ? 1u : 0u;
        out->homeostat_scale_q8 = g_simplex.homeostat.scale_q8;
        out->homeostat_v_max = (uint32_t)latch_homeostat_vmax(&g_simplex);
        out->homeostat_stress_epochs = g_simplex.homeostat.stress_epochs;
        /* Producer-scoped lease telemetry (L-2, extension_version >= 5). */
        out->lease_owner_tag = (uint32_t)g_simplex.gov_lease_owner_tag;
        out->lease_owner_valid = g_simplex.gov_lease_owner_valid ? 1u : 0u;
        out->session_dead = g_simplex.gov_session_dead ? 1u : 0u;
        out->foreign_frames = g_simplex.gov_foreign_frames;
        out->producer_takeovers = g_simplex.gov_producer_takeovers;
        /* Session-epoch telemetry (RT-02, extension_version >= 6). */
        out->session_epoch = g_simplex.gov_session_epoch;
        out->session_epoch_valid = g_simplex.gov_session_epoch_valid ? 1u : 0u;

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) return true;
    }
    return false;
}

static bool latch_fill_hold_status(latch_hold_status_t *out) {
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    for (int tries = 0; tries < 4; ++tries) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) return false;
        atomic_thread_fence(memory_order_acquire);

        out->struct_size = (uint32_t)sizeof(*out);
        out->hold_locked = atomic_load_explicit(&g_simplex.operator_hold_locked,
                                                memory_order_acquire);
        out->rung = (uint32_t)g_simplex.gov_ladder.rung;
        out->release_deferred_ticks = atomic_load_explicit(
            &g_simplex.operator_release_deferred_ticks, memory_order_acquire);
        if (atomic_load_explicit(&g_simplex.operator_release_armed,
                                 memory_order_acquire) != 0u) {
            out->release_state = LATCH_RELEASE_ARMED;
        } else if (atomic_load_explicit(&g_simplex.operator_release_pending,
                                        memory_order_acquire) != 0u) {
            out->release_state = LATCH_RELEASE_DEFERRED;
        } else {
            out->release_state = LATCH_RELEASE_NONE;
        }

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) return true;
    }
    return false;
}

/*
 * THE OPERATOR-HOLD COMMAND'S STATE AND SNAPSHOT.
 *
 * These two helpers exist so that the QNX resource manager and the host
 * simulation drive the SAME shared decision (`latch_hold_command()` in
 * qnx/latch_hold.h) instead of each carrying its own copy of it.  The copy
 * is how the fail-open came to exist in two places.
 */
static void latch_hold_state_view(latch_hold_state_t *out) {
    if (out == NULL) return;
    out->hold_locked = &g_simplex.operator_hold_locked;
    out->release_pending = &g_simplex.operator_release_pending;
    out->release_armed = &g_simplex.operator_release_armed;
    out->release_deferred_ticks = &g_simplex.operator_release_deferred_ticks;
    out->release_rung = &g_simplex.operator_release_rung;
}

static bool latch_hold_snapshot_cb(void *ctx, latch_hold_status_t *out) {
    (void)ctx;
    return latch_fill_hold_status(out);
}

static bool latch_fill_session_status(latch_session_status_t *out) {
    if (out == NULL) return false;
    memset(out, 0, sizeof(*out));
    /*
     * Both fields are independent atomics, so no seqlock retry is needed:
     * a reader can never observe a half-updated struct, and the pair it
     * sees is a truthful (writer_held, generation) sample even if a writer
     * session starts between the two loads.  The generation only ever
     * increases, so a stale generation can never be mistaken for a newer
     * one.
     */
    out->struct_size = (uint32_t)sizeof(*out);
    out->writer_held = atomic_load_explicit(&g_simplex.open_writers,
                                            memory_order_acquire) ? 1u : 0u;
    out->session_generation = atomic_load_explicit(&g_simplex.session_generation,
                                                   memory_order_acquire);
    return true;
}

static bool latch_fill_tape_dump(latch_tape_dump_t *dump) {
    for (int retry = 0; retry < 5; ++retry) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) {
            return false;
        }
        atomic_thread_fence(memory_order_acquire);

        uint32_t cap = g_manifest.tape.capacity;
        if (cap == 0u || cap > LATCH_TAPE_CAPACITY) cap = LATCH_TAPE_CAPACITY;

        uint64_t wr_idx = atomic_load_explicit(&g_tape_write_idx, memory_order_acquire);
        uint32_t req_count = dump->count;
        if (req_count == 0u || req_count > LATCH_DUMP_MAX_ENTRIES) {
            req_count = LATCH_DUMP_MAX_ENTRIES;
        }
        if (req_count > cap) req_count = cap;

        uint64_t start = dump->start_index;
        if (start == UINT64_MAX) {
            if (req_count > wr_idx) {
                req_count = (uint32_t)wr_idx;
            }
            start = (wr_idx >= req_count) ? (wr_idx - req_count) : 0u;
        } else {
            /* Support pagination from start_index: clamp if overwritten by ring capacity */
            if (wr_idx > cap && start < wr_idx - cap) {
                start = wr_idx - cap;
            }
            if (start >= wr_idx) {
                req_count = 0u;
            } else {
                uint64_t avail = wr_idx - start;
                if (req_count > avail) {
                    req_count = (uint32_t)avail;
                }
            }
        }

        for (uint32_t i = 0; i < req_count; ++i) {
            dump->entries[i] = g_latch_tape[(start + i) % cap];
        }
        dump->start_index = start;
        dump->count       = req_count;
        dump->latest_tick = g_simplex.tick;
        memcpy(dump->manifest_sha256, g_manifest.sha256, sizeof(dump->manifest_sha256));

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) {
            return true;
        }
    }
    /* The writer never settled: the dump is not trustworthy. Report the
     * failure rather than serving a partial dump as if it were complete. */
    return false;
}

static bool latch_fill_governor_event_dump(latch_gov_event_dump_t *dump) {
    if (dump == NULL) return false;
    for (int retry = 0; retry < 5; ++retry) {
        uint32_t g1 = 0u;
        if (!latch_snapshot_wait_even(&g1)) return false;
        atomic_thread_fence(memory_order_acquire);

        uint64_t write_index = atomic_load_explicit(&g_gov_event_write_idx,
                                                   memory_order_acquire);
        uint64_t start = dump->start_index;
        uint32_t count = dump->count;
        if (count == 0u || count > LATCH_GOV_EVENT_DUMP_MAX) {
            count = LATCH_GOV_EVENT_DUMP_MAX;
        }
        if (start == UINT64_MAX) {
            start = write_index > count ? write_index - count : 0u;
        }

        uint32_t dropped = 0u;
        if (write_index > LATCH_GOV_EVENT_CAPACITY) {
            uint64_t earliest = write_index - LATCH_GOV_EVENT_CAPACITY;
            if (start < earliest) {
                dropped = (uint32_t)(earliest - start);
                start = earliest;
            }
        }

        if (start >= write_index) {
            count = 0u;
        } else if ((uint64_t)count > write_index - start) {
            count = (uint32_t)(write_index - start);
        }

        for (uint32_t i = 0u; i < count; ++i) {
            dump->entries[i] = g_gov_events[(start + i) % LATCH_GOV_EVENT_CAPACITY];
        }
        dump->start_index = start;
        dump->latest_index = write_index;
        dump->count = count;
        dump->dropped = dropped;
        dump->overflow = atomic_load_explicit(&g_gov_event_overflow, memory_order_acquire);
        dump->record_version = 1u;
        memcpy(dump->manifest_sha256, g_manifest.sha256, sizeof(dump->manifest_sha256));

        atomic_thread_fence(memory_order_acquire);
        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) return true;
    }
    return false;
}

/* ==========================================================================
 * 10. QNX SDP 8.0 Resource Manager & Monotonic Timer Loop (__QNXNTO__)
 * ========================================================================== */

#ifdef __QNXNTO__

typedef struct latch_dev_attr {
    iofunc_attr_t attr;
    bool          is_actuator_node;
} latch_dev_attr_t;

static int              g_ability_actuator_id = -1;
static int              g_ability_propose_id  = -1;
static int              g_timer_chid          = -1;
static int              g_timer_coid          = -1;
static timer_t          g_timer_id;
static latch_dev_attr_t g_proposal_attr;
static latch_dev_attr_t g_actuator_attr;
static latch_dev_attr_t g_governor_attr;

/* /dev/latch/proposal runs on its own dedicated dispatch_t + worker thread
 * (D-25 Decision 2). Check latch/propose on ALL opens (including O_RDONLY)
 * and writes, passing real ioflag to iofunc_client_info_able(). */
static int latch_verify_propose_ability(resmgr_context_t *ctp, int ioflag) {
    struct _client_info *info = NULL;
    struct _client_able able;
    memset(&able, 0, sizeof(able));
    able.ability = (uint32_t)g_ability_propose_id;
    int status = iofunc_client_info_able(ctp, ioflag, &info, 0, &able, 1);
    if (status != EOK) {
        if (info != NULL) iofunc_client_info_ext_free(&info);
        return status;
    }
    bool allowed = info != NULL && (info->flags & _NTO_CI_UNABLE) == 0u;
    if (info != NULL) iofunc_client_info_ext_free(&info);
    return allowed ? EOK : EPERM;
}

static int latch_pin_to_cpu(unsigned int cpu_index) {
    unsigned int num_cpu = _syspage_ptr->num_cpu;
    if (cpu_index >= num_cpu) {
        cpu_index = 0u;
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

    RMSK_SET(cpu_index, runmask);
    RMSK_SET(cpu_index, inheritmask);

    int rc = ThreadCtl(_NTO_TCTL_RUNMASK_GET_AND_SET_INHERIT, buf);
    int saved_errno = errno;
    free(buf);

    return (rc == -1) ? -saved_errno : 0;
}

/*
 * Check custom ability "latch/actuator" using iofunc_client_info_able().
 * Fix E-1: Callee sets _NTO_CI_UNABLE in info->flags if client lacks ability.
 */
static int latch_verify_actuator_ability(resmgr_context_t *ctp,
                                         iofunc_ocb_t *io_ocb) {
    struct _client_info *info = NULL;
    struct _client_able  able;

    memset(&able, 0, sizeof(able));
    able.ability  = (uint32_t)g_ability_actuator_id;
    able.flags    = 0u;
    able.range_lo = 0u;
    able.range_hi = 0u;

    int status = iofunc_client_info_able(ctp, io_ocb->ioflag, &info, 0, &able, 1);
    if (status != EOK) {
        if (info != NULL) {
            iofunc_client_info_ext_free(&info);
        }
        return status;
    }

    bool authorized = (info != NULL) && ((info->flags & _NTO_CI_UNABLE) == 0u);
#ifdef LATCH_ABLE_STRICT_FLAGS
    authorized = authorized && (able.flags != 0u);
#endif

    iofunc_client_info_ext_free(&info);

    if (!authorized) {
        latch_record_eperm_fault();
        return EPERM;
    }
    return EOK;
}

static int latch_io_open(resmgr_context_t *ctp,
                         io_open_t *msg,
                         RESMGR_HANDLE_T *handle,
                         void *extra) {
    latch_dev_attr_t *lattr = (latch_dev_attr_t *)handle;
    if (lattr != NULL && lattr->is_actuator_node) {
        /* Mutating open of actuator node requires 'latch/actuator' ability */
        if (msg->connect.ioflag & _IO_FLAG_WR) {
            struct _client_info *info = NULL;
            struct _client_able  able;
            memset(&able, 0, sizeof(able));
            able.ability  = (uint32_t)g_ability_actuator_id;
            able.flags    = 0u;
            able.range_lo = 0u;
            able.range_hi = 0u;

            int status = iofunc_client_info_able(ctp, msg->connect.ioflag, &info, 0, &able, 1);
            if (status != EOK) {
                if (info != NULL) iofunc_client_info_ext_free(&info);
                return status;
            }
            bool authorized = (info != NULL) && ((info->flags & _NTO_CI_UNABLE) == 0u);
            iofunc_client_info_ext_free(&info);
            if (!authorized) {
                latch_record_eperm_fault();
                return EPERM;
            }
        }
    } else if (lattr != NULL && !lattr->is_actuator_node) {
        /* Require latch/propose ability on ALL /dev/latch/proposal opens
         * (including O_RDONLY, not only _IO_FLAG_WR). */
        int authorized = latch_verify_propose_ability(ctp, (int)msg->connect.ioflag);
        if (authorized != EOK) return authorized;
        if (msg->connect.ioflag & _IO_FLAG_WR) {
            /* The IPC producer tag is supplied by the sender, so it cannot
             * establish writer identity. Permit one writer OCB per session. */
            if (!latch_claim_writer(&g_simplex.open_writers)) {
                return EBUSY;
            }
            /* Do not flush a session or advance session_generation for an open
             * that fails permissions or OCB allocation. */
            int rc = latch_rm_open_default(ctp, msg, handle, extra);
            if (rc != 0) {
                atomic_store_explicit(&g_simplex.open_writers, 0u, memory_order_release);
                return rc;
            }

            /*
             * This open succeeded on the 0 -> 1 writer transition, so it starts
             * a new writer session. Advance session_generation ONLY after
             * iofunc_open_default() succeeds.
             */
            atomic_fetch_add_explicit(&g_simplex.session_generation, 1u,
                                      memory_order_acq_rel);

            {
                /*
                 * Discard the PREVIOUS session's queued frames -- they belong
                 * to a producer that is gone -- and COUNT them, so the loss
                 * is visible in the telemetry instead of being silent.
                 *
                 * The epoch is bumped FIRST, so a consumer that is already
                 * copying a slot from the previous session sees the change
                 * and refuses the frame instead of delivering it into the
                 * new session (see latch_consume_proposal()).
                 */
                uint32_t stale = latch_ring_flush_session(&g_pub_buf);
                if (stale > 0u) {
                    atomic_fetch_add_explicit(&g_simplex.total_ring_drops, stale, memory_order_relaxed);
                }
                atomic_store_explicit(&g_simplex.writer_closed_eof, 0u, memory_order_release);
                atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
            }

            return rc;
        }
    }
    return latch_rm_open_default(ctp, msg, handle, extra);
}

static int latch_io_close_ocb(resmgr_context_t *ctp,
                              void *reserved,
                              RESMGR_OCB_T *ocb) {
    (void)reserved;
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    if (io_ocb != NULL && io_ocb->attr != NULL) {
        latch_dev_attr_t *lattr = (latch_dev_attr_t *)io_ocb->attr;
        if (!lattr->is_actuator_node && (io_ocb->ioflag & _IO_FLAG_WR)) {
            /* Publish EOF before making the slot available: a new opener
             * clears EOF after it claims the slot. */
            atomic_store_explicit(&g_simplex.writer_closed_eof, 1u, memory_order_release);
            atomic_store_explicit(&g_simplex.open_writers, 0u, memory_order_release);
        }
    }
    return latch_rm_close_ocb_default(ctp, reserved, ocb);
}

static int latch_io_write(resmgr_context_t *ctp,
                           io_write_t *msg,
                           RESMGR_OCB_T *ocb) {
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    latch_dev_attr_t *lattr = (latch_dev_attr_t *)io_ocb->attr;

    int status = latch_rm_write_verify(ctp, msg, io_ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;

    if (lattr->is_actuator_node) {
        latch_record_eperm_fault();
        return EPERM;
    }

    status = latch_verify_propose_ability(ctp, io_ocb->ioflag);
    if (status != EOK) return status;

    size_t nbytes = _IO_WRITE_GET_NBYTES(msg);
    if (nbytes != sizeof(latch_ipc_proposal_t) &&
        nbytes != sizeof(latch_ipc_proposal_v2_t)) return EMSGSIZE;

    uint8_t wire_message[sizeof(latch_ipc_proposal_v2_t)];
    ssize_t got = resmgr_msgread(ctp, wire_message, nbytes, sizeof(msg->i));
    latch_proposal_t prop;
    if (got != (ssize_t)nbytes ||
        latch_ipc_decode_contract(wire_message, nbytes, g_manifest.protocol.version, &prop) != 0) {
        return EBADMSG;
    }
    if (prop.wire_version == 2u &&
        (g_manifest.schema_version != LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION ||
         g_manifest.protocol.version != 2u || g_manifest.governor.enabled == 0u)) {
        return EPROTONOSUPPORT;
    }

    latch_publish_proposal(&g_pub_buf, &prop);
    _IO_SET_WRITE_NBYTES(ctp, (int)nbytes);
    return EOK;
}

static int latch_io_devctl(resmgr_context_t *ctp,
                            io_devctl_t *msg,
                            RESMGR_OCB_T *ocb) {
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    latch_dev_attr_t *lattr = (latch_dev_attr_t *)io_ocb->attr;

    int status = latch_rm_devctl_default(ctp, msg, io_ocb);
    if (status != _RESMGR_DEFAULT) return status;
    if (!lattr->is_actuator_node) return ENOTTY;

    if (ctp->size < sizeof(msg->i)) {
        return EBADMSG;
    }

    const void *in_data = _IO_INPUT_PAYLOAD(msg);
    void *out_data      = _IO_OUTPUT_PAYLOAD(msg);
    size_t nbytes_out   = 0u;

    switch ((unsigned int)msg->i.dcmd) {
        case (unsigned int)DCMD_LATCH_FORCE_HOLD: {
            /* Mutating control operations require custom ability 'latch/actuator' */
            int perm_status = latch_verify_actuator_ability(ctp, io_ocb);
            if (perm_status != EOK) return perm_status;

            if (msg->i.nbytes < sizeof(latch_force_hold_cmd_t) ||
                ctp->size < sizeof(msg->i) + sizeof(latch_force_hold_cmd_t) ||
                ctp->msg_max_size < sizeof(msg->i) + sizeof(latch_force_hold_cmd_t)) {
                return EBADMSG;
            }
            const latch_force_hold_cmd_t *cmd =
                (const latch_force_hold_cmd_t *)in_data;

            /*
             * THE ORDER IS INSIDE THE SHARED DECISION.
             *
             * `latch_hold_command()` takes the snapshot FIRST and mutates
             * NOTHING if the snapshot is torn, so a refused command cannot
             * have released the hold.  The old code stored
             * `operator_hold_locked = 0` FIRST and only THEN took the
             * snapshot, so an EBUSY return left the hold released even
             * though the operator was told the command had failed.
             */
            latch_hold_state_t hold_state;
            latch_hold_state_view(&hold_state);
            if (!latch_hold_command(&hold_state, latch_hold_snapshot_cb, NULL,
                                    cmd)) {
                /* FAIL LOUDLY: a torn snapshot means the supervisor state
                 * is not trustworthy, and recording a release against an
                 * unknown rung would be exactly the silent-application
                 * defect this fix exists to remove.  Nothing was written,
                 * so the operator's hold is exactly as it was. */
                return EBUSY;
            }
            nbytes_out = 0u;
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_HOLD_STATUS: {
            if (msg->i.nbytes < sizeof(latch_hold_status_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_hold_status_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_hold_status_t)) {
                return EBADMSG;
            }
            latch_hold_status_t rep;
            if (!latch_fill_hold_status(&rep)) return EBUSY;
            memcpy(out_data, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_SESSION_STATUS: {
            /* Output-only. Grants no authority and mutates nothing. */
            if (msg->i.nbytes < sizeof(latch_session_status_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_session_status_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_session_status_t)) {
                return EBADMSG;
            }
            latch_session_status_t rep;
            if (!latch_fill_session_status(&rep)) return EBUSY;
            memcpy(out_data, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_PROBE_ABILITY: {
            int perm_status = latch_verify_actuator_ability(ctp, io_ocb);
            if (perm_status != EOK) return perm_status;
            nbytes_out = 0u;
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_STATUS: {
            if (msg->i.nbytes < sizeof(latch_status_reply_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_status_reply_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_status_reply_t)) {
                return EBADMSG;
            }
            latch_status_reply_t rep;
            memset(&rep, 0, sizeof(rep));
            /* FAIL LOUDLY if a consistent snapshot could not be taken. A
             * torn or all-zero reply served as "valid" would tell the
             * operator a lie about the supervisor's state. */
            if (!latch_fill_status(&rep)) {
                return EBUSY;
            }
            memcpy(out_data, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_GOV_STATUS: {
            if (msg->i.nbytes < sizeof(latch_governor_status_reply_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_governor_status_reply_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_governor_status_reply_t)) {
                return EBADMSG;
            }
            latch_governor_status_reply_t rep;
            if (!latch_fill_governor_status(&rep)) return EBUSY;
            memcpy(out_data, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_LATENCY_STATS: {
            if (msg->i.nbytes < sizeof(latch_latency_stats_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_latency_stats_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_latency_stats_t)) {
                return EBADMSG;
            }
            latch_latency_stats_t rep;
            memset(&rep, 0, sizeof(rep));
            if (!latch_fill_latency_stats(&rep)) {
                return EBUSY;
            }
            memcpy(out_data, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_DUMP_TAPE: {
            if (msg->i.nbytes < sizeof(latch_tape_dump_t) ||
                ctp->size < sizeof(msg->i) + sizeof(latch_tape_dump_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_tape_dump_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_tape_dump_t)) {
                return EBADMSG;
            }
            const latch_tape_dump_t *in_dump = (const latch_tape_dump_t *)in_data;
            latch_tape_dump_t *dump = (latch_tape_dump_t *)out_data;
            dump->start_index = in_dump->start_index;
            dump->count       = in_dump->count;
            if (!latch_fill_tape_dump(dump)) {
                return EBUSY;
            }
            nbytes_out = sizeof(*dump);
            break;
        }
        case (unsigned int)DCMD_LATCH_DUMP_GOV_EVENTS: {
            if (msg->i.nbytes < sizeof(latch_gov_event_dump_t) ||
                ctp->size < sizeof(msg->i) + sizeof(latch_gov_event_dump_t) ||
                ctp->msg_max_size < sizeof(msg->o) + sizeof(latch_gov_event_dump_t) ||
                ctp->info.dstmsglen < 0 ||
                (size_t)ctp->info.dstmsglen < sizeof(msg->o) + sizeof(latch_gov_event_dump_t)) {
                return EBADMSG;
            }
            const latch_gov_event_dump_t *in_dump = (const latch_gov_event_dump_t *)in_data;
            latch_gov_event_dump_t *dump = (latch_gov_event_dump_t *)out_data;
            dump->start_index = in_dump->start_index;
            dump->count       = in_dump->count;
            if (!latch_fill_governor_event_dump(dump)) {
                return EBUSY;
            }
            nbytes_out = sizeof(*dump);
            break;
        }
        default:
            return ENOTTY;
    }

    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.ret_val = EOK;
    msg->o.nbytes  = (uint32_t)nbytes_out;
    return _RESMGR_PTR(ctp, &msg->o, sizeof(msg->o) + nbytes_out);
}

static void *latch_decision_thread(void *arg) {
    (void)arg;

    if (latch_pin_to_cpu(g_manifest.decision.cpu) != 0) {
        perror("latchd: ThreadCtl(pin decision cpu)");
    }

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = (int)g_manifest.decision.priority;
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0) {
        perror("latchd: pthread_setschedparam");
    }

    struct nto_channel_config ch_cfg;
    memset(&ch_cfg, 0, sizeof(ch_cfg));
    SIGEV_NONE_INIT(&ch_cfg.event);
    ch_cfg.num_pulses = 64;
    ch_cfg.rearm_threshold = 16;
    ch_cfg.options = _NTO_CHO_CUSTOM_EVENT;

    g_timer_chid = ChannelCreatePulsePool(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_PRIVATE, &ch_cfg);
    if (g_timer_chid == -1) {
        g_timer_chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_PRIVATE);
    }
    if (g_timer_chid == -1) {
        perror("latchd: ChannelCreatePulsePool");
        g_running = 0;
        return NULL;
    }

    g_timer_coid = ConnectAttach(0, 0, g_timer_chid, _NTO_SIDE_CHANNEL, 0);
    if (g_timer_coid == -1) {
        perror("latchd: ConnectAttach");
        ChannelDestroy(g_timer_chid);
        g_running = 0;
        return NULL;
    }

    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, g_timer_coid, (int)g_manifest.decision.pulse_priority, LATCH_PULSE_CODE_TICK, 0);

    if (timer_create(CLOCK_MONOTONIC, &ev, &g_timer_id) == -1) {
        perror("latchd: timer_create");
        ConnectDetach(g_timer_coid);
        ChannelDestroy(g_timer_chid);
        g_running = 0;
        return NULL;
    }

    struct itimerspec it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_nsec    = (long)g_simplex.period_ns;
    it.it_interval.tv_nsec = (long)g_simplex.period_ns;

    if (timer_settime(g_timer_id, 0, &it, NULL) == -1) {
        perror("latchd: timer_settime");
        timer_delete(g_timer_id);
        ConnectDetach(g_timer_coid);
        ChannelDestroy(g_timer_chid);
        g_running = 0;
        return NULL;
    }

    struct _pulse pulse;
    while (g_running) {
        rcvid_t rcvid = MsgReceivePulse(g_timer_chid, &pulse, sizeof(pulse), NULL);
        if (rcvid == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (pulse.code == LATCH_PULSE_CODE_QUIT) break;
        if (pulse.code == LATCH_PULSE_CODE_TICK) {
            latch_simplex_tick(&g_simplex, &g_pub_buf);
        }
    }

    timer_delete(g_timer_id);
    ConnectDetach(g_timer_coid);
    ChannelDestroy(g_timer_chid);
    return NULL;
}

static void *latch_actuator_io_thread(void *arg) {
    (void)arg;
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 20;
    (void)pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    uint64_t last_seq_num = 0u;
    struct _pulse pulse;
    while (g_running) {
        rcvid_t rcvid = MsgReceivePulse(g_actuator_io_chid, &pulse, sizeof(pulse), NULL);
        if (rcvid == -1) {
            if (errno == EINTR) continue;
            break;
        }
        if (pulse.code == LATCH_PULSE_CODE_QUIT) break;
        if (pulse.code == LATCH_PULSE_CODE_ACTUATE) {
            int32_t target_theta = 0;
            if (latch_actuator_read_target(&g_simplex.actuator_io, &last_seq_num, &target_theta)) {
                if (latch_pca9685_write_angle(g_simplex.i2c_fd, target_theta) != 0) {
                    atomic_store_explicit(&g_simplex.actuator_io.io_fault_pending,
                                          1u, memory_order_release);
                }
            }
        }
    }
    return NULL;
}

static void *latch_proposal_thread(void *arg) {
    dispatch_context_t *ctp = (dispatch_context_t *)arg;
    while (g_running) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) continue;
            break;
        }
        (void)dispatch_handler(ctp);
    }
    return NULL;
}

static void latch_sig_handler(int signo) {
    (void)signo;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    const char *manifest_path = "latch.manifest";
    const char *i2c_bus_path  = NULL;
    const char *feedback_path = NULL;
    bool force_no_i2c         = false;

    int opt;
    while ((opt = getopt(argc, argv, "m:b:nf:")) != -1) {
        switch (opt) {
            case 'm': manifest_path = optarg; break;
            case 'b': i2c_bus_path  = optarg; break;
            case 'n': force_no_i2c  = true;   break;
            case 'f': feedback_path = optarg; break;
            default:
                fprintf(stderr, "Usage: %s [-m latch.manifest] [-b /dev/i2c1] [-n] "
                                "[-f <feedback node>]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    latch_time_init();

    /* Load zero-hardcoding manifest strictly (fail-closed) */
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latchd: FATAL: Failed to load manifest '%s': %s (Fail-Closed)\n",
                manifest_path, err_buf);
        return EXIT_FAILURE;
    }
    printf("latchd: Loaded manifest '%s' (plant='%s', SHA-256=%.16s...)\n",
           manifest_path, g_manifest.plant_name, g_manifest.sha256_hex);

    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        perror("latchd: mlockall (warning: requires PROCMGR_AID_MEM_LOCK or root)");
    }

    if (!force_no_i2c && i2c_bus_path == NULL) {
        i2c_bus_path = g_manifest.paths.i2c_bus;
    }

    memset(&g_simplex, 0, sizeof(g_simplex));
    g_simplex.mode          = (uint8_t)LATCH_MODE_HP;
    g_simplex.theta_mrad    = g_manifest.envelope.home_mrad;
    g_simplex.period_ns     = g_manifest.timing.period_us * 1000u;
    g_simplex.ticks_per_sec = (int32_t)(1000000000u / g_simplex.period_ns);
    g_simplex.i2c_fd        = -1;
    latch_governor_init_state(&g_simplex);

    /* Create custom ability "latch/actuator" with flags=0 (neither root nor non-root) */
    g_ability_actuator_id = procmgr_ability_create(g_manifest.paths.ability, 0);
    if (g_ability_actuator_id < 0) {
        perror("latchd: procmgr_ability_create(latch/actuator)");
        return EXIT_FAILURE;
    }

    /* Neither root nor nonroot receives this ability by default; security
     * policy grants it to the ingest and explicit verification domains. */
    g_ability_propose_id = procmgr_ability_create("latch/propose", 0);
    if (g_ability_propose_id < 0) {
        perror("latchd: procmgr_ability_create(latch/propose)");
        return EXIT_FAILURE;
    }

    if (!force_no_i2c && i2c_bus_path != NULL) {
        g_simplex.i2c_fd = open(i2c_bus_path, O_RDWR);
        if (g_simplex.i2c_fd < 0) {
            perror("latchd: open I2C bus");
            if (g_manifest.actuator.required) {
                fprintf(stderr, "latchd: FATAL: Actuator bus '%s' required by manifest but open failed (Fail-Closed)\n",
                        i2c_bus_path);
                return EXIT_FAILURE;
            }
        } else {
            int init_rc = latch_pca9685_init(g_simplex.i2c_fd);
            if (init_rc != 0) {
                fprintf(stderr, "latchd: WARNING: PCA9685 init failed (code %d)\n", init_rc);
                if (g_manifest.actuator.required) {
                    fprintf(stderr, "latchd: FATAL: Actuator required by manifest but init failed (Fail-Closed)\n");
                    close(g_simplex.i2c_fd);
                    return EXIT_FAILURE;
                }
            } else {
                /* Park actuator at manifest envelope home position immediately upon hardware init */
                (void)latch_pca9685_write_angle(g_simplex.i2c_fd, g_manifest.envelope.home_mrad);
            }
        }
    } else {
        if (g_manifest.actuator.required) {
            fprintf(stderr, "latchd: FATAL: Actuator required by manifest but -n (no-i2c) was requested (Fail-Closed)\n");
            return EXIT_FAILURE;
        }
        printf("latchd: Operating in NO-I2C mock mode (-n)\n");
    }

    /* Set up dedicated actuator I/O pulse channel & worker thread so blocking
     * DCMD_I2C_SEND writes never run inside SCHED_FIFO 63 latch_simplex_tick(). */
    g_actuator_io_chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_PRIVATE);
    if (g_actuator_io_chid == -1) {
        perror("latchd: ChannelCreate(actuator_io)");
        return EXIT_FAILURE;
    }
    g_actuator_io_coid = ConnectAttach(0, 0, g_actuator_io_chid, _NTO_SIDE_CHANNEL, 0);
    if (g_actuator_io_coid == -1) {
        perror("latchd: ConnectAttach(actuator_io)");
        ChannelDestroy(g_actuator_io_chid);
        return EXIT_FAILURE;
    }

    /* Separate dispatch_t for /dev/latch/actuator + /dev/governor vs
     * /dev/latch/proposal (D-25 Decision 2). */
    dispatch_t *dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    dispatch_t *dpp_prop = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    if (dpp == NULL || dpp_prop == NULL) {
        perror("latchd: dispatch_create_channel");
        return EXIT_FAILURE;
    }

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t      io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
                     _RESMGR_IO_NFUNCS, &io_funcs);
    connect_funcs.open = latch_io_open;
    io_funcs.close_ocb = latch_io_close_ocb;
    io_funcs.write     = latch_io_write;
    io_funcs.devctl    = latch_io_devctl;

    /* Proposal mailbox is world-writable (untrusted AI / guest domain) */
    iofunc_attr_init(&g_proposal_attr.attr, S_IFCHR | 0666, NULL, NULL);
    g_proposal_attr.is_actuator_node = false;

    /* Actuator and Governor interfaces have separate iofunc_attr_t instances */
    iofunc_attr_init(&g_actuator_attr.attr, S_IFCHR | 0666, NULL, NULL);
    g_actuator_attr.is_actuator_node = true;

    iofunc_attr_init(&g_governor_attr.attr, S_IFCHR | 0666, NULL, NULL);
    g_governor_attr.is_actuator_node = true;

    _Static_assert(sizeof(latch_tape_dump_t) >= sizeof(latch_gov_event_dump_t),
                   "rattr.msg_max_size assumes latch_tape_dump_t >= latch_gov_event_dump_t");
    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max   = 1;
    rattr.msg_max_size = sizeof(io_devctl_t) + sizeof(latch_tape_dump_t) + 256u;

    resmgr_attr_t rattr_prop;
    memset(&rattr_prop, 0, sizeof(rattr_prop));
    rattr_prop.nparts_max   = 1;
    rattr_prop.msg_max_size = 2048u;

    int id_proposal = resmgr_attach(dpp_prop, &rattr_prop, g_manifest.paths.proposal,
                                    _FTYPE_ANY, 0, &connect_funcs,
                                    &io_funcs, &g_proposal_attr.attr);
    int id_actuator = resmgr_attach(dpp, &rattr, g_manifest.paths.actuator,
                                    _FTYPE_ANY, 0, &connect_funcs,
                                    &io_funcs, &g_actuator_attr.attr);
    int id_governor = resmgr_attach(dpp, &rattr, LATCH_DEV_GOVERNOR,
                                    _FTYPE_ANY, 0, &connect_funcs,
                                    &io_funcs, &g_governor_attr.attr);
    if (id_proposal == -1 || id_actuator == -1 || id_governor == -1) {
        perror("latchd: resmgr_attach");
        return EXIT_FAILURE;
    }

    dispatch_context_t *prop_ctp = dispatch_context_alloc(dpp_prop);
    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    if (prop_ctp == NULL || ctp == NULL) {
        perror("latchd: dispatch_context_alloc");
        return EXIT_FAILURE;
    }

    signal(SIGINT, latch_sig_handler);
    signal(SIGTERM, latch_sig_handler);

    /*
     * THE FEEDBACK PUBLISHER (W5).
     *
     * The publisher carries the supervisor's verdict on each proposal to
     * the guest over the advisory LFBK channel.  It is OPTIONAL: the
     * supervisor's safety does not depend on it, and a deployment that does
     * not run the `-f` option simply does not publish verdicts.
     *
     * It is started BEFORE the decision thread, so a verdict published in
     * the very first tick already has a writer thread waiting for it.
     */
    if (feedback_path != NULL) {
        if (latch_feedback_pub_start(feedback_path) == 0) {
            g_feedback_pub_enabled = true;
            printf("latchd: publishing verdicts on %s\n", feedback_path);
            fflush(stdout);
        } else {
            /* NOT FATAL.  The channel is advisory; the safety envelope, the
             * lease and the dead-man are unaffected by its absence.  Saying
             * so is the point: an operator must be able to tell "the
             * channel is off" from "the channel is broken". */
            fprintf(stderr, "latchd: WARNING: cannot start the feedback "
                            "publisher on '%s'; verdicts will NOT be "
                            "published (the safety envelope is unaffected)\n",
                    feedback_path);
        }
    }

    pthread_t actuator_io_tid;
    if (pthread_create(&actuator_io_tid, NULL, latch_actuator_io_thread, NULL) != 0) {
        perror("latchd: pthread_create(actuator_io)");
        return EXIT_FAILURE;
    }

    pthread_t prop_tid;
    if (pthread_create(&prop_tid, NULL, latch_proposal_thread, prop_ctp) != 0) {
        perror("latchd: pthread_create(proposal)");
        g_running = 0;
        (void)MsgSendPulse(g_actuator_io_coid, 20, LATCH_PULSE_CODE_QUIT, 0);
        pthread_join(actuator_io_tid, NULL);
        return EXIT_FAILURE;
    }

    pthread_t decision_tid;
    if (pthread_create(&decision_tid, NULL, latch_decision_thread, NULL) != 0) {
        perror("latchd: pthread_create(decision)");
        g_running = 0;
        dispatch_unblock(prop_ctp);
        pthread_join(prop_tid, NULL);
        (void)MsgSendPulse(g_actuator_io_coid, 20, LATCH_PULSE_CODE_QUIT, 0);
        pthread_join(actuator_io_tid, NULL);
        return EXIT_FAILURE;
    }

    while (g_running) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) continue;
            break;
        }
        (void)dispatch_handler(ctp);
    }

    dispatch_unblock(prop_ctp);
    (void)MsgSendPulse(g_actuator_io_coid, 20, LATCH_PULSE_CODE_QUIT, 0);
    pthread_join(decision_tid, NULL);
    pthread_join(prop_tid, NULL);
    pthread_join(actuator_io_tid, NULL);
    resmgr_detach(dpp, id_governor, _RESMGR_DETACH_ALL);
    resmgr_detach(dpp, id_actuator, _RESMGR_DETACH_ALL);
    resmgr_detach(dpp_prop, id_proposal, _RESMGR_DETACH_ALL);
    dispatch_context_free(ctp);
    dispatch_context_free(prop_ctp);
    ConnectDetach(g_actuator_io_coid);
    ChannelDestroy(g_actuator_io_chid);
    if (g_simplex.i2c_fd >= 0) {
        close(g_simplex.i2c_fd);
    }
    return EXIT_SUCCESS;
}

#else /* LATCH_HOST_SIM */

/* ==========================================================================
 * 11. Host Simulation & Pipe-Driven Verification Mode (LATCH_HOST_SIM)
 * ========================================================================== */

/* The tick at which the host-sim EPERM probe fires:
 * latch_sim_devctl_actuator(DCMD_LATCH_FORCE_HOLD) from a caller WITHOUT
 * the latch/actuator ability. This verifies the ability gate is enforced
 * even in the test harness. The value 109 places it after the 100-tick
 * suite window but well before the 200-tick test ends. */
#define LATCH_SIM_EPERM_PROBE_TICK 109u

static const char *latch_mode_str(uint16_t mode) {
    switch (mode) {
        case LATCH_MODE_HP:   return "HP";
        case LATCH_MODE_HOLD: return "HOLD";
        case LATCH_MODE_HOME: return "HOME";
        default:              return "UNK";
    }
}

static void latch_sim_reset(void) {
    memset(&g_pub_buf, 0, sizeof(g_pub_buf));
    memset(&g_simplex, 0, sizeof(g_simplex));
    memset(g_latch_tape, 0, sizeof(g_latch_tape));
    atomic_store_explicit(&g_tape_write_idx, 0u, memory_order_relaxed);
    memset(g_gov_events, 0, sizeof(g_gov_events));
    atomic_store_explicit(&g_gov_event_write_idx, 0u, memory_order_relaxed);
    atomic_store_explicit(&g_gov_event_overflow, 0u, memory_order_relaxed);
    g_simplex.mode           = (uint8_t)LATCH_MODE_HP;
    g_simplex.theta_mrad     = g_manifest.envelope.home_mrad;
    latch_governor_init_state(&g_simplex);
    g_simplex.session_active = false;
    atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
    g_simplex.period_ns      = g_manifest.timing.period_us * 1000u;
    g_simplex.ticks_per_sec  = (int32_t)(1000000000u / g_simplex.period_ns);
    g_simplex.i2c_fd         = -1;
    (void)latch_pca9685_init(g_simplex.i2c_fd);
}

static int latch_sim_devctl_actuator(bool caller_has_ability,
                                     unsigned int dcmd,
                                     void *payload) {
    if ((dcmd == (unsigned int)DCMD_LATCH_FORCE_HOLD || dcmd == (unsigned int)DCMD_LATCH_PROBE_ABILITY) && !caller_has_ability) {
        latch_record_eperm_fault();
        return EPERM;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_PROBE_ABILITY) {
        return 0;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_FORCE_HOLD && payload != NULL) {
        const latch_force_hold_cmd_t *cmd = (const latch_force_hold_cmd_t *)payload;
        /*
         * The SAME shared decision the QNX resource manager uses, so the
         * two paths cannot drift apart again.  The snapshot comes first and
         * a refused command changes NOTHING.
         */
        latch_hold_state_t hold_state;
        latch_hold_state_view(&hold_state);
        if (!latch_hold_command(&hold_state, latch_hold_snapshot_cb, NULL,
                                cmd)) {
            return EBUSY;
        }
        return 0;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_GET_HOLD_STATUS && payload != NULL) {
        return latch_fill_hold_status((latch_hold_status_t *)payload) ? 0 : EBUSY;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_GET_SESSION_STATUS && payload != NULL) {
        return latch_fill_session_status((latch_session_status_t *)payload) ? 0 : EBUSY;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_GET_STATUS && payload != NULL) {
        /* EBUSY if a consistent snapshot could not be taken: a torn reply
         * served as valid would misreport the supervisor's state. */
        return latch_fill_status((latch_status_reply_t *)payload) ? 0 : EBUSY;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_GET_GOV_STATUS && payload != NULL) {
        return latch_fill_governor_status((latch_governor_status_reply_t *)payload) ? 0 : EBUSY;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_DUMP_TAPE && payload != NULL) {
        return latch_fill_tape_dump((latch_tape_dump_t *)payload) ? 0 : EBUSY;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_DUMP_GOV_EVENTS && payload != NULL) {
        return latch_fill_governor_event_dump((latch_gov_event_dump_t *)payload) ? 0 : EBUSY;
    }
    return ENOTTY;
}

static int latch_export_tape_csv(const char *csv_path) {
    FILE *fp = fopen(csv_path, "w");
    if (fp == NULL) {
        perror("latchd: fopen csv");
        return -1;
    }
    bool gov_on = (g_manifest.governor.enabled != 0u);
    if (gov_on) {
        fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,mode_name,fault_bits,rung\n");
    } else {
        fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,mode_name,fault_bits\n");
    }
    uint64_t wr_idx = atomic_load_explicit(&g_tape_write_idx, memory_order_acquire);
    /* The tape is WRITTEN with `% cap` (the manifest's tape.capacity), so it
     * must be READ the same way. The previous form used a fixed
     * `& LATCH_TAPE_MASK`, which reads the wrong slots for any manifest
     * whose capacity is not 4096. */
    uint32_t cap = g_manifest.tape.capacity;
    if (cap == 0u || cap > LATCH_TAPE_CAPACITY) cap = LATCH_TAPE_CAPACITY;
    uint32_t count = (wr_idx > cap) ? cap : (uint32_t)wr_idx;
    uint64_t start = wr_idx - count;
    uint64_t gov_cnt = gov_on ? atomic_load_explicit(&g_gov_event_write_idx, memory_order_acquire) : 0u;
    uint32_t gov_limit = (gov_cnt > LATCH_GOV_EVENT_CAPACITY) ? LATCH_GOV_EVENT_CAPACITY : (uint32_t)gov_cnt;
    for (uint32_t i = 0; i < count; ++i) {
        const latch_tape_entry_t *e = &g_latch_tape[(start + i) % cap];
        uint64_t lat = e->cycles_out - e->cycles_in;
        if (gov_on) {
            uint8_t rung = (uint8_t)g_simplex.gov_ladder.rung;
            for (uint32_t g = 0; g < gov_limit; ++g) {
                if (g_gov_events[g].seq == e->seq && g_gov_events[g].tick == e->tick) {
                    rung = g_gov_events[g].rung_after;
                    break;
                }
            }
            fprintf(fp,
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%u,%s,0x%04X,%u\n",
                    e->tick,
                    e->cycles_in,
                    e->cycles_out,
                    lat,
                    e->seq,
                    e->u_proposed,
                    e->theta_applied,
                    (unsigned int)e->mode,
                    latch_mode_str(e->mode),
                    (unsigned int)e->fault_bits,
                    (unsigned int)rung);
        } else {
            fprintf(fp,
                    "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%d,%d,%u,%s,0x%04X\n",
                    e->tick,
                    e->cycles_in,
                    e->cycles_out,
                    lat,
                    e->seq,
                    e->u_proposed,
                    e->theta_applied,
                    (unsigned int)e->mode,
                    latch_mode_str(e->mode),
                    (unsigned int)e->fault_bits);
        }
    }
    fclose(fp);
    return 0;
}

static int latch_export_events_json(const char *json_path) {
    if (json_path == NULL) return 0;
    FILE *fp = fopen(json_path, "w");
    if (fp == NULL) {
        perror("latchd: fopen events json");
        return -1;
    }
    latch_gov_event_dump_t dump;
    memset(&dump, 0, sizeof(dump));
    dump.start_index = UINT64_MAX;
    dump.count = LATCH_GOV_EVENT_DUMP_MAX;
    (void)latch_fill_governor_event_dump(&dump);

    char sha_hex[65];
    for (int i = 0; i < 32; ++i) snprintf(&sha_hex[i * 2], 3, "%02x", dump.manifest_sha256[i]);
    sha_hex[64] = '\0';

    fprintf(fp, "{\n");
    fprintf(fp, "  \"start_index\": %" PRIu64 ",\n", dump.start_index);
    fprintf(fp, "  \"latest_index\": %" PRIu64 ",\n", dump.latest_index);
    fprintf(fp, "  \"count\": %u,\n", dump.count);
    fprintf(fp, "  \"dropped\": %u,\n", dump.dropped);
    fprintf(fp, "  \"overflow\": %u,\n", dump.overflow);
    fprintf(fp, "  \"record_version\": %u,\n", dump.record_version);
    fprintf(fp, "  \"manifest_sha256\": \"%s\",\n", sha_hex);
    fprintf(fp, "  \"events\": [\n");
    for (uint32_t i = 0; i < dump.count; ++i) {
        const latch_gov_event_t *e = &dump.entries[i];
        char ev_hex[125];
        for (size_t b = 0; b < sizeof(*e); ++b) snprintf(&ev_hex[b * 2], 3, "%02x", ((const uint8_t *)e)[b]);
        ev_hex[124] = '\0';
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"event_index\": %" PRIu64 ",\n", e->event_index);
        fprintf(fp, "      \"tick\": %" PRIu64 ",\n", e->tick);
        fprintf(fp, "      \"cycles\": %" PRIu64 ",\n", e->cycles);
        fprintf(fp, "      \"seq\": %u,\n", e->seq);
        fprintf(fp, "      \"raw_u_mrad\": %d,\n", e->raw_u_mrad);
        fprintf(fp, "      \"normalized_u_mrad\": %d,\n", e->normalized_u_mrad);
        fprintf(fp, "      \"theta_applied_mrad\": %d,\n", e->theta_applied_mrad);
        fprintf(fp, "      \"unit_id\": %u,\n", e->unit_id);
        fprintf(fp, "      \"coherence_ctr\": %u,\n", e->coherence_ctr);
        fprintf(fp, "      \"lease_remaining\": %u,\n", e->lease_remaining);
        fprintf(fp, "      \"fault_bits\": %u,\n", (unsigned int)e->fault_bits);
        fprintf(fp, "      \"mode\": %u,\n", (unsigned int)e->mode);
        fprintf(fp, "      \"rung_before\": %u,\n", (unsigned int)e->rung_before);
        fprintf(fp, "      \"rung_after\": %u,\n", (unsigned int)e->rung_after);
        fprintf(fp, "      \"kind\": %u,\n", (unsigned int)e->kind);
        fprintf(fp, "      \"verdict\": %u,\n", (unsigned int)e->verdict);
        fprintf(fp, "      \"agent_state\": %u,\n", (unsigned int)e->agent_state);
        fprintf(fp, "      \"confidence_q8\": %u,\n", (unsigned int)e->confidence_q8);
        fprintf(fp, "      \"coherence_valid\": %u,\n", (unsigned int)e->coherence_valid);
        fprintf(fp, "      \"bytes_hex\": \"%s\"\n", ev_hex);
        fprintf(fp, "    }%s\n", (i + 1 < dump.count) ? "," : "");
    }
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    return 0;
}

static int latch_run_pipe_simulation(const char *csv_path, const char *events_json_path) {
    latch_sim_reset();
    latch_proposal_t prop;
    /*
     * The host-sim has no proposal OCB -- the producer is an in-process pipe
     * -- so `writer_held` is truthfully 0 here.  It still models ONE writer
     * session, and the generation counter says so, so a host-sim session
     * status and a target session status mean the same thing.
     */
    bool session_started = false;

    while (1) {
        uint8_t wire_prop[sizeof(latch_ipc_proposal_v2_t)];
        size_t total = 0u;

        /* The wire buffer has to hold the larger of the two proposal wire
         * formats. The protocol header pins both sizes; this ties the buffer
         * to them so a future format cannot silently outgrow it. */
        _Static_assert(sizeof(latch_ipc_proposal_v2_t) >= sizeof(latch_ipc_proposal_t),
                       "wire buffer must hold the largest proposal wire format");

        while (total < sizeof(uint32_t)) {
            const size_t want = sizeof(uint32_t) - total;
            ssize_t n = read(STDIN_FILENO, wire_prop + total, want);
            if (n > 0) {
                /* read() never returns more than `want`, but the clamp makes
                 * that explicit, so `total` can never exceed the bytes that
                 * were requested. */
                const size_t got = ((size_t)n > want) ? want : (size_t)n;
                total += got;
            } else if (n == 0) {
                break;
            } else if (errno != EINTR) {
                fprintf(stderr, "latchd: failed while reading IPC magic\n");
                return EXIT_FAILURE;
            }
        }
        if (total == 0u) break;
        if (total != sizeof(uint32_t)) {
            fprintf(stderr, "latchd: truncated IPC magic on pipe\n");
            return EXIT_FAILURE;
        }
        uint32_t ipc_magic = 0u;
        memcpy(&ipc_magic, wire_prop, sizeof(ipc_magic));
        size_t packet_len = (ipc_magic == LATCH_IPC_PROPOSAL_MAGIC)
                                ? sizeof(latch_ipc_proposal_t)
                                : (ipc_magic == LATCH_IPC_PROPOSAL_V2_MAGIC)
                                      ? sizeof(latch_ipc_proposal_v2_t) : 0u;
        if (packet_len == 0u) {
            fprintf(stderr, "latchd: invalid IPC proposal on pipe\n");
            return EXIT_FAILURE;
        }
        /* Fail-closed admission: a wire format larger than the buffer is
         * rejected outright, never truncated into it. */
        if (packet_len > sizeof(wire_prop)) {
            fprintf(stderr, "latchd: IPC proposal exceeds the wire buffer\n");
            return EXIT_FAILURE;
        }
        /* Read the rest of the packet.
         *
         * `remaining` only ever decreases, so the read length can never wrap
         * around, and `room` is the space left in `wire_prop`. The count is
         * the smaller of the two, so no single read can ever ask for more
         * bytes than the destination has room for -- and the compiler can
         * prove it, which is what keeps -Werror=stringop-overflow honest on
         * every toolchain instead of only the ones whose value ranges it
         * happens to track. */
        size_t remaining = packet_len - total;
        while (remaining > 0u) {
            if (total > sizeof(wire_prop)) {
                fprintf(stderr, "latchd: IPC proposal exceeds the wire buffer\n");
                return EXIT_FAILURE;
            }
            const size_t room = sizeof(wire_prop) - total;
            const size_t want = (remaining < room) ? remaining : room;
            if (want == 0u) {
                fprintf(stderr, "latchd: IPC proposal exceeds the wire buffer\n");
                return EXIT_FAILURE;
            }
            ssize_t n = read(STDIN_FILENO, wire_prop + total, want);
            if (n > 0) {
                /* read() cannot return more than `want`; clamp anyway so that
                 * `total` and `remaining` stay consistent no matter what. */
                size_t got = (size_t)n;
                if (got > want) got = want;
                if (got > remaining) got = remaining;
                total += got;
                remaining -= got;
            } else if (n == 0) {
                break;
            } else if (errno != EINTR) {
                fprintf(stderr, "latchd: failed while reading IPC proposal\n");
                return EXIT_FAILURE;
            }
        }
        if (total != packet_len ||
            latch_ipc_decode_contract(wire_prop, total, g_manifest.protocol.version, &prop) != 0) {
            fprintf(stderr, "latchd: invalid or truncated IPC proposal on pipe\n");
            return EXIT_FAILURE;
        }
        /* At tick LATCH_SIM_EPERM_PROBE_TICK+1 (before tick runs), simulate unauthorized client devctl calling force_hold */
        if (g_simplex.tick == LATCH_SIM_EPERM_PROBE_TICK) {
            latch_force_hold_cmd_t fcmd = { .lock_hold = 0u, .reason_code = 99u };
            (void)latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_FORCE_HOLD, &fcmd);
        }
        if (!session_started) {
            session_started = true;
            atomic_fetch_add_explicit(&g_simplex.session_generation, 1u,
                                      memory_order_acq_rel);
        }
        latch_publish_proposal(&g_pub_buf, &prop);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }

    if (csv_path != NULL) {
        if (latch_export_tape_csv(csv_path) != 0) {
            return EXIT_FAILURE;
        }
    }
    if (events_json_path != NULL) {
        if (latch_export_events_json(events_json_path) != 0) {
            return EXIT_FAILURE;
        }
    }

    latch_status_reply_t st;
    memset(&st, 0, sizeof(st));
    latch_fill_status(&st);
    printf("[LATCH_PIPE_SIM] Completed %" PRIu64 " ticks | rx=%u | wire_faults=%u | "
           "env_faults=%u | eperm_rejects=%u | max_latency=%" PRIu64 " ns\n",
           st.tick,
           st.total_proposals_rx,
           st.total_wire_faults,
           st.total_envelope_faults,
           st.total_eperm_rejects,
           st.max_latency_cycles);

    /*
     * THE DECISION-LATENCY DISTRIBUTION (U-4), in the host-sim too.
     *
     * The host-sim's numbers are HOST-LOAD dependent, so they are NOT the
     * project's latency claim -- the on-target TCG measurement is.  But the
     * histogram is the same code in both builds, and printing it here means
     * the aggregation path is exercised on every CI run instead of only on
     * the target.
     */
    {
        latch_latency_stats_t lat;
        memset(&lat, 0, sizeof(lat));
        if (latch_fill_latency_stats(&lat)) {
            printf("[LATCH_LATENCY] samples=%" PRIu64 " decision=%" PRIu64 " idle=%" PRIu64
                   " motion=%" PRIu64
                   " | min=%" PRIu64 " cyc | max=%" PRIu64 " cyc"
                   " | over_budget=%" PRIu64 " over_period=%" PRIu64
                   " | hist_decision_nonzero=%u hist_idle_nonzero=%u\n",
                   lat.samples_total, lat.samples_decision, lat.samples_idle,
                   lat.samples_motion,
                   lat.min_cycles, lat.max_cycles,
                   lat.over_budget, lat.over_period,
                   latch_latency_nonzero_buckets(lat.hist_decision, LATCH_LATENCY_BUCKETS),
                   latch_latency_nonzero_buckets(lat.hist_idle, LATCH_LATENCY_BUCKETS));
        } else {
            fprintf(stderr, "latchd: FATAL: the latency snapshot never settled\n");
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}

/* The in-process host-sim producer identity (L-2). */
#define LATCH_TEST_PRODUCER_TAG 1u
#define LATCH_TEST_FOREIGN_TAG 2u
/* Session epochs (RT-02): one per producer, exactly as a real bridge
 * instance has -- each bridge opens its own session with its own epoch. */
#define LATCH_TEST_PRODUCER_EPOCH 0xA11CE001u
#define LATCH_TEST_FOREIGN_EPOCH 0xA11CE002u

static void latch_governor_test_frame_epoch(uint8_t kind, uint32_t seq, uint32_t coherence,
                                             int32_t u_mrad, uint8_t confidence_q8,
                                             uint16_t producer_tag, uint32_t session_epoch) {
    latch_proposal_t proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.ipc_magic = LATCH_IPC_PROPOSAL_MAGIC;
    proposal.seq = seq;
    proposal.u_mrad = u_mrad;
    proposal.wire_flags = kind;
    proposal.ingest_cycles = latch_clock_cycles();
    proposal.wire_version = 2u;
    proposal.kind = kind;
    proposal.confidence_q8 = confidence_q8;
    /* L-2: the producer identity decides who holds the lease. */
    proposal.producer_tag = producer_tag;
    /* RT-02: the session epoch decides which session the frame belongs to. */
    proposal.session_epoch = session_epoch;
    proposal.unit_id = kind == GOVERNOR_WIRE_CMD_V2
                           ? ((u_mrad == 370000) ? 999u : (u_mrad == 37000) ? 3u : 1u)
                           : 0u;
    proposal.agent_state = 1u;
    proposal.coherence_ctr = coherence;
    if (kind == GOVERNOR_WIRE_SHRINK_REQ) {
        proposal.shrink_v = (uint32_t)u_mrad;
        proposal.shrink_scale_q8 = confidence_q8;
    }
    latch_publish_proposal(&g_pub_buf, &proposal);
    latch_simplex_tick(&g_simplex, &g_pub_buf);
}

static void latch_governor_test_frame_tagged(uint8_t kind, uint32_t seq, uint32_t coherence,
                                              int32_t u_mrad, uint8_t confidence_q8,
                                              uint16_t producer_tag) {
    latch_governor_test_frame_epoch(kind, seq, coherence, u_mrad, confidence_q8,
                                    producer_tag,
                                    (producer_tag == LATCH_TEST_FOREIGN_TAG)
                                        ? LATCH_TEST_FOREIGN_EPOCH
                                        : LATCH_TEST_PRODUCER_EPOCH);
}

static void latch_governor_test_frame(uint8_t kind, uint32_t seq, uint32_t coherence,
                                      int32_t u_mrad, uint8_t confidence_q8) {
    latch_governor_test_frame_tagged(kind, seq, coherence, u_mrad, confidence_q8,
                                     LATCH_TEST_PRODUCER_TAG);
}

static int latch_run_governor_integration_test(void) {
    latch_manifest_t saved_manifest = g_manifest;
    const char *gov_manifest_path = "contracts/governor_servo.manifest";
    if (access(gov_manifest_path, F_OK) != 0 && access("qnx/contracts/governor_servo.manifest", F_OK) == 0) {
        gov_manifest_path = "qnx/contracts/governor_servo.manifest";
    }
    char err_buf[256];
    if (latch_manifest_load(gov_manifest_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "FAIL: could not load signed governor test manifest '%s': %s\n",
                gov_manifest_path, err_buf);
        goto fail;
    }
    latch_sim_reset();

    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 1u, 0x00FFFFFEu, 0, 0u);
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 2u, 1u, 0, 0u);
    if ((g_simplex.active_faults & LATCH_FAULT_HEARTBEAT) != 0u ||
        g_simplex.gov_last_coherence != 1u || g_simplex.gov_warmup_seen != 2u) {
        fprintf(stderr, "FAIL: 24-bit coherence counter did not wrap within the configured gap\n");
        goto fail;
    }

    /* A queued producer and consumer must continue across counter wrap. */
    {
        _Atomic uint32_t writers = 0u;
        if (!latch_claim_writer(&writers) || latch_claim_writer(&writers)) {
            fprintf(stderr, "FAIL: exclusive proposal writer claim\n");
            goto fail;
        }
        atomic_store_explicit(&writers, 0u, memory_order_release);
        if (!latch_claim_writer(&writers)) {
            fprintf(stderr, "FAIL: proposal writer claim after close\n");
            goto fail;
        }
        latch_publish_buffer_t wrap_buf;
        memset(&wrap_buf, 0, sizeof(wrap_buf));
        atomic_store_explicit(&wrap_buf.write_head, UINT32_MAX, memory_order_relaxed);
        atomic_store_explicit(&wrap_buf.read_tail, UINT32_MAX, memory_order_relaxed);
        latch_proposal_t in = { .seq = 42u };
        latch_publish_proposal(&wrap_buf, &in);
        uint32_t consumed_gen = 0u;
        latch_proposal_t out;
        if (!latch_consume_proposal(&wrap_buf, &consumed_gen, &out) || out.seq != 42u ||
            atomic_load_explicit(&wrap_buf.read_tail, memory_order_relaxed) != 0u) {
            fprintf(stderr, "FAIL: queued ring did not consume across counter wrap\n");
            goto fail;
        }
        latch_publish_proposal(&wrap_buf, &in);
        if (latch_ring_flush_session(&wrap_buf) != 1u ||
            latch_consume_proposal(&wrap_buf, &consumed_gen, &out)) {
            fprintf(stderr, "FAIL: wrapped queued ring session flush\n");
            goto fail;
        }
    }

    latch_sim_reset();

    /* Tape cursors remain usable past the old 32-bit wrap, and the
     * reserved latest-page sentinel must never be reached by wrapping. */
    {
        latch_tape_dump_t dump;
        atomic_store_explicit(&g_tape_write_idx, (uint64_t)UINT32_MAX, memory_order_relaxed);
        latch_record_tape(100u, 1u, 2u, 1u, 0, 0, 0u, 0u);
        latch_record_tape(101u, 1u, 2u, 2u, 0, 0, 0u, 0u);
        memset(&dump, 0, sizeof(dump));
        dump.start_index = UINT64_MAX;
        dump.count = 2u;
        if (!latch_fill_tape_dump(&dump) || dump.start_index != (uint64_t)UINT32_MAX ||
            dump.count != 2u || dump.entries[0].tick != 100u || dump.entries[1].tick != 101u) {
            fprintf(stderr, "FAIL: tape pagination across 32-bit cursor boundary\n");
            goto fail;
        }
        atomic_store_explicit(&g_tape_write_idx, UINT64_MAX, memory_order_relaxed);
        latch_record_tape(102u, 1u, 2u, 3u, 0, 0, 0u, 0u);
        if (atomic_load_explicit(&g_tape_write_idx, memory_order_relaxed) != UINT64_MAX) {
            fprintf(stderr, "FAIL: tape cursor wrapped past UINT64_MAX\n");
            goto fail;
        }
    }

    latch_sim_reset();

    latch_governor_test_frame(GOVERNOR_WIRE_SHRINK_REQ, 1u, 1u, 12, 128u);
    if (g_simplex.gov_v2_session || g_simplex.gov_lease_remaining != 0u ||
        g_simplex.gov_gate.shrink_active != 0u) {
        fprintf(stderr, "FAIL: SHRINK_REQ created a v2 session or lease before a heartbeat/command\n");
        goto fail;
    }

    latch_sim_reset();

    uint32_t seq = 1u;
    uint32_t coh = 1u;
    const uint32_t lease = g_manifest.governor.lease_ticks;
    const uint32_t warmup = g_manifest.governor.warmup_heartbeats;
    const uint32_t promote = g_manifest.governor.promote_clean_frames;
    const uint32_t demote = g_manifest.governor.demote_faults_per_rung;

    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    if (!g_simplex.gov_v2_session || g_simplex.gov_lease_remaining != lease ||
        g_simplex.gov_warmup_seen != 1u || g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: GOVERNOR heartbeat did not open a lease-only warm-up session\n");
        goto fail;
    }
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    if ((g_simplex.active_faults & LATCH_FAULT_HEARTBEAT) == 0u ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_ADVISE ||
        g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: frozen coherence was not dropped and degraded one rung\n");
        goto fail;
    }
    for (uint32_t w = 1u; w < warmup; ++w) {
        coh++;
        latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    }
    if (g_simplex.gov_warmup_seen != warmup || g_simplex.gov_lease_remaining != lease) {
        fprintf(stderr, "FAIL: advancing heartbeat did not restore lease and complete warm-up\n");
        goto fail;
    }
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_ADVISE ||
        g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: heartbeat-only traffic promoted the ladder or moved the plant\n");
        goto fail;
    }
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, seq++, coh, 25, 255u);
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_ADVISE ||
        g_simplex.gov_ladder.clean_frame_streak != 1u) {
        fprintf(stderr, "FAIL: one clean command bypassed the configured recovery streak\n");
        goto fail;
    }
    for (uint32_t p = 1u; p < promote; ++p) {
        coh++;
        latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, seq++, coh, 25, 255u);
    }
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_HP ||
        g_simplex.mode != LATCH_MODE_HP || g_simplex.theta_mrad <= g_manifest.envelope.home_mrad ||
        g_simplex.theta_mrad > g_manifest.envelope.v_max) {
        fprintf(stderr, "FAIL: clean command streak did not recover and admit a confidence-limited command\n");
        goto fail;
    }

    int32_t before_unit = g_simplex.theta_mrad;
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, seq++, coh, 370000, 255u);
    if ((g_simplex.active_faults & LATCH_FAULT_UNIT) == 0u ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_ADVISE ||
        g_simplex.theta_mrad != before_unit || g_simplex.mode != LATCH_MODE_HP) {
        fprintf(stderr, "FAIL: unit anomaly changed plant state or entered legacy HOLD\n");
        goto fail;
    }
    for (uint32_t d = 0u; d < demote; ++d) {
        coh++;
        latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, seq++, coh, 370000, 255u);
    }
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_CLAMP || g_simplex.theta_mrad != before_unit) {
        fprintf(stderr, "FAIL: repeated advisory unit anomalies did not reach CLAMP safely\n");
        goto fail;
    }

    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_SHRINK_REQ, seq++, coh, 12, 128u);
    if (g_simplex.gov_gate.shrink_v != 12u || g_simplex.gov_gate.shrink_scale_q8 != 128u ||
        g_simplex.gov_lease_remaining != lease - 1u) {
        fprintf(stderr, "FAIL: SHRINK_REQ did not narrow limits without renewing the lease\n");
        goto fail;
    }
    uint64_t last_lease_tick = g_simplex.gov_last_lease_tick;
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_SHRINK_REQ, seq++, coh, 13, 150u);
    if ((g_simplex.active_faults & LATCH_FAULT_WIDEN) == 0u ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_SLOW ||
        g_simplex.gov_lease_remaining != lease - 2u ||
        g_simplex.gov_last_lease_tick != last_lease_tick) {
        fprintf(stderr, "FAIL: wider SHRINK_REQ was not rejected with one-rung demotion\n");
        goto fail;
    }

    latch_governor_status_reply_t lease_status;
    if (latch_fill_governor_status(&lease_status) != true ||
        lease_status.lease_age_ticks != (uint32_t)(g_simplex.tick - last_lease_tick)) {
        fprintf(stderr, "FAIL: status age tracked SHRINK_REQ activity instead of lease renewal\n");
        goto fail;
    }

    g_simplex.gov_lease_remaining = 1u;
    latch_simplex_tick(&g_simplex, &g_pub_buf);
    if ((g_simplex.active_faults & LATCH_FAULT_HEARTBEAT) == 0u ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_SAFE_STOP) {
        fprintf(stderr, "FAIL: host-tick lease expiry did not demote exactly one rung\n");
        goto fail;
    }

    /* A hard envelope fault must still enter the legacy HOLD path and LATCH rung. */
    g_simplex.gov_ladder.rung = GOVERNOR_RUNG_HP;
    g_simplex.gov_gate.shrink_active = 0u;
    g_simplex.gov_gate.rate_tokens = g_manifest.governor.rate_burst_tokens;
    g_simplex.theta_mrad = 240;
    g_simplex.velocity_mrad_tick = 0;
    g_simplex.accel_mrad_tick2 = 0;
    latch_governor_test_frame(GOVERNOR_WIRE_CMD, seq++, 0u, 260, 0u);
    if ((g_simplex.active_faults & LATCH_FAULT_KEEPOUT) == 0u ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_LATCH ||
        g_simplex.mode != LATCH_MODE_HOLD || g_simplex.theta_mrad != 240) {
        fprintf(stderr, "FAIL: hard envelope fault did not retain LATCH/HOLD authority\n");
        goto fail;
    }
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_LATCH) {
        fprintf(stderr, "FAIL: LATCH recovered without an operator release\n");
        goto fail;
    }
    g_simplex.session_active = false;
    latch_simplex_tick(&g_simplex, &g_pub_buf);
    if (g_simplex.mode != LATCH_MODE_HOLD || g_simplex.theta_mrad != 240 ||
        g_simplex.gov_ladder.rung != GOVERNOR_RUNG_LATCH) {
        fprintf(stderr, "FAIL: idle Governor LATCH changed mode or position\n");
        goto fail;
    }
    g_simplex.session_active = true;
    latch_force_hold_cmd_t release = { .lock_hold = 0u, .reason_code = 7u };
    if (latch_sim_devctl_actuator(true, (unsigned int)DCMD_LATCH_FORCE_HOLD, &release) != 0) {
        fprintf(stderr, "FAIL: authorized operator release command failed\n");
        goto fail;
    }
    coh++;
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, seq++, coh, 0, 0u);
    for (uint32_t p = 0u; p < promote; ++p) {
        coh++;
        latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, seq++, coh, 240, 255u);
    }
    if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_SAFE_STOP) {
        fprintf(stderr, "FAIL: operator release plus clean command streak did not enter SAFE_STOP\n");
        goto fail;
    }
    latch_governor_status_reply_t status;
    if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_GOV_STATUS,
                                  &status) != 0 || status.extension_version != 6u ||
        status.enabled != 1u || status.rung != GOVERNOR_RUNG_SAFE_STOP ||
        status.v2_session != 1u || status.coherence_ctr != coh) {
        fprintf(stderr, "FAIL: versioned GOVERNOR status did not expose a coherent policy snapshot\n");
        goto fail;
    }
    /* L-2: the lease owner is the producer that established the session. */
    if (status.lease_owner_valid != 1u || status.lease_owner_tag != LATCH_TEST_PRODUCER_TAG ||
        status.foreign_frames != 0u || status.producer_takeovers != 0u) {
        fprintf(stderr, "FAIL: the GOVERNOR status did not report the producer-scoped lease owner\n");
        goto fail;
    }
    /* RT-02: the session's identity is observable, and it is the epoch the
     * producer stamped on the frames that opened the session. */
    if (status.session_epoch_valid != 1u ||
        status.session_epoch != LATCH_TEST_PRODUCER_EPOCH) {
        fprintf(stderr, "FAIL: the GOVERNOR status did not report the bound session epoch\n");
        goto fail;
    }
    /* HOMEOSTAT is DEFAULT-OFF: with no `homeostat` section in the manifest
     * it must report itself as disabled and impose no velocity ceiling. */
    if (status.homeostat_enabled != 0u || status.homeostat_v_max != 0u) {
        fprintf(stderr, "FAIL: HOMEOSTAT was active without a manifest section\n");
        goto fail;
    }

    latch_gov_event_dump_t edump;
    memset(&edump, 0, sizeof(edump));
    edump.start_index = UINT64_MAX;
    edump.count = 64;
    if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_DUMP_GOV_EVENTS, &edump) != 0 ||
        edump.count == 0u || edump.latest_index == 0u || edump.record_version != 1u) {
        fprintf(stderr, "FAIL: DCMD_LATCH_DUMP_GOV_EVENTS did not expose a coherent event dump\n");
        goto fail;
    }

    /*
     * Test (L-2): the dead-man lease is scoped to the PRODUCER.
     *
     * The defect this pins: the lease was renewed by ANY frame that arrived
     * on the proposal node. A second unprivileged writer could therefore keep
     * a session alive whose real planner had died -- which is precisely what
     * a dead-man's switch exists to prevent.
     *
     * The properties asserted here:
     *   1. A foreign producer's frame does NOT renew the lease.
     *   2. A foreign producer's frame does NOT move the plant.
     *   3. A foreign producer's frame does NOT advance the owner's coherence
     *      baseline, so it cannot fake liveness.
     *   4. A foreign producer's frame does NOT reset the recovery ladder's
     *      clean-frame streak.
     *   5. When the owner goes silent, the lease EXPIRES even though the
     *      foreign producer keeps talking: the dead-man's switch fires.
     *   6. After that expiry the foreign producer MAY take the session over
     *      -- with a NEW sequence epoch and its own warm-up.
     */
    {
        latch_sim_reset();

        /* The owner (producer 1) opens the session and completes its
         * warm-up. */
        uint32_t l2_seq = 1u;
        for (uint32_t w = 0u; w < warmup; ++w) {
            latch_governor_test_frame_tagged(GOVERNOR_WIRE_HEARTBEAT, l2_seq, l2_seq, 0, 0u,
                                             LATCH_TEST_PRODUCER_TAG);
            l2_seq++;
        }
        if (!g_simplex.gov_v2_session || g_simplex.gov_warmup_seen != warmup ||
            g_simplex.gov_lease_owner_tag != LATCH_TEST_PRODUCER_TAG ||
            !g_simplex.gov_lease_owner_valid) {
            fprintf(stderr, "FAIL: the owner producer did not establish the lease\n");
            goto fail;
        }

        /* One accepted owner command: it earns a clean-frame credit, so the
         * recovery-streak assertion below is not vacuous. */
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, l2_seq, l2_seq, 25, 255u,
                                         LATCH_TEST_PRODUCER_TAG);
        l2_seq++;
        if (g_simplex.gov_ladder.clean_frame_streak != 1u) {
            fprintf(stderr, "FAIL: the owner command did not earn a clean-frame credit\n");
            goto fail;
        }

        const uint32_t lease_before = g_simplex.gov_lease_remaining;
        const uint32_t coherence_before = g_simplex.gov_last_coherence;
        const int32_t theta_before = g_simplex.theta_mrad;
        const uint32_t streak_before = g_simplex.gov_ladder.clean_frame_streak;

        /* A SECOND producer (tag 2) sends a well-formed, coherent-looking
         * command that WOULD move the plant. It must be completely inert. */
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, 100u, 100u, -25, 255u,
                                         LATCH_TEST_FOREIGN_TAG);
        if (g_simplex.gov_lease_remaining >= lease_before) {
            fprintf(stderr, "FAIL: a foreign producer renewed the dead-man lease\n");
            goto fail;
        }
        if (g_simplex.theta_mrad != theta_before) {
            fprintf(stderr, "FAIL: a foreign producer moved the plant\n");
            goto fail;
        }
        if (g_simplex.gov_last_coherence != coherence_before) {
            fprintf(stderr, "FAIL: a foreign producer advanced the coherence baseline\n");
            goto fail;
        }
        if (g_simplex.gov_ladder.clean_frame_streak != streak_before) {
            fprintf(stderr, "FAIL: a foreign producer disturbed the recovery streak\n");
            goto fail;
        }
        if (g_simplex.gov_foreign_frames != 1u) {
            fprintf(stderr, "FAIL: a foreign producer's frame was not counted as lease-inert\n");
            goto fail;
        }

        /* The owner's sequence epoch must be intact: the next owner frame
         * is accepted, not mistaken for a replay. */
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, l2_seq, l2_seq, 25, 255u,
                                         LATCH_TEST_PRODUCER_TAG);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) != 0u) {
            fprintf(stderr, "FAIL: a foreign producer disturbed the owner's sequence epoch\n");
            goto fail;
        }

        /* The owner dies. The foreign producer keeps talking -- and the
         * dead-man's switch must still fire. */
        bool lease_expired = false;
        for (uint32_t i = 0u; i < g_manifest.governor.lease_ticks + 1u; ++i) {
            latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, 101u + i, 101u + i,
                                             -25, 255u, LATCH_TEST_FOREIGN_TAG);
            if ((g_simplex.active_faults & LATCH_FAULT_HEARTBEAT) != 0u) {
                lease_expired = true;
                break;
            }
        }
        if (!lease_expired) {
            fprintf(stderr, "FAIL: the dead-man lease did not expire while a foreign producer kept talking\n");
            goto fail;
        }
        if (g_simplex.gov_ladder.rung == GOVERNOR_RUNG_HP) {
            fprintf(stderr, "FAIL: the dead-man lease expiry did not demote the ladder\n");
            goto fail;
        }
        if (!g_simplex.gov_session_dead) {
            fprintf(stderr, "FAIL: the expired session was not declared dead\n");
            goto fail;
        }

        /* The foreign producer may now take the session over -- and the
         * takeover starts a NEW sequence epoch with its own warm-up. */
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_HEARTBEAT, 200u, 200u, 0, 0u,
                                         LATCH_TEST_FOREIGN_TAG);
        if (g_simplex.gov_producer_takeovers != 1u ||
            g_simplex.gov_lease_owner_tag != LATCH_TEST_FOREIGN_TAG ||
            !g_simplex.gov_v2_session || g_simplex.gov_warmup_seen != 1u) {
            fprintf(stderr, "FAIL: the expired session was not taken over with a fresh epoch\n");
            goto fail;
        }
    }

    /*
     * Test: the SESSION EPOPH (RT-02).
     *
     * The defect this pins: the supervisor's sequence baseline is re-based
     * when a session opens, and the FIRST frame of a session was accepted
     * with ANY non-zero sequence number.  A frame captured in an earlier
     * session -- say one carrying `seq = 999999` -- was therefore accepted
     * as the first frame of the new session, became the new baseline, and
     * could move the plant.
     *
     * The properties asserted here:
     *   1. The first frame of a new session must carry `seq == 1`.
     *   2. A frame naming the WRONG epoch is rejected outright and cannot
     *      move the plant.
     *   3. An epoch that has already been SPENT cannot be bound again, so a
     *      restarted producer cannot resume the previous session's identity.
     *   4. An unscoped frame (epoch 0) is rejected.
     */
    {
        const uint32_t epoch_a = 0x5E5510A1u;
        const uint32_t epoch_b = 0x5E5510B2u;
        const uint32_t epoch_spent = 0x5E5510C3u;

        latch_sim_reset();

        /* --- 1. The first frame of a session must carry seq == 1 --------- */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 999999u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_a);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) == 0u) {
            fprintf(stderr, "FAIL: a first frame with seq != 1 was accepted (RT-02)\n");
            goto fail;
        }
        if (g_simplex.gov_session_epoch_valid) {
            fprintf(stderr, "FAIL: a rejected first frame still bound the session epoch (RT-02)\n");
            goto fail;
        }
        if (g_simplex.gov_v2_session) {
            fprintf(stderr, "FAIL: a rejected first frame still opened a session (RT-02)\n");
            goto fail;
        }

        /* --- 2. The genuine opening frame (seq == 1) binds the epoch ----- */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_a);
        if (!g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_a ||
            !g_simplex.gov_v2_session) {
            fprintf(stderr, "FAIL: the genuine opening frame did not bind the epoch (RT-02)\n");
            goto fail;
        }

        /* --- 3. A frame from ANOTHER epoch is rejected and moves nothing -- */
        const int32_t theta_bound = g_simplex.theta_mrad;
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_CMD_V2, 2u, 2u, 25, 255u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_b);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) == 0u) {
            fprintf(stderr, "FAIL: a cross-epoch frame was not rejected (RT-02)\n");
            goto fail;
        }
        if (g_simplex.theta_mrad != theta_bound) {
            fprintf(stderr, "FAIL: a cross-epoch frame moved the plant (RT-02)\n");
            goto fail;
        }
        if (g_simplex.gov_session_epoch != epoch_a) {
            fprintf(stderr, "FAIL: a rejected cross-epoch frame changed the bound epoch (RT-02)\n");
            goto fail;
        }

        /* --- 4. An unscoped frame (epoch 0) is rejected ------------------- */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_CMD_V2, 3u, 3u, 25, 255u,
                                         LATCH_TEST_PRODUCER_TAG, LATCH_SESSION_EPOCH_NONE);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) == 0u) {
            fprintf(stderr, "FAIL: an unscoped frame was not rejected (RT-02)\n");
            goto fail;
        }
        if (g_simplex.theta_mrad != theta_bound) {
            fprintf(stderr, "FAIL: an unscoped frame moved the plant (RT-02)\n");
            goto fail;
        }

        /* --- 5. A SPENT epoch cannot be bound again ---------------------- */
        /* Open a session on `epoch_spent`, then reset the session the way a
         * writer reconnect does, and try to re-open it on the SAME epoch. */
        latch_sim_reset();
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_spent);
        if (!g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_spent) {
            fprintf(stderr, "FAIL: the first session did not bind its epoch (RT-02)\n");
            goto fail;
        }
        /* A genuine reconnect: the writer opens the node again, so the
         * supervisor re-bases the sequence and clears the lease owner. */
        atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_spent);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) == 0u) {
            fprintf(stderr, "FAIL: a REUSED epoch was accepted after a reconnect (RT-02)\n");
            goto fail;
        }
        if (g_simplex.gov_session_epoch_valid &&
            g_simplex.gov_session_epoch == epoch_spent) {
            fprintf(stderr, "FAIL: a reused epoch rebound the session (RT-02)\n");
            goto fail;
        }

        /* --- 6. A FRESH epoch opens the reconnected session -------------- */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_b);
        if (!g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_b ||
            !g_simplex.gov_v2_session) {
            fprintf(stderr, "FAIL: a fresh epoch did not open the reconnected session (RT-02)\n");
            goto fail;
        }
    }

    /*
     * Regression tests (W2 items 1, 2, 4, 5):
     *   1. Bare GOVERNOR_WIRE_CMD (kind=0) with seq=1 must NOT bind session_epoch
     *      without also binding gov_lease_owner_valid.
     *   2. Spent-epoch, seq==0, and corrupted foreign takeover frames must
     *      preserve prior gov_lease_owner_tag, gov_v2_session, and gov_session_epoch.
     *   3. SAFE_STOP must not stall HOME retraction on reconnect_retracting, and
     *      hold_ticks_elapsed must not double-increment on tick 1.
     *   4. Medical LATCH_FAULT_DOSE pre-clamp bypass is closed.
     *   5. 1-slot seqlock actuator I/O + io_fault_pending -> LATCH_FAULT_I2C + HOLD,
     *      and 64-bit PWM scaling does not overflow on large spans.
     */
    {
        const uint32_t epoch_cmd   = 0x5E552001u;
        const uint32_t epoch_owner = 0x5E552002u;
        const uint32_t epoch_take  = 0x5E552003u;

        latch_sim_reset();

        /* 1. Bare CMD with seq=1 must NOT bind gov_session_epoch or lease owner */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_CMD, 1u, 0u, 10, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_cmd);
        if (g_simplex.gov_session_epoch_valid || g_simplex.gov_lease_owner_valid ||
            g_simplex.seq_valid || g_simplex.gov_v2_session ||
            latch_epoch_already_used(&g_simplex, epoch_cmd)) {
            fprintf(stderr, "FAIL: bare CMD bound session_epoch or poisoned sequence state (RT-02)\n");
            goto fail;
        }

        /* 2. Owner opens session with epoch_owner, then expires (session_dead) */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u,
                                         LATCH_TEST_PRODUCER_TAG, epoch_owner);
        if (!g_simplex.gov_lease_owner_valid || !g_simplex.gov_v2_session ||
            !g_simplex.gov_session_epoch_valid || g_simplex.gov_session_epoch != epoch_owner) {
            fprintf(stderr, "FAIL: owner failed to establish session before takeover test\n");
            goto fail;
        }
        g_simplex.gov_session_dead = true;

        /* 2a. Spent-epoch takeover attempt preserves prior owner/session/epoch */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 50u, 1u, 0, 0u,
                                         LATCH_TEST_FOREIGN_TAG, epoch_owner);
        if (g_simplex.gov_lease_owner_tag != LATCH_TEST_PRODUCER_TAG ||
            !g_simplex.gov_v2_session || !g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_owner || g_simplex.gov_producer_takeovers != 0u) {
            fprintf(stderr, "FAIL: spent-epoch takeover mutated prior owner/session/epoch\n");
            goto fail;
        }

        /* 2b. seq==0 takeover attempt preserves prior owner/session/epoch */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 0u, 1u, 0, 0u,
                                         LATCH_TEST_FOREIGN_TAG, epoch_take);
        if (g_simplex.gov_lease_owner_tag != LATCH_TEST_PRODUCER_TAG ||
            !g_simplex.gov_v2_session || !g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_owner || g_simplex.gov_producer_takeovers != 0u) {
            fprintf(stderr, "FAIL: seq==0 takeover mutated prior owner/session/epoch\n");
            goto fail;
        }

        /* 2c. Corrupted (pre_fault_bits != 0) takeover attempt preserves prior state */
        {
            latch_proposal_t bad_takeover;
            memset(&bad_takeover, 0, sizeof(bad_takeover));
            bad_takeover.ipc_magic = LATCH_IPC_PROPOSAL_MAGIC;
            bad_takeover.seq = 50u;
            bad_takeover.u_mrad = 0;
            bad_takeover.wire_flags = GOVERNOR_WIRE_HEARTBEAT;
            bad_takeover.pre_fault_bits = LATCH_FAULT_CRC;
            bad_takeover.ingest_cycles = latch_clock_cycles();
            bad_takeover.wire_version = 2u;
            bad_takeover.kind = GOVERNOR_WIRE_HEARTBEAT;
            bad_takeover.producer_tag = LATCH_TEST_FOREIGN_TAG;
            bad_takeover.session_epoch = epoch_take;
            bad_takeover.agent_state = 1u;
            bad_takeover.coherence_ctr = 1u;
            latch_publish_proposal(&g_pub_buf, &bad_takeover);
            latch_simplex_tick(&g_simplex, &g_pub_buf);
            if (g_simplex.gov_lease_owner_tag != LATCH_TEST_PRODUCER_TAG ||
                !g_simplex.gov_v2_session || !g_simplex.gov_session_epoch_valid ||
                g_simplex.gov_session_epoch != epoch_owner || g_simplex.gov_producer_takeovers != 0u) {
                fprintf(stderr, "FAIL: corrupted foreign takeover mutated prior owner/session/epoch\n");
                goto fail;
            }
        }

        /* 2d. Valid foreign takeover now succeeds with fresh epoch_take */
        latch_governor_test_frame_epoch(GOVERNOR_WIRE_HEARTBEAT, 50u, 1u, 0, 0u,
                                         LATCH_TEST_FOREIGN_TAG, epoch_take);
        if (g_simplex.gov_lease_owner_tag != LATCH_TEST_FOREIGN_TAG ||
            !g_simplex.gov_v2_session || !g_simplex.gov_session_epoch_valid ||
            g_simplex.gov_session_epoch != epoch_take || g_simplex.gov_producer_takeovers != 1u) {
            fprintf(stderr, "FAIL: valid foreign takeover did not succeed after rejected attempts\n");
            goto fail;
        }

        /* 3. SAFE_STOP vs reconnect_retracting & single hold_ticks_elapsed increment */
        latch_sim_reset();
        g_simplex.theta_mrad = 50;
        g_simplex.gov_ladder.rung = GOVERNOR_RUNG_SAFE_STOP;
        atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
        latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u);
        if (!g_simplex.reconnect_retracting || g_simplex.mode != LATCH_MODE_HOLD ||
            g_simplex.hold_ticks_elapsed != 1u) {
            fprintf(stderr, "FAIL: reconnect tick 1 hold_ticks_elapsed=%u (expected 1)\n",
                    g_simplex.hold_ticks_elapsed);
            goto fail;
        }
        uint32_t retract_budget = g_manifest.recovery.hold_to_home_ticks + 20u;
        for (uint32_t t = 0u; t < retract_budget; ++t) {
            latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 2u + t, 2u + t, 0, 0u);
        }
        if (g_simplex.theta_mrad != g_manifest.envelope.home_mrad || g_simplex.reconnect_retracting) {
            fprintf(stderr, "FAIL: SAFE_STOP stalled HOME retraction on reconnect (theta=%d)\n",
                    g_simplex.theta_mrad);
            goto fail;
        }

        /* 4. Medical LATCH_FAULT_DOSE pre-clamp bypass check */
        const char *syr_path = "contracts/syringe_governor.manifest";
        if (access(syr_path, F_OK) != 0 && access("qnx/contracts/syringe_governor.manifest", F_OK) == 0) {
            syr_path = "qnx/contracts/syringe_governor.manifest";
        }
        latch_manifest_t gov_saved = g_manifest;
        if (latch_manifest_load(syr_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
            fprintf(stderr, "FAIL: could not load syringe_governor.manifest: %s\n", err_buf);
            g_manifest = gov_saved;
            goto fail;
        }
        latch_sim_reset();
        uint32_t mseq = 1u;
        for (uint32_t w = 0u; w < g_manifest.governor.warmup_heartbeats; ++w) {
            latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, mseq, mseq, 0, 0u);
            mseq++;
        }
        /* Send over-bolus command u=150 (> max_bolus_uL=100, <= v_max=200) in HP;
         * kinematic accel clamp (a_max=50) clamps u_candidate to 49, so only checking
         * pre-clamp normalized_target catches the DOSE violation. */
        latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, mseq, mseq, 150, 255u);
        if ((g_simplex.active_faults & LATCH_FAULT_DOSE) == 0u ||
            g_simplex.mode != LATCH_MODE_HOLD ||
            g_simplex.gov_ladder.rung != GOVERNOR_RUNG_LATCH ||
            g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
            fprintf(stderr, "FAIL: medical over-bolus bypassed LATCH_FAULT_DOSE via kinematic clamp\n");
            g_manifest = gov_saved;
            goto fail;
        }
        g_manifest = gov_saved;
        latch_sim_reset();

        /* 5. 1-slot seqlock actuator target + io_fault_pending + 64-bit PWM math */
        uint64_t act_seq = 0u;
        int32_t act_theta = 0;
        latch_actuator_publish_target(&g_simplex, 123);
        if (!latch_actuator_read_target(&g_simplex.actuator_io, &act_seq, &act_theta) ||
            act_theta != 123 || act_seq == 0u ||
            latch_pca9685_write_angle(g_simplex.i2c_fd, act_theta) != 0) {
            fprintf(stderr, "FAIL: 1-slot actuator seqlock round-trip\n");
            goto fail;
        }
        atomic_store_explicit(&g_simplex.actuator_io.io_fault_pending, 1u, memory_order_release);
        latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u);
        if ((g_simplex.active_faults & LATCH_FAULT_I2C) == 0u ||
            g_simplex.mode != LATCH_MODE_HOLD) {
            fprintf(stderr, "FAIL: io_fault_pending did not assert LATCH_FAULT_I2C and HOLD\n");
            goto fail;
        }
        latch_manifest_t pwm_saved = g_manifest;
        g_manifest.envelope.theta_max_mrad = 100000000;
        g_manifest.axes[0].max = 100000000;
        uint16_t pwm_hi = latch_mrad_to_pca9685_off(100000000);
        g_manifest = pwm_saved;
        if (pwm_hi != (uint16_t)g_manifest.actuator.pwm_max) {
            fprintf(stderr, "FAIL: 64-bit PWM scaling produced %u (expected %d)\n",
                    (unsigned int)pwm_hi, g_manifest.actuator.pwm_max);
            goto fail;
        }

        /* 6. Live-lease corrupt foreign frame (LATCH_FAULT_CRC / LATCH_NAN_MRAD)
         * must remain lease-inert and not fault or demote the active owner. */
        latch_sim_reset();
        uint32_t lc_seq = 1u;
        for (uint32_t w = 0u; w < warmup; ++w) {
            latch_governor_test_frame_tagged(GOVERNOR_WIRE_HEARTBEAT, lc_seq, lc_seq, 0, 0u,
                                             LATCH_TEST_PRODUCER_TAG);
            lc_seq++;
        }
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, lc_seq, lc_seq, 20, 255u,
                                         LATCH_TEST_PRODUCER_TAG);
        lc_seq++;
        const int32_t theta_before_foreign = g_simplex.theta_mrad;
        {
            latch_proposal_t corrupt_foreign;
            memset(&corrupt_foreign, 0, sizeof(corrupt_foreign));
            corrupt_foreign.ipc_magic = LATCH_IPC_PROPOSAL_MAGIC;
            corrupt_foreign.seq = 0u;
            corrupt_foreign.u_mrad = LATCH_NAN_MRAD;
            corrupt_foreign.wire_flags = GOVERNOR_WIRE_CMD_V2;
            corrupt_foreign.ingest_cycles = latch_clock_cycles();
            corrupt_foreign.wire_version = 2u;
            corrupt_foreign.kind = GOVERNOR_WIRE_CMD_V2;
            corrupt_foreign.confidence_q8 = 0u;
            corrupt_foreign.producer_tag = LATCH_TEST_FOREIGN_TAG;
            corrupt_foreign.session_epoch = LATCH_TEST_FOREIGN_EPOCH;
            corrupt_foreign.pre_fault_bits = LATCH_FAULT_CRC;
            latch_publish_proposal(&g_pub_buf, &corrupt_foreign);
            latch_simplex_tick(&g_simplex, &g_pub_buf);
        }
        if ((g_simplex.active_faults & (LATCH_FAULT_CRC | LATCH_FAULT_NAN)) != 0u ||
            g_simplex.gov_ladder.rung != GOVERNOR_RUNG_HP ||
            g_simplex.mode != LATCH_MODE_HP ||
            g_simplex.theta_mrad != theta_before_foreign ||
            g_simplex.gov_foreign_frames != 1u ||
            g_simplex.gov_lease_owner_tag != LATCH_TEST_PRODUCER_TAG) {
            fprintf(stderr, "FAIL: live-lease corrupt foreign frame disrupted active owner (faults=0x%x rung=%u)\n",
                    g_simplex.active_faults, g_simplex.gov_ladder.rung);
            goto fail;
        }
        latch_governor_test_frame_tagged(GOVERNOR_WIRE_CMD_V2, lc_seq, lc_seq, 25, 255u,
                                         LATCH_TEST_PRODUCER_TAG);
        if (g_simplex.mode != LATCH_MODE_HP || g_simplex.active_faults != 0u ||
            g_simplex.theta_mrad <= theta_before_foreign) {
            fprintf(stderr, "FAIL: active owner did not continue normally after foreign corrupt frame\n");
            goto fail;
        }
    }

    /*
     * Test: the operator release is RETAINED when it cannot be armed (L-5).
     *
     * The defect this pins: `operator_release_pending` was exchanged to zero
     * on EVERY governor tick, while the ladder only arms a release while the
     * rung is LATCH.  A release issued at any other rung was therefore
     * silently discarded -- the operator was told the hold was released and
     * nothing happened, with no diagnostic anywhere.
     *
     * The property asserted here: the request is RETAINED while the rung is
     * unchanged (and reported as DEFERRED), and it is INVALIDATED as soon
     * as the rung moves -- so a stale authorisation can never authorise a
     * later, unrelated exit from LATCH.
     */
    {
        latch_hold_status_t hs;
        memset(&hs, 0, sizeof(hs));

        /* Keep the governor loop quiet for the duration of this test: a
         * healthy lease, an active session and no proposal, so the only
         * thing that can move the rung is the test itself. */
        uint8_t saved_rung = g_simplex.gov_ladder.rung;
        bool saved_session = g_simplex.session_active;
        bool saved_v2 = g_simplex.gov_v2_session;
        uint32_t saved_lease = g_simplex.gov_lease_remaining;
        g_simplex.gov_v2_session = true;
        g_simplex.gov_lease_remaining = g_manifest.governor.lease_ticks;
        g_simplex.last_rx_tick = g_simplex.tick;
        g_simplex.session_active = true;

        /* Start from a rung where a release has no effect. */
        g_simplex.gov_ladder.rung = GOVERNOR_RUNG_ADVISE;
        latch_force_hold_cmd_t deferred_release = { .lock_hold = 0u, .reason_code = 9u };
        if (latch_sim_devctl_actuator(true, (unsigned int)DCMD_LATCH_FORCE_HOLD,
                                      &deferred_release) != 0) {
            fprintf(stderr, "FAIL: deferred operator release command failed\n");
            goto fail;
        }
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_HOLD_STATUS,
                                      &hs) != 0 || hs.release_state != LATCH_RELEASE_DEFERRED ||
            hs.rung != GOVERNOR_RUNG_ADVISE) {
            fprintf(stderr, "FAIL: a release issued off-LATCH was not reported as DEFERRED\n");
            goto fail;
        }

        /* A tick at the SAME rung must NOT consume the request. */
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.gov_ladder.rung != GOVERNOR_RUNG_ADVISE) {
            fprintf(stderr, "FAIL: the governor rung moved during the release test\n");
            goto fail;
        }
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_HOLD_STATUS,
                                      &hs) != 0 || hs.release_state != LATCH_RELEASE_DEFERRED) {
            fprintf(stderr, "FAIL: a deferred operator release was silently consumed\n");
            goto fail;
        }
        if (hs.release_deferred_ticks == 0u) {
            fprintf(stderr, "FAIL: a deferred operator release did not count its wait\n");
            goto fail;
        }

        /* A rung CHANGE invalidates the stale authorisation. */
        g_simplex.gov_ladder.rung = GOVERNOR_RUNG_CLAMP;
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_HOLD_STATUS,
                                      &hs) != 0 || hs.release_state != LATCH_RELEASE_NONE) {
            fprintf(stderr, "FAIL: a stale operator release survived a rung change\n");
            goto fail;
        }

        /* At LATCH the release is ARMED and consumed. */
        g_simplex.gov_ladder.rung = GOVERNOR_RUNG_LATCH;
        latch_force_hold_cmd_t armed_release = { .lock_hold = 0u, .reason_code = 10u };
        if (latch_sim_devctl_actuator(true, (unsigned int)DCMD_LATCH_FORCE_HOLD,
                                      &armed_release) != 0) {
            fprintf(stderr, "FAIL: operator release at LATCH failed\n");
            goto fail;
        }
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_HOLD_STATUS,
                                      &hs) != 0 || hs.release_state != LATCH_RELEASE_ARMED) {
            fprintf(stderr, "FAIL: an operator release at LATCH was not reported as ARMED\n");
            goto fail;
        }

        /* Restore the state the rest of the suite expects. */
        g_simplex.gov_ladder.rung = saved_rung;
        g_simplex.session_active = saved_session;
        g_simplex.gov_v2_session = saved_v2;
        g_simplex.gov_lease_remaining = saved_lease;
        atomic_store_explicit(&g_simplex.operator_release_pending, 0u, memory_order_release);
        atomic_store_explicit(&g_simplex.operator_release_armed, 0u, memory_order_release);
        atomic_store_explicit(&g_simplex.operator_release_deferred_ticks, 0u, memory_order_release);
    }

    /* Test ring buffer overflow, wrap-around and pagination clamping */
    latch_proposal_t dummy_prop = { .kind = GOVERNOR_WIRE_CMD_V2, .u_mrad = 10, .unit_id = 0, .coherence_ctr = 20 };
    governor_ladder_result_t dummy_lad = { .rung_before = GOVERNOR_RUNG_HP, .rung_after = GOVERNOR_RUNG_HP };
    for (uint32_t i = 0; i < LATCH_GOV_EVENT_CAPACITY + 10u; ++i) {
        latch_record_governor_event(&dummy_prop, true, true, 1000u + i, 2000u + i, 10, 10,
                                    LATCH_FAULT_NONE, LATCH_MODE_HP, dummy_lad, 100u + i);
    }
    memset(&edump, 0, sizeof(edump));
    edump.start_index = 0u; /* overwritten */
    edump.count = 32u;
    if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_DUMP_GOV_EVENTS, &edump) != 0 ||
        edump.overflow != 1u || edump.dropped == 0u || edump.start_index == 0u) {
        fprintf(stderr, "FAIL: circular event ring did not report overflow/dropped on wrap\n");
        goto fail;
    }

    /* A gated command must not poison a later frame-less tick. */
    latch_sim_reset();
    latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, 1u, 1u, 100, 255u);
    if (g_simplex.last_u_proposed_mrad != g_manifest.envelope.home_mrad ||
        g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: warm-up gated command cached or moved target\n");
        goto fail;
    }
    latch_simplex_tick(&g_simplex, &g_pub_buf);
    if (g_simplex.theta_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: gated target replayed on idle tick\n");
        goto fail;
    }

    /* Even a previously cached target near a keepout is never reused by an
     * empty tick or a heartbeat; only the current position is held. */
    latch_sim_reset();
    g_simplex.session_active = true;
    g_simplex.gov_v2_session = true;
    g_simplex.gov_lease_remaining = g_manifest.governor.lease_ticks;
    atomic_store_explicit(&g_simplex.session_reset_pending, 0u, memory_order_release);
    g_simplex.theta_mrad = 240;
    g_simplex.last_u_proposed_mrad = 260;
    latch_simplex_tick(&g_simplex, &g_pub_buf);
    if (g_simplex.theta_mrad != 240) {
        fprintf(stderr, "FAIL: frame-less tick moved toward stale keepout target\n");
        goto fail;
    }

    /* A new writer must clear the old target and keep retraction active. */
    atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
    latch_governor_test_frame(GOVERNOR_WIRE_HEARTBEAT, 1u, 1u, 0, 0u);
    if (!g_simplex.reconnect_retracting || g_simplex.mode == LATCH_MODE_HP ||
        g_simplex.last_u_proposed_mrad != 240) {
        fprintf(stderr, "FAIL: reconnect did not clear target and retain HOLD/retraction\n");
        goto fail;
    }

    /* Advisory RATE must not allow a failed acceleration check to actuate. */
    latch_sim_reset();
    g_manifest.governor.warmup_heartbeats = 0u;
    g_manifest.governor.advise_fault_mask |= LATCH_FAULT_RATE;
    g_manifest.envelope.j_max = 1;
    latch_governor_test_frame(GOVERNOR_WIRE_CMD_V2, 1u, 1u, 25, 255u);
    if ((g_simplex.active_faults & LATCH_FAULT_RATE) == 0u ||
        g_simplex.theta_mrad != g_manifest.envelope.home_mrad ||
        g_simplex.last_u_proposed_mrad != g_manifest.envelope.home_mrad) {
        fprintf(stderr, "FAIL: advisory RATE faults=%x theta=%d cached=%d\n", g_simplex.active_faults, g_simplex.theta_mrad, g_simplex.last_u_proposed_mrad);
        goto fail;
    }

    /* Legal full-range positions must not overflow the HOME delta. */
    g_manifest.envelope.theta_min_mrad = INT32_MIN;
    g_manifest.envelope.theta_max_mrad = INT32_MAX;
    g_manifest.envelope.num_keepouts = 0u;
    g_manifest.envelope.v_home = 25;
    {
        int32_t velocity = 0;
        g_manifest.envelope.home_mrad = INT32_MAX;
        int32_t position = latch_ha_home(INT32_MIN, &velocity);
        if (position != INT32_MIN + 25 || velocity != 25) {
            fprintf(stderr, "FAIL: full-range positive HOME step\n");
            goto fail;
        }
        g_manifest.envelope.home_mrad = INT32_MIN;
        position = latch_ha_home(INT32_MAX, &velocity);
        if (position != INT32_MAX - 25 || velocity != -25) {
            fprintf(stderr, "FAIL: full-range negative HOME step\n");
            goto fail;
        }
    }

    g_manifest = saved_manifest;
    latch_sim_reset();
    puts("[GOVERNOR_INTEGRATION] PASS: lease, coherence, warm-up, prechecks, ladder, hard-fault fallback and operator release");
    return 0;

fail:
    g_manifest = saved_manifest;
    latch_sim_reset();
    return -1;
}

static int latch_run_self_tests(void) {
    printf("[LATCH_HOST_SIM] Running 5-Fault, Seqlock & Manifest Self-Tests...\n");

    /* Test 0: IEEE 802.3 CRC32 standard vector */
    uint32_t crc_std = latch_crc32_ieee("123456789", 9u);
    if (crc_std != 0xCBF43926u) {
        fprintf(stderr, "FAIL: CRC32 vector mismatch: 0x%08X\n", crc_std);
        return EXIT_FAILURE;
    }

    /* Test 0b: NIST FIPS 180-2 SHA-256 standard vectors ("" and "abc") */
    if (latch_manifest_selftest_sha256() != 0) {
        fprintf(stderr, "FAIL: SHA-256 NIST test vectors mismatch\n");
        return EXIT_FAILURE;
    }

    /* Test 1: 256-Slot Ring Queue FIFO Ordering */
    latch_publish_buffer_t test_buf;
    memset(&test_buf, 0, sizeof(test_buf));
    for (uint32_t s = 1; s <= 32; ++s) {
        latch_proposal_t in = {
            .ipc_magic = LATCH_IPC_PROPOSAL_MAGIC,
            .seq = s,
            .u_mrad = (int32_t)(s * 10),
            .wire_flags = 0,
            .pre_fault_bits = 0,
            .ingest_cycles = s
        };
        latch_publish_proposal(&test_buf, &in);
    }
    for (uint32_t s = 1; s <= 32; ++s) {
        uint32_t consumed_gen = s - 1;
        latch_proposal_t out;
        bool ok = latch_consume_proposal(&test_buf, &consumed_gen, &out);
        if (!ok || out.seq != s || out.u_mrad != (int32_t)(s * 10)) {
            fprintf(stderr, "FAIL: Ring buffer FIFO test failed at sequence %u\n", s);
            return EXIT_FAILURE;
        }
    }

    /*
     * Test 1b: the session flush never lets the read tail REGRESS (L-3).
     *
     * The defect this pins: the flush ran on the dispatch thread and moved
     * `read_tail` to the write head while the tick thread could be mid-copy
     * holding a stale tail.  The consumer then stored `read_tail = t + 1`,
     * moving the tail BACKWARDS, so a pre-reset frame was delivered into the
     * new session -- where a fresh sequence baseline accepts any seq != 0.
     *
     * The property asserted here is the one that closes it: the tail is
     * advanced by compare-and-swap from the slot the frame was actually read
     * from, so a consumer that was overtaken by a flush can never move the
     * tail backwards, and the flushed frames are never delivered.
     */
    {
        latch_publish_buffer_t race_buf;
        memset(&race_buf, 0, sizeof(race_buf));
        for (uint32_t s = 1; s <= 3u; ++s) {
            latch_proposal_t in = {
                .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
                .seq            = s,
                .u_mrad         = (int32_t)(s * 10),
                .wire_flags     = 0u,
                .pre_fault_bits = 0u,
                .ingest_cycles  = s
            };
            latch_publish_proposal(&race_buf, &in);
        }

        /* A consumer has loaded the tail and copied the payload of slot 0,
         * but has NOT advanced the tail yet. */
        uint32_t stale_tail = atomic_load_explicit(&race_buf.read_tail, memory_order_relaxed);

        /* Meanwhile the first-writer open flushes the ring. */
        uint32_t dropped = latch_ring_flush_session(&race_buf);
        if (dropped != 3u) {
            fprintf(stderr, "FAIL: session flush dropped %u frames, expected 3\n", dropped);
            return EXIT_FAILURE;
        }
        uint32_t after_flush = atomic_load_explicit(&race_buf.read_tail, memory_order_relaxed);
        if (after_flush != 3u) {
            fprintf(stderr, "FAIL: session flush left read_tail=%u, expected 3\n", after_flush);
            return EXIT_FAILURE;
        }

        /* The overtaken consumer now tries to advance the tail from the slot
         * it read. The CAS MUST fail: it cannot regress the tail. */
        uint32_t expected = stale_tail;
        if (atomic_compare_exchange_strong_explicit(&race_buf.read_tail, &expected,
                                                     stale_tail + 1u,
                                                     memory_order_release,
                                                     memory_order_relaxed)) {
            fprintf(stderr, "FAIL: an overtaken consumer regressed the read tail\n");
            return EXIT_FAILURE;
        }
        uint32_t final_tail = atomic_load_explicit(&race_buf.read_tail, memory_order_relaxed);
        if (final_tail != after_flush) {
            fprintf(stderr, "FAIL: read tail moved after the flush (%u -> %u)\n",
                    after_flush, final_tail);
            return EXIT_FAILURE;
        }

        /* And the flushed frames are NOT delivered into the new session. */
        uint32_t consumed_gen = 0u;
        latch_proposal_t out;
        if (latch_consume_proposal(&race_buf, &consumed_gen, &out)) {
            fprintf(stderr, "FAIL: a flushed frame was delivered into the new session\n");
            return EXIT_FAILURE;
        }
    }

    latch_sim_reset();

    int32_t step = (g_manifest.envelope.a_max > 0) ? g_manifest.envelope.a_max : 10;
    if (step > g_manifest.envelope.v_max) step = g_manifest.envelope.v_max;
    int32_t dir = (g_manifest.envelope.theta_min_mrad < g_manifest.envelope.home_mrad) ? -1 : 1;
    int32_t home = g_manifest.envelope.home_mrad;
    int32_t keepout_val = (g_manifest.envelope.num_keepouts > 0)
                              ? (g_manifest.envelope.keepout[0].lo_mrad + g_manifest.envelope.keepout[0].hi_mrad) / 2
                              : 450;

    /* Nominal tracking in HP mode */
    int32_t pos = home;
    uint32_t seq = 1u;
    for (int i = 0; i < 10; ++i) {
        pos += dir * step;
        latch_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq++,
            .u_mrad         = pos,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_NONE,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.mode != (uint8_t)LATCH_MODE_HP || g_simplex.theta_mrad != pos) {
            fprintf(stderr, "FAIL: Nominal tracking failed at step %d: mode=%u, theta=%d, expected=%d, active_faults=0x%04X\n",
                    i, (unsigned int)g_simplex.mode, g_simplex.theta_mrad, pos, g_simplex.active_faults);
            return EXIT_FAILURE;
        }
    }

    int32_t last_held_pos = pos;

    /* Fault 1: Keep-out box violation */
    {
        latch_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq++,
            .u_mrad         = keepout_val,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_NONE,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.mode != (uint8_t)LATCH_MODE_HOLD ||
            (g_simplex.active_faults & LATCH_FAULT_KEEPOUT) == 0u ||
            g_simplex.theta_mrad != last_held_pos) {
            fprintf(stderr, "FAIL: Fault 1 (keep-out veto) failed\n");
            return EXIT_FAILURE;
        }
    }

    /* 25-Clean-Frame Hysteresis recovery back to HP */
    for (uint32_t i = 0; i < g_manifest.recovery.hysteresis_clean_frames; ++i) {
        latch_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq++,
            .u_mrad         = last_held_pos,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_NONE,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }
    if (g_simplex.mode != (uint8_t)LATCH_MODE_HP) {
        fprintf(stderr, "FAIL: Hysteresis recovery failed\n");
        return EXIT_FAILURE;
    }

    /* Fault 2: CRC corruption flagged by ingest */
    {
        latch_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = 0u,
            .u_mrad         = 0,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_CRC,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.mode != (uint8_t)LATCH_MODE_HOLD ||
            (g_simplex.active_faults & LATCH_FAULT_CRC) == 0u) {
            fprintf(stderr, "FAIL: Fault 2 (CRC reject) failed\n");
            return EXIT_FAILURE;
        }
    }

    /* Fault 3: Sequence replay */
    {
        latch_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq - 1u,
            .u_mrad         = last_held_pos,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_NONE,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if ((g_simplex.active_faults & LATCH_FAULT_SEQ) == 0u) {
            fprintf(stderr, "FAIL: Fault 3 (Sequence replay) failed\n");
            return EXIT_FAILURE;
        }
    }

    /* Silence: trips WATCHDOG, enters HOME, retracts to home */
    uint32_t v_home = (g_manifest.envelope.v_home > 0) ? (uint32_t)g_manifest.envelope.v_home : 10u;
    uint32_t retract_dist = (uint32_t)abs(last_held_pos - home);
    uint32_t retract_ticks = (retract_dist + v_home - 1u) / v_home;
    uint32_t silence_ticks = g_manifest.recovery.hold_to_home_ticks + retract_ticks + 20u;

    for (uint32_t t = 0; t < silence_ticks; ++t) {
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }
    if (g_simplex.theta_mrad != home || g_simplex.mode != (uint8_t)LATCH_MODE_HOLD) {
        fprintf(stderr, "FAIL: Fault 4 (Watchdog -> HA-HOME -> home) failed (theta=%d, mode=%u)\n",
                g_simplex.theta_mrad, (unsigned int)g_simplex.mode);
        return EXIT_FAILURE;
    }

    /* Fault 5: Unauthorized caller gets EPERM on mutation devctl */
    latch_force_hold_cmd_t fcmd = { .lock_hold = 1u, .reason_code = 1u };
    int rc_unauth = latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_FORCE_HOLD, &fcmd);
    if (rc_unauth != EPERM) {
        fprintf(stderr, "FAIL: Fault 5 (ability EPERM check) returned %d\n", rc_unauth);
        return EXIT_FAILURE;
    }

    /* Dedicated read-only ability probe test */
    int probe_unauth = latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_PROBE_ABILITY, NULL);
    if (probe_unauth != EPERM) {
        fprintf(stderr, "FAIL: Ability probe unauthorized check returned %d (expected EPERM)\n", probe_unauth);
        return EXIT_FAILURE;
    }
    int probe_auth = latch_sim_devctl_actuator(true, (unsigned int)DCMD_LATCH_PROBE_ABILITY, NULL);
    if (probe_auth != 0) {
        fprintf(stderr, "FAIL: Ability probe authorized check returned %d (expected 0)\n", probe_auth);
        return EXIT_FAILURE;
    }

    /* Fault 6: Atomic EPERM pending flag lands on next single-writer tick without cross-thread race */
    {
        uint16_t prev_latched = g_simplex.latched_faults;
        g_simplex.session_active = true;
        g_simplex.latched_faults = 0u;
        latch_force_hold_cmd_t fcmd2 = { .lock_hold = 1u, .reason_code = 2u };
        (void)latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_FORCE_HOLD, &fcmd2);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if ((g_simplex.active_faults & LATCH_FAULT_EPERM) == 0u ||
            (g_simplex.latched_faults & LATCH_FAULT_EPERM) == 0u) {
            fprintf(stderr, "FAIL: Fault 6 (EPERM pending tick consumption) failed\n");
            return EXIT_FAILURE;
        }
        g_simplex.latched_faults |= prev_latched;
    }

    /* Test 7: Empty ticks between session open (session_reset_pending) and Frame #1 do NOT trip WATCHDOG */
    latch_sim_reset();
    atomic_store_explicit(&g_simplex.session_reset_pending, 1u, memory_order_release);
    for (uint32_t t = 0; t < g_manifest.timing.watchdog_ticks + 5u; ++t) {
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.active_faults != LATCH_FAULT_NONE || g_simplex.mode != (uint8_t)LATCH_MODE_HP) {
            fprintf(stderr, "FAIL: Pre-Frame-1 idle wait tripped spurious fault 0x%04X mode=%u\n",
                    g_simplex.active_faults, (unsigned int)g_simplex.mode);
            return EXIT_FAILURE;
        }
    }
    /* Now send Frame #1 after wait: should start cleanly in HP */
    pos = home + dir * step;
    {
        latch_proposal_t p = {
            .ipc_magic = LATCH_IPC_PROPOSAL_MAGIC, .seq = 1u, .u_mrad = pos,
            .wire_flags = 0u, .pre_fault_bits = LATCH_FAULT_NONE, .ingest_cycles = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.mode != (uint8_t)LATCH_MODE_HP || g_simplex.theta_mrad != pos) {
            fprintf(stderr, "FAIL: Post-wait Frame #1 failed to enter HP cleanly\n");
            return EXIT_FAILURE;
        }
    }

    /* Test 8: Writer EOF disconnect mid-motion does NOT teleport in 1 tick; retracts via WATCHDOG->HOLD->HOME */
    for (int i = 0; i < 6; ++i) {
        pos += dir * step;
        latch_proposal_t p = {
            .ipc_magic = LATCH_IPC_PROPOSAL_MAGIC, .seq = (uint32_t)(2 + i), .u_mrad = pos,
            .wire_flags = 0u, .pre_fault_bits = LATCH_FAULT_NONE, .ingest_cycles = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }
    int32_t eof_start_pos = g_simplex.theta_mrad;
    atomic_store_explicit(&g_simplex.writer_closed_eof, 1u, memory_order_release);
    latch_simplex_tick(&g_simplex, &g_pub_buf);
    if (!g_simplex.session_active || g_simplex.theta_mrad == home) {
        fprintf(stderr, "FAIL: Writer EOF immediately deactivated session or teleported to home\n");
        return EXIT_FAILURE;
    }
    uint32_t eof_retract_dist = (uint32_t)abs(eof_start_pos - home);
    uint32_t eof_retract_ticks = (eof_retract_dist + v_home - 1u) / v_home;
    uint32_t eof_budget = g_manifest.timing.watchdog_ticks + g_manifest.recovery.hold_to_home_ticks + eof_retract_ticks + 10u;
    for (uint32_t t = 0; t < eof_budget; ++t) {
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }
    if (!g_simplex.retracted_home || !g_simplex.tape_frozen || g_simplex.session_active || g_simplex.theta_mrad != home) {
        fprintf(stderr, "FAIL: Writer EOF controlled retraction did not park and freeze cleanly\n");
        return EXIT_FAILURE;
    }

    /* Test 9: Strict anti-silent-defaults manifest parser rejects stripped JSON */
    {
        const char *bad_path = "/tmp/latch_test_stripped_manifest.json";
        FILE *bf = fopen(bad_path, "wb");
        if (bf) {
            fputs("{\"schema_version\":2}\n", bf);
            fclose(bf);
            latch_manifest_t bad_m;
            char bad_err[128];
            int brc = latch_manifest_load_opts(bad_path, &bad_m, false, bad_err, sizeof(bad_err));
            remove(bad_path);
            if (brc == 0) {
                fprintf(stderr, "FAIL: Stripped manifest unexpectedly succeeded\n");
                return EXIT_FAILURE;
            }
        }
    }

    /* Test 10: The session-status devctl is OUTPUT-ONLY and reports the
     * writer state.
     *
     * Two properties matter and both are checked here:
     *
     *  - An unauthorized (no `latch/actuator`) caller must still be able to
     *    READ it.  The reply is the observable handoff point between writer
     *    sessions, so it has to be reachable by the unprivileged operator
     *    shell; gating it on the actuator ability would make it useless
     *    exactly where it is needed.
     *  - It must report the writer state truthfully: 1 while the exclusive
     *    writer OCB is held, 0 once it is released, and the session
     *    generation must advance across the transition.
     */
    {
        latch_session_status_t sst;
        memset(&sst, 0xAA, sizeof(sst));
        int rc_sess = latch_sim_devctl_actuator(false,
                                                 (unsigned int)DCMD_LATCH_GET_SESSION_STATUS,
                                                 &sst);
        if (rc_sess != 0) {
            fprintf(stderr, "FAIL: Session status devctl returned %d for an "
                            "unauthorized READ-ONLY caller (expected 0)\n", rc_sess);
            return EXIT_FAILURE;
        }
        if (sst.struct_size != (uint32_t)sizeof(latch_session_status_t)) {
            fprintf(stderr, "FAIL: Session status struct_size is %u (expected %zu)\n",
                    sst.struct_size, sizeof(latch_session_status_t));
            return EXIT_FAILURE;
        }
        uint32_t gen_before = sst.session_generation;

        if (!latch_claim_writer(&g_simplex.open_writers)) {
            fprintf(stderr, "FAIL: could not claim the writer slot in the "
                            "session-status self-test\n");
            return EXIT_FAILURE;
        }
        atomic_fetch_add_explicit(&g_simplex.session_generation, 1u,
                                  memory_order_acq_rel);
        memset(&sst, 0, sizeof(sst));
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_SESSION_STATUS,
                                      &sst) != 0 || sst.writer_held != 1u) {
            fprintf(stderr, "FAIL: Session status did not report the held writer\n");
            return EXIT_FAILURE;
        }

        atomic_store_explicit(&g_simplex.open_writers, 0u, memory_order_release);
        memset(&sst, 0, sizeof(sst));
        if (latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_GET_SESSION_STATUS,
                                      &sst) != 0 || sst.writer_held != 0u) {
            fprintf(stderr, "FAIL: Session status did not report the released writer\n");
            return EXIT_FAILURE;
        }
        if (sst.session_generation != gen_before + 1u) {
            fprintf(stderr, "FAIL: Session generation did not advance across the "
                            "writer session (%u -> %u)\n",
                    gen_before, sst.session_generation);
            return EXIT_FAILURE;
        }
    }

    if (latch_run_governor_integration_test() != 0) {
        return EXIT_FAILURE;
    }

    printf("[LATCH_HOST_SIM] PASS: All safety, EOF, parser & Seqlock self-tests verified (PWM center=%u counts).\n",
           (unsigned int)latch_mrad_to_pca9685_off(0));
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    bool pipe_mode = false;
    const char *csv_path = NULL;
    const char *events_json_path = NULL;
    const char *manifest_path = "latch.manifest";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--pipe-in") == 0) {
            pipe_mode = true;
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (strcmp(argv[i], "--events-json") == 0 && i + 1 < argc) {
            events_json_path = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            manifest_path = argv[++i];
        }
    }

    latch_time_init();

    char err_buf[256];
    if (access(manifest_path, F_OK) != 0 && strcmp(manifest_path, "latch.manifest") == 0) {
        if (access("qnx/latch.manifest", F_OK) == 0) {
            manifest_path = "qnx/latch.manifest";
        }
    }
    if (latch_manifest_load(manifest_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latchd: FATAL: Failed to load manifest '%s': %s (Fail-Closed)\n",
                manifest_path, err_buf);
        return EXIT_FAILURE;
    }

    if (pipe_mode) {
        return latch_run_pipe_simulation(csv_path, events_json_path);
    }
    return latch_run_self_tests();
}

#endif /* __QNXNTO__ */
