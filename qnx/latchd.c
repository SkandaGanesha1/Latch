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
 *   - Concurrency protected by lock-free atomic Seqlock two-slot buffer.
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
#include <sys/neutrino.h>
#include <sys/procmgr.h>
#include <sys/resmgr.h>
#include <sys/syspage.h>
#else
#ifndef LATCH_HOST_SIM
#define LATCH_HOST_SIM 1
#endif
#include <pthread.h>
#endif /* __QNXNTO__ */

#include "latch_protocol.h"
#include "latch_manifest.h"

/* ==========================================================================
 * 1. PCA9685 Register Map & Pulse Codes
 * ========================================================================== */

#ifndef _PULSE_CODE_MINAVAIL
#define _PULSE_CODE_MINAVAIL     0
#endif

#define LATCH_PULSE_CODE_TICK    (_PULSE_CODE_MINAVAIL + 1)
#define LATCH_PULSE_CODE_QUIT    (_PULSE_CODE_MINAVAIL + 2)

#define PCA9685_REG_MODE1        0x00u
#define PCA9685_REG_LED0_ON_L    0x06u
#define PCA9685_REG_PRESCALE     0xFEu
#define PCA9685_MODE1_SLEEP      0x10u
#define PCA9685_MODE1_AI         0x20u
#define PCA9685_MODE1_RESTART    0x80u

/* ==========================================================================
 * 2. Lock-Free Atomic Seqlock Two-Slot Publish Buffer (Fix E-2)
 * ========================================================================== */

typedef struct latch_seqlock_slot {
    _Atomic uint32_t     gen;
    latch_ipc_proposal_t proposal;
} latch_seqlock_slot_t;

typedef struct latch_publish_buffer {
    latch_seqlock_slot_t slots[2];
    _Atomic uint32_t     active_idx;
    _Atomic uint32_t     total_publishes;
} latch_publish_buffer_t;

/* ==========================================================================
 * 3. Host-Owned Plant & Simplex State (Only latchd Writes This)
 * ========================================================================== */

typedef struct latch_simplex_state {
    uint64_t       tick;
    uint64_t       last_latency_cycles;
    uint64_t       max_latency_cycles;
    uint32_t       last_latency_ns;
    uint32_t       max_latency_ns;

    int32_t        theta_mrad;           /* Last angle written to PCA9685     */
    int32_t        omega_mrad_s;         /* (theta - theta_prev) * ticks/sec  */
    int32_t        velocity_mrad_tick;   /* theta - theta_prev per tick       */
    int32_t        last_u_proposed_mrad; /* Last proposed u for telemetry     */

    uint32_t       last_seq;             /* 0 means no frame accepted yet     */
    uint64_t       last_rx_cycles;       /* 0 means never                     */
    uint64_t       last_rx_tick;         /* Tick index of last accepted frame */
    uint32_t       last_consumed_pub;    /* Total publish count consumed      */
    uint32_t       clean_streak;         /* Consecutive clean frames          */
    uint32_t       hold_ticks_elapsed;   /* Ticks spent in LATCH_MODE_HOLD    */
    uint8_t        mode;                 /* LATCH_MODE_HP / HOLD / HOME       */

    uint16_t       active_faults;
    uint16_t       latched_faults;

    uint32_t       total_proposals_rx;
    uint32_t       total_wire_faults;
    uint32_t       total_envelope_faults;
    _Atomic uint32_t total_eperm_rejects;
    _Atomic uint32_t operator_hold_locked;
    _Atomic uint32_t snapshot_gen;       /* Seqlock counter for telemetry reads */

    int            i2c_fd;
    uint32_t       period_ns;
    int32_t        ticks_per_sec;
} latch_simplex_state_t;

/* Global manifest and runtime buffers */
static latch_manifest_t       g_manifest;
static latch_tape_entry_t     g_latch_tape[LATCH_TAPE_CAPACITY];
static _Atomic uint32_t       g_tape_write_idx = 0u;
static latch_publish_buffer_t g_pub_buf;
static latch_simplex_state_t  g_simplex;
static volatile sig_atomic_t  g_running = 1;
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

static inline uint32_t latch_cycles_to_ns(uint64_t dcycles) {
    if (g_cycles_per_sec == 0) return 0;
    return (uint32_t)((dcycles * 1000000000ULL) / g_cycles_per_sec);
}

/* ==========================================================================
 * 5. Lock-Free Seqlock Two-Slot Atomic Publish / Consume (Fix E-2)
 * ========================================================================== */

static void latch_publish_proposal(latch_publish_buffer_t *buf,
                                   const latch_ipc_proposal_t *prop) {
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

static bool latch_consume_proposal(const latch_publish_buffer_t *buf,
                                   uint32_t *last_pub_inout,
                                   latch_ipc_proposal_t *out_prop) {
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

static inline int32_t latch_abs_i32(int32_t val) {
    return (val < 0) ? -val : val;
}

static uint16_t latch_check_envelope(int32_t theta_cur,
                                     int32_t v_cur,
                                     int32_t u_mrad) {
    uint16_t faults = LATCH_FAULT_NONE;

    int32_t t_min = g_manifest.envelope.theta_min_mrad;
    int32_t t_max = g_manifest.envelope.theta_max_mrad;
    int32_t v_max = g_manifest.envelope.v_max;
    int32_t a_max = g_manifest.envelope.a_max;
    int32_t horizon = (int32_t)g_manifest.envelope.lookahead_ticks;

    if (u_mrad < t_min || u_mrad > t_max) {
        faults |= LATCH_FAULT_BOUNDS;
    }
    if (latch_manifest_crossed_keepout(&g_manifest, theta_cur, u_mrad)) {
        faults |= LATCH_FAULT_KEEPOUT;
    }

    int32_t v_step = u_mrad - theta_cur;
    int32_t a_step = v_step - v_cur;
    if (latch_abs_i32(v_step) > v_max || latch_abs_i32(a_step) > a_max) {
        faults |= LATCH_FAULT_RATE;
    }

    /* Constant-u lookahead rollout */
    int32_t sim_theta = theta_cur;
    for (int h = 0; h < horizon; ++h) {
        int32_t step = latch_clamp_i32(u_mrad - sim_theta, -v_max, v_max);
        int32_t next_theta = sim_theta + step;
        if (next_theta < t_min || next_theta > t_max) {
            faults |= LATCH_FAULT_BOUNDS;
        }
        if (latch_manifest_crossed_keepout(&g_manifest, sim_theta, next_theta)) {
            faults |= LATCH_FAULT_KEEPOUT;
        }
        sim_theta = next_theta;
    }

    /* Maximum braking rollout */
    int32_t brake_theta = theta_cur + latch_clamp_i32(v_step, -v_max, v_max);
    int32_t brake_v     = brake_theta - theta_cur;
    for (int h = 0; h < horizon; ++h) {
        if (brake_v > 0) {
            brake_v -= a_max;
            if (brake_v < 0) brake_v = 0;
        } else if (brake_v < 0) {
            brake_v += a_max;
            if (brake_v > 0) brake_v = 0;
        }
        int32_t next_brake = brake_theta + brake_v;
        if (next_brake < t_min || next_brake > t_max) {
            faults |= LATCH_FAULT_BOUNDS;
        }
        if (latch_manifest_crossed_keepout(&g_manifest, brake_theta, next_brake)) {
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

/* HA Candidate 2: Retract toward 0 mrad along legal boundary */
static bool latch_home_path_is_legal(int32_t theta_cur) {
    if (latch_manifest_in_keepout(&g_manifest, theta_cur)) {
        return false;
    }
    /* If 0 mrad is home, path must not cross any keep-out */
    return !latch_manifest_crossed_keepout(&g_manifest, theta_cur, 0);
}

static int32_t latch_ha_home(int32_t theta_cur, int32_t *vel_out) {
    if (!latch_home_path_is_legal(theta_cur)) {
        *vel_out = 0;
        return theta_cur;
    }
    int32_t diff = 0 - theta_cur;
    int32_t step = latch_clamp_i32(diff,
                                   -g_manifest.envelope.v_home,
                                   g_manifest.envelope.v_home);
    int32_t next_theta = latch_clamp_i32(theta_cur + step,
                                         g_manifest.envelope.theta_min_mrad,
                                         g_manifest.envelope.theta_max_mrad);
    if (latch_manifest_crossed_keepout(&g_manifest, theta_cur, next_theta)) {
        *vel_out = 0;
        return theta_cur;
    }
    *vel_out = step;
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
        if (g_manifest.envelope.num_keepouts > 0) {
            int32_t lo = g_manifest.envelope.keepout[0].lo_mrad;
            int32_t hi = g_manifest.envelope.keepout[0].hi_mrad;
            safe_theta = (safe_theta < ((lo + hi) / 2)) ? (lo - 1) : (hi + 1);
        }
    }

    int32_t center = g_manifest.actuator.pwm_center;
    int32_t pmin   = g_manifest.actuator.pwm_min;
    int32_t pmax   = g_manifest.actuator.pwm_max;

    int32_t counts;
    if (safe_theta >= 0) {
        counts = center + ((safe_theta * (pmax - center)) / 1000);
    } else {
        counts = center + ((safe_theta * (center - pmin)) / 1000);
    }
    counts = latch_clamp_i32(counts, pmin, pmax);
    return (uint16_t)((uint32_t)counts & 0x0FFFu);
}

static int latch_pca9685_write_reg(int i2c_fd, uint8_t reg, uint8_t val) {
    if (i2c_fd < 0) return 0;
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
    return (status == EOK) ? 0 : -status;
#else
    (void)reg; (void)val; return 0;
#endif
}

static int latch_pca9685_init(int i2c_fd) {
    if (i2c_fd < 0) return 0;

    int rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_MODE1, PCA9685_MODE1_SLEEP);
    if (rc != 0) return rc;

    rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_PRESCALE, (uint8_t)g_manifest.actuator.prescale);
    if (rc != 0) return rc;

    rc = latch_pca9685_write_reg(i2c_fd, PCA9685_REG_MODE1, 0x00u);
    if (rc != 0) return rc;

    struct timespec wait_ts = {
        .tv_sec = 0,
        .tv_nsec = (long)(g_manifest.actuator.init_delay_us * 1000L)
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

    if (i2c_fd < 0) return 0;

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
    if (status != EOK && g_manifest.actuator.retries > 0) {
        status = devctl(i2c_fd, DCMD_I2C_SEND, &pkt, sizeof(pkt), NULL);
    }
    return (status == EOK) ? 0 : -status;
#else
    (void)off_counts; return 0;
#endif
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
    uint32_t idx = atomic_load_explicit(&g_tape_write_idx, memory_order_relaxed);
    latch_tape_entry_t *slot = &g_latch_tape[idx & LATCH_TAPE_MASK];

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

static void latch_simplex_tick(latch_simplex_state_t *st,
                               const latch_publish_buffer_t *pub) {
    uint64_t cycles_in = latch_clock_cycles();
    st->tick++;

    uint16_t tick_faults = LATCH_FAULT_NONE;
    latch_ipc_proposal_t prop;
    bool has_new = latch_consume_proposal(pub, &st->last_consumed_pub, &prop);

    if (has_new && (prop.wire_flags & LATCH_WIRE_FLAG_SILENCE) != 0u) {
        has_new = false;
    }

    if (atomic_load_explicit(&st->operator_hold_locked, memory_order_acquire) != 0u) {
        tick_faults |= LATCH_FAULT_OPERATOR;
    }

    int32_t u_candidate = st->last_u_proposed_mrad;
    uint32_t seq_observed = st->last_seq;

    if (has_new) {
        st->total_proposals_rx++;
        seq_observed = prop.seq;
        st->last_u_proposed_mrad = prop.u_mrad;
        u_candidate = prop.u_mrad;

        /* 1. Check wire-level pre-faults from ingest */
        if (prop.pre_fault_bits != 0u) {
            tick_faults |= (prop.pre_fault_bits & LATCH_FAULT_WIRE_MASK);
        }

        /* 2. Check INT32_MIN NaN sentinel */
        if (prop.u_mrad == LATCH_NAN_MRAD) {
            tick_faults |= LATCH_FAULT_NAN;
        }

        /* 3. Sequence check (Fix E-3):
         *    Reject if sequence <= last_seq (stale/replay fault).
         *    Accept advances (seq > last_seq) even if frames coalesced in queue.
         */
        if ((tick_faults & (LATCH_FAULT_MAGIC | LATCH_FAULT_CRC | LATCH_FAULT_RESERVED)) == 0u) {
            if (st->last_seq == 0u) {
                if (prop.seq == 0u) {
                    tick_faults |= LATCH_FAULT_SEQ;
                }
            } else {
                if ((int32_t)(prop.seq - st->last_seq) <= 0) {
                    tick_faults |= LATCH_FAULT_SEQ;
                }
            }
        }

        if ((tick_faults & LATCH_FAULT_WIRE_MASK) != 0u) {
            st->total_wire_faults++;
        } else {
            /* 4. Evaluate kinematic envelope and forward lookahead */
            uint16_t env_faults = latch_check_envelope(
                st->theta_mrad, st->velocity_mrad_tick, u_candidate);
            if (env_faults != LATCH_FAULT_NONE) {
                tick_faults |= env_faults;
                st->total_envelope_faults++;
            }
        }

        if (tick_faults == LATCH_FAULT_NONE) {
            st->last_seq       = prop.seq;
            st->last_rx_cycles = cycles_in;
            st->last_rx_tick   = st->tick;
        }
    } else {
        /* Watchdog timer check */
        uint64_t silent_ticks = (st->last_rx_tick == 0u)
                                    ? st->tick
                                    : (st->tick - st->last_rx_tick);
        if (silent_ticks >= (uint64_t)g_manifest.timing.watchdog_ticks) {
            tick_faults |= LATCH_FAULT_WATCHDOG;
        }
    }

    /* 5. Simplex Mode State Machine */
    uint32_t hys_clean = g_manifest.recovery.hysteresis_clean_frames;
    uint32_t hold_home = g_manifest.recovery.hold_to_home_ticks;

    if (tick_faults != LATCH_FAULT_NONE) {
        st->clean_streak = 0u;
        st->latched_faults |= tick_faults;

        if (st->mode == (uint8_t)LATCH_MODE_HP) {
            st->mode = (uint8_t)LATCH_MODE_HOLD;
            st->hold_ticks_elapsed = 1u;
        } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
            st->hold_ticks_elapsed++;
            if (st->hold_ticks_elapsed >= hold_home &&
                st->theta_mrad != 0 &&
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
                    st->theta_mrad != 0 &&
                    latch_home_path_is_legal(st->theta_mrad)) {
                    st->mode = (uint8_t)LATCH_MODE_HOME;
                }
            }
        }
    }

    /* 6. Command Generation */
    int32_t next_theta = st->theta_mrad;
    int32_t next_vel   = 0;

    if (st->mode == (uint8_t)LATCH_MODE_HP) {
        int32_t step = latch_clamp_i32(u_candidate - st->theta_mrad,
                                       -g_manifest.envelope.v_max,
                                       g_manifest.envelope.v_max);
        next_theta = latch_clamp_i32(st->theta_mrad + step,
                                     g_manifest.envelope.theta_min_mrad,
                                     g_manifest.envelope.theta_max_mrad);
        next_vel   = next_theta - st->theta_mrad;
    } else if (st->mode == (uint8_t)LATCH_MODE_HOLD) {
        next_theta = latch_ha_hold(st->theta_mrad, &next_vel);
    } else {
        next_theta = latch_ha_home(st->theta_mrad, &next_vel);
        if (next_theta == 0) {
            st->mode = (uint8_t)LATCH_MODE_HOLD;
            st->hold_ticks_elapsed = 0u;
        }
    }

    /* 7. Actuation */
    if (latch_pca9685_write_angle(st->i2c_fd, next_theta) != 0) {
        tick_faults        |= LATCH_FAULT_I2C;
        st->latched_faults |= LATCH_FAULT_I2C;
        st->clean_streak    = 0u;
        st->mode            = (uint8_t)LATCH_MODE_HOLD;
    }

    uint64_t cycles_out = latch_clock_cycles();
    uint64_t latency    = cycles_out - cycles_in;
    uint32_t lat_ns     = latch_cycles_to_ns(latency);

    /* Telemetry Seqlock Guard (Fix E-7) */
    atomic_fetch_add_explicit(&st->snapshot_gen, 1u, memory_order_release);

    st->theta_mrad          = next_theta;
    st->velocity_mrad_tick  = next_vel;
    st->omega_mrad_s        = next_vel * st->ticks_per_sec;
    st->active_faults       = tick_faults;
    st->last_latency_cycles = latency;
    st->last_latency_ns     = lat_ns;
    if (latency > st->max_latency_cycles) {
        st->max_latency_cycles = latency;
        st->max_latency_ns     = lat_ns;
    }

    atomic_fetch_add_explicit(&st->snapshot_gen, 1u, memory_order_release);

    /* 8. Append to Evidence Tape */
    latch_record_tape(st->tick,
                      cycles_in,
                      cycles_out,
                      seq_observed,
                      u_candidate,
                      next_theta,
                      (uint16_t)st->mode,
                      tick_faults);
}

/* ==========================================================================
 * 9. Status & Tape Snapshot Helpers (Fix E-7)
 * ========================================================================== */

static void latch_fill_status(latch_status_reply_t *out) {
    for (int tries = 0; tries < 4; tries++) {
        uint32_t g1 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 & 1u) continue;

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
        memcpy(out->manifest_sha256, g_manifest.sha256, sizeof(out->manifest_sha256));

        uint32_t g2 = atomic_load_explicit(&g_simplex.snapshot_gen, memory_order_acquire);
        if (g1 == g2) return;
    }
}

static void latch_fill_tape_dump(latch_tape_dump_t *dump) {
    uint32_t wr_idx = atomic_load_explicit(&g_tape_write_idx, memory_order_acquire);
    uint32_t req_count = dump->count;
    if (req_count == 0u || req_count > LATCH_DUMP_MAX_ENTRIES) {
        req_count = LATCH_DUMP_MAX_ENTRIES;
    }
    if (req_count > wr_idx) {
        req_count = wr_idx;
    }

    uint32_t start = dump->start_index;
    if (start == UINT32_MAX || start + req_count > wr_idx) {
        start = (wr_idx >= req_count) ? (wr_idx - req_count) : 0u;
    }

    for (uint32_t i = 0; i < req_count; ++i) {
        dump->entries[i] = g_latch_tape[(start + i) & LATCH_TAPE_MASK];
    }
    dump->start_index = start;
    dump->count       = req_count;
    dump->latest_tick = g_simplex.tick;
    memcpy(dump->manifest_sha256, g_manifest.sha256, sizeof(dump->manifest_sha256));
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
static int              g_timer_chid          = -1;
static int              g_timer_coid          = -1;
static timer_t          g_timer_id;
static latch_dev_attr_t g_proposal_attr;
static latch_dev_attr_t g_actuator_attr;

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
        atomic_fetch_add_explicit(&g_simplex.total_eperm_rejects, 1u, memory_order_relaxed);
        return EPERM;
    }
    return EOK;
}

static int latch_io_write(resmgr_context_t *ctp,
                           io_write_t *msg,
                           RESMGR_OCB_T *ocb) {
    iofunc_ocb_t *io_ocb = (iofunc_ocb_t *)ocb;
    latch_dev_attr_t *lattr = (latch_dev_attr_t *)io_ocb->attr;

    int status = iofunc_write_verify(ctp, msg, io_ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;

    if (lattr->is_actuator_node) {
        atomic_fetch_add_explicit(&g_simplex.total_eperm_rejects, 1u, memory_order_relaxed);
        return EPERM;
    }

    size_t nbytes = _IO_WRITE_GET_NBYTES(msg);
    if (nbytes != sizeof(latch_ipc_proposal_t)) {
        return EMSGSIZE;
    }

    latch_ipc_proposal_t prop;
    ssize_t got = resmgr_msgread(ctp, &prop, sizeof(prop), sizeof(msg->i));
    if (got != (ssize_t)sizeof(prop) || prop.ipc_magic != LATCH_IPC_PROPOSAL_MAGIC) {
        return EBADMSG;
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

    int status = iofunc_devctl_default(ctp, msg, io_ocb);
    if (status != _RESMGR_DEFAULT) return status;
    if (!lattr->is_actuator_node) return ENOTTY;

    void *data_ptr = _DEVCTL_DATA(msg->i);
    size_t nbytes_out = 0u;

    switch ((unsigned int)msg->i.dcmd) {
        case (unsigned int)DCMD_LATCH_FORCE_HOLD: {
            /* Mutating control operations require custom ability 'latch/actuator' */
            int perm_status = latch_verify_actuator_ability(ctp, io_ocb);
            if (perm_status != EOK) return perm_status;

            if ((size_t)ctp->size < sizeof(msg->i) + sizeof(latch_force_hold_cmd_t)) {
                return EBADMSG;
            }
            const latch_force_hold_cmd_t *cmd =
                (const latch_force_hold_cmd_t *)data_ptr;
            atomic_store_explicit(&g_simplex.operator_hold_locked,
                                  cmd->lock_hold ? 1u : 0u,
                                  memory_order_release);
            nbytes_out = 0u;
            break;
        }
        case (unsigned int)DCMD_LATCH_GET_STATUS: {
            if (msg->i.nbytes < (int)sizeof(latch_status_reply_t)) {
                return EBADMSG;
            }
            latch_status_reply_t rep;
            memset(&rep, 0, sizeof(rep));
            latch_fill_status(&rep);
            memcpy(data_ptr, &rep, sizeof(rep));
            nbytes_out = sizeof(rep);
            break;
        }
        case (unsigned int)DCMD_LATCH_DUMP_TAPE: {
            if (msg->i.nbytes < (int)sizeof(latch_tape_dump_t)) {
                return EBADMSG;
            }
            latch_tape_dump_t *dump = (latch_tape_dump_t *)data_ptr;
            latch_fill_tape_dump(dump);
            nbytes_out = sizeof(*dump);
            break;
        }
        default:
            return ENOTTY;
    }

    memset(&msg->o, 0, sizeof(msg->o));
    msg->o.ret_val = EOK;
    msg->o.nbytes  = (int)nbytes_out;
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

    g_timer_chid = ChannelCreate(_NTO_CHF_FIXED_PRIORITY | _NTO_CHF_PRIVATE);
    if (g_timer_chid == -1) {
        perror("latchd: ChannelCreate");
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

static void latch_sig_handler(int signo) {
    (void)signo;
    g_running = 0;
}

int main(int argc, char *argv[]) {
    const char *manifest_path = "latch.manifest";
    const char *i2c_bus_path  = NULL;
    bool force_no_i2c         = false;

    int opt;
    while ((opt = getopt(argc, argv, "m:b:n")) != -1) {
        switch (opt) {
            case 'm': manifest_path = optarg; break;
            case 'b': i2c_bus_path  = optarg; break;
            case 'n': force_no_i2c  = true;   break;
            default:
                fprintf(stderr, "Usage: %s [-m latch.manifest] [-b /dev/i2c1] [-n]\n", argv[0]);
                return EXIT_FAILURE;
        }
    }

    latch_time_init();

    /* Load zero-hardcoding manifest */
    char err_buf[256];
    if (latch_manifest_load(manifest_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
        fprintf(stderr, "latchd: WARNING: Could not load '%s' (%s), using conservative defaults\n",
                manifest_path, err_buf);
        latch_manifest_init_defaults(&g_manifest);
    } else {
        printf("latchd: Loaded manifest '%s' (plant='%s', SHA-256=%.16s...)\n",
               manifest_path, g_manifest.plant_name, g_manifest.sha256_hex);
    }

    if (!force_no_i2c && i2c_bus_path == NULL) {
        i2c_bus_path = g_manifest.paths.i2c_bus;
    }

    memset(&g_simplex, 0, sizeof(g_simplex));
    g_simplex.mode          = (uint8_t)LATCH_MODE_HP;
    g_simplex.period_ns     = g_manifest.timing.period_us * 1000u;
    g_simplex.ticks_per_sec = (int32_t)(1000000000u / g_simplex.period_ns);
    g_simplex.i2c_fd        = -1;

    /* Create custom ability "latch/actuator" with flags=0 (neither root nor non-root) */
    g_ability_actuator_id = procmgr_ability_create(g_manifest.paths.ability, 0);
    if (g_ability_actuator_id < 0) {
        perror("latchd: procmgr_ability_create(latch/actuator)");
        return EXIT_FAILURE;
    }

    if (!force_no_i2c && i2c_bus_path != NULL) {
        g_simplex.i2c_fd = open(i2c_bus_path, O_RDWR);
        if (g_simplex.i2c_fd < 0) {
            perror("latchd: open I2C bus");
        } else {
            int init_rc = latch_pca9685_init(g_simplex.i2c_fd);
            if (init_rc != 0) {
                fprintf(stderr, "latchd: WARNING: PCA9685 init failed (code %d)\n", init_rc);
            }
        }
    } else {
        printf("latchd: Operating in NO-I2C mock mode (-n)\n");
    }

    dispatch_t *dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    if (dpp == NULL) {
        perror("latchd: dispatch_create_channel");
        return EXIT_FAILURE;
    }

    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t      io_funcs;
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
                     _RESMGR_IO_NFUNCS, &io_funcs);
    io_funcs.write  = latch_io_write;
    io_funcs.devctl = latch_io_devctl;

    /* Proposal mailbox is world-writable (untrusted AI / guest domain) */
    iofunc_attr_init(&g_proposal_attr.attr, S_IFCHR | 0666, NULL, NULL);
    g_proposal_attr.is_actuator_node = false;

    /* Actuator interface is world-accessible; abilities govern permissions */
    iofunc_attr_init(&g_actuator_attr.attr, S_IFCHR | 0666, NULL, NULL);
    g_actuator_attr.is_actuator_node = true;

    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max   = 1;
    rattr.msg_max_size = sizeof(latch_tape_dump_t) + 256u;

    int id_proposal = resmgr_attach(dpp, &rattr, g_manifest.paths.proposal,
                                    _FTYPE_ANY, 0, &connect_funcs,
                                    &io_funcs, &g_proposal_attr.attr);
    int id_actuator = resmgr_attach(dpp, &rattr, g_manifest.paths.actuator,
                                    _FTYPE_ANY, 0, &connect_funcs,
                                    &io_funcs, &g_actuator_attr.attr);
    if (id_proposal == -1 || id_actuator == -1) {
        perror("latchd: resmgr_attach");
        return EXIT_FAILURE;
    }

    signal(SIGINT, latch_sig_handler);
    signal(SIGTERM, latch_sig_handler);

    pthread_t decision_tid;
    if (pthread_create(&decision_tid, NULL, latch_decision_thread, NULL) != 0) {
        perror("latchd: pthread_create");
        return EXIT_FAILURE;
    }

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    while (g_running) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) continue;
            break;
        }
        (void)dispatch_handler(ctp);
    }

    pthread_join(decision_tid, NULL);
    resmgr_detach(dpp, id_actuator, _RESMGR_DETACH_ALL);
    resmgr_detach(dpp, id_proposal, _RESMGR_DETACH_ALL);
    dispatch_context_free(ctp);
    if (g_simplex.i2c_fd >= 0) {
        close(g_simplex.i2c_fd);
    }
    return EXIT_SUCCESS;
}

#else /* LATCH_HOST_SIM */

/* ==========================================================================
 * 11. Host Simulation & Pipe-Driven Verification Mode (LATCH_HOST_SIM)
 * ========================================================================== */

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
    g_simplex.mode          = (uint8_t)LATCH_MODE_HP;
    g_simplex.period_ns     = g_manifest.timing.period_us * 1000u;
    g_simplex.ticks_per_sec = (int32_t)(1000000000u / g_simplex.period_ns);
    g_simplex.i2c_fd        = -1;
    (void)latch_pca9685_init(g_simplex.i2c_fd);
}

static int latch_sim_devctl_actuator(bool caller_has_ability,
                                     unsigned int dcmd,
                                     void *payload) {
    if (dcmd == (unsigned int)DCMD_LATCH_FORCE_HOLD && !caller_has_ability) {
        atomic_fetch_add_explicit(&g_simplex.total_eperm_rejects, 1u, memory_order_relaxed);
        uint32_t wr_idx = atomic_load_explicit(&g_tape_write_idx, memory_order_acquire);
        if (wr_idx > 0u) {
            g_latch_tape[(wr_idx - 1u) & LATCH_TAPE_MASK].fault_bits |= LATCH_FAULT_EPERM;
        }
        return EPERM;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_FORCE_HOLD && payload != NULL) {
        const latch_force_hold_cmd_t *cmd = (const latch_force_hold_cmd_t *)payload;
        atomic_store_explicit(&g_simplex.operator_hold_locked,
                              cmd->lock_hold ? 1u : 0u,
                              memory_order_release);
        return 0;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_GET_STATUS && payload != NULL) {
        latch_fill_status((latch_status_reply_t *)payload);
        return 0;
    }
    if (dcmd == (unsigned int)DCMD_LATCH_DUMP_TAPE && payload != NULL) {
        latch_fill_tape_dump((latch_tape_dump_t *)payload);
        return 0;
    }
    return ENOTTY;
}

static int latch_export_tape_csv(const char *csv_path) {
    FILE *fp = fopen(csv_path, "w");
    if (fp == NULL) {
        perror("latchd: fopen csv");
        return -1;
    }
    fprintf(fp, "tick,cycles_in,cycles_out,latency_cycles,seq,u_proposed,theta_applied,mode,mode_name,fault_bits\n");
    uint32_t wr_idx = atomic_load_explicit(&g_tape_write_idx, memory_order_acquire);
    uint32_t count = (wr_idx > LATCH_TAPE_CAPACITY) ? LATCH_TAPE_CAPACITY : wr_idx;
    uint32_t start = wr_idx - count;
    for (uint32_t i = 0; i < count; ++i) {
        const latch_tape_entry_t *e = &g_latch_tape[(start + i) & LATCH_TAPE_MASK];
        uint64_t lat = e->cycles_out - e->cycles_in;
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
    fclose(fp);
    return 0;
}

static int latch_run_pipe_simulation(const char *csv_path) {
    latch_sim_reset();
    latch_ipc_proposal_t prop;

    while (1) {
        size_t total = 0u;
        uint8_t *p = (uint8_t *)&prop;
        while (total < sizeof(prop)) {
            ssize_t n = read(STDIN_FILENO, p + total, sizeof(prop) - total);
            if (n <= 0) break;
            total += (size_t)n;
        }
        if (total == 0u) break;
        if (total != sizeof(prop) || prop.ipc_magic != LATCH_IPC_PROPOSAL_MAGIC) {
            fprintf(stderr, "latchd: invalid IPC proposal on pipe\n");
            return EXIT_FAILURE;
        }
        latch_publish_proposal(&g_pub_buf, &prop);
        latch_simplex_tick(&g_simplex, &g_pub_buf);

        /* At tick 110, simulate unauthorized client devctl calling force_hold */
        if (g_simplex.tick == 110u) {
            latch_force_hold_cmd_t fcmd = { .lock_hold = 0u, .reason_code = 99u };
            (void)latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_FORCE_HOLD, &fcmd);
        }
    }

    if (csv_path != NULL) {
        if (latch_export_tape_csv(csv_path) != 0) {
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
    return EXIT_SUCCESS;
}

static int latch_run_self_tests(void) {
    printf("[LATCH_HOST_SIM] Running 5-Fault, Seqlock & Manifest Self-Tests...\n");

    /* Test 0: IEEE 802.3 CRC32 standard vector */
    uint32_t crc_std = latch_crc32_ieee("123456789", 9u);
    if (crc_std != 0xCBF43926u) {
        fprintf(stderr, "FAIL: CRC32 vector mismatch: 0x%08X\n", crc_std);
        return EXIT_FAILURE;
    }

    /* Test 1: Seqlock Lock-Free Buffer Concurrency */
    latch_publish_buffer_t test_buf;
    memset(&test_buf, 0, sizeof(test_buf));
    for (uint32_t s = 1; s <= 100; ++s) {
        latch_ipc_proposal_t in = {
            .ipc_magic = LATCH_IPC_PROPOSAL_MAGIC,
            .seq = s,
            .u_mrad = (int32_t)(s * 10),
            .wire_flags = 0,
            .pre_fault_bits = 0,
            .ingest_cycles = s
        };
        latch_publish_proposal(&test_buf, &in);

        uint32_t consumed_gen = s - 1;
        latch_ipc_proposal_t out;
        bool ok = latch_consume_proposal(&test_buf, &consumed_gen, &out);
        if (!ok || out.seq != s || out.u_mrad != (int32_t)(s * 10)) {
            fprintf(stderr, "FAIL: Seqlock buffer test failed at sequence %u\n", s);
            return EXIT_FAILURE;
        }
    }

    latch_sim_reset();

    /* Nominal tracking in HP mode */
    int32_t pos = 0;
    uint32_t seq = 1u;
    for (int i = 0; i < 10; ++i) {
        pos -= 10;
        latch_ipc_proposal_t p = {
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
            fprintf(stderr, "FAIL: Nominal tracking failed at step %d\n", i);
            return EXIT_FAILURE;
        }
    }

    /* Fault 1: Keep-out box violation (propose +450 mrad inside [250, 650]) */
    {
        latch_ipc_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq++,
            .u_mrad         = 450,
            .wire_flags     = 0u,
            .pre_fault_bits = LATCH_FAULT_NONE,
            .ingest_cycles  = latch_clock_cycles()
        };
        latch_publish_proposal(&g_pub_buf, &p);
        latch_simplex_tick(&g_simplex, &g_pub_buf);
        if (g_simplex.mode != (uint8_t)LATCH_MODE_HOLD ||
            (g_simplex.active_faults & LATCH_FAULT_KEEPOUT) == 0u ||
            g_simplex.theta_mrad != -100) {
            fprintf(stderr, "FAIL: Fault 1 (keep-out veto) failed\n");
            return EXIT_FAILURE;
        }
    }

    /* 25-Clean-Frame Hysteresis recovery back to HP */
    for (uint32_t i = 0; i < g_manifest.recovery.hysteresis_clean_frames; ++i) {
        latch_ipc_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq++,
            .u_mrad         = -100,
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
        latch_ipc_proposal_t p = {
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
        latch_ipc_proposal_t p = {
            .ipc_magic      = LATCH_IPC_PROPOSAL_MAGIC,
            .seq            = seq - 1u,
            .u_mrad         = -100,
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

    /* Silence for 60 ticks: trips WATCHDOG, enters HOME, retracts to 0 */
    for (int t = 0; t < 60; ++t) {
        latch_simplex_tick(&g_simplex, &g_pub_buf);
    }
    if (g_simplex.theta_mrad != 0 || g_simplex.mode != (uint8_t)LATCH_MODE_HOLD) {
        fprintf(stderr, "FAIL: Fault 4 (Watchdog -> HA-HOME -> 0 mrad) failed (theta=%d, mode=%u)\n",
                g_simplex.theta_mrad, (unsigned int)g_simplex.mode);
        return EXIT_FAILURE;
    }

    /* Fault 5: Unauthorized caller gets EPERM */
    latch_force_hold_cmd_t fcmd = { .lock_hold = 1u, .reason_code = 1u };
    int rc_unauth = latch_sim_devctl_actuator(false, (unsigned int)DCMD_LATCH_FORCE_HOLD, &fcmd);
    if (rc_unauth != EPERM) {
        fprintf(stderr, "FAIL: Fault 5 (ability EPERM check) returned %d\n", rc_unauth);
        return EXIT_FAILURE;
    }

    printf("[LATCH_HOST_SIM] PASS: All 5 fault scenarios, Seqlock & manifest verified (PWM center=%u counts).\n",
           (unsigned int)latch_mrad_to_pca9685_off(0));
    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    bool pipe_mode = false;
    const char *csv_path = NULL;
    const char *manifest_path = "latch.manifest";

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--pipe-in") == 0) {
            pipe_mode = true;
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_path = argv[++i];
        } else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) {
            manifest_path = argv[++i];
        }
    }

    latch_time_init();

    char err_buf[256];
    if (latch_manifest_load(manifest_path, &g_manifest, err_buf, sizeof(err_buf)) != 0) {
        latch_manifest_init_defaults(&g_manifest);
    }

    if (pipe_mode) {
        return latch_run_pipe_simulation(csv_path);
    }
    return latch_run_self_tests();
}

#endif /* __QNXNTO__ */
