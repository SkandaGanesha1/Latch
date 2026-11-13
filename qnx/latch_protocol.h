/*
 * qnx/latch_protocol.h
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * 32-byte packed little-endian wire protocol, internal IPC proposal message,
 * resource-manager devctl() commands, integer kinematic safety envelope
 * constants, Simplex mode/fault bitmasks, and 4096-entry .bss cycle tape.
 *
 * Compiles cleanly with zero warnings under:
 *   qcc -Vgcc_ntoaarch64le -Wall -Wextra -Werror -Wpedantic -O2 -std=c11
 *   qcc -Vgcc_ntox86_64    -Wall -Wextra -Werror -Wpedantic -O2 -std=c11
 *   gcc                    -Wall -Wextra -Werror -Wpedantic -O2 -std=c11
 */

#ifndef LATCH_PROTOCOL_H_
#define LATCH_PROTOCOL_H_

#if !defined(_QNX_SOURCE) && !defined(LATCH_HOST_SIM)
#   error "LATCH must be compiled with qcc -Vgcc_ntoaarch64le -D_QNX_SOURCE (QNX SDP 8.0) or -DLATCH_HOST_SIM"
#endif

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __QNXNTO__
#include <devctl.h>
#else
#include <sys/ioctl.h>
#ifndef EOK
#define EOK 0
#endif
#ifndef devctl
#define devctl(fd, cmd, data, size, flags) ioctl((fd), (cmd), (data))
#endif
#ifndef _DCMD_MISC
#define _DCMD_MISC 0x05
#endif
#ifndef __DIOT
#define __DIOT(type, cmd, data)  _IOW((type), (cmd), data)
#endif
#ifndef __DIOF
#define __DIOF(type, cmd, data)  _IOR((type), (cmd), data)
#endif
#ifndef __DIOTF
#define __DIOTF(type, cmd, data) _IOWR((type), (cmd), data)
#endif
#ifndef __DION
#define __DION(type, cmd)        _IO((type), (cmd))
#endif
#endif /* __QNXNTO__ */

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * 1. Resource Manager Nodes, Custom Ability & Hardware Bus Constants
 * ========================================================================== */

#define LATCH_DEV_PROPOSAL       "/dev/latch/proposal"
#define LATCH_DEV_ACTUATOR       "/dev/latch/actuator"
#define LATCH_ABILITY_ACTUATOR   "latch/actuator"

#define LATCH_I2C_DEFAULT_BUS    "/dev/i2c1"
#define LATCH_PCA9685_I2C_ADDR   0x40u

/* ==========================================================================
 * 2. Wire Frame (Guest -> latch-ingest), 32 Bytes, Packed, Little-Endian
 *
 * Offset  Field     Type      Rule
 * ------  --------  --------  ----------------------------------------------
 * 0       magic     uint32_t  0x4C415448 ('LATH')
 * 4       version   uint16_t  1
 * 6       joint     uint8_t   0 only in this build
 * 7       flags     uint8_t   Guest demo bits; ignored by host for safety
 * 8       seq       uint32_t  Must strictly exceed last_accepted (seq > last_seq)
 * 12      u_mrad    int32_t   Proposed position in manifest units (integer)
 * 16      crc32     uint32_t  IEEE 802.3 CRC32 over bytes [0, 16)
 * 20      reserved  uint8[12] Must be all zero; non-zero is a fault
 * ========================================================================== */

#define LATCH_WIRE_MAGIC         0x4C415448u  /* "LATH" little-endian u32    */
#define LATCH_WIRE_VERSION       1u
#define LATCH_WIRE_JOINT_DEFAULT 0u
#define LATCH_NAN_MRAD           INT32_MIN    /* -2147483648 NaN sentinel    */
#define LATCH_CRC32_POLY_REFL    0xEDB88320u  /* IEEE 802.3 reflected poly   */
#define LATCH_CRC_COVERED_BYTES  16u          /* Bytes [0..16) covered       */

/* Optional guest demo flags (never trusted to relax safety) */
#define LATCH_WIRE_FLAG_NONE     0x00u
#define LATCH_WIRE_FLAG_DEMO     0x01u
#define LATCH_WIRE_FLAG_SILENCE  0x80u        /* Simulation harness idle tick */

typedef struct __attribute__((packed)) latch_wire_frame {
    uint32_t magic;         /* [0..4)   0x4C415448 ('LATH')                  */
    uint16_t version;       /* [4..6)   1                                    */
    uint8_t  joint;         /* [6]      0                                    */
    uint8_t  flags;         /* [7]      Guest demo flags                     */
    uint32_t seq;           /* [8..12)  Monotonic sequence counter           */
    int32_t  u_mrad;        /* [12..16) Proposed joint angle in milliradians */
    uint32_t crc32;         /* [16..20) IEEE CRC32 over bytes [0..16)        */
    uint8_t  reserved[12];  /* [20..32) Must be zero                         */
} latch_wire_frame_t;

_Static_assert(sizeof(latch_wire_frame_t) == 32,
               "latch_wire_frame_t must be exactly 32 bytes");
_Static_assert(offsetof(latch_wire_frame_t, version) == 4,
               "version must be at offset 4");
_Static_assert(offsetof(latch_wire_frame_t, joint) == 6,
               "joint must be at offset 6");
_Static_assert(offsetof(latch_wire_frame_t, flags) == 7,
               "flags must be at offset 7");
_Static_assert(offsetof(latch_wire_frame_t, seq) == 8,
               "seq must be at offset 8");
_Static_assert(offsetof(latch_wire_frame_t, u_mrad) == 12,
               "u_mrad must be at offset 12");
_Static_assert(offsetof(latch_wire_frame_t, crc32) == 16,
               "crc32 must be at offset 16");
_Static_assert(offsetof(latch_wire_frame_t, reserved) == 20,
               "reserved must be at offset 20");

/* ==========================================================================
 * 3. Simplex Memory Ring Capacity
 * Note: All plant kinematics, keep-out boundaries, timing budgets, and PWM
 * calibrations are loaded dynamically at runtime from signed latch.manifest
 * (Zero Hardcoding Architecture).
 * ========================================================================== */

#define LATCH_TAPE_CAPACITY      (4096u)  /* Fixed evidence ring in .bss       */
#define LATCH_TAPE_MASK          (LATCH_TAPE_CAPACITY - 1u)

/* ==========================================================================
 * 4. Simplex Modes & Fault Bitmask Definitions
 * ========================================================================== */

typedef enum latch_mode {
    LATCH_MODE_HP   = 0,  /* High-Performance untrusted guest follower        */
    LATCH_MODE_HOLD = 1,  /* High-Assurance HOLD (zero velocity command)      */
    LATCH_MODE_HOME = 2   /* High-Assurance HOME (retract toward 0 mrad)      */
} latch_mode_t;

#define LATCH_FAULT_NONE         (0u)
#define LATCH_FAULT_MAGIC        (1u << 0)   /* Bad magic, version, or joint  */
#define LATCH_FAULT_CRC          (1u << 1)   /* IEEE 802.3 CRC32 mismatch     */
#define LATCH_FAULT_SEQ          (1u << 2)   /* Sequence gap or replay        */
#define LATCH_FAULT_NAN          (1u << 3)   /* u_mrad == INT32_MIN           */
#define LATCH_FAULT_RESERVED     (1u << 4)   /* Non-zero reserved[12] bytes   */
#define LATCH_FAULT_KEEPOUT      (1u << 5)   /* Enters/crosses keep-out interval */
#define LATCH_FAULT_BOUNDS       (1u << 6)   /* Outside manifest envelope stops  */
#define LATCH_FAULT_RATE         (1u << 7)   /* Exceeds v_max / a_max / j_max    */
#define LATCH_FAULT_WATCHDOG     (1u << 8)   /* Silent past watchdog_ticks       */
#define LATCH_FAULT_I2C          (1u << 9)   /* PCA9685 I2C transfer error    */
#define LATCH_FAULT_OPERATOR     (1u << 10)  /* Operator GPIO / devctl HOLD   */
#define LATCH_FAULT_EPERM        (1u << 11)  /* Unauthorized actuator devctl  */

#define LATCH_FAULT_WIRE_MASK \
    (LATCH_FAULT_MAGIC | LATCH_FAULT_CRC | LATCH_FAULT_SEQ | \
     LATCH_FAULT_NAN   | LATCH_FAULT_RESERVED)

#define LATCH_FAULT_ENVELOPE_MASK \
    (LATCH_FAULT_KEEPOUT | LATCH_FAULT_BOUNDS | LATCH_FAULT_RATE)

/* ==========================================================================
 * 5. Evidence Tape Record (4096-entry Ring in .bss)
 * ========================================================================== */

typedef struct __attribute__((packed)) latch_tape_entry {
    uint64_t tick;           /* Monotonic tick index                          */
    uint64_t cycles_in;      /* ClockCycles() at start of tick                */
    uint64_t cycles_out;     /* ClockCycles() after I2C command completes     */
    uint32_t seq;            /* Sequence number evaluated on this tick        */
    int32_t  u_proposed;     /* Guest proposed angle (or discarded sentinel)  */
    int32_t  theta_applied;  /* Angle actually commanded to PCA9685 (mrad)    */
    uint16_t mode;           /* Active latch_mode_t (HP=0, HOLD=1, HOME=2)    */
    uint16_t fault_bits;     /* Active fault bitmask for this tick            */
} latch_tape_entry_t;

_Static_assert(sizeof(latch_tape_entry_t) == 40,
               "latch_tape_entry_t must be 40 bytes packed");

/* ==========================================================================
 * 6. Internal Checked Proposal Struct (latch-ingest -> /dev/latch/proposal)
 * ========================================================================== */

#define LATCH_IPC_PROPOSAL_MAGIC 0x4C505250u /* "LPRP" */

typedef struct __attribute__((packed)) latch_ipc_proposal {
    uint32_t ipc_magic;      /* Must be LATCH_IPC_PROPOSAL_MAGIC              */
    uint32_t seq;            /* Wire sequence number (0 if payload dropped)   */
    int32_t  u_mrad;         /* Checked proposed angle (0 if payload dropped) */
    uint16_t wire_flags;     /* Flags from wire header                        */
    uint16_t pre_fault_bits; /* Wire faults caught by latch-ingest            */
    uint64_t ingest_cycles;  /* Host ClockCycles() when frame arrived         */
} latch_ipc_proposal_t;

_Static_assert(sizeof(latch_ipc_proposal_t) == 24,
               "latch_ipc_proposal_t must be 24 bytes packed");

/* ==========================================================================
 * 7. Actuator Node (/dev/latch/actuator) devctl() Payloads & Commands
 * ========================================================================== */

typedef struct latch_force_hold_cmd {
    uint32_t lock_hold;      /* 1 = force HA-HOLD, 0 = release operator hold  */
    uint32_t reason_code;    /* Operator audit reason                         */
} latch_force_hold_cmd_t;

typedef struct latch_status_reply {
    uint64_t tick;
    uint64_t last_latency_cycles;
    uint64_t max_latency_cycles;
    uint64_t last_rx_cycles;
    uint32_t last_latency_ns;
    uint32_t max_latency_ns;
    uint32_t last_seq;
    int32_t  theta_mrad;
    int32_t  omega_mrad_s;
    int32_t  velocity_mrad_tick;
    int32_t  last_u_proposed_mrad;
    uint16_t mode;
    uint16_t active_faults;
    uint16_t latched_faults;
    uint16_t clean_streak;
    uint32_t hold_ticks_elapsed;
    uint32_t total_proposals_rx;
    uint32_t total_wire_faults;
    uint32_t total_envelope_faults;
    uint32_t total_eperm_rejects;
    uint32_t total_ring_drops;
    uint32_t wcet_overruns;
    uint32_t max_backlog_seen;   /* Peak proposal-queue depth observed (frames) */
    uint32_t backlog_overruns;   /* Ticks where the queue exceeded timing.max_backlog_ticks */
    uint32_t operator_hold_locked;
    uint8_t  manifest_sha256[32];
} latch_status_reply_t;

#define LATCH_DUMP_MAX_ENTRIES   128u

typedef struct latch_tape_dump {
    uint32_t start_index;
    uint32_t count;
    uint64_t latest_tick;
    uint8_t  manifest_sha256[32];
    latch_tape_entry_t entries[LATCH_DUMP_MAX_ENTRIES];
} latch_tape_dump_t;

#define DCMD_LATCH_FORCE_HOLD \
    __DIOT(_DCMD_MISC, 0x40, latch_force_hold_cmd_t)
#define DCMD_LATCH_GET_STATUS \
    __DIOF(_DCMD_MISC, 0x41, latch_status_reply_t)
#define DCMD_LATCH_DUMP_TAPE \
    __DIOTF(_DCMD_MISC, 0x42, latch_tape_dump_t)

/* ==========================================================================
 * Cross-Process Payload Layout Asserts
 *
 * `latch_status_reply_t` and `latch_tape_dump_t` are devctl payloads: the
 * supervisor builds one and another process reads it. Their SIZE and their
 * FIELD OFFSETS are therefore part of the ABI, exactly as the wire frame and
 * the IPC proposal are -- and those two already carry static asserts.
 *
 * Without these, adding a field to the status struct silently changes the
 * payload layout, and a mismatch between the supervisor and a client built
 * from a different revision is diagnosed as "random garbage" rather than as
 * a layout error. `latch_tape_dump_t` is additionally padding-sensitive: it
 * carries a uint64_t after two uint32_t, so its offsets depend on the
 * alignment rules of the compiler.
 * ========================================================================== */

_Static_assert(sizeof(latch_status_reply_t) % 8u == 0u,
               "latch_status_reply_t must be a multiple of its 8-byte alignment");
_Static_assert(offsetof(latch_status_reply_t, tick) == 0u,
               "latch_status_reply_t: tick must be the first field");
_Static_assert(offsetof(latch_status_reply_t, last_seq) >=
                   offsetof(latch_status_reply_t, max_latency_cycles),
               "latch_status_reply_t: field order changed");
/* The digest is the last FIELD. Trailing padding up to the struct's
 * alignment is expected and carries no meaning -- but the field's END must
 * still lie inside the struct, or the layout is broken. */
_Static_assert(offsetof(latch_status_reply_t, manifest_sha256) +
                   sizeof(((latch_status_reply_t *)0)->manifest_sha256) <=
               sizeof(latch_status_reply_t),
               "latch_status_reply_t: manifest_sha256 must be the last field");

_Static_assert(sizeof(latch_tape_dump_t) % 8u == 0u,
               "latch_tape_dump_t must be a multiple of its 8-byte alignment");
_Static_assert(offsetof(latch_tape_dump_t, start_index) == 0u,
               "latch_tape_dump_t: start_index must be the first field");
_Static_assert(offsetof(latch_tape_dump_t, latest_tick) % 8u == 0u,
               "latch_tape_dump_t: latest_tick must be 8-byte aligned");
_Static_assert(offsetof(latch_tape_dump_t, entries) ==
                   offsetof(latch_tape_dump_t, manifest_sha256) +
                   sizeof(((latch_tape_dump_t *)0)->manifest_sha256),
               "latch_tape_dump_t: entries must follow the manifest digest");
_Static_assert(offsetof(latch_tape_dump_t, entries) +
                   sizeof(((latch_tape_dump_t *)0)->entries) <=
               sizeof(latch_tape_dump_t),
               "latch_tape_dump_t: entries must be the last field");

_Static_assert(sizeof(latch_force_hold_cmd_t) == 8u,
               "latch_force_hold_cmd_t must be 8 bytes");
#define DCMD_LATCH_PROBE_ABILITY \
    __DION(_DCMD_MISC, 0x43)

/* ==========================================================================
 * 8. Self-Contained IEEE 802.3 CRC32 (Reflected Polynomial 0xEDB88320)
 * ========================================================================== */

static inline uint32_t latch_crc32_ieee(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;

    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)bytes[i];
        for (unsigned int bit = 0; bit < 8u; ++bit) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1u) ^ (LATCH_CRC32_POLY_REFL & mask);
        }
    }
    return ~crc;
}

static inline int latch_wire_reserved_is_zero(const latch_wire_frame_t *frame) {
    uint8_t acc = 0u;
    for (size_t i = 0; i < sizeof(frame->reserved); ++i) {
        acc |= frame->reserved[i];
    }
    return (acc == 0u);
}

#ifdef __cplusplus
}
#endif

#endif /* LATCH_PROTOCOL_H_ */
