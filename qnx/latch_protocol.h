/*
 * qnx/latch_protocol.h
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * 32-byte packed little-endian wire protocol, versioned IPC proposal message,
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
#define LATCH_DEV_GOVERNOR       "/dev/governor"
/* Guest-lifecycle control node. Served by latch_guestd, NOT by latchd. */
#define LATCH_DEV_GUESTCTL       "/dev/latch/guestctl"
#define LATCH_ABILITY_ACTUATOR   "latch/actuator"

#define LATCH_I2C_DEFAULT_BUS    "/dev/i2c1"
#define LATCH_PCA9685_I2C_ADDR   0x40u

/* ==========================================================================
 * 2. Wire Frame (Guest -> latch-ingest), 32 Bytes, Packed, Little-Endian
 *
 * Offset  Field     Type      Rule
 * ------  --------  --------  ----------------------------------------------
 * 0       magic     uint32_t  0x4C415448 ('LATH')
 * 4       version   uint16_t  1 (legacy) or 2 (GOVERNOR v2)
 * 6       joint     uint8_t   0 only in this build
 * 7       flags/kind uint8_t  v1 demo bits; v2 version-gated message kind
 * 8       seq       uint32_t  Must strictly exceed last_accepted (seq > last_seq)
 * 12      u_mrad    int32_t   Proposed position in manifest units (integer)
 * 16      crc32     uint32_t  v1 [0,16); v2 concatenated [0,16)+[20,32)
 * 20..31  metadata  uint8[12] v1 zero; v2 kind-specific fields, CRC covered
 * ========================================================================== */

#define LATCH_WIRE_MAGIC         0x4C415448u  /* "LATH" little-endian u32    */
#define LATCH_WIRE_VERSION       1u           /* Wire v1 (legacy)             */
#define LATCH_WIRE_VERSION_V2    2u           /* Wire v2 (GOVERNOR)           */
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
#define LATCH_FAULT_UNIT         (1u << 12)  /* Unknown or invalid unit metadata   */
#define LATCH_FAULT_HEARTBEAT    (1u << 13)  /* Guest lease/coherence fault    */
#define LATCH_FAULT_WIDEN        (1u << 14)  /* Guest requested wider limits  */
#define LATCH_FAULT_DOSE         (1u << 15)  /* Dose rate exceeds ladder rung limit or envelope */
#define LATCH_FAULT_CONSIST      LATCH_FAULT_DOSE /* Backward compatibility alias */

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

#define LATCH_IPC_PROPOSAL_V2_MAGIC 0x4C505232u /* "LPR2" */

typedef struct __attribute__((packed)) latch_ipc_proposal_v2 {
    uint32_t ipc_magic;
    uint32_t seq;
    int32_t  u_mrad;
    uint16_t wire_flags;
    uint16_t pre_fault_bits;
    uint64_t ingest_cycles;
    uint16_t ipc_version;
    uint8_t  wire_version;
    uint8_t  kind;
    uint8_t  confidence_q8;
    uint8_t  agent_state;
    /*
     * Producer identity (L-2).
     *
     * This field was `reserved0` and was REQUIRED to be zero. It is now the
     * producer tag: the identity of the bridge that produced this frame.
     * The supervisor's dead-man lease is scoped to the producer that
     * established the session, so a second producer's frames are
     * lease-inert -- they cannot renew the lease, cannot advance the
     * coherence baseline, cannot earn warm-up credit and cannot move the
     * plant while the owner's lease is live.
     *
     * 0 (LATCH_PRODUCER_TAG_NONE) is RESERVED and REJECTED on a v2 frame:
     * an unscoped frame must not be able to slip past the lease authority.
     * Repurposing this field did not change the struct size on its own; the
     * struct is 56 bytes now because the session epoch was appended below
     * (RT-02), and the 32-byte WIRE frame is untouched either way.
     */
    uint16_t producer_tag;
    uint32_t coherence_ctr;
    uint32_t shrink_v;
    uint32_t shrink_scale_q8;
    uint32_t unit_id;
    /*
     * Session epoch (RT-02).
     *
     * The producer chooses a FRESH epoch for every session it opens and
     * stamps it on every frame it forwards.  The supervisor binds the epoch
     * of the session it is running and rejects any frame that carries a
     * different one.
     *
     * Why this exists: the supervisor's sequence baseline is re-based when a
     * session opens, and the FIRST frame of a session was accepted with any
     * non-zero sequence number.  A frame captured in an earlier session --
     * say one carrying `seq = 999999` -- was therefore accepted as the first
     * frame of the new session, became the new baseline, and could move the
     * plant.  The epoch makes the session's identity explicit: a stale frame
     * carries the OLD epoch, and the supervisor knows the old epoch.
     *
     * `reserved1` MUST be zero.  It is the room this structure needs to keep
     * a fixed size and a fixed field order, and a non-zero value means the
     * sender is using a layout this supervisor does not understand.
     */
    uint32_t session_epoch;
    uint32_t reserved1;
} latch_ipc_proposal_v2_t;

_Static_assert(sizeof(latch_ipc_proposal_v2_t) == 56u,
               "latch_ipc_proposal_v2_t must be exactly 56 bytes");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, ipc_version) == 24u,
               "LPR2 ipc_version offset changed");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, producer_tag) == 30u,
               "LPR2 producer_tag offset changed");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, coherence_ctr) == 32u,
               "LPR2 coherence counter offset changed");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, unit_id) == 44u,
               "LPR2 unit_id offset changed");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, session_epoch) == 48u,
               "LPR2 session_epoch offset changed");
_Static_assert(offsetof(latch_ipc_proposal_v2_t, reserved1) == 52u,
               "LPR2 reserved1 offset changed");

/* Session epoch constants (RT-02). */
#define LATCH_SESSION_EPOCH_NONE 0u   /* RESERVED: rejected on a v2 frame */
/* How many spent epochs the supervisor remembers. A producer that restarts
 * and reuses one of these is rejected instead of resuming the old session's
 * identity. */
#define LATCH_SESSION_EPOCH_RING 16u

/* Producer identity constants (L-2). */
#define LATCH_PRODUCER_TAG_NONE  0u   /* RESERVED: rejected on a v2 frame */
#define LATCH_PRODUCER_TAG_MAX   0xFFFFu

/* Native supervisor-side representation; never sent across the IPC boundary. */
typedef struct latch_proposal {
    uint32_t ipc_magic;
    uint32_t seq;
    int32_t  u_mrad;
    uint16_t wire_flags;
    uint16_t pre_fault_bits;
    uint64_t ingest_cycles;
    uint8_t  wire_version;
    uint8_t  kind;
    uint8_t  confidence_q8;
    uint8_t  agent_state;
    uint16_t producer_tag;   /* 0 for a v1 (unscoped) frame                 */
    uint32_t coherence_ctr;
    uint32_t shrink_v;
    uint32_t shrink_scale_q8;
    uint32_t unit_id;
    uint32_t session_epoch;  /* 0 for a v1 (unscoped) frame (RT-02)          */
} latch_proposal_t;

/* ==========================================================================
 * 7. Actuator Node (/dev/latch/actuator) devctl() Payloads & Commands
 * ========================================================================== */

typedef struct latch_force_hold_cmd {
    uint32_t lock_hold;      /* 1 = force HA-HOLD, 0 = release operator hold  */
    uint32_t reason_code;    /* Operator audit reason                         */
} latch_force_hold_cmd_t;

/* Operator-release acknowledgement (L-5).
 *
 * `release_state` tells the operator what ACTUALLY happened to a
 * `latchctl hold 0`, instead of silently accepting it:
 *
 *   0 = NO RELEASE REQUESTED (the operator hold is engaged)
 *   1 = RELEASE RECORDED, DEFERRED -- the ladder was not at LATCH, which is
 *       the only rung from which a release has any effect, so the request is
 *       held rather than thrown away
 *   2 = RELEASE ARMED -- the ladder was at LATCH and the release is effective
 *
 * The supervisor consumes the request on the next 1 ms tick, so this reply
 * describes the state at the moment of the command; `latchctl` re-reads it
 * so the operator sees the settled outcome.
 */
#define LATCH_RELEASE_NONE     0u
#define LATCH_RELEASE_DEFERRED 1u
#define LATCH_RELEASE_ARMED    2u

typedef struct latch_hold_status {
    uint32_t struct_size;
    uint32_t hold_locked;             /* 1 = the operator hold is engaged      */
    uint32_t rung;                    /* Governor rung (0..5)                  */
    uint32_t release_state;           /* LATCH_RELEASE_*                       */
    uint32_t release_deferred_ticks;  /* Ticks the release has waited          */
    uint32_t reserved;
} latch_hold_status_t;

/*
 * Session status (output-only, L-2 handoff).
 *
 * `writer_held` says whether the EXCLUSIVE proposal writer OCB is currently
 * open.  The proposal node admits one writer at a time (L-2): a second
 * writer is refused with EBUSY rather than being allowed to interleave
 * frames with the session that owns the plant.
 *
 * That exclusivity is what made the legacy QEMU verification ambiguous.  The
 * harness used to kill the guest's ingest and then WAIT A FIXED TWO SECONDS
 * before starting the verifier, on the assumption that the resource manager
 * would have processed the ingest's disconnect by then.  When it had not, the
 * verifier's own open was refused with EBUSY and the run failed for a reason
 * that had nothing to do with the invariants it was checking.  A fixed sleep
 * is not a handoff: it is a hope.
 *
 * This reply is the observable handoff point.  The harness now polls it and
 * starts the verifier only after the supervisor itself reports that the
 * writer OCB is released -- so the ordering is enforced by observed state
 * instead of by a timer, and a genuine failure to release shows up as
 * "writer still held" instead of as a confusing EBUSY from the verifier.
 *
 * `session_generation` counts the writer sessions the supervisor has seen.
 * It increments on every 0 -> 1 writer transition, so a harness can assert
 * that the verifier runs in a DIFFERENT session from the guest's -- which is
 * a stronger statement than "the handle was free at that instant".
 *
 * This is a READ-ONLY view of internal state.  It grants no authority: it
 * cannot open, write, or release anything, and it is served from the
 * actuator node like every other status reply.
 */
typedef struct latch_session_status {
    uint32_t struct_size;
    uint32_t writer_held;             /* 1 = an exclusive writer OCB is open    */
    uint32_t session_generation;      /* Writer sessions seen so far           */
    uint32_t reserved;
} latch_session_status_t;

/* ==========================================================================
 * Guest lifecycle control (U-1: latchctl guest-restart)
 * ==========================================================================
 *
 * The guest VM is a CHILD of `latch_guestd`, a narrowly-typed process whose
 * only job is to own that child and to expose exactly two mutating
 * operations on a dedicated channel (`/dev/latch/guestctl`, channel type
 * `guest_ctl_t`).
 *
 * WHY THIS EXISTS.  Measured on the QEMU AArch64 target on 2026-11-25:
 *
 *   - `slay -9 qvm` from the operator shell WORKS, and the writer-session
 *     handoff is observable (the ingest sees EOF, exits, and the supervisor
 *     reports `Writer Held : 0`).
 *   - `on -T qvm_host_t ... qvm @qvmconf` is REFUSED with
 *     `on: Operation not permitted`, because `operator_shell_t` holds no
 *     `settypeid` and no `spawn`.
 *
 * So the operator shell can stop the guest but cannot start it.  Granting
 * the operator shell `settypeid:qvm_host_t` would fix that and would also
 * collapse the "the operator shell is deliberately unprivileged" property
 * that the EPERM demonstration depends on.  A dedicated lifecycle process
 * keeps the hypervisor-spawning privilege in ONE typed domain that holds no
 * actuator ability and no proposal-write right.
 *
 * WHY STOP AND START ARE SEPARATE OPERATIONS.  A server-side "restart"
 * that killed the guest and immediately respawned it would RACE the writer
 * handoff: the new guest's ingest opens the proposal node, and if the old
 * ingest has not yet released the exclusive writer OCB, that open is
 * refused with EBUSY and the guest silently never streams again.  A
 * handoff must be OBSERVED, never timed (see AGENTS.md).  So the client
 * performs the sequence:
 *
 *     STOP  ->  poll the supervisor's session status until the writer is
 *               released  ->  START
 *
 * and refuses to START if the handoff was not observed.  There is
 * deliberately NO single-shot server-side "restart" operation that skips
 * that observation: an operation that can silently produce a guest that
 * never streams is worse than no operation at all.
 */
typedef struct latch_guest_status {
    uint32_t struct_size;
    uint32_t running;            /* 1 = a guest VM child is alive right now   */
    uint32_t generation;         /* successful launches since latch_guestd    */
    uint32_t last_exit_status;   /* raw wait status of the last child to exit */
    int32_t  pid;                /* pid of the live guest VM, or -1           */
    uint32_t reserved;
} latch_guest_status_t;

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

/* Versioned extension; legacy GET_STATUS remains byte-for-byte unchanged. */
typedef struct latch_governor_status_reply {
    latch_status_reply_t latch;
    uint32_t extension_version;
    uint32_t enabled;
    uint32_t rung;
    uint32_t v2_session;
    uint32_t lease_ticks_remaining;
    uint32_t lease_age_ticks;
    uint32_t warmup_heartbeats_seen;
    uint32_t agent_state;
    uint32_t rate_tokens_remaining;
    uint32_t shrink_active;
    uint32_t shrink_v_max;
    uint32_t shrink_scale_q8;
    uint32_t coherence_ctr;
    uint32_t coherence_valid;
    uint32_t clean_command_streak;
    uint32_t deadline_misses;
    /* HOMEOSTAT outer-loop telemetry (extension_version >= 4).
     * `homeostat_enabled` is 0 when the manifest has no `homeostat` section
     * or the section is disabled; `homeostat_scale_q8` is the current
     * velocity scale (256 == unity) and `homeostat_v_max` is the contracting
     * velocity ceiling it currently imposes (0 == no ceiling imposed). */
    uint32_t homeostat_enabled;
    uint32_t homeostat_scale_q8;
    uint32_t homeostat_v_max;
    uint32_t homeostat_stress_epochs;
    /* Producer-scoped lease telemetry (extension_version >= 5).
     *
     * `lease_owner_tag` is the producer that currently holds the dead-man
     * lease; `lease_owner_valid` is 0 when no producer has established a
     * session. `session_dead` is 1 when the owner's lease has expired: the
     * session is no longer authoritative, and another producer may take it
     * over (which starts a NEW sequence epoch and re-earns the warm-up).
     * `foreign_frames` counts frames that arrived from a producer other than
     * the owner while the lease was live -- those frames were lease-inert
     * and could not move the plant. `producer_takeovers` counts the
     * takeovers. */
    uint32_t lease_owner_tag;
    uint32_t lease_owner_valid;
    uint32_t session_dead;
    uint32_t foreign_frames;
    uint32_t producer_takeovers;
    /* Session-epoch telemetry (extension_version >= 6, RT-02).
     *
     * `session_epoch` is the epoch the supervisor has BOUND to the session
     * it is running, and `session_epoch_valid` is 0 when no epoch is bound
     * yet.  Reporting it makes the session's identity observable from
     * outside, so an operator can tell two sessions apart instead of
     * inferring it from a sequence number. */
    uint32_t session_epoch;
    uint32_t session_epoch_valid;
} latch_governor_status_reply_t;

#define LATCH_DUMP_MAX_ENTRIES   128u

/* ==========================================================================
 * 4b. THE LATENCY DISTRIBUTION (U-4: the honest latency measurement)
 * ==========================================================================
 *
 * WHY THIS EXISTS
 * ---------------
 * The project's rejected latency document claimed a bounded "WCET" from a
 * generator that INSERTED FIXED VALUES.  The replacement has to be a real
 * measurement of the supervisor's decision loop over a large sample, and
 * the sample has to be aggregated ON THE TARGET: ten-to-the-six ticks
 * cannot be shipped across a 115200-baud serial console, and a host-side
 * sample of a host-side run is not a measurement of the target at all.
 *
 * So the supervisor keeps a HISTOGRAM of its own per-tick decision latency,
 * and this payload is the readout.  It is OUTPUT-ONLY and grants no
 * authority, exactly like every other status reply.
 *
 * WHAT IS MEASURED
 * ----------------
 * The decision latency is the time from the entry to the exit of
 * `latch_simplex_tick()` -- the same quantity the existing "Decision
 * Latency" telemetry reports as `last` and `max`.  One sample is taken per
 * tick.
 *
 * TWO HISTOGRAMS, NOT ONE
 * -----------------------
 * A tick that CONSUMES A PROPOSAL runs the whole decision path: the frame is
 * parsed, the envelope is evaluated, the governor ladder is updated and the
 * actuation is published.  A tick with an EMPTY queue runs none of that.
 * Averaging the two together would produce a number that describes neither,
 * so the two are counted separately:
 *
 *   hist_decision : ticks that DEQUEUED A PROPOSAL  (the proposal path)
 *   hist_idle     : ticks with an EMPTY proposal queue (the supervisor's cost
 *                   when it has nothing to decide)
 *
 * `samples_motion` counts the subset of the decision-path ticks on which a
 * MOTION proposal was actually evaluated -- the ones that ran the governor
 * gate and the kinematic envelope.  A heartbeat, a foreign frame or a
 * proposal refused before the envelope did less work than a real command,
 * so a reader can tell how much of the decision-path sample was the
 * decision path proper.
 *
 * `mode_ticks` counts the ticks per supervisor mode, so a reader can
 * see whether the sample was taken while the supervisor was following the
 * guest (HP) or had already failed closed.
 *
 * THE BUCKET SCHEME
 * -----------------
 * Buckets 0..63 are EXACT cycle counts.  Above that, every octave of the
 * cycle count is split into three sub-buckets, so the resolution inside an
 * octave is 25%:
 *
 *     bucket = LATCH_LATENCY_EXACT + 3 * (k - 6) + sub
 *     k      = floor(log2(cycles))                 (k >= 6)
 *     q      = (cycles >> (k - 2)) & 3             (0..3, the quarter index)
 *     sub    = min(q, 2)                           (0, 1 or 2)
 *
 * so octave k covers [1.00, 1.25), [1.25, 1.50) and [1.50, 2.00) times 2^k.
 *
 * WHY `sub` IS A SATURATION AND NOT A SUBTRACTION.  The scheme has THREE
 * sub-buckets per octave but the quarter index `q` is TWO bits wide, so it
 * has FOUR values.  The fourth quarter of an octave -- [1.75, 2.00) -- has
 * no bucket of its own, because the third sub-bucket is the one that spans
 * the LAST HALF of the octave, [1.50, 2.00).  So the mapping is
 * {0,1,2,3} -> {0,1,2,2}: the top quarter collapses into the third
 * sub-bucket.  Writing that as `q - 2` or `q - 4` in UNSIGNED arithmetic
 * WRAPS, and a wrapped sub-bucket index puts every sample FOUR buckets
 * low -- which is exactly the defect this rule exists to prevent.  The
 * scheme is therefore a SATURATION, and `latch_latency_bucket()` and
 * `latch_latency_bucket_range()` are ONE scheme expressed twice; the
 * property that binds them is the round trip
 *
 *     latch_latency_bucket_range(latch_latency_bucket(c)).lo <= c < .hi
 *
 * which `qnx/latch_latency_test.c` checks over the WHOLE domain and
 * `tools/consistency_check.py` gates.
 *
 * A percentile is therefore reported as a RANGE, never as a fabricated
 * point estimate: the reader is told the bucket the sample fell into.
 * `min_cycles` and `max_cycles` are EXACT.
 * ========================================================================== */

#define LATCH_LATENCY_EXACT     64u   /* buckets 0..63 are exact cycle counts */
#define LATCH_LATENCY_BUCKETS  112u   /* 64 exact + 3 per octave up to 2^22    */
#define LATCH_LATENCY_MODES     8u    /* latch_mode_t has 3; the rest are slack */

/*
 * The domain the histogram represents, DERIVED from the bucket count
 * rather than written down: every octave above the exact range carries
 * three buckets, so the number of octaves is (BUCKETS - EXACT) / 3, and
 * the top octave's exclusive upper bound is 2^(6 + octaves).
 *
 * A cycle count at or above this bound is SATURATED into the last bucket:
 * the histogram has no room for it, and a sample must never be reported as
 * belonging to a bucket whose range does not contain it.
 */
#define LATCH_LATENCY_OCTAVES \
    ((LATCH_LATENCY_BUCKETS - LATCH_LATENCY_EXACT) / 3u)
#define LATCH_LATENCY_DOMAIN_CYCLES (1ULL << (6u + LATCH_LATENCY_OCTAVES))

/* The scheme is three sub-buckets per octave; the bucket count has to say
 * so, or the two halves of the scheme cannot describe the same table. */
_Static_assert((LATCH_LATENCY_BUCKETS - LATCH_LATENCY_EXACT) % 3u == 0u,
               "the latency histogram must carry three sub-buckets per "
               "octave, or the bucket index and the bucket range describe "
               "two different tables");

/*
 * The bucket of a latency, in cycles.  Kept here -- and not in the
 * supervisor -- because the READER has to compute the SAME bucket to turn a
 * count back into a range, and two implementations of the scheme would be
 * two chances to disagree.
 */
static inline unsigned latch_latency_bucket(uint64_t cycles) {
    if (cycles < (uint64_t)LATCH_LATENCY_EXACT) {
        return (unsigned)cycles;
    }
    unsigned k = 63u - (unsigned)__builtin_clzll(cycles);   /* floor(log2) */
    /* The quarter index is TWO bits wide, so it has FOUR values for a
     * scheme that has THREE sub-buckets per octave: the top quarter of the
     * octave collapses into the LAST sub-bucket, which spans half an
     * octave.  So the mapping SATURATES at 2.  It must not be written as a
     * subtraction: in unsigned arithmetic that wraps and puts every sample
     * FOUR buckets low. */
    unsigned q = (unsigned)((cycles >> (k - 2u)) & 3u);    /* 0..3 */
    unsigned sub = (q >= 2u) ? 2u : q;                     /* 0, 1 or 2 */
    unsigned idx = LATCH_LATENCY_EXACT + 3u * (k - 6u) + sub;
    if (idx >= LATCH_LATENCY_BUCKETS) {
        idx = LATCH_LATENCY_BUCKETS - 1u;
    }
    return idx;
}

/* The inclusive lower and exclusive upper cycle bound of a bucket. */
static inline void latch_latency_bucket_range(unsigned bucket,
                                              uint64_t *lo, uint64_t *hi) {
    if (bucket < LATCH_LATENCY_EXACT) {
        *lo = (uint64_t)bucket;
        *hi = (uint64_t)bucket + 1u;
        return;
    }
    unsigned idx = bucket - LATCH_LATENCY_EXACT;
    unsigned k = 6u + idx / 3u;
    unsigned sub = idx % 3u;
    uint64_t octave = (uint64_t)1u << k;
    uint64_t quarter = octave / 4u;
    switch (sub) {
        case 0u:  *lo = octave;       *hi = octave + quarter;     break;
        case 1u:  *lo = octave + quarter; *hi = octave + 2u * quarter; break;
        default:  *lo = octave + 2u * quarter; *hi = 2u * octave;  break;
    }
}

/* How many buckets of a histogram are non-empty.  A diagnostic that shows
 * the SHAPE of a distribution without dumping a hundred lines of it. */
static inline unsigned latch_latency_nonzero_buckets(const uint64_t *hist,
                                                     unsigned n) {
    unsigned count = 0u;
    if (hist == NULL) return 0u;
    for (unsigned i = 0u; i < n; ++i) {
        if (hist[i] != 0u) count++;
    }
    return count;
}

typedef struct latch_latency_stats {
    uint32_t struct_size;
    uint32_t buckets;              /* LATCH_LATENCY_BUCKETS                    */
    uint32_t modes;                /* LATCH_LATENCY_MODES                      */
    uint32_t reserved0;
    uint64_t cycles_per_sec;       /* the target's own cycle rate              */
    uint64_t samples_total;        /* every tick sampled                        */
    uint64_t samples_decision;     /* ticks that dequeued a proposal            */
    uint64_t samples_idle;         /* ticks with an empty proposal queue        */
    uint64_t samples_motion;       /* of those: ticks that evaluated a motion   */
    uint64_t min_cycles;           /* EXACT, over EVERY sample                  */
    uint64_t max_cycles;           /* EXACT, over EVERY sample                  */
    uint64_t sum_cycles;           /* the sum over EVERY sample                */
    uint64_t sum_decision_cycles;  /* the sum over the DECISION-path samples   */
    uint64_t min_decision_cycles;  /* EXACT, over the DECISION-path samples    */
    uint64_t max_decision_cycles;  /* EXACT, over the DECISION-path samples    */
    uint64_t first_tick;           /* the tick of the first sample             */
    uint64_t last_tick;            /* the tick of the most recent sample       */
    uint64_t over_budget;          /* samples over the manifest's budget       */
    uint64_t over_period;          /* samples over the tick period             */
    uint32_t mode_ticks[LATCH_LATENCY_MODES];
    uint64_t hist_decision[LATCH_LATENCY_BUCKETS];
    uint64_t hist_idle[LATCH_LATENCY_BUCKETS];
} latch_latency_stats_t;

/*
 * The tape dump's cursor is 64-BIT.
 *
 * The ring's write index counts every tick ever recorded. As a uint32 it
 * wrapped after 2^32 ticks -- about 49.7 days at the 1 kHz decision rate --
 * and the pagination arithmetic (`wr_idx - cap`, `wr_idx - start`,
 * `start >= wr_idx`) assumes a MONOTONICALLY GROWING index. After the wrap
 * the comparison inverted and the dump returned NOTHING: the evidence
 * recorder went blind exactly when a long-running system most needs it.
 *
 * A uint64 cursor does not wrap for 584 million years at 1 kHz. The
 * "give me the latest page" sentinel is therefore UINT64_MAX.
 */
typedef struct latch_tape_dump {
    uint64_t start_index;
    uint32_t count;
    uint64_t latest_tick;
    uint8_t  manifest_sha256[32];
    latch_tape_entry_t entries[LATCH_DUMP_MAX_ENTRIES];
} latch_tape_dump_t;

/* GOVERNOR event ABI is separate from the frozen legacy tape/status ABI. */
#define LATCH_GOV_EVENT_CAPACITY 4096u
#define LATCH_GOV_EVENT_DUMP_MAX 64u

typedef struct __attribute__((packed)) latch_gov_event {
    uint64_t event_index;
    uint64_t tick;
    uint64_t cycles;
    uint32_t seq;
    int32_t raw_u_mrad;
    int32_t normalized_u_mrad;
    int32_t theta_applied_mrad;
    uint32_t unit_id;
    uint32_t coherence_ctr;
    uint32_t lease_remaining;
    uint16_t fault_bits;
    uint8_t mode;
    uint8_t rung_before;
    uint8_t rung_after;
    uint8_t kind;
    uint8_t verdict;
    uint8_t agent_state;
    uint8_t confidence_q8;
    uint8_t coherence_valid;
} latch_gov_event_t;

_Static_assert(sizeof(latch_gov_event_t) == 62u,
               "latch_gov_event_t must be 62 bytes packed");

/*
 * THE HEX BUFFER SIZES, DERIVED.
 *
 * A hex rendering needs two characters per byte plus the terminator, and
 * the number of bytes is a fact about the EVENT and about the DIGEST --
 * not a number anybody should write down a third time.  These constants
 * exist so that a change to `latch_gov_event_t` cannot leave a buffer that
 * is one field too small: the old code declared `char ev_hex[125]` and
 * `char sha_hex[65]`, which were right BY COINCIDENCE.
 */
#define LATCH_GOV_EVENT_HEX_CHARS (sizeof(latch_gov_event_t) * 2u + 1u)
#define LATCH_SHA256_BYTES         32u
#define LATCH_SHA256_HEX_CHARS    (LATCH_SHA256_BYTES * 2u + 1u)

/* A SHA-256 digest is 32 bytes BY DEFINITION (FIPS 180-4).  The fact is
 * stated once, here; the hex size is DERIVED from it, so the number 65 --
 * the old `char sha_hex[65]` -- is never written down anywhere.
 *
 * The event's own size needs no such assert: the `_Static_assert` above
 * already pins `latch_gov_event_t` at 62 bytes, and the hex size follows
 * from `sizeof`. */
_Static_assert(LATCH_SHA256_BYTES == 32u,
               "a SHA-256 digest is 32 bytes (FIPS 180-4)");

typedef struct latch_gov_event_dump {
    uint64_t start_index;
    uint64_t latest_index;
    uint32_t count;
    uint32_t dropped;
    uint32_t overflow;
    uint32_t record_version;
    uint8_t manifest_sha256[LATCH_SHA256_BYTES];
    latch_gov_event_t entries[LATCH_GOV_EVENT_DUMP_MAX];
} latch_gov_event_dump_t;

#define DCMD_LATCH_FORCE_HOLD \
    __DIOT(_DCMD_MISC, 0x40, latch_force_hold_cmd_t)
#define DCMD_LATCH_GET_STATUS \
    __DIOF(_DCMD_MISC, 0x41, latch_status_reply_t)
#define DCMD_LATCH_DUMP_TAPE \
    __DIOTF(_DCMD_MISC, 0x42, latch_tape_dump_t)
#define DCMD_LATCH_GET_GOV_STATUS \
    __DIOF(_DCMD_MISC, 0x43, latch_governor_status_reply_t)
#define DCMD_LATCH_DUMP_GOV_EVENTS \
    __DIOTF(_DCMD_MISC, 0x44, latch_gov_event_dump_t)
/* Operator-release acknowledgement (L-5). Output-only, like GET_STATUS. */
#define DCMD_LATCH_GET_HOLD_STATUS \
    __DIOF(_DCMD_MISC, 0x46, latch_hold_status_t)
/* Writer-session status (L-2 handoff). Output-only; grants no authority. */
#define DCMD_LATCH_GET_SESSION_STATUS \
    __DIOF(_DCMD_MISC, 0x47, latch_session_status_t)
/* Guest lifecycle (U-1). Served by latch_guestd on /dev/latch/guestctl,
 * NOT by latchd: the supervisor that enforces the envelope must never hold
 * the power to start or stop the guest that it is supervising. */
#define DCMD_LATCH_GUEST_STOP \
    __DIOF(_DCMD_MISC, 0x48, latch_guest_status_t)
#define DCMD_LATCH_GUEST_START \
    __DIOF(_DCMD_MISC, 0x49, latch_guest_status_t)
#define DCMD_LATCH_GET_GUEST_STATUS \
    __DIOF(_DCMD_MISC, 0x4A, latch_guest_status_t)
/* Latency distribution (U-4). Output-only; grants no authority. */
#define DCMD_LATCH_GET_LATENCY_STATS \
    __DIOF(_DCMD_MISC, 0x4B, latch_latency_stats_t)

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
 * carries a uint64_t cursor followed by a uint32_t count, so its offsets
 * depend on the alignment rules of the compiler.
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
_Static_assert(offsetof(latch_governor_status_reply_t, extension_version) ==
                   sizeof(latch_status_reply_t),
               "GOVERNOR status extension must preserve the legacy status prefix");
_Static_assert(sizeof(latch_governor_status_reply_t) % 8u == 0u,
               "latch_governor_status_reply_t must be 8-byte aligned in size");

_Static_assert(sizeof(latch_tape_dump_t) % 8u == 0u,
               "latch_tape_dump_t must be a multiple of its 8-byte alignment");
_Static_assert(offsetof(latch_tape_dump_t, start_index) == 0u,
               "latch_tape_dump_t: start_index must be the first field");
_Static_assert(sizeof(((latch_tape_dump_t *)0)->start_index) == 8u,
               "latch_tape_dump_t: the cursor must be 64-bit (it must not wrap)");
_Static_assert(offsetof(latch_tape_dump_t, count) == 8u,
               "latch_tape_dump_t: count must follow the 64-bit cursor");
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
_Static_assert(sizeof(latch_hold_status_t) == 24u,
               "latch_hold_status_t must be 24 bytes");
_Static_assert(offsetof(latch_hold_status_t, struct_size) == 0u,
               "latch_hold_status_t: struct_size must be the first field");
_Static_assert(sizeof(latch_session_status_t) == 16u,
               "latch_session_status_t must be 16 bytes");
_Static_assert(offsetof(latch_session_status_t, struct_size) == 0u,
               "latch_session_status_t: struct_size must be the first field");
_Static_assert(offsetof(latch_session_status_t, writer_held) == 4u,
               "latch_session_status_t: writer_held must follow struct_size");
_Static_assert(offsetof(latch_session_status_t, session_generation) == 8u,
               "latch_session_status_t: session_generation must follow writer_held");
_Static_assert(sizeof(latch_guest_status_t) == 24u,
               "latch_guest_status_t must be 24 bytes");
_Static_assert(offsetof(latch_guest_status_t, struct_size) == 0u,
               "latch_guest_status_t: struct_size must be the first field");
_Static_assert(offsetof(latch_guest_status_t, running) == 4u,
               "latch_guest_status_t: running must follow struct_size");
_Static_assert(offsetof(latch_guest_status_t, generation) == 8u,
               "latch_guest_status_t: generation must follow running");
_Static_assert(offsetof(latch_guest_status_t, last_exit_status) == 12u,
               "latch_guest_status_t: last_exit_status must follow generation");
_Static_assert(offsetof(latch_guest_status_t, pid) == 16u,
               "latch_guest_status_t: pid must follow last_exit_status");

/* The latency-statistics payload is a devctl payload, so its SIZE and its
 * FIELD OFFSETS are part of the ABI exactly like the wire frame and the IPC
 * proposal are.  A mismatch between the supervisor and a client built from a
 * different revision is diagnosed as "random garbage" rather than as a
 * layout error, so the layout is pinned here. */
_Static_assert(sizeof(latch_latency_stats_t) % 8u == 0u,
               "latch_latency_stats_t must be a multiple of its 8-byte alignment");
_Static_assert(offsetof(latch_latency_stats_t, struct_size) == 0u,
               "latch_latency_stats_t: struct_size must be the first field");
_Static_assert(offsetof(latch_latency_stats_t, cycles_per_sec) == 16u,
               "latch_latency_stats_t: cycles_per_sec must follow the header");
_Static_assert(offsetof(latch_latency_stats_t, samples_total) == 24u,
               "latch_latency_stats_t: samples_total must follow cycles_per_sec");
_Static_assert(offsetof(latch_latency_stats_t, min_cycles) == 56u,
               "latch_latency_stats_t: min_cycles must follow the sample counts");
_Static_assert(offsetof(latch_latency_stats_t, max_cycles) == 64u,
               "latch_latency_stats_t: max_cycles must follow min_cycles");
_Static_assert(offsetof(latch_latency_stats_t, sum_cycles) == 72u,
               "latch_latency_stats_t: sum_cycles must follow max_cycles");
_Static_assert(offsetof(latch_latency_stats_t, sum_decision_cycles) == 80u,
               "latch_latency_stats_t: sum_decision_cycles must follow sum_cycles");
_Static_assert(offsetof(latch_latency_stats_t, min_decision_cycles) == 88u,
               "latch_latency_stats_t: min_decision_cycles must follow sum_decision_cycles");
_Static_assert(offsetof(latch_latency_stats_t, max_decision_cycles) == 96u,
               "latch_latency_stats_t: max_decision_cycles must follow min_decision_cycles");
_Static_assert(offsetof(latch_latency_stats_t, first_tick) == 104u,
               "latch_latency_stats_t: first_tick must follow max_decision_cycles");
_Static_assert(offsetof(latch_latency_stats_t, last_tick) == 112u,
               "latch_latency_stats_t: last_tick must follow first_tick");
_Static_assert(offsetof(latch_latency_stats_t, over_budget) == 120u,
               "latch_latency_stats_t: over_budget must follow last_tick");
_Static_assert(offsetof(latch_latency_stats_t, over_period) == 128u,
               "latch_latency_stats_t: over_period must follow over_budget");
_Static_assert(offsetof(latch_latency_stats_t, mode_ticks) == 136u,
               "latch_latency_stats_t: mode_ticks must follow the counters");
_Static_assert(offsetof(latch_latency_stats_t, hist_decision) ==
                    offsetof(latch_latency_stats_t, mode_ticks) +
                    sizeof(((latch_latency_stats_t *)0)->mode_ticks),
               "latch_latency_stats_t: hist_decision must follow mode_ticks");
_Static_assert(offsetof(latch_latency_stats_t, hist_decision) % 8u == 0u,
               "latch_latency_stats_t: hist_decision must be 8-byte aligned");
_Static_assert(offsetof(latch_latency_stats_t, hist_idle) ==
                    offsetof(latch_latency_stats_t, hist_decision) +
                    sizeof(((latch_latency_stats_t *)0)->hist_decision),
               "latch_latency_stats_t: hist_idle must follow hist_decision");
_Static_assert(offsetof(latch_latency_stats_t, hist_idle) +
                    sizeof(((latch_latency_stats_t *)0)->hist_idle) ==
                sizeof(latch_latency_stats_t),
               "latch_latency_stats_t: the histograms must be the last fields");
/* The bucket scheme has to stay inside the array it indexes. */
_Static_assert(LATCH_LATENCY_BUCKETS >= LATCH_LATENCY_EXACT + 3u * 16u,
               "LATCH_LATENCY_BUCKETS must cover 16 octaves above the exact range");
_Static_assert(LATCH_LATENCY_MODES > (unsigned)LATCH_MODE_HOME,
               "LATCH_LATENCY_MODES must cover every supervisor mode");
#define DCMD_LATCH_PROBE_ABILITY \
    __DION(_DCMD_MISC, 0x45)

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
