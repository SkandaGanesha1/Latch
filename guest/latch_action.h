/*
 * guest/latch_action.h -- the action schema, its INDEPENDENT validator, and
 * the wire-v2 frame packer.
 *
 * FREESTANDING BY DESIGN
 * ----------------------
 * This header uses only <stdint.h> and <stddef.h>.  It is included by
 *
 *   - guest/latch_infer.cpp      the C++ inference program (the model side)
 *   - tools/latch_action_test.c  the host-side regression test
 *
 * and it must never grow a libc dependency, because the freestanding
 * policy binary is built with -nostdlib -ffreestanding.
 *
 * WHAT THIS FILE IS NOT
 * ---------------------
 * IT IS NOT THE SAFETY ENVELOPE.
 *
 * The keep-out box, the rate limit, the lease and the unit whitelist live
 * in the SIGNED MANIFEST and are enforced by exactly one component: the
 * trusted QNX supervisor.  They are deliberately NOT duplicated here:
 *
 *   1. a safety parameter in code is a defect in this project (the
 *      manifest is the single source of truth), and
 *   2. this code runs in the UNTRUSTED guest.  A guest-side copy of the
 *      envelope would be an untrusted copy of a safety parameter -- it
 *      could be patched by whoever controls the guest, so it could not be
 *      relied upon even if it were signed.
 *
 * So the split is:
 *
 *   guest (untrusted)   structure   -- "is this a well-formed action with
 *                                      representable integers?"
 *   QNX host (trusted)  safety      -- "is this action admissible for the
 *                                      plant, right now, under the lease?"
 *
 * The host re-validates EVERYTHING anyway.  The gate here exists so that
 * a model that emits nonsense does not turn into a stream of malformed
 * frames on the safety-relevant channel -- it is hygiene, not authority.
 *
 * THE WIRE FORMAT
 * ----------------
 * 32 bytes, little-endian.  Keep this layout aligned with
 * docs/GOVERNOR_PROTOCOL_V2.md and with the policy's packer in
 * guest/latch_guest_init.c (pack_governor_frame).
 *
 *   offset  size  field
 *   ------  ----  --------------------------------------------------
 *        0     4  magic          0x4C415448 ("LATH")
 *        4     2  version        2
 *        6     1  joint          0
 *        7     1  kind           1=HEARTBEAT 2=CMD_V2 3=SHRINK_REQ
 *        8     4  seq            monotonic per session, starts at 1
 *       12     4  value          int32, the commanded quantity
 *       16     4  crc32          IEEE CRC-32 over bytes [0..15]+[20..31]
 *       20     4  confidence_q8  0..255 (the low byte is the confidence)
 *       24     1  agent_state
 *       25     3  coherence      24-bit
 *       28     4  unit_id
 */

#ifndef LATCH_ACTION_H
#define LATCH_ACTION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------- */
/* The action schema                                                      */
/* ---------------------------------------------------------------------- */

/*
 * The schema, exactly:
 *
 *     {"u_mrad":<int32>,"unit_id":<uint32>,"confidence":<0..255>}
 *
 * The key ORDER is fixed, because the GBNF grammar fixes it too, and
 * because a fixed order keeps the validator a straight-line parser with
 * no backtracking.
 */
#define LATCH_ACTION_MAX_TEXT 256u

typedef struct {
    int32_t  u_mrad;
    uint32_t unit_id;
    uint32_t confidence;
} latch_action_t;

typedef enum {
    LATCH_ACTION_OK = 0,
    /* The text is a valid PREFIX of the schema: keep generating. */
    LATCH_ACTION_INCOMPLETE,
    /* The text is not the schema at all. */
    LATCH_ACTION_ERR_SYNTAX,
    /* A key is present but not the one the schema requires. */
    LATCH_ACTION_ERR_KEY,
    /* A value is not a decimal integer. */
    LATCH_ACTION_ERR_TYPE,
    /* A value is an integer that does not fit its field. */
    LATCH_ACTION_ERR_RANGE
} latch_action_status_t;

/*
 * Parse and validate a candidate action.
 *
 * `text`/`len` need not be NUL-terminated.  `out` is written only when
 * the return value is LATCH_ACTION_OK.
 *
 * The parser is deliberately independent of llama.cpp: it is a second,
 * separate implementation of the schema, so a bug in the grammar cannot
 * silently become the definition of what is acceptable.
 */
latch_action_status_t latch_action_parse(const char *text, size_t len,
                                         latch_action_t *out);

/* A short, stable, human-readable name for a status. Never NULL. */
const char *latch_action_status_str(latch_action_status_t st);

/* ---------------------------------------------------------------------- */
/* The wire-v2 frame                                                      */
/* ---------------------------------------------------------------------- */

#define LATCH_WIRE_V2_SIZE       32u
#define LATCH_WIRE_V2_MAGIC      0x4C415448u   /* "LATH" */
#define LATCH_WIRE_V2_VERSION    2u
#define LATCH_WIRE_V2_JOINT      0u

#define LATCH_GOV_KIND_HEARTBEAT  1u
#define LATCH_GOV_KIND_CMD_V2     2u
#define LATCH_GOV_KIND_SHRINK_REQ 3u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint8_t  joint;
    uint8_t  kind;
    uint32_t seq;
    int32_t  value;
    uint32_t crc32;
    uint32_t confidence_q8;
    uint8_t  agent_state;
    uint8_t  coherence[3];
    uint32_t unit_id;
} latch_wire_v2_t;

/* IEEE CRC-32 (reflected, polynomial 0xEDB88320, init/final 0xFFFFFFFF). */
uint32_t latch_crc32_ieee(const uint8_t *buf, size_t len);

/* Pack a frame, little-endian, with the CRC already computed. */
void latch_wire_v2_pack(uint8_t *frame,
                        uint8_t  kind,
                        uint32_t seq,
                        uint32_t coherence,
                        int32_t  value,
                        uint32_t confidence_q8,
                        uint8_t  agent_state,
                        uint32_t unit_id);

/*
 * Check a received frame: length, magic, version, joint and CRC.
 * Returns 0 when the frame is well formed, and a negative value
 * otherwise.  This is the same structural check the policy applies to
 * the frames it relays.
 */
int latch_wire_v2_check(const uint8_t *frame, size_t len);

/*
 * Re-stamp a frame's sequence number and coherence counter, and
 * recompute its CRC.
 *
 * WHY THE GUEST POLICY RE-STAMPS
 * ------------------------------
 * The in-guest policy is the ONLY writer on the guest's virtio-console,
 * so it -- not the inference child -- owns the wire's sequence number
 * and coherence counter.  The reason is concrete: the supervisor's
 * deadman requires `warmup_heartbeats` heartbeats BEFORE the first
 * command is admissible, and it rejects a frame whose coherence counter
 * jumps by more than `coherence_max_gap`.  If the policy sent warm-up
 * heartbeats with its own counters and then relayed the child's frame
 * verbatim, the child's coherence counter (which starts at zero) would
 * be a huge backwards jump from the policy's -- and the supervisor would
 * reject the command as incoherent.
 *
 * So the child's seq/coherence are internal to the guest, and the
 * policy stamps them on the way out.  The child's payload (the
 * commanded value, the confidence, the agent state and the unit id) is
 * relayed UNCHANGED.
 */
void latch_wire_v2_restamp(uint8_t *frame, uint32_t seq, uint32_t coherence);

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* LATCH_ACTION_H */
