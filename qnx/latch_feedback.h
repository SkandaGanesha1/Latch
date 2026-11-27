#ifndef LATCH_FEEDBACK_H_
#define LATCH_FEEDBACK_H_

#include <stddef.h>
#include <stdint.h>

#define LATCH_FEEDBACK_MAGIC 0x4B42464Cu /* little-endian "LFBK" */
/* Version 2: the frame grew from 24 to 28 bytes so that it carries the
 * SESSION EPOCH beside the proposal sequence number.  A v1 frame is not
 * accepted as a v2 frame -- the size field and the version field are both
 * checked, and the version bump is what makes the change explicit on the
 * wire. */
#define LATCH_FEEDBACK_VERSION 2u
#define LATCH_FEEDBACK_SIZE 28u
#define LATCH_FEEDBACK_FLAG_TIMEOUT 0x0001u

/*
 * THE VERDICT VOCABULARY
 * ----------------------
 * The verdict is ADVISORY to the guest: it tells the guest whether its
 * proposal was accepted, so a guest that is told "no" stops proposing
 * instead of guessing.  It is NOT an authorisation.  The guest cannot
 * actuate anything, and the supervisor's decision does not depend on the
 * guest believing it -- the guest's only power over the plant is to stop
 * asking, which is the fail-closed direction.
 *
 * The vocabulary is CLOSED, and that is a safety property rather than a
 * tidiness convention.  A verdict the receiver does not understand must be
 * REJECTED, not guessed at: "I did not understand what the supervisor said"
 * is emphatically not "the supervisor said yes".  The decoder therefore
 * refuses any verdict outside this set, and the guest's decoder treats an
 * unrecognised verdict exactly like a rejection.
 *
 * The timeout verdict is the ABSENCE of a verdict, so it is only legal
 * WITH the timeout flag, and it carries no rung and no fault bits: a
 * timeout that also reported a rung would be claiming a decision it did
 * not make.
 */
#define LATCH_FEEDBACK_VERDICT_ACCEPT  0x01u
#define LATCH_FEEDBACK_VERDICT_REJECT  0x02u
#define LATCH_FEEDBACK_VERDICT_TIMEOUT 0xFFu

/*
 * The governor rung the decision was taken at.  The rungs are policy state
 * (qnx/governor_policy.h): 0 = HP, 1 = ADVISE, 2 = CLAMP, 3 = SLOW,
 * 4 = SAFE_STOP, 5 = LATCH.  The frame carries the rung so the guest can
 * SEE that the supervisor has demoted itself, which is information the
 * guest cannot derive on its own.
 */
#define LATCH_FEEDBACK_RUNG_MIN 0u
#define LATCH_FEEDBACK_RUNG_MAX 5u

/*
 * THE WIRE LAYOUT
 * ----------------
 *   0  uint32 magic          "LFBK"
 *   4  uint16 version        2
 *   6  uint16 size           28
 *   8  uint32 seq            the proposal's sequence number
 *  12  uint32 session_epoch  the producer's session epoch (never 0)
 *  16  uint8  verdict        ACCEPT / REJECT / ...
 *  17  uint8  rung           the supervisor's rung at the decision
 *  18  uint16 fault_bits     the low fault bits
 *  20  uint16 fault_bits2    the high fault bits
 *  22  uint16 flags          LATCH_FEEDBACK_FLAG_TIMEOUT
 *  24  uint32 crc32          CRC-32/IEEE over bytes [0..23]
 *
 * WHY THE EPOCH IS ON THE FRAME
 * ------------------------------
 * The feedback is CORRELATED with the proposal it answers.  The sequence
 * number alone is not enough: a producer may pick a fresh sequence number
 * after a session handoff while the OLD session's verdict is still in
 * flight, and the guest would then attribute a stale verdict to a fresh
 * proposal.  The RT-02 session epoch (the producer-chosen, supervisor-bound
 * session identifier) is what makes the correlation unambiguous: a verdict
 * is accepted only when BOTH the sequence number and the epoch match the
 * proposal the guest is waiting for.
 *
 * The epoch is an IDENTIFIER, not a secret.  It protects against STALE
 * frames, not against a malicious peer forging a current one -- the guest
 * is untrusted, and the supervisor's verdict is advisory to it.
 */
typedef struct __attribute__((packed)) latch_feedback {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t seq;
    uint32_t session_epoch;
    uint8_t verdict;
    uint8_t rung;
    uint16_t fault_bits;
    uint16_t fault_bits2;
    uint16_t flags;
    uint32_t crc32;
} latch_feedback_t;

_Static_assert(sizeof(latch_feedback_t) == LATCH_FEEDBACK_SIZE,
               "latch_feedback_t must be a fixed 28-byte frame");
_Static_assert(offsetof(latch_feedback_t, session_epoch) == 12u,
               "the session epoch must sit beside the sequence number");
_Static_assert(offsetof(latch_feedback_t, crc32) == 24u,
               "feedback CRC must cover the first 24 bytes");

int latch_feedback_encode(latch_feedback_t *frame);
int latch_feedback_decode(const void *bytes, size_t size, latch_feedback_t *out);
int latch_feedback_decode_for_seq(const void *bytes, size_t size,
                                  uint32_t expected_seq, latch_feedback_t *out);
int latch_feedback_decode_for_proposal(const void *bytes, size_t size,
                                       uint32_t expected_seq,
                                       uint32_t expected_epoch,
                                       latch_feedback_t *out);
/* Is this a verdict the receiver is allowed to understand?  A receiver that
 * is handed anything else must treat it as a rejection. */
int latch_feedback_verdict_is_known(uint8_t verdict);

#endif
