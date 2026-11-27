#include "latch_feedback.h"
#include "latch_protocol.h"

#include <errno.h>
#include <string.h>

int latch_feedback_encode(latch_feedback_t *frame) {
    if (frame == NULL) return -EINVAL;
    frame->magic = LATCH_FEEDBACK_MAGIC;
    frame->version = LATCH_FEEDBACK_VERSION;
    frame->size = LATCH_FEEDBACK_SIZE;
    frame->crc32 = latch_crc32_ieee(frame, offsetof(latch_feedback_t, crc32));
    return 0;
}

int latch_feedback_verdict_is_known(uint8_t verdict) {
    return verdict == (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT ||
           verdict == (uint8_t)LATCH_FEEDBACK_VERDICT_REJECT ||
           verdict == (uint8_t)LATCH_FEEDBACK_VERDICT_TIMEOUT;
}

int latch_feedback_decode(const void *bytes, size_t size, latch_feedback_t *out) {
    if (bytes == NULL || out == NULL || size != LATCH_FEEDBACK_SIZE) return -EINVAL;
    latch_feedback_t frame;
    memcpy(&frame, bytes, sizeof(frame));
    if (frame.magic != LATCH_FEEDBACK_MAGIC || frame.version != LATCH_FEEDBACK_VERSION ||
        frame.size != LATCH_FEEDBACK_SIZE || frame.flags & (uint16_t)~LATCH_FEEDBACK_FLAG_TIMEOUT ||
        frame.crc32 != latch_crc32_ieee(&frame, offsetof(latch_feedback_t, crc32))) return -EBADMSG;
    /* The epoch is never 0: the supervisor binds a producer-chosen, non-zero
     * session epoch, and a frame that claims epoch 0 belongs to no session.
     * Rejecting it here means a frame can never be attributed to the wrong
     * session by accident. */
    if (frame.session_epoch == 0u) return -EBADMSG;
    /* THE VERDICT VOCABULARY IS CLOSED.
     *
     * A receiver must never GUESS at a verdict it does not understand: the
     * whole point of the channel is that "the supervisor said no" stops the
     * guest, and a guess in the other direction is the one failure this
     * channel must not have.  An unknown verdict is therefore a framing
     * error, exactly like a bad CRC. */
    if (!latch_feedback_verdict_is_known(frame.verdict)) return -EBADMSG;
    /* Timeout is an explicit absence of a supervisor verdict, never a verdict
     * synthesized by the transport. Keep its wire representation canonical:
     * the flag, the verdict and the rung agree, and it carries no faults. */
    if ((frame.flags & LATCH_FEEDBACK_FLAG_TIMEOUT) != 0u) {
        if (frame.verdict != (uint8_t)LATCH_FEEDBACK_VERDICT_TIMEOUT ||
            frame.rung != (uint8_t)LATCH_FEEDBACK_VERDICT_TIMEOUT ||
            frame.fault_bits != 0u || frame.fault_bits2 != 0u) return -EBADMSG;
    } else if (frame.verdict == (uint8_t)LATCH_FEEDBACK_VERDICT_TIMEOUT) {
        /* The timeout verdict WITHOUT the timeout flag is not canonical: a
         * receiver that honoured it would stop the guest on a frame that
         * never claimed to be a timeout. */
        return -EBADMSG;
    }
    *out = frame;
    return 0;
}

int latch_feedback_decode_for_seq(const void *bytes, size_t size,
                                  uint32_t expected_seq, latch_feedback_t *out) {
    int rc = latch_feedback_decode(bytes, size, out);
    if (rc != 0) return rc;
    return out->seq == expected_seq ? 0 : -ESTALE;
}

int latch_feedback_decode_for_proposal(const void *bytes, size_t size,
                                       uint32_t expected_seq,
                                       uint32_t expected_epoch,
                                       latch_feedback_t *out) {
    int rc = latch_feedback_decode(bytes, size, out);
    if (rc != 0) return rc;
    /* Both halves of the correlation must match.  A sequence number alone is
     * not a correlation: after a session handoff the producer starts a new
     * sequence run while the previous session's verdict may still be in
     * flight, and the guest would then attribute a stale verdict to a fresh
     * proposal. */
    if (out->seq != expected_seq || out->session_epoch != expected_epoch) return -ESTALE;
    return 0;
}
