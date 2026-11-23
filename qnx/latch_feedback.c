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

int latch_feedback_decode(const void *bytes, size_t size, latch_feedback_t *out) {
    if (bytes == NULL || out == NULL || size != LATCH_FEEDBACK_SIZE) return -EINVAL;
    latch_feedback_t frame;
    memcpy(&frame, bytes, sizeof(frame));
    if (frame.magic != LATCH_FEEDBACK_MAGIC || frame.version != LATCH_FEEDBACK_VERSION ||
        frame.size != LATCH_FEEDBACK_SIZE || frame.flags & (uint16_t)~LATCH_FEEDBACK_FLAG_TIMEOUT ||
        frame.crc32 != latch_crc32_ieee(&frame, offsetof(latch_feedback_t, crc32))) return -EBADMSG;
    /* Timeout is an explicit absence of a supervisor verdict, never a verdict
     * synthesized by the transport. Keep its wire representation canonical. */
    if ((frame.flags & LATCH_FEEDBACK_FLAG_TIMEOUT) != 0u &&
        (frame.verdict != 0xFFu || frame.rung != 0xFFu ||
         frame.fault_bits != 0u || frame.fault_bits2 != 0u)) return -EBADMSG;
    *out = frame;
    return 0;
}

int latch_feedback_decode_for_seq(const void *bytes, size_t size,
                                  uint32_t expected_seq, latch_feedback_t *out) {
    int rc = latch_feedback_decode(bytes, size, out);
    if (rc != 0) return rc;
    return out->seq == expected_seq ? 0 : -ESTALE;
}
