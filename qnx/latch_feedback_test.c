#include "latch_feedback.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", (msg)); return 1; } while (0)

int main(void) {
    latch_feedback_t sent = { .seq = 0x12345678u, .session_epoch = 0xB7BA19BDu,
                              .verdict = 1u, .rung = 3u,
                              .fault_bits = 0x2000u, .fault_bits2 = 2u };
    latch_feedback_t got;
    uint8_t raw[LATCH_FEEDBACK_SIZE];

    /* The frame is 28 bytes and the epoch sits beside the sequence number:
     * that is what makes the verdict correlatable with the proposal it
     * answers, across a session handoff. */
    if (sizeof(latch_feedback_t) != 28u) FAIL("the feedback frame is not 28 bytes");
    if (offsetof(latch_feedback_t, session_epoch) != 12u) FAIL("the epoch is not at offset 12");
    if (offsetof(latch_feedback_t, crc32) != 24u) FAIL("the CRC is not at offset 24");

    if (latch_feedback_encode(&sent) != 0) FAIL("encode");
    memcpy(raw, &sent, sizeof(raw));
    if (latch_feedback_decode(raw, sizeof(raw), &got) != 0 || got.seq != sent.seq ||
        got.session_epoch != sent.session_epoch ||
        got.rung != sent.rung || got.fault_bits != sent.fault_bits || got.fault_bits2 != 2u) {
        FAIL("supervisor feedback frame round-trip");
    }

    /* The sequence number alone is NOT a correlation. */
    if (latch_feedback_decode_for_seq(raw, sizeof(raw), sent.seq, &got) != 0 ||
        latch_feedback_decode_for_seq(raw, sizeof(raw), sent.seq + 1u, &got) != -ESTALE) {
        FAIL("feedback proposal sequence correlation");
    }

    /* The full correlation needs BOTH the sequence number and the epoch. */
    if (latch_feedback_decode_for_proposal(raw, sizeof(raw), sent.seq,
                                           sent.session_epoch, &got) != 0) {
        FAIL("feedback proposal+epoch correlation (matching)");
    }
    if (latch_feedback_decode_for_proposal(raw, sizeof(raw), sent.seq + 1u,
                                           sent.session_epoch, &got) != -ESTALE) {
        FAIL("feedback proposal+epoch correlation (wrong sequence)");
    }
    if (latch_feedback_decode_for_proposal(raw, sizeof(raw), sent.seq,
                                           sent.session_epoch + 1u, &got) != -ESTALE) {
        FAIL("feedback proposal+epoch correlation (wrong epoch)");
    }

    raw[7]++;
    if (latch_feedback_decode(raw, sizeof(raw), &got) == 0) {
        FAIL("corrupt feedback CRC was admitted");
    }

    if (latch_feedback_decode(&sent, sizeof(sent) - 1u, &got) == 0) {
        FAIL("truncated feedback frame was admitted");
    }

    sent.flags = 2u;
    (void)latch_feedback_encode(&sent);
    if (latch_feedback_decode(&sent, sizeof(sent), &got) == 0) {
        FAIL("unknown feedback flags were admitted");
    }

    /* Epoch 0 belongs to no session and must never be admitted. */
    memset(&sent, 0, sizeof(sent));
    sent.seq = 19u;
    sent.session_epoch = 0u;
    sent.verdict = 1u;
    if (latch_feedback_encode(&sent) != 0 ||
        latch_feedback_decode(&sent, sizeof(sent), &got) == 0) {
        FAIL("a zero session epoch was admitted");
    }

    memset(&sent, 0, sizeof(sent));
    sent.seq = 19u;
    sent.session_epoch = 0x11223344u;
    sent.verdict = 0xFFu;
    sent.rung = 0xFFu;
    sent.flags = LATCH_FEEDBACK_FLAG_TIMEOUT;
    if (latch_feedback_encode(&sent) != 0 ||
        latch_feedback_decode_for_proposal(&sent, sizeof(sent), sent.seq,
                                           sent.session_epoch, &got) != 0 ||
        got.flags != LATCH_FEEDBACK_FLAG_TIMEOUT || got.verdict != 0xFFu || got.rung != 0xFFu) {
        FAIL("canonical supervisor-timeout response");
    }
    sent.verdict = 0u;
    if (latch_feedback_encode(&sent) != 0 ||
        latch_feedback_decode(&sent, sizeof(sent), &got) == 0) {
        FAIL("non-canonical timeout carried a fabricated verdict");
    }

    /* A version-1 frame (the pre-epoch 24-byte layout) must NOT be admitted
     * as a version-2 frame: the layout changed and the change is explicit
     * on the wire. */
    {
        uint8_t v1[LATCH_FEEDBACK_SIZE];
        memset(v1, 0, sizeof(v1));
        v1[0] = 0x4Cu; v1[1] = 0x46u; v1[2] = 0x42u; v1[3] = 0x4Bu; /* "LFBK" */
        v1[4] = 1u; v1[5] = 0u;                                     /* version 1 */
        v1[6] = 24u; v1[7] = 0u;                                    /* size 24 */
        if (latch_feedback_decode(v1, sizeof(v1), &got) == 0) {
            FAIL("a version-1 feedback frame was admitted as version 2");
        }
    }

    puts("[LATCH_FEEDBACK] PASS: 28-byte frame, session epoch, CRC, reserved flags, "
         "sequence+epoch correlation, zero-epoch rejection, explicit timeout, "
         "version-1 rejection");
    return 0;
}
