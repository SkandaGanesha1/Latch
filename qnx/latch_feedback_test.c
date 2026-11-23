#include "latch_feedback.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    latch_feedback_t sent = { .seq = 0x12345678u, .verdict = 1u, .rung = 3u,
                              .fault_bits = 0x2000u, .fault_bits2 = 2u };
    latch_feedback_t got;
    uint8_t raw[LATCH_FEEDBACK_SIZE];
    if (latch_feedback_encode(&sent) != 0) return 1;
    memcpy(raw, &sent, sizeof(raw));
    if (latch_feedback_decode(raw, sizeof(raw), &got) != 0 || got.seq != sent.seq ||
        got.rung != sent.rung || got.fault_bits != sent.fault_bits || got.fault_bits2 != 2u) {
        fprintf(stderr, "FAIL: supervisor feedback frame round-trip\n"); return 1;
    }
    if (latch_feedback_decode_for_seq(raw, sizeof(raw), sent.seq, &got) != 0 ||
        latch_feedback_decode_for_seq(raw, sizeof(raw), sent.seq + 1u, &got) != -ESTALE) {
        fprintf(stderr, "FAIL: feedback proposal sequence correlation\n"); return 1;
    }
    raw[7]++;
    if (latch_feedback_decode(raw, sizeof(raw), &got) == 0) {
        fprintf(stderr, "FAIL: corrupt feedback CRC was admitted\n"); return 1;
    }
    if (latch_feedback_decode(&sent, sizeof(sent) - 1u, &got) == 0) {
        fprintf(stderr, "FAIL: truncated feedback frame was admitted\n"); return 1;
    }
    sent.flags = 2u;
    (void)latch_feedback_encode(&sent);
    if (latch_feedback_decode(&sent, sizeof(sent), &got) == 0) {
        fprintf(stderr, "FAIL: unknown feedback flags were admitted\n"); return 1;
    }
    memset(&sent, 0, sizeof(sent));
    sent.seq = 19u;
    sent.verdict = 0xFFu;
    sent.rung = 0xFFu;
    sent.flags = LATCH_FEEDBACK_FLAG_TIMEOUT;
    if (latch_feedback_encode(&sent) != 0 ||
        latch_feedback_decode_for_seq(&sent, sizeof(sent), sent.seq, &got) != 0 ||
        got.flags != LATCH_FEEDBACK_FLAG_TIMEOUT || got.verdict != 0xFFu || got.rung != 0xFFu) {
        fprintf(stderr, "FAIL: canonical supervisor-timeout response\n"); return 1;
    }
    sent.verdict = 0u;
    if (latch_feedback_encode(&sent) != 0 ||
        latch_feedback_decode(&sent, sizeof(sent), &got) == 0) {
        fprintf(stderr, "FAIL: non-canonical timeout carried a fabricated verdict\n"); return 1;
    }
    puts("[LATCH_FEEDBACK] PASS: exact-size, CRC, reserved flags, sequence correlation and explicit timeout");
    return 0;
}
