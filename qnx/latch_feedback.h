#ifndef LATCH_FEEDBACK_H_
#define LATCH_FEEDBACK_H_

#include <stddef.h>
#include <stdint.h>

#define LATCH_FEEDBACK_MAGIC 0x4B42464Cu /* little-endian "LFBK" */
#define LATCH_FEEDBACK_VERSION 1u
#define LATCH_FEEDBACK_SIZE 24u
#define LATCH_FEEDBACK_FLAG_TIMEOUT 0x0001u

typedef struct __attribute__((packed)) latch_feedback {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t seq;
    uint8_t verdict;
    uint8_t rung;
    uint16_t fault_bits;
    uint16_t fault_bits2;
    uint16_t flags;
    uint32_t crc32;
} latch_feedback_t;

_Static_assert(sizeof(latch_feedback_t) == LATCH_FEEDBACK_SIZE,
               "latch_feedback_t must be a fixed 24-byte frame");
_Static_assert(offsetof(latch_feedback_t, crc32) == 20u,
               "feedback CRC must cover the first 20 bytes");

int latch_feedback_encode(latch_feedback_t *frame);
int latch_feedback_decode(const void *bytes, size_t size, latch_feedback_t *out);
int latch_feedback_decode_for_seq(const void *bytes, size_t size,
                                  uint32_t expected_seq, latch_feedback_t *out);

#endif
