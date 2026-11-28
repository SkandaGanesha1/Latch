/*
 * qnx/latch_hex.h
 *
 * THE HEX RENDERING, WITH A BOUNDS CHECK
 * ======================================
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * Two translation units render bytes as lowercase hex: `latchctl` (which
 * prints the governor event ring as JSON) and `latchd` (which writes the
 * same JSON into a file for the evidence archive).  Both used to declare
 * their output buffer with a LITERAL length:
 *
 *     char ev_hex[125];      // 62 bytes of event -> 124 hex chars + NUL
 *     char sha_hex[65];      // 32 bytes of digest -> 64 hex chars + NUL
 *
 * The literals were RIGHT, and that is exactly the problem: they were
 * right by coincidence.  The buffer's size is a fact about the EVENT
 * STRUCT and about the DIGEST LENGTH, and it was written down a third
 * time.  Add a field to `latch_gov_event_t`, update its `_Static_assert`
 * -- which is a natural thing to do, because the assert says "must be 62
 * bytes" -- and `ev_hex[125]` is one field too small.  The rendering then
 * writes `2 * 64 + 1 = 129` bytes into a 125-byte stack buffer.
 *
 * The size is now DERIVED, twice over:
 *
 *     LATCH_GOV_EVENT_HEX_CHARS  = sizeof(latch_gov_event_t) * 2 + 1
 *     LATCH_SHA256_HEX_CHARS     = LATCH_SHA256_BYTES * 2 + 1
 *
 * And the renderer itself takes the buffer's CAPACITY and refuses a buffer
 * that is too small, so a caller that gets the size wrong gets a REFUSAL
 * instead of a stack overflow.  A renderer that cannot overflow is worth
 * more than a renderer that is currently given enough room.
 *
 * It is a header because the property has to be reachable from a host
 * test: `qnx/latch_hex_test.c` compiles this file and RUNS it.
 */

#ifndef LATCH_HEX_H_
#define LATCH_HEX_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Render `len` bytes as lowercase hex into `out`.
 *
 * `out_cap` is the capacity of `out` IN BYTES, INCLUDING the terminating
 * NUL.  The rendering needs `len * 2 + 1` bytes.
 *
 * Returns true when the bytes were rendered, false when the buffer is too
 * small -- and on refusal the buffer is left UNTOUCHED, so a caller that
 * ignores the result prints nothing rather than printing garbage.
 *
 * The capacity check is the point of this function: a hex renderer that
 * trusts its caller is a stack overflow waiting for the day the caller's
 * struct grows.
 */
static inline bool latch_bytes_to_hex(const uint8_t *bytes, size_t len,
                                      char *out, size_t out_cap) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (out == NULL || out_cap == 0u) {
        return false;
    }
    if (bytes == NULL && len != 0u) {
        return false;
    }
    /* The overflow-safe form of `len * 2 + 1 > out_cap`. */
    if (len > (out_cap - 1u) / 2u) {
        return false;
    }

    for (i = 0u; i < len; ++i) {
        out[i * 2u] = digits[(bytes[i] >> 4) & 0x0Fu];
        out[i * 2u + 1u] = digits[bytes[i] & 0x0Fu];
    }
    out[len * 2u] = '\0';
    return true;
}

#endif /* LATCH_HEX_H_ */
