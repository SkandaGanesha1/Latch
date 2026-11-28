/*
 * qnx/latch_hex_test.c
 *
 * THE HOST-SIM TEST FOR THE HEX RENDERING
 * =======================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * Two translation units render bytes as lowercase hex: `latchctl` (which
 * prints the governor event ring as JSON) and `latchd` (which writes the
 * same JSON into the evidence archive).  Both used to declare their output
 * buffer with a LITERAL length -- `char ev_hex[125]` and `char sha_hex[65]`
 * -- which were right BY COINCIDENCE: the buffer's size is a fact about
 * the event struct and about the digest length, and it had been written
 * down a third time.
 *
 * Add a field to `latch_gov_event_t`, update its `_Static_assert` -- a
 * natural thing to do, because the assert says "must be 62 bytes" -- and
 * the old buffer is one field too small.  The rendering then writes
 * 2 * 64 + 1 = 129 bytes into a 125-byte stack buffer.
 *
 * Two things fix that:
 *
 *   1. the buffer's size is DERIVED (`LATCH_GOV_EVENT_HEX_CHARS`), so it
 *      cannot drift away from the struct it renders; and
 *   2. the renderer CHECKS ITS OWN CAPACITY, so a caller that gets the
 *      size wrong gets a REFUSAL instead of a stack overflow.
 *
 * The second is the one this test proves, because it is the one that is a
 * property rather than a derivation: a hex renderer that trusts its caller
 * is a stack overflow waiting for the day the caller's struct grows.
 *
 * It runs on the host, so it is part of `make check-governor` and it runs
 * in CI.
 */

#include "latch_hex.h"
#include "latch_protocol.h"

#include <stdio.h>
#include <string.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int ok, const char *what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        printf("  FAIL: %s\n", what);
    }
}

/* A KNOWN VECTOR.  The digest of the empty string is a standard test
 * vector, and the rendering of a few bytes catches every nibble swap. */
static void test_the_rendering_is_correct(void) {
    static const uint8_t zeros[4] = {0x00u, 0x01u, 0x0fu, 0xffu};
    char out[16];

    check(latch_bytes_to_hex(zeros, sizeof(zeros), out, sizeof(out)),
          "a buffer that is big enough is accepted");
    check(strcmp(out, "00010fff") == 0,
          "the rendering is lowercase hex, two characters per byte, in "
          "order");

    static const uint8_t empty[1] = {0u};
    check(latch_bytes_to_hex(empty, 0u, out, sizeof(out)),
          "rendering zero bytes is accepted");
    check(out[0] == '\0',
          "rendering zero bytes produces an empty string");

    static const uint8_t digest[32] = {
        0xe3u, 0xb0u, 0xc4u, 0x42u, 0x98u, 0xfcu, 0x1cu, 0x14u,
        0x9au, 0xfbu, 0xf4u, 0xc8u, 0x99u, 0x6fu, 0xb9u, 0x24u,
        0x27u, 0xaeu, 0x41u, 0xe4u, 0x64u, 0x9bu, 0x93u, 0x4cu,
        0xa4u, 0x95u, 0x99u, 0x1bu, 0x78u, 0x52u, 0xb8u, 0x55u
    };
    char sha[LATCH_SHA256_HEX_CHARS];
    check(latch_bytes_to_hex(digest, sizeof(digest), sha, sizeof(sha)),
          "a SHA-256 digest renders into its derived buffer");
    check(strcmp(sha,
                 "e3b0c44298fc1c149afbf4c8996fb924"
                 "27ae41e4649b934ca495991b7852b855") == 0,
          "the digest renders as the standard hex of the standard bytes");
    check(strlen(sha) == LATCH_SHA256_HEX_CHARS - 1u,
          "the rendering is exactly one character per nibble, with no "
          "padding and no truncation");
}

/*
 * THE BOUNDS CHECK.
 *
 * A buffer that is ONE BYTE too small must be refused -- and refused
 * WITHOUT being written, so a caller that ignores the result prints
 * nothing rather than printing whatever was on the stack.
 */
static void test_a_too_small_buffer_is_refused(void) {
    static const uint8_t data[4] = {0xdeu, 0xadu, 0xbeu, 0xefu};
    char out[16];

    /* Exactly enough: 4 bytes -> 8 characters + NUL = 9. */
    check(latch_bytes_to_hex(data, sizeof(data), out, 9u),
          "a buffer of exactly the needed size is accepted");
    check(strcmp(out, "deadbeef") == 0, "and the rendering is correct");

    /* One byte too small. */
    memset(out, 0x5a, sizeof(out));
    check(!latch_bytes_to_hex(data, sizeof(data), out, 8u),
          "a buffer ONE BYTE too small is REFUSED");
    check(out[0] == (char)0x5a && out[8] == (char)0x5a,
          "a refused rendering leaves the buffer UNTOUCHED");

    /* Half the size. */
    memset(out, 0x5a, sizeof(out));
    check(!latch_bytes_to_hex(data, sizeof(data), out, 4u),
          "a buffer half the needed size is REFUSED");
    check(out[0] == (char)0x5a,
          "a refused rendering still leaves the buffer untouched");

    /* The classic overflow trap: a length that overflows `len * 2 + 1`. */
    memset(out, 0x5a, sizeof(out));
    check(!latch_bytes_to_hex(data, (size_t)-1, out, sizeof(out)),
          "a length that would overflow the size computation is REFUSED");
    check(out[0] == (char)0x5a,
          "the overflow case leaves the buffer untouched too");
}

/* IT FAILS CLOSED ON A BUFFER IT CANNOT USE. */
static void test_it_fails_closed(void) {
    static const uint8_t data[2] = {0x01u, 0x02u};
    char out[8];

    check(!latch_bytes_to_hex(data, sizeof(data), NULL, 8u),
          "a NULL output buffer is REFUSED");
    check(!latch_bytes_to_hex(data, sizeof(data), out, 0u),
          "a zero-capacity output buffer is REFUSED");
    check(!latch_bytes_to_hex(NULL, 2u, out, sizeof(out)),
          "a NULL input with a non-zero length is REFUSED");
    check(latch_bytes_to_hex(NULL, 0u, out, sizeof(out)),
          "a NULL input with a zero length is accepted (there is nothing to "
          "render)");
}

/*
 * THE DERIVED SIZES AGREE WITH THE THINGS THEY RENDER.
 *
 * The event's hex buffer is sized from the EVENT, and the digest's from
 * the DIGEST LENGTH -- so a change to either is carried into the buffer
 * automatically.  These checks are what make the derivation visible.
 */
static void test_the_derived_sizes_agree(void) {
    char ev[LATCH_GOV_EVENT_HEX_CHARS];
    latch_gov_event_t event;
    memset(&event, 0, sizeof(event));

    check(LATCH_GOV_EVENT_HEX_CHARS == sizeof(event) * 2u + 1u,
          "the event's hex buffer is sized from the EVENT itself");
    check(latch_bytes_to_hex((const uint8_t *)&event, sizeof(event),
                             ev, sizeof(ev)),
          "the whole event fits its derived hex buffer");
    check(strlen(ev) == sizeof(event) * 2u,
          "the rendering covers every byte of the event");

    char sha[LATCH_SHA256_HEX_CHARS];
    uint8_t digest[LATCH_SHA256_BYTES];
    memset(digest, 0xa5, sizeof(digest));
    check(latch_bytes_to_hex(digest, sizeof(digest), sha, sizeof(sha)),
          "the digest fits its derived hex buffer");
    check(strlen(sha) == LATCH_SHA256_BYTES * 2u,
          "the digest's rendering covers every byte of the digest");
}

int main(void) {
    printf("[LATCH_HEX] the hex rendering must be correct AND must refuse "
           "a buffer that is too small\n");

    test_the_rendering_is_correct();
    test_a_too_small_buffer_is_refused();
    test_it_fails_closed();
    test_the_derived_sizes_agree();

    if (g_failures == 0) {
        printf("[LATCH_HEX] PASS: %d checks, 0 failures -- the rendering is "
               "correct, and a buffer that is one byte too small is refused "
               "instead of overflowing\n", g_checks);
        return 0;
    }
    printf("[LATCH_HEX] FAIL: %d checks, %d failure(s)\n",
           g_checks, g_failures);
    return 1;
}
