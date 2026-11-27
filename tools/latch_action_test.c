/*
 * tools/latch_action_test.c -- the host-side regression test for the
 * in-guest action validator and the wire-v2 packer.
 *
 * WHY A SEPARATE TEST
 * -------------------
 * The action validator is the gate between a language model and the
 * safety-relevant channel, and it is the piece that a CI runner can
 * actually check: it has no llama.cpp dependency, so it compiles and
 * runs on any host in a second.  The parts of W6 that need an AArch64
 * cross toolchain (llama.cpp, the inference binary) are NOT covered by
 * this test -- they are covered by the on-target transcript.
 *
 * WHAT IS ASSERTED
 * ----------------
 *   1. the schema: well-formed actions parse, and every malformed shape
 *      is rejected with the right status;
 *   2. the wire-v2 packer: the byte layout is exactly the documented
 *      one, the CRC is the IEEE CRC-32, and the checker accepts a good
 *      frame and rejects every corrupted one;
 *   3. the CRC covers bytes [0..15] + [20..31] and NOT the CRC field
 *      itself -- a frame whose CRC field is corrupted must fail.
 */

#include <stdio.h>
#include <string.h>

#include "../guest/latch_action.h"

static int g_failures = 0;
static int g_checks = 0;

static void check(int cond, const char *what) {
    g_checks++;
    if (!cond) {
        g_failures++;
        printf("[FAIL] %s\n", what);
    }
}

static latch_action_status_t parse(const char *s) {
    latch_action_t a;
    return latch_action_parse(s, strlen(s), &a);
}

static void expect(const char *text, latch_action_status_t want, const char *what) {
    latch_action_status_t got = parse(text);
    if (got != want) {
        g_checks++;
        g_failures++;
        printf("[FAIL] %s: '%s' -> %s, expected %s\n",
               what, text, latch_action_status_str(got), latch_action_status_str(want));
        return;
    }
    g_checks++;
}

/* ---------------------------------------------------------------------- */

static void test_schema(void) {
    latch_action_t a;

    /* The canonical shape. */
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":210}", LATCH_ACTION_OK,
           "canonical action");
    expect("{\"u_mrad\":0,\"unit_id\":1,\"confidence\":0}", LATCH_ACTION_OK,
           "zero values");
    expect("{\"u_mrad\":-2147483648,\"unit_id\":4294967295,\"confidence\":255}",
           LATCH_ACTION_OK, "extreme but representable values");
    expect("{\"u_mrad\":2147483647,\"unit_id\":0,\"confidence\":255}",
           LATCH_ACTION_OK, "int32 max");

    /* Whitespace around the separators is tolerated. */
    expect("{\"u_mrad\" : -20 , \"unit_id\" : 1 , \"confidence\" : 210 }",
           LATCH_ACTION_OK, "whitespace tolerated");

    /* Truncated prefixes are INCOMPLETE, not errors: the generator uses
     * that to know when to keep sampling. */
    expect("", LATCH_ACTION_INCOMPLETE, "empty text");
    expect("{", LATCH_ACTION_INCOMPLETE, "open brace only");
    expect("{\"u_mrad\":", LATCH_ACTION_INCOMPLETE, "after the first colon");
    expect("{\"u_mrad\":-2", LATCH_ACTION_INCOMPLETE, "truncated number");
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":", LATCH_ACTION_INCOMPLETE,
           "truncated before the last value");
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":210",
           LATCH_ACTION_INCOMPLETE, "truncated before the closing brace");

    /* Wrong shape. */
    expect("not json", LATCH_ACTION_ERR_SYNTAX, "free text");
    expect("[]", LATCH_ACTION_ERR_SYNTAX, "an array");
    expect("{\"u_rad\":-20,\"unit_id\":1,\"confidence\":210}", LATCH_ACTION_ERR_KEY,
           "a misspelled key");
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":210,\"extra\":1}",
           LATCH_ACTION_ERR_KEY, "an extra key");

    /* Wrong types. */
    expect("{\"u_mrad\":-20.5,\"unit_id\":1,\"confidence\":210}", LATCH_ACTION_ERR_TYPE,
           "a fractional value");
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":true}", LATCH_ACTION_ERR_TYPE,
           "a boolean value");
    expect("{\"u_mrad\":-20,\"unit_id\":1,\"confidence\":007}", LATCH_ACTION_ERR_TYPE,
           "a leading zero");
    expect("{\"u_mrad\":+20,\"unit_id\":1,\"confidence\":210}", LATCH_ACTION_ERR_TYPE,
           "a leading plus");

    /* Out of range. */
    expect("{\"u_mrad\":2147483648,\"unit_id\":1,\"confidence\":210}",
           LATCH_ACTION_ERR_RANGE, "int32 overflow");
    expect("{\"u_mrad\":-2147483649,\"unit_id\":1,\"confidence\":210}",
           LATCH_ACTION_ERR_RANGE, "int32 underflow");
    expect("{\"u_mrad\":20,\"unit_id\":4294967296,\"confidence\":210}",
           LATCH_ACTION_ERR_RANGE, "uint32 overflow");
    expect("{\"u_mrad\":20,\"unit_id\":-1,\"confidence\":210}", LATCH_ACTION_ERR_RANGE,
           "a negative unit id");
    expect("{\"u_mrad\":20,\"unit_id\":1,\"confidence\":256}", LATCH_ACTION_ERR_RANGE,
           "confidence above 255");
    expect("{\"u_mrad\":20,\"unit_id\":1,\"confidence\":-1}", LATCH_ACTION_ERR_RANGE,
           "a negative confidence");

    /* Trailing garbage is rejected: a frame must not be smuggled in
     * behind a valid prefix. */
    expect("{\"u_mrad\":20,\"unit_id\":1,\"confidence\":210} trailing",
           LATCH_ACTION_ERR_SYNTAX, "trailing text");
    expect("{\"u_mrad\":20,\"unit_id\":1,\"confidence\":210}{\"u_mrad\":0}",
           LATCH_ACTION_ERR_SYNTAX, "a second object");

    /* The parsed values are the ones that were written. */
    static const char k_text[] = "{\"u_mrad\":-37,\"unit_id\":3,\"confidence\":128}";
    latch_action_status_t st = latch_action_parse(k_text, sizeof(k_text) - 1u, &a);
    check(st == LATCH_ACTION_OK, "the explicit-length parse succeeds");
    check(a.u_mrad == -37, "u_mrad is parsed");
    check(a.unit_id == 3u, "unit_id is parsed");
    check(a.confidence == 128u, "confidence is parsed");
}

/* The documented byte layout, spelled out. */
static void test_wire_layout(void) {
    uint8_t frame[LATCH_WIRE_V2_SIZE];
    latch_wire_v2_pack(frame, LATCH_GOV_KIND_CMD_V2, 0x01020304u, 0x00010203u,
                       -20, 210u, 1u, 0x0A0B0C0Du);

    /* The magic is the VALUE 0x4C415448 ("LATH" read as a word) stored
     * LITTLE-ENDIAN, exactly as the host's load_le32() reads it. */
    check(frame[0] == 0x48u && frame[1] == 0x54u && frame[2] == 0x41u &&
          frame[3] == 0x4Cu, "the magic is 0x4C415448, little-endian");
    check(frame[4] == 2u && frame[5] == 0u, "the version is 2, little-endian");
    check(frame[6] == 0u, "the joint is 0");
    check(frame[7] == LATCH_GOV_KIND_CMD_V2, "the kind is CMD_V2");

    check(frame[8] == 0x04u && frame[9] == 0x03u && frame[10] == 0x02u &&
          frame[11] == 0x01u, "seq is little-endian");
    check(frame[12] == 0xECu && frame[13] == 0xFFu && frame[14] == 0xFFu &&
          frame[15] == 0xFFu, "the value is -20, little-endian");
    check(frame[20] == 0xD2u && frame[21] == 0x00u && frame[22] == 0x00u &&
          frame[23] == 0x00u, "the confidence is 210, little-endian");
    check(frame[24] == 1u, "the agent state is 1");
    check(frame[25] == 0x03u && frame[26] == 0x02u && frame[27] == 0x01u,
          "the coherence is 24-bit, little-endian");
    check(frame[28] == 0x0Du && frame[29] == 0x0Cu && frame[30] == 0x0Bu &&
          frame[31] == 0x0Au, "the unit id is little-endian");

    check(latch_wire_v2_check(frame, LATCH_WIRE_V2_SIZE) == 0,
          "a freshly packed frame checks out");

    /* The CRC must cover [0..15] and [20..31], and must NOT cover the
     * CRC field itself: corrupting the CRC field has to be detected. */
    uint8_t bad[LATCH_WIRE_V2_SIZE];
    memcpy(bad, frame, sizeof(frame));
    bad[16] ^= 0x01u;
    check(latch_wire_v2_check(bad, sizeof(bad)) != 0,
          "a corrupted CRC field is detected");

    memcpy(bad, frame, sizeof(frame));
    bad[25] ^= 0x01u;
    check(latch_wire_v2_check(bad, sizeof(bad)) != 0,
          "a corrupted coherence byte is detected");

    memcpy(bad, frame, sizeof(frame));
    bad[12] ^= 0x01u;
    check(latch_wire_v2_check(bad, sizeof(bad)) != 0,
          "a corrupted value byte is detected");

    memcpy(bad, frame, sizeof(frame));
    bad[0] = 0x00u;
    check(latch_wire_v2_check(bad, sizeof(bad)) != 0,
          "a corrupted magic is detected");

    memcpy(bad, frame, sizeof(frame));
    bad[4] = 1u;
    check(latch_wire_v2_check(bad, sizeof(bad)) != 0,
          "a wrong version is detected");

    check(latch_wire_v2_check(frame, LATCH_WIRE_V2_SIZE - 1u) != 0,
          "a short frame is rejected");
    check(latch_wire_v2_check(frame, LATCH_WIRE_V2_SIZE + 1u) != 0,
          "a long frame is rejected");
}

/* The CRC must be the IEEE CRC-32, not some other CRC with a similar
 * name. The check value for "123456789" is 0xCBF43926. */
static void test_crc_vector(void) {
    const char *text = "123456789";
    uint32_t crc = latch_crc32_ieee((const uint8_t *)text, strlen(text));
    check(crc == 0xCBF43926u, "the CRC-32 is the IEEE one (check value)");
}

/*
 * The re-stamp path.
 *
 * The guest policy is the only writer on the virtio-console, so it owns
 * the wire's sequence number and coherence counter and stamps them onto
 * the frame the inference child produced.  Two things must hold:
 *
 *   1. the payload (value, confidence, agent state, unit id) survives
 *      the re-stamp UNCHANGED -- the policy is a transport, not a
 *      filter, and the supervisor must see exactly what the model
 *      asked for;
 *   2. the CRC is RECOMPUTED.  The CRC covers bytes [0..15] and
 *      [20..31], so a changed sequence number invalidates it.  A
 *      re-stamp that leaves the old CRC behind would produce a frame
 *      the supervisor drops as a CRC fault -- and the guest would go
 *      silent, which looks exactly like a hung guest.
 */
static void test_restamp(void) {
    uint8_t frame[LATCH_WIRE_V2_SIZE];
    latch_wire_v2_pack(frame, LATCH_GOV_KIND_CMD_V2, 1u, 0u, -20, 210u, 1u, 3u);

    /* The payload the supervisor acts on: the confidence, the agent state
     * and the unit id.  The coherence counter (offset 25..27) is
     * deliberately NOT in this list -- it is the field the re-stamp is
     * supposed to change. */
    uint8_t payload_before[12];
    memcpy(payload_before, frame + 20, 5u);      /* confidence + agent state */
    memcpy(payload_before + 5, frame + 28, 4u);  /* unit id */
    uint8_t value_before[4];
    memcpy(value_before, frame + 12, 4u);        /* the commanded value */

    latch_wire_v2_restamp(frame, 77u, 9u);

    check(frame[8] == 77u && frame[9] == 0u && frame[10] == 0u && frame[11] == 0u,
          "the re-stamp writes the sequence number, little-endian");
    check(frame[25] == 9u && frame[26] == 0u && frame[27] == 0u,
          "the re-stamp writes the coherence counter, little-endian");
    check(memcmp(payload_before, frame + 20, 5u) == 0 &&
          memcmp(payload_before + 5, frame + 28, 4u) == 0,
          "the re-stamp leaves the payload untouched");
    check(memcmp(value_before, frame + 12, 4u) == 0,
          "the re-stamp leaves the commanded value untouched");
    check(latch_wire_v2_check(frame, sizeof(frame)) == 0,
          "the re-stamped frame still passes the structural check");

    /* The CRC must have been recomputed, not merely copied: a stale CRC
     * over a changed sequence number is exactly the failure mode. */
    uint8_t stale[LATCH_WIRE_V2_SIZE];
    memcpy(stale, frame, sizeof(frame));
    stale[16] ^= 0x01u;
    check(latch_wire_v2_check(stale, sizeof(stale)) != 0,
          "the re-stamped frame's CRC is a fresh one, not the old one");

    /* The coherence counter is 24-bit: a value wider than that is
     * truncated, never truncated into the neighbouring field. */
    latch_wire_v2_restamp(frame, 1u, 0x01020304u);
    check(frame[25] == 0x04u && frame[26] == 0x03u && frame[27] == 0x02u,
          "the coherence counter is truncated to 24 bits");
    check(frame[28] == 3u && frame[29] == 0u && frame[30] == 0u && frame[31] == 0u,
          "the truncation does not spill into the unit id");
    check(latch_wire_v2_check(frame, sizeof(frame)) == 0,
          "the truncated frame still passes the structural check");
}

int main(void) {
    test_schema();
    test_wire_layout();
    test_crc_vector();
    test_restamp();

    printf("[LATCH_ACTION] %d checks, %d failure(s)\n", g_checks, g_failures);
    if (g_failures != 0) {
        printf("[LATCH_ACTION] FAIL\n");
        return 1;
    }
    printf("[LATCH_ACTION] PASS: the schema validator and the wire-v2 packer agree "
           "with the documented layout\n");
    return 0;
}
