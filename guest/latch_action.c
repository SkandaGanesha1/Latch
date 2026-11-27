/*
 * guest/latch_action.c -- the action validator and the wire-v2 packer.
 *
 * FREESTANDING: <stdint.h> and <stddef.h> only.  No libc.
 *
 * See guest/latch_action.h for why the safety envelope is NOT here.
 */

#include "latch_action.h"

/* ---------------------------------------------------------------------- */
/* CRC-32 (IEEE 802.3, reflected)                                         */
/* ---------------------------------------------------------------------- */

uint32_t latch_crc32_ieee(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0u; i < len; ++i) {
        crc ^= (uint32_t)buf[i];
        for (int bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* ---------------------------------------------------------------------- */
/* The parser                                                             */
/* ---------------------------------------------------------------------- */

typedef struct {
    const char *p;
    const char *end;
} scan_t;

static int at_end(const scan_t *s) { return s->p >= s->end; }

/* A local strlen: this file must not pull in <string.h>, because it is
 * linked into the -nostdlib freestanding policy as well. */
static size_t lit_len(const char *lit) {
    size_t n = 0u;
    while (lit[n] != '\0') {
        n++;
    }
    return n;
}

/* Skip JSON whitespace. The schema allows none, but being liberal about
 * whitespace around the separators costs nothing and avoids turning a
 * cosmetic difference into a dropped frame. */
static void skip_ws(scan_t *s) {
    while (!at_end(s)) {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            s->p++;
        } else {
            break;
        }
    }
}

/* Match a literal byte. */
static int match_byte(scan_t *s, char c) {
    if (at_end(s) || *s->p != c) {
        return 0;
    }
    s->p++;
    return 1;
}

/* Match a literal string. */
static int match_str(scan_t *s, const char *lit) {
    size_t n = lit_len(lit);
    if ((size_t)(s->end - s->p) < n) {
        return 0;
    }
    for (size_t i = 0u; i < n; ++i) {
        if (s->p[i] != lit[i]) {
            return 0;
        }
    }
    s->p += n;
    return 1;
}

/*
 * Parse a decimal integer.
 *
 * Rules (these are also what the GBNF grammar allows, so the grammar and
 * this parser agree by construction):
 *   - optional '-'
 *   - no leading '+'
 *   - no leading zeros, except the single digit "0"
 *   - no whitespace inside the number
 *   - the magnitude must fit in a uint64, and the caller range-checks it
 *
 * Returns LATCH_ACTION_OK and stores the magnitude, or
 * LATCH_ACTION_ERR_TYPE / _ERR_RANGE / _INCOMPLETE.
 */
static latch_action_status_t parse_int(scan_t *s, uint64_t *magnitude, int *negative) {
    if (at_end(s)) {
        return LATCH_ACTION_INCOMPLETE;
    }

    *negative = 0;
    if (*s->p == '-') {
        *negative = 1;
        s->p++;
        if (at_end(s)) {
            return LATCH_ACTION_INCOMPLETE;
        }
    }

    if (at_end(s) || *s->p < '0' || *s->p > '9') {
        /* Not a digit at all. If we are at the end of the text it is a
         * truncated number, otherwise it is a type error. */
        return at_end(s) ? LATCH_ACTION_INCOMPLETE : LATCH_ACTION_ERR_TYPE;
    }

    if (*s->p == '0') {
        s->p++;
        /* "0" is fine; "01" is not. */
        if (!at_end(s) && *s->p >= '0' && *s->p <= '9') {
            return LATCH_ACTION_ERR_TYPE;
        }
        *magnitude = 0u;
        return LATCH_ACTION_OK;
    }

    uint64_t v = 0u;
    while (!at_end(s) && *s->p >= '0' && *s->p <= '9') {
        uint64_t digit = (uint64_t)(*s->p - '0');
        if (v > (UINT64_MAX - digit) / 10u) {
            return LATCH_ACTION_ERR_RANGE;
        }
        v = v * 10u + digit;
        s->p++;
    }
    *magnitude = v;
    return LATCH_ACTION_OK;
}

/*
 * After a number, a character that could continue a number means the
 * value was not a plain integer ("-20.5", "12abc", "1_000").  Report it
 * as a TYPE error rather than a generic syntax error, so the caller can
 * tell "the model wrote a float" from "the model wrote nonsense".
 */
static latch_action_status_t number_tail(scan_t *s) {
    if (at_end(s)) {
        return LATCH_ACTION_OK;
    }
    char c = *s->p;
    if (c == '.' || c == '_' ||
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        return LATCH_ACTION_ERR_TYPE;
    }
    return LATCH_ACTION_OK;
}

/* Parse "key": and return the status. */
static latch_action_status_t expect_key(scan_t *s, const char *key) {
    skip_ws(s);
    if (at_end(s)) {
        return LATCH_ACTION_INCOMPLETE;
    }
    if (*s->p != '"') {
        return LATCH_ACTION_ERR_SYNTAX;
    }
    s->p++;
    if (!match_str(s, key)) {
        /* Distinguish "not yet here" from "the wrong key". */
        if ((size_t)(s->end - s->p) < lit_len(key)) {
            return LATCH_ACTION_INCOMPLETE;
        }
        return LATCH_ACTION_ERR_KEY;
    }
    if (at_end(s)) {
        return LATCH_ACTION_INCOMPLETE;
    }
    if (*s->p != '"') {
        return LATCH_ACTION_ERR_SYNTAX;
    }
    s->p++;
    skip_ws(s);
    if (at_end(s)) {
        return LATCH_ACTION_INCOMPLETE;
    }
    if (*s->p != ':') {
        return LATCH_ACTION_ERR_SYNTAX;
    }
    s->p++;
    return LATCH_ACTION_OK;
}

latch_action_status_t latch_action_parse(const char *text, size_t len,
                                         latch_action_t *out) {
    if (text == NULL || len == 0u) {
        return LATCH_ACTION_INCOMPLETE;
    }

    scan_t s = { text, text + len };
    latch_action_t a;
    a.u_mrad = 0;
    a.unit_id = 0u;
    a.confidence = 0u;

    skip_ws(&s);
    if (at_end(&s)) {
        return LATCH_ACTION_INCOMPLETE;
    }
    if (!match_byte(&s, '{')) {
        return LATCH_ACTION_ERR_SYNTAX;
    }

    latch_action_status_t st;

    /* ---- u_mrad ---------------------------------------------------- */
    st = expect_key(&s, "u_mrad");
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    skip_ws(&s);
    uint64_t mag = 0u;
    int neg = 0;
    st = parse_int(&s, &mag, &neg);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    st = number_tail(&s);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    if (neg) {
        if (mag > 2147483648u) {
            return LATCH_ACTION_ERR_RANGE;
        }
        a.u_mrad = (mag == 2147483648u)
                 ? (int32_t)(-2147483647 - 1)
                 : (int32_t)(-(int64_t)mag);
    } else {
        if (mag > 2147483647u) {
            return LATCH_ACTION_ERR_RANGE;
        }
        a.u_mrad = (int32_t)mag;
    }
    skip_ws(&s);
    if (!match_byte(&s, ',')) {
        if (at_end(&s)) {
            return LATCH_ACTION_INCOMPLETE;
        }
        /* A ',' where the schema wants '}' means the object carries an
         * EXTRA KEY. */
        if (s.p[0] == ',') {
            return LATCH_ACTION_ERR_KEY;
        }
        return LATCH_ACTION_ERR_SYNTAX;
    }

    /* ---- unit_id --------------------------------------------------- */
    st = expect_key(&s, "unit_id");
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    skip_ws(&s);
    st = parse_int(&s, &mag, &neg);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    st = number_tail(&s);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    if (neg) {
        return LATCH_ACTION_ERR_RANGE;
    }
    if (mag > 4294967295u) {
        return LATCH_ACTION_ERR_RANGE;
    }
    a.unit_id = (uint32_t)mag;
    skip_ws(&s);
    if (!match_byte(&s, ',')) {
        if (at_end(&s)) {
            return LATCH_ACTION_INCOMPLETE;
        }
        if (s.p[0] == ',') {
            return LATCH_ACTION_ERR_KEY;
        }
        return LATCH_ACTION_ERR_SYNTAX;
    }

    /* ---- confidence ------------------------------------------------ */
    st = expect_key(&s, "confidence");
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    skip_ws(&s);
    st = parse_int(&s, &mag, &neg);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    st = number_tail(&s);
    if (st != LATCH_ACTION_OK) {
        return st;
    }
    if (neg) {
        return LATCH_ACTION_ERR_RANGE;
    }
    if (mag > 255u) {
        return LATCH_ACTION_ERR_RANGE;
    }
    a.confidence = (uint32_t)mag;
    skip_ws(&s);
    if (!match_byte(&s, '}')) {
        if (at_end(&s)) {
            return LATCH_ACTION_INCOMPLETE;
        }
        if (s.p[0] == ',') {
            return LATCH_ACTION_ERR_KEY;
        }
        return LATCH_ACTION_ERR_SYNTAX;
    }

    /* Nothing may follow the object except whitespace. */
    skip_ws(&s);
    if (!at_end(&s)) {
        return LATCH_ACTION_ERR_SYNTAX;
    }

    if (out != NULL) {
        *out = a;
    }
    return LATCH_ACTION_OK;
}

const char *latch_action_status_str(latch_action_status_t st) {
    switch (st) {
        case LATCH_ACTION_OK:         return "OK";
        case LATCH_ACTION_INCOMPLETE: return "INCOMPLETE";
        case LATCH_ACTION_ERR_SYNTAX: return "ERR_SYNTAX";
        case LATCH_ACTION_ERR_KEY:    return "ERR_KEY";
        case LATCH_ACTION_ERR_TYPE:   return "ERR_TYPE";
        case LATCH_ACTION_ERR_RANGE:  return "ERR_RANGE";
        default:                      return "ERR_UNKNOWN";
    }
}

/* ---------------------------------------------------------------------- */
/* The wire-v2 packer                                                      */
/* ---------------------------------------------------------------------- */

static void store_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void store_le24(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
}

static void store_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

void latch_wire_v2_pack(uint8_t *frame,
                        uint8_t  kind,
                        uint32_t seq,
                        uint32_t coherence,
                        int32_t  value,
                        uint32_t confidence_q8,
                        uint8_t  agent_state,
                        uint32_t unit_id) {
    uint8_t *p = frame;
    uint8_t crc_input[28];

    for (size_t i = 0u; i < LATCH_WIRE_V2_SIZE; ++i) {
        p[i] = 0u;
    }
    store_le32(p + 0, LATCH_WIRE_V2_MAGIC);
    store_le16(p + 4, (uint16_t)LATCH_WIRE_V2_VERSION);
    p[6] = (uint8_t)LATCH_WIRE_V2_JOINT;
    p[7] = kind;
    store_le32(p + 8, seq);
    store_le32(p + 12, (uint32_t)value);
    store_le32(p + 20, confidence_q8);
    p[24] = agent_state;
    store_le24(p + 25, coherence & 0x00FFFFFFu);
    store_le32(p + 28, unit_id);

    for (size_t i = 0u; i < 16u; ++i) {
        crc_input[i] = p[i];
    }
    for (size_t i = 0u; i < 12u; ++i) {
        crc_input[16u + i] = p[20u + i];
    }
    store_le32(p + 16, latch_crc32_ieee(crc_input, sizeof(crc_input)));
}

int latch_wire_v2_check(const uint8_t *frame, size_t len) {
    if (frame == NULL || len != LATCH_WIRE_V2_SIZE) {
        return -1;
    }
    /* Every field is LITTLE-ENDIAN, exactly as the host's decoder in
     * qnx/governor_wire.c reads it (load_le32 / load_le16 / load_le24).
     * Reading the magic big-endian here would accept every frame the
     * host rejects -- and reject every frame the host accepts. */
    uint32_t magic = (uint32_t)frame[0] | ((uint32_t)frame[1] << 8u) |
                     ((uint32_t)frame[2] << 16u) | ((uint32_t)frame[3] << 24u);
    if (magic != LATCH_WIRE_V2_MAGIC) {
        return -2;
    }
    uint16_t version = (uint16_t)((uint16_t)frame[4] | ((uint16_t)frame[5] << 8u));
    if (version != (uint16_t)LATCH_WIRE_V2_VERSION) {
        return -3;
    }
    if (frame[6] != LATCH_WIRE_V2_JOINT) {
        return -4;
    }

    uint8_t crc_input[28];
    for (size_t i = 0u; i < 16u; ++i) {
        crc_input[i] = frame[i];
    }
    for (size_t i = 0u; i < 12u; ++i) {
        crc_input[16u + i] = frame[20u + i];
    }
    uint32_t want = (uint32_t)frame[16] | ((uint32_t)frame[17] << 8u) |
                    ((uint32_t)frame[18] << 16u) | ((uint32_t)frame[19] << 24u);
    if (want != latch_crc32_ieee(crc_input, sizeof(crc_input))) {
        return -5;
    }
    return 0;
}

/*
 * Re-stamp the sequence number and the coherence counter, then recompute
 * the CRC over the same byte ranges the packer uses.
 *
 * The CRC covers bytes [0..15] and [20..31] -- i.e. everything EXCEPT the
 * CRC field itself -- so changing the sequence number (offset 8) or the
 * coherence counter (offset 25..27) invalidates it and it MUST be
 * recomputed.  Forgetting that is not a theoretical bug: the supervisor
 * would drop the frame as a CRC fault and the guest would go silent.
 */
void latch_wire_v2_restamp(uint8_t *frame, uint32_t seq, uint32_t coherence) {
    uint8_t crc_input[28];

    if (frame == NULL) {
        return;
    }

    store_le32(frame + 8, seq);
    store_le24(frame + 25, coherence & 0x00FFFFFFu);

    for (size_t i = 0u; i < 16u; ++i) {
        crc_input[i] = frame[i];
    }
    for (size_t i = 0u; i < 12u; ++i) {
        crc_input[16u + i] = frame[20u + i];
    }
    store_le32(frame + 16, latch_crc32_ieee(crc_input, sizeof(crc_input)));
}
