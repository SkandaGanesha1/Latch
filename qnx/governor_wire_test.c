#include "governor_wire.h"

#include <stdio.h>
#include <string.h>

static void store_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8u);
}

static void store_le24(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8u);
    p[2] = (uint8_t)(value >> 16u);
}

static void store_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8u);
    p[2] = (uint8_t)(value >> 16u);
    p[3] = (uint8_t)(value >> 24u);
}

static uint32_t crc_update(uint32_t crc, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        crc ^= bytes[i];
        for (unsigned int bit = 0; bit < 8u; ++bit) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1u) ^ (LATCH_CRC32_POLY_REFL & mask);
        }
    }
    return crc;
}

static void seal(uint8_t frame[32]) {
    uint32_t crc = 0xFFFFFFFFu;
    crc = crc_update(crc, frame, 16u);
    crc = crc_update(crc, frame + 20u, 12u);
    store_le32(frame + 16u, ~crc);
}

static void make_frame(uint8_t frame[32], governor_wire_kind_t kind) {
    memset(frame, 0, 32u);
    store_le32(frame, LATCH_WIRE_MAGIC);
    store_le16(frame + 4u, 2u);
    frame[6u] = LATCH_WIRE_JOINT_DEFAULT;
    frame[7u] = (uint8_t)kind;
    store_le32(frame + 8u, 7u);
    if (kind == GOVERNOR_WIRE_CMD || kind == GOVERNOR_WIRE_CMD_V2) {
        store_le32(frame + 12u, 125u);
    }
    if (kind == GOVERNOR_WIRE_CMD_V2 || kind == GOVERNOR_WIRE_HEARTBEAT ||
        kind == GOVERNOR_WIRE_SHRINK_REQ) {
        frame[24u] = 1u;
        store_le24(frame + 25u, 23u);
    }
    if (kind == GOVERNOR_WIRE_CMD_V2) {
        store_le32(frame + 20u, 200u);
        store_le32(frame + 28u, 0xA11CEu);
    }
    if (kind == GOVERNOR_WIRE_SHRINK_REQ) {
        store_le32(frame + 12u, 80u);
        store_le32(frame + 20u, 128u);
    }
    seal(frame);
}

static int expect_parse(uint8_t frame[32], uint16_t expected, const char *label) {
    governor_wire_message_t message;
    uint16_t actual = governor_wire_v2_parse(frame, 32u, &message);
    if (actual != expected) {
        fprintf(stderr, "[GOVERNOR_WIRE] FAIL %s: got faults 0x%04x expected 0x%04x\n",
                label, actual, expected);
        return -1;
    }
    return 0;
}

int main(void) {
    uint8_t frame[32];
    governor_wire_message_t message;
    const governor_wire_kind_t kinds[] = {
        GOVERNOR_WIRE_CMD, GOVERNOR_WIRE_HEARTBEAT,
        GOVERNOR_WIRE_CMD_V2, GOVERNOR_WIRE_SHRINK_REQ
    };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
        make_frame(frame, kinds[i]);
        if (expect_parse(frame, LATCH_FAULT_NONE, "valid kind") != 0) return 1;
        if (governor_wire_v2_parse(frame, 32u, &message) != LATCH_FAULT_NONE ||
            message.kind != kinds[i] || message.seq != 7u) return 1;
        if (kinds[i] == GOVERNOR_WIRE_CMD_V2 && message.unit_id != 0xA11CEu) return 1;
        if (kinds[i] == GOVERNOR_WIRE_SHRINK_REQ &&
            (message.shrink_v != 80u || message.shrink_scale_q8 != 128u)) return 1;
    }

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    frame[3u] ^= 1u;
    if (expect_parse(frame, LATCH_FAULT_MAGIC | LATCH_FAULT_CRC, "header corruption") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    frame[25u] ^= 1u;
    if (expect_parse(frame, LATCH_FAULT_CRC, "metadata-tail corruption") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD);
    frame[20u] = 1u;
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_RESERVED, "CMD metadata must be zero") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_HEARTBEAT);
    store_le32(frame + 12u, 1u);
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_RESERVED, "heartbeat has no command") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_SHRINK_REQ);
    store_le32(frame + 20u, 0u);
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_RESERVED, "shrink scale cannot be zero") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    frame[24u] = 5u;
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_RESERVED, "unknown agent state") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    frame[28u] = 1u;
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_NONE, "explicit unit id is valid") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    memset(frame + 28u, 0, 4u);
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_RESERVED, "command requires explicit unit id") != 0) return 1;

    make_frame(frame, GOVERNOR_WIRE_CMD_V2);
    if (governor_wire_v2_parse(frame, 31u, &message) != LATCH_FAULT_MAGIC) return 1;
    if (governor_wire_v2_parse(frame, 32u, NULL) != LATCH_FAULT_MAGIC) return 1;
    frame[7u] = 4u;
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_MAGIC, "unknown kind") != 0) return 1;

    frame[7u] = 0x80u;
    seal(frame);
    if (expect_parse(frame, LATCH_FAULT_MAGIC, "flags=0x80 rejected as kind") != 0) return 1;

    puts("[GOVERNOR_WIRE] PASS: v2 framing, CRC coverage, kind rules, and fail-closed faults");
    return 0;
}
