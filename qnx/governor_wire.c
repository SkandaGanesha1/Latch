#include "governor_wire.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define GOVERNOR_WIRE_V2_VERSION LATCH_WIRE_VERSION_V2
#define GOVERNOR_WIRE_FRAME_BYTES 32u

static uint16_t load_le16(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8u));
}

static uint32_t load_le24(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) | ((uint32_t)p[2] << 16u);
}

static uint32_t load_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8u) |
           ((uint32_t)p[2] << 16u) | ((uint32_t)p[3] << 24u);
}

static int32_t load_le_i32(const uint8_t *p) {
    uint32_t value = load_le32(p);
    if (value <= INT32_MAX) return (int32_t)value;
    return -1 - (int32_t)(UINT32_MAX - value);
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)bytes[i];
        for (unsigned int bit = 0; bit < 8u; ++bit) {
            uint32_t mask = 0u - (crc & 1u);
            crc = (crc >> 1u) ^ (LATCH_CRC32_POLY_REFL & mask);
        }
    }
    return crc;
}

static uint32_t v2_crc(const uint8_t *frame) {
    uint32_t crc = 0xFFFFFFFFu;
    crc = crc32_update(crc, frame, 16u);
    crc = crc32_update(crc, frame + 20u, 12u);
    return ~crc;
}

static bool bytes_are_zero(const uint8_t *p, size_t len) {
    uint8_t acc = 0u;
    for (size_t i = 0; i < len; ++i) acc |= p[i];
    return acc == 0u;
}

uint16_t governor_wire_v2_parse(const uint8_t *frame, uint32_t frame_len,
                                governor_wire_message_t *message) {
    if (message != NULL) memset(message, 0, sizeof(*message));
    if (frame == NULL || message == NULL || frame_len != GOVERNOR_WIRE_FRAME_BYTES) {
        return LATCH_FAULT_MAGIC;
    }

    uint16_t faults = LATCH_FAULT_NONE;
    uint32_t magic = load_le32(frame);
    uint16_t version = load_le16(frame + 4u);
    uint8_t joint = frame[6u];
    uint8_t kind = frame[7u];
    uint32_t seq = load_le32(frame + 8u);
    int32_t u_mrad = load_le_i32(frame + 12u);
    uint32_t crc = load_le32(frame + 16u);
    uint32_t confidence = load_le32(frame + 20u);
    uint8_t agent_state = frame[24u];
    uint32_t coherence = load_le24(frame + 25u);
    uint32_t unit_id = load_le32(frame + 28u);

    if (magic != LATCH_WIRE_MAGIC || version != GOVERNOR_WIRE_V2_VERSION ||
        joint != LATCH_WIRE_JOINT_DEFAULT || kind > GOVERNOR_WIRE_SHRINK_REQ) {
        faults |= LATCH_FAULT_MAGIC;
    }
    if (crc != v2_crc(frame)) faults |= LATCH_FAULT_CRC;
    if (confidence > 255u || agent_state > 4u) faults |= LATCH_FAULT_RESERVED;
    if (kind == GOVERNOR_WIRE_CMD) {
        if (confidence != 0u || agent_state != 0u || coherence != 0u ||
            unit_id != 0u || !bytes_are_zero(frame + 20u, 8u)) faults |= LATCH_FAULT_RESERVED;
    } else if (kind == GOVERNOR_WIRE_HEARTBEAT) {
        if (u_mrad != 0 || confidence != 0u || unit_id != 0u) faults |= LATCH_FAULT_RESERVED;
    } else if (kind == GOVERNOR_WIRE_CMD_V2) {
        /* Agent state, coherence, confidence and explicit source unit are meaningful. */
        if (unit_id == 0u) faults |= LATCH_FAULT_RESERVED;
    } else if (kind == GOVERNOR_WIRE_SHRINK_REQ) {
        if (u_mrad < 0 || confidence == 0u || unit_id != 0u) faults |= LATCH_FAULT_RESERVED;
    }

    if (faults != LATCH_FAULT_NONE) return faults;

    message->kind = (governor_wire_kind_t)kind;
    message->seq = seq;
    message->u_mrad = u_mrad;
    message->confidence_q8 = (uint8_t)confidence;
    message->agent_state = agent_state;
    message->coherence_ctr = coherence;
    message->unit_id = unit_id;
    if (kind == GOVERNOR_WIRE_SHRINK_REQ) {
        message->shrink_v = (uint32_t)u_mrad;
        message->shrink_scale_q8 = confidence;
    }
    return LATCH_FAULT_NONE;
}
