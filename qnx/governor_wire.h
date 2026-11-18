#ifndef GOVERNOR_WIRE_H_
#define GOVERNOR_WIRE_H_

#include <stdint.h>

#include "latch_protocol.h"

typedef enum governor_wire_kind {
    GOVERNOR_WIRE_CMD = 0,
    GOVERNOR_WIRE_HEARTBEAT = 1,
    GOVERNOR_WIRE_CMD_V2 = 2,
    GOVERNOR_WIRE_SHRINK_REQ = 3
} governor_wire_kind_t;

typedef struct governor_wire_message {
    governor_wire_kind_t kind;
    uint32_t seq;
    int32_t u_mrad;
    uint8_t confidence_q8;
    uint8_t agent_state;
    uint32_t coherence_ctr;
    uint32_t unit_id;
    uint32_t shrink_v;
    uint32_t shrink_scale_q8;
} governor_wire_message_t;

/* Parse exactly one wire-v2 frame. Returns zero on success and wire faults otherwise. */
uint16_t governor_wire_v2_parse(const uint8_t *frame, uint32_t frame_len,
                                governor_wire_message_t *message);

#endif
