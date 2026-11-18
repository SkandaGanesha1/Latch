#include "latch_ipc.h"

#include <string.h>

static int valid_pre_faults(uint16_t bits) {
    return (bits & (uint16_t)~LATCH_FAULT_WIRE_MASK) == 0u;
}

static int valid_v2_payload(const latch_ipc_proposal_v2_t *v2) {
    if (v2->agent_state > 4u) return 0;
    switch (v2->kind) {
        case 0u: /* CMD */
            return v2->confidence_q8 == 0u && v2->agent_state == 0u &&
                   v2->coherence_ctr == 0u && v2->shrink_v == 0u &&
                   v2->shrink_scale_q8 == 0u && v2->unit_id == 0u;
        case 1u: /* HEARTBEAT */
            return v2->u_mrad == 0 && v2->confidence_q8 == 0u &&
                   v2->shrink_v == 0u && v2->shrink_scale_q8 == 0u &&
                   v2->unit_id == 0u;
        case 2u: /* CMD_V2 */
            return v2->shrink_v == 0u && v2->shrink_scale_q8 == 0u &&
                   v2->unit_id != 0u;
        case 3u: /* SHRINK_REQ */
            return v2->u_mrad >= 0 && v2->confidence_q8 != 0u &&
                   v2->shrink_v == (uint32_t)v2->u_mrad &&
                   v2->shrink_scale_q8 == (uint32_t)v2->confidence_q8 &&
                   v2->unit_id == 0u;
        default:
            return 0;
    }
}

int latch_ipc_decode(const void *bytes, size_t length, latch_proposal_t *out) {
    if (bytes == NULL || out == NULL) return -1;
    memset(out, 0, sizeof(*out));

    if (length == sizeof(latch_ipc_proposal_t)) {
        latch_ipc_proposal_t v1;
        memcpy(&v1, bytes, sizeof(v1));
        if (v1.ipc_magic != LATCH_IPC_PROPOSAL_MAGIC ||
            !valid_pre_faults(v1.pre_fault_bits)) return -1;
        out->ipc_magic = v1.ipc_magic;
        out->seq = v1.seq;
        out->u_mrad = v1.u_mrad;
        out->wire_flags = v1.wire_flags;
        out->pre_fault_bits = v1.pre_fault_bits;
        out->ingest_cycles = v1.ingest_cycles;
        out->wire_version = 1u;
        out->kind = (uint8_t)(v1.wire_flags & 0xFFu);
        return 0;
    }

    if (length == sizeof(latch_ipc_proposal_v2_t)) {
        latch_ipc_proposal_v2_t v2;
        memcpy(&v2, bytes, sizeof(v2));
        if (v2.ipc_magic != LATCH_IPC_PROPOSAL_V2_MAGIC ||
            v2.ipc_version != 2u || v2.wire_version != 2u ||
            v2.kind > 3u || v2.wire_flags != (uint16_t)v2.kind ||
            v2.reserved0 != 0u ||
            (v2.coherence_ctr & 0xFF000000u) != 0u ||
            !valid_pre_faults(v2.pre_fault_bits) || !valid_v2_payload(&v2)) return -1;

        out->ipc_magic = LATCH_IPC_PROPOSAL_MAGIC;
        out->seq = v2.seq;
        out->u_mrad = v2.u_mrad;
        out->wire_flags = v2.wire_flags;
        out->pre_fault_bits = v2.pre_fault_bits;
        out->ingest_cycles = v2.ingest_cycles;
        out->wire_version = v2.wire_version;
        out->kind = v2.kind;
        out->confidence_q8 = v2.confidence_q8;
        out->agent_state = v2.agent_state;
        out->coherence_ctr = v2.coherence_ctr;
        out->unit_id = v2.unit_id;
        out->shrink_v = v2.shrink_v;
        out->shrink_scale_q8 = v2.shrink_scale_q8;
        return 0;
    }
    return -1;
}
