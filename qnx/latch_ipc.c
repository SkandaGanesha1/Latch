#include "latch_ipc.h"

#include <string.h>

int latch_ipc_decode_contract(const void *bytes, size_t length,
                              unsigned int protocol_version,
                              latch_proposal_t *out) {
    if ((protocol_version == 1u && length != sizeof(latch_ipc_proposal_t)) ||
        (protocol_version == 2u && length != sizeof(latch_ipc_proposal_v2_t)) ||
        (protocol_version != 1u && protocol_version != 2u)) {
        if (out != NULL) memset(out, 0, sizeof(*out));
        return -1;
    }
    return latch_ipc_decode(bytes, length, out);
}

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
        out->producer_tag = LATCH_PRODUCER_TAG_NONE;
        return 0;
    }

    if (length == sizeof(latch_ipc_proposal_v2_t)) {
        latch_ipc_proposal_v2_t v2;
        memcpy(&v2, bytes, sizeof(v2));
        if (v2.ipc_magic != LATCH_IPC_PROPOSAL_V2_MAGIC ||
            v2.ipc_version != 2u || v2.wire_version != 2u ||
            v2.kind > 3u || v2.wire_flags != (uint16_t)v2.kind ||
            /* L-2: a v2 frame MUST name its producer. An unscoped frame
             * (tag 0) would be a frame the lease authority cannot reason
             * about, so it is rejected here -- fail closed at the boundary
             * rather than silently treating it as "the owner". */
            v2.producer_tag == LATCH_PRODUCER_TAG_NONE ||
            /* RT-02: a v2 frame MUST name the session it belongs to. An
             * unscoped frame (epoch 0) cannot be checked against the
             * session's epoch, which is exactly the frame a cross-session
             * replay would be. Rejected at the boundary. */
            v2.session_epoch == LATCH_SESSION_EPOCH_NONE ||
            /* The reserved word must be zero: a non-zero value means the
             * sender is using a layout this supervisor does not know. */
            v2.reserved1 != 0u ||
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
        out->producer_tag = v2.producer_tag;
        out->coherence_ctr = v2.coherence_ctr;
        out->unit_id = v2.unit_id;
        out->shrink_v = v2.shrink_v;
        out->shrink_scale_q8 = v2.shrink_scale_q8;
        out->session_epoch = v2.session_epoch;
        return 0;
    }
    return -1;
}
