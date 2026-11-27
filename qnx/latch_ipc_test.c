#include "latch_ipc.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    latch_ipc_proposal_t v1 = {
        .ipc_magic = LATCH_IPC_PROPOSAL_MAGIC,
        .seq = 9u,
        .u_mrad = 42,
        .wire_flags = 0u,
        .pre_fault_bits = LATCH_FAULT_NONE,
        .ingest_cycles = 123u
    };
    latch_proposal_t decoded;
    if (latch_ipc_decode(&v1, sizeof(v1), &decoded) != 0 ||
        decoded.wire_version != 1u || decoded.seq != 9u || decoded.u_mrad != 42) {
        fprintf(stderr, "[LATCH_IPC] FAIL LPRP v1 compatibility\n");
        return 1;
    }
    if (latch_ipc_decode_contract(&v1, sizeof(v1), 1u, &decoded) != 0 ||
        latch_ipc_decode_contract(&v1, sizeof(v1), 2u, &decoded) == 0 ||
        latch_ipc_decode_contract(&v1, sizeof(v1), 0u, &decoded) == 0) {
        fprintf(stderr, "[LATCH_IPC] FAIL manifest version admission for LPRP\n");
        return 1;
    }

    latch_ipc_proposal_v2_t v2;
    memset(&v2, 0, sizeof(v2));
    v2.ipc_magic = LATCH_IPC_PROPOSAL_V2_MAGIC;
    v2.seq = 10u;
    v2.u_mrad = 77;
    v2.wire_flags = 2u;
    v2.ingest_cycles = 456u;
    v2.ipc_version = 2u;
    v2.wire_version = 2u;
    v2.kind = 2u;
    v2.confidence_q8 = 200u;
    v2.agent_state = 1u;
    v2.producer_tag = 7u;
    v2.coherence_ctr = 0x123456u;
    v2.unit_id = 1u;
    v2.session_epoch = 0x0BADC0DEu;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) != 0 ||
        decoded.wire_version != 2u || decoded.seq != 10u || decoded.u_mrad != 77 ||
        decoded.confidence_q8 != 200u || decoded.coherence_ctr != 0x123456u ||
        decoded.unit_id != 1u || decoded.producer_tag != 7u ||
        decoded.session_epoch != 0x0BADC0DEu) {
        fprintf(stderr, "[LATCH_IPC] FAIL LPR2 v2 decode\n");
        return 1;
    }
    if (latch_ipc_decode_contract(&v2, sizeof(v2), 2u, &decoded) != 0 ||
        latch_ipc_decode_contract(&v2, sizeof(v2), 1u, &decoded) == 0 ||
        latch_ipc_decode_contract(&v2, sizeof(v2) - 1u, 2u, &decoded) == 0) {
        fprintf(stderr, "[LATCH_IPC] FAIL manifest version admission for LPR2\n");
        return 1;
    }

    /* L-2: a v2 frame MUST name its producer. An unscoped frame (tag 0) is
     * rejected at the boundary, so it can never slip past the lease
     * authority as "the owner". */
    v2.producer_tag = LATCH_PRODUCER_TAG_NONE;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) {
        fprintf(stderr, "[LATCH_IPC] FAIL an unscoped LPR2 frame was accepted\n");
        return 1;
    }
    v2.producer_tag = 7u;

    /* RT-02: a v2 frame MUST name its session. An unscoped frame (epoch 0)
     * is rejected at the boundary, so it can never be judged against -- or
     * bind -- a session. */
    v2.session_epoch = LATCH_SESSION_EPOCH_NONE;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) {
        fprintf(stderr, "[LATCH_IPC] FAIL an unscoped LPR2 frame was accepted\n");
        return 1;
    }
    v2.session_epoch = 0x0BADC0DEu;

    /* RT-02: the reserved word must be zero. A non-zero value means the
     * sender is using a layout this supervisor does not understand. */
    v2.reserved1 = 1u;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) {
        fprintf(stderr, "[LATCH_IPC] FAIL an LPR2 frame with a non-zero reserved word was accepted\n");
        return 1;
    }
    v2.reserved1 = 0u;

    if (latch_ipc_decode(&v2, sizeof(v2) - 1u, &decoded) == 0) return 1;
    v2.unit_id = 0u;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) return 1;
    v2.unit_id = 1u;
    v2.wire_flags = 0x102u;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) return 1;
    v2.wire_flags = 2u;
    v2.shrink_v = 1u;
    if (latch_ipc_decode(&v2, sizeof(v2), &decoded) == 0) return 1;

    puts("[LATCH_IPC] PASS: exact-size LPRP/LPR2 decoding and structural rejection");
    return 0;
}
