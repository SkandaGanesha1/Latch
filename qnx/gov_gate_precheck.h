#ifndef GOV_GATE_PRECHECK_H_
#define GOV_GATE_PRECHECK_H_

#include <stdint.h>

#include "governor_policy.h"
#include "governor_wire.h"
#include "latch_manifest.h"
#include "latch_protocol.h"

typedef struct gov_gate_state {
    uint32_t rate_tokens;
    uint32_t shrink_v;
    uint32_t shrink_scale_q8;
    uint8_t shrink_active;
    uint64_t cumulative_window_dose_uL;
    uint64_t window_start_tick;
    uint64_t last_bolus_tick;
} gov_gate_state_t;

typedef struct gov_gate_input {
    governor_rung_t rung;
    uint8_t kind;
    uint8_t confidence_q8;
    uint32_t unit_id;
    uint8_t has_v2_metadata;
    int32_t theta;
    int32_t velocity;
    int32_t acceleration;
    int32_t candidate;
    uint64_t tick;
} gov_gate_input_t;

typedef struct gov_gate_result {
    uint16_t faults;
    int32_t candidate;
    int32_t normalized_target;
    int32_t effective_v_max;
    int32_t effective_a_max;
    uint8_t command_valid;
    uint8_t message_only;
} gov_gate_result_t;

void gov_gate_init(const latch_manifest_governor_t *config, gov_gate_state_t *state);
gov_gate_result_t gov_gate_precheck(const latch_manifest_t *manifest,
                                    const latch_manifest_governor_t *config,
                                    gov_gate_state_t *state,
                                    const gov_gate_input_t *input);

#endif
