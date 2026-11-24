#ifndef GOV_GATE_PRECHECK_H_
#define GOV_GATE_PRECHECK_H_

#include <stdint.h>

#include "governor_policy.h"
#include "governor_wire.h"
#include "latch_manifest.h"
#include "latch_protocol.h"

/* Fixed memory budget; a full history rejects additional positive motion. */
#define GOV_DOSE_HISTORY_CAPACITY 256u

typedef struct gov_dose_entry {
    uint64_t tick;
    uint64_t dose;
} gov_dose_entry_t;

typedef struct gov_gate_state {
    uint32_t rate_tokens;
    uint32_t shrink_v;
    uint32_t shrink_scale_q8;
    uint8_t shrink_active;
    uint64_t cumulative_window_dose_uL;
    uint64_t last_bolus_tick;
    uint64_t dose_last_tick;
    uint32_t dose_head;
    uint32_t dose_count;
    gov_dose_entry_t dose_history[GOV_DOSE_HISTORY_CAPACITY];
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
    /*
     * HOMEOSTAT velocity ceiling for this tick.
     *
     * 0 means "not applied" (HOMEOSTAT absent or disabled) and reproduces the
     * pre-HOMEOSTAT behaviour EXACTLY. A positive value is an additional
     * CONTRACTING limit: the gate uses min(manifest v_max, homeostat_v_max),
     * so it can only ever lower the ceiling, never raise it. The HOMEOSTAT
     * scale composes multiplicatively with the agent confidence scale.
     */
    int32_t homeostat_v_max;
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
uint16_t gov_medical_check(const latch_manifest_t *manifest, gov_gate_state_t *state,
                           uint64_t tick, int32_t theta, int32_t candidate);
void gov_medical_commit(gov_gate_state_t *state, uint64_t tick,
                        int32_t theta, int32_t accepted);
gov_gate_result_t gov_gate_precheck(const latch_manifest_t *manifest,
                                    const latch_manifest_governor_t *config,
                                    gov_gate_state_t *state,
                                    const gov_gate_input_t *input);

#endif
