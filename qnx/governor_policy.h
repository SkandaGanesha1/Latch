#ifndef GOVERNOR_POLICY_H_
#define GOVERNOR_POLICY_H_

#include <stdint.h>

typedef enum governor_advice {
    GOVERNOR_ADVICE_NOMINAL = 0,
    GOVERNOR_ADVICE_REDUCE = 1,
    GOVERNOR_ADVICE_SAFE_STOP = 2,
    GOVERNOR_ADVICE_INVALID = 3
} governor_advice_t;

#define GOVERNOR_REASON_NONE       0u
#define GOVERNOR_REASON_CONFIDENCE (1u << 0)
#define GOVERNOR_REASON_COHERENCE  (1u << 1)
#define GOVERNOR_REASON_HARD_FAULT (1u << 2)
#define GOVERNOR_REASON_METADATA   (1u << 3)

typedef struct governor_policy_config {
    uint8_t enabled;
    uint8_t min_confidence_q8;
    uint8_t max_coherence_age;
} governor_policy_config_t;

typedef struct governor_policy_input {
    uint8_t confidence_q8;
    uint8_t coherence_age;
    uint8_t has_metadata;
    uint8_t hard_fault;
} governor_policy_input_t;

typedef struct governor_policy_result {
    governor_advice_t advice;
    uint32_t reasons;
} governor_policy_result_t;

governor_policy_result_t governor_policy_evaluate(const governor_policy_config_t *config,
                                                   const governor_policy_input_t *input);

int governor_policy_config_validate(const governor_policy_config_t *config);

/*
 * GOVERNOR supervisory rung state is deliberately separate from latch_mode_t
 * and the evidence-tape mode column. These values are policy state only.
 */
typedef enum governor_rung {
    GOVERNOR_RUNG_HP = 0,
    GOVERNOR_RUNG_ADVISE = 1,
    GOVERNOR_RUNG_CLAMP = 2,
    GOVERNOR_RUNG_SLOW = 3,
    GOVERNOR_RUNG_SAFE_STOP = 4,
    GOVERNOR_RUNG_LATCH = 5
} governor_rung_t;

typedef struct governor_ladder_config {
    uint8_t enabled;
    uint32_t advisory_fault_mask;
    uint32_t faults_per_demotion;
    uint32_t clean_frames_per_promotion;
} governor_ladder_config_t;

typedef struct governor_ladder_state {
    governor_rung_t rung;
    uint32_t advisory_fault_streak;
    uint32_t clean_frame_streak;
    uint8_t operator_release_armed;
} governor_ladder_state_t;

typedef struct governor_ladder_input {
    uint32_t fault_bits;
    uint8_t frame_accepted;
    uint8_t coherent;
    /* Separates an idle decision tick from a rejected/message-only frame. */
    uint8_t frame_present;
    uint8_t immediate_demotion;
    uint8_t safe_stop_complete;
    uint8_t operator_release;
} governor_ladder_input_t;

typedef struct governor_ladder_result {
    governor_rung_t rung_before;
    governor_rung_t rung_after;
    uint8_t changed;
    uint8_t hard_fault;
} governor_ladder_result_t;

int governor_ladder_config_validate(const governor_ladder_config_t *config);
void governor_ladder_init(governor_ladder_state_t *state);
governor_ladder_result_t governor_ladder_step(const governor_ladder_config_t *config,
                                              governor_ladder_state_t *state,
                                              const governor_ladder_input_t *input);

#endif
