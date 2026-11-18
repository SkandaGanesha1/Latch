#include "governor_policy.h"

int governor_policy_config_validate(const governor_policy_config_t *config) {
    if (config == 0 || config->enabled > 1u || config->max_coherence_age == 0u) {
        return -1;
    }
    return 0;
}

int governor_ladder_config_validate(const governor_ladder_config_t *config) {
    if (config == 0 || config->enabled > 1u) {
        return -1;
    }
    if (config->enabled != 0u &&
        (config->faults_per_demotion == 0u ||
         config->clean_frames_per_promotion == 0u)) {
        return -1;
    }
    return 0;
}

void governor_ladder_init(governor_ladder_state_t *state) {
    if (state == 0) return;
    state->rung = GOVERNOR_RUNG_HP;
    state->advisory_fault_streak = 0u;
    state->clean_frame_streak = 0u;
    state->operator_release_armed = 0u;
}

static governor_rung_t governor_rung_demote(governor_rung_t rung) {
    if (rung < GOVERNOR_RUNG_LATCH) {
        return (governor_rung_t)((unsigned int)rung + 1u);
    }
    return GOVERNOR_RUNG_LATCH;
}

static governor_rung_t governor_rung_promote(governor_rung_t rung) {
    if (rung > GOVERNOR_RUNG_HP && rung <= GOVERNOR_RUNG_LATCH) {
        return (governor_rung_t)((unsigned int)rung - 1u);
    }
    return GOVERNOR_RUNG_HP;
}

static uint32_t governor_sat_inc(uint32_t value) {
    return value == UINT32_MAX ? value : value + 1u;
}

governor_ladder_result_t governor_ladder_step(const governor_ladder_config_t *config,
                                              governor_ladder_state_t *state,
                                              const governor_ladder_input_t *input) {
    governor_ladder_result_t result;
    result.rung_before = state != 0 ? state->rung : GOVERNOR_RUNG_LATCH;
    result.rung_after = result.rung_before;
    result.changed = 0u;
    result.hard_fault = 0u;

    if (governor_ladder_config_validate(config) != 0 || state == 0 || input == 0 ||
        state->rung < GOVERNOR_RUNG_HP || state->rung > GOVERNOR_RUNG_LATCH ||
        input->frame_accepted > 1u || input->coherent > 1u ||
        input->frame_present > 1u ||
        (input->frame_accepted != 0u && input->frame_present == 0u) ||
        input->immediate_demotion > 1u || input->safe_stop_complete > 1u ||
        input->operator_release > 1u || state->operator_release_armed > 1u) {
        result.rung_after = GOVERNOR_RUNG_LATCH;
        result.hard_fault = 1u;
        if (state != 0) {
            state->rung = GOVERNOR_RUNG_LATCH;
            state->advisory_fault_streak = 0u;
            state->clean_frame_streak = 0u;
            state->operator_release_armed = 0u;
        }
        result.changed = (result.rung_before != result.rung_after) ? 1u : 0u;
        return result;
    }

    if (config->enabled == 0u) {
        return result;
    }

    uint32_t advisory_faults = input->fault_bits & config->advisory_fault_mask;
    uint32_t hard_faults = input->fault_bits & ~config->advisory_fault_mask;
    if (hard_faults != 0u) {
        state->rung = GOVERNOR_RUNG_LATCH;
        state->advisory_fault_streak = 0u;
        state->clean_frame_streak = 0u;
        state->operator_release_armed = 0u;
        result.hard_fault = 1u;
    } else if (input->immediate_demotion != 0u) {
        state->rung = governor_rung_demote(state->rung);
        state->advisory_fault_streak = 0u;
        state->clean_frame_streak = 0u;
    } else if (advisory_faults != 0u) {
        state->clean_frame_streak = 0u;
        if (state->rung == GOVERNOR_RUNG_HP) {
            state->rung = GOVERNOR_RUNG_ADVISE;
            state->advisory_fault_streak = 0u;
        } else {
            state->advisory_fault_streak = governor_sat_inc(state->advisory_fault_streak);
        }
        if (state->rung != GOVERNOR_RUNG_ADVISE &&
            state->advisory_fault_streak >= config->faults_per_demotion) {
            state->rung = governor_rung_demote(state->rung);
            state->advisory_fault_streak = 0u;
        } else if (state->rung == GOVERNOR_RUNG_ADVISE &&
                   state->advisory_fault_streak >= config->faults_per_demotion) {
            state->rung = GOVERNOR_RUNG_CLAMP;
            state->advisory_fault_streak = 0u;
        }
    } else {
        state->advisory_fault_streak = 0u;
        if (state->rung == GOVERNOR_RUNG_LATCH && input->operator_release != 0u) {
            state->operator_release_armed = 1u;
        }
        if (input->frame_accepted != 0u && input->coherent != 0u) {
            state->clean_frame_streak = governor_sat_inc(state->clean_frame_streak);
            if (state->clean_frame_streak >= config->clean_frames_per_promotion &&
                (state->rung != GOVERNOR_RUNG_SAFE_STOP || input->safe_stop_complete != 0u) &&
                (state->rung != GOVERNOR_RUNG_LATCH || state->operator_release_armed != 0u)) {
                state->rung = governor_rung_promote(state->rung);
                state->clean_frame_streak = 0u;
                state->operator_release_armed = 0u;
            }
        } else if (input->frame_present != 0u) {
            state->clean_frame_streak = 0u;
        }
    }

    result.rung_after = state->rung;
    result.changed = (result.rung_before != result.rung_after) ? 1u : 0u;
    return result;
}

governor_policy_result_t governor_policy_evaluate(const governor_policy_config_t *config,
                                                   const governor_policy_input_t *input) {
    governor_policy_result_t result = { GOVERNOR_ADVICE_INVALID, GOVERNOR_REASON_METADATA };

    if (governor_policy_config_validate(config) != 0 || input == 0 ||
        input->has_metadata > 1u || input->hard_fault > 1u) {
        return result;
    }

    result.reasons = GOVERNOR_REASON_NONE;
    result.advice = GOVERNOR_ADVICE_NOMINAL;

    if (config->enabled == 0u) {
        return result;
    }
    if (input->has_metadata == 0u) {
        result.advice = GOVERNOR_ADVICE_INVALID;
        result.reasons = GOVERNOR_REASON_METADATA;
        return result;
    }
    if (input->hard_fault != 0u) {
        result.advice = GOVERNOR_ADVICE_SAFE_STOP;
        result.reasons = GOVERNOR_REASON_HARD_FAULT;
        return result;
    }
    if (input->confidence_q8 < config->min_confidence_q8) {
        result.advice = GOVERNOR_ADVICE_REDUCE;
        result.reasons |= GOVERNOR_REASON_CONFIDENCE;
    }
    if (input->coherence_age > config->max_coherence_age) {
        result.advice = GOVERNOR_ADVICE_REDUCE;
        result.reasons |= GOVERNOR_REASON_COHERENCE;
    }
    return result;
}
