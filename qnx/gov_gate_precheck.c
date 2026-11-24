#include "gov_gate_precheck.h"
#include "governor_wire.h"

#include <stdbool.h>
#include <string.h>

static int64_t abs64(int64_t v) {
    return v < 0 ? -v : v;
}

static int64_t clamp64(int64_t v, int64_t lo, int64_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int32_t clamp_i32_from64(int64_t v) {
    if (v < INT32_MIN) return INT32_MIN;
    if (v > INT32_MAX) return INT32_MAX;
    return (int32_t)v;
}

static uint32_t sat_add_u32(uint32_t a, uint32_t b) {
    return UINT32_MAX - a < b ? UINT32_MAX : a + b;
}

static uint32_t q8_scale(uint32_t value, uint32_t q8) {
    uint64_t scaled = ((uint64_t)value * q8) / 256u;
    /* Implicit 1-unit floor: if the scaled value would underflow to 0
     * but the original value was non-zero, return 1. This prevents
     * a confidence-SHRINK from collapsing the envelope to zero velocity,
     * which would be indistinguishable from a bug. The floor is the
     * smallest non-zero step the kinematic model can represent.
     *
     * The floor is a KINEMATIC-MODEL property, not a safety parameter, so
     * it is a constant rather than a manifest field: there is no such key
     * in any schema, and a comment naming one would be a phantom key --
     * the exact "narrative ahead of evidence" failure this project exists
     * to avoid. A plant that needs a larger minimum step declares it in
     * its own envelope `v_max`, and the floor never raises that value
     * above it. */
    if (scaled == 0u && value != 0u) return 1u;
    return scaled > INT32_MAX ? INT32_MAX : (uint32_t)scaled;
}

void gov_gate_init(const latch_manifest_governor_t *config, gov_gate_state_t *state) {
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->rate_tokens = config != NULL ? config->rate_burst_tokens : 0u;
    state->shrink_scale_q8 = 255u;
}

/* Window at tick t contains entries with t - entry.tick < window_ticks.
 * A reversed clock, missing tick, or full history fails closed. */
uint16_t gov_medical_check(const latch_manifest_t *manifest, gov_gate_state_t *state,
                           uint64_t tick, int32_t theta, int32_t candidate) {
    if (manifest == NULL || state == NULL) return LATCH_FAULT_DOSE;
    if (!manifest->medical_present) return 0u;
    if (tick == 0u || (state->dose_last_tick != 0u && tick < state->dose_last_tick) ||
        manifest->medical.cumulative_dose_window_ticks == 0u) return LATCH_FAULT_DOSE;
    state->dose_last_tick = tick;
    while (state->dose_count > 0u) {
        gov_dose_entry_t *oldest = &state->dose_history[state->dose_head];
        if (tick < oldest->tick) return LATCH_FAULT_DOSE;
        if (tick - oldest->tick < manifest->medical.cumulative_dose_window_ticks) break;
        state->cumulative_window_dose_uL -= oldest->dose;
        state->dose_head = (state->dose_head + 1u) % GOV_DOSE_HISTORY_CAPACITY;
        state->dose_count--;
    }
    int64_t delta = (int64_t)candidate - theta;
    if (delta <= 0) return 0u;
    if (state->last_bolus_tick != 0u &&
        (tick < state->last_bolus_tick ||
         tick - state->last_bolus_tick < manifest->medical.min_bolus_interval_ticks))
        return LATCH_FAULT_DOSE;
    if ((uint64_t)delta > manifest->medical.max_bolus_uL ||
        state->cumulative_window_dose_uL >= manifest->medical.max_cumulative_dose_uL ||
        (uint64_t)delta > manifest->medical.max_cumulative_dose_uL - state->cumulative_window_dose_uL ||
        state->dose_count == GOV_DOSE_HISTORY_CAPACITY) return LATCH_FAULT_DOSE;
    return 0u;
}

/* Called only after the supervisor decides to issue a positive motion.
 * Account an I/O failure conservatively because delivered motion is unknown. */
void gov_medical_commit(gov_gate_state_t *state, uint64_t tick,
                        int32_t theta, int32_t accepted) {
    int64_t delta = (int64_t)accepted - theta;
    if (state == NULL || delta <= 0 || state->dose_count >= GOV_DOSE_HISTORY_CAPACITY) return;
    uint32_t index = (state->dose_head + state->dose_count) % GOV_DOSE_HISTORY_CAPACITY;
    state->dose_history[index].tick = tick;
    state->dose_history[index].dose = (uint64_t)delta;
    state->dose_count++;
    state->cumulative_window_dose_uL += (uint64_t)delta;
    state->last_bolus_tick = tick;
}

static bool gov_apply_unit_policy(const latch_manifest_governor_t *config,
                                  uint32_t unit_id,
                                  int32_t *candidate,
                                  uint16_t *faults) {
    if (unit_id == config->canonical_unit_id) return true;
    if (config->units_enabled == 0u) {
        *faults |= LATCH_FAULT_UNIT;
        return false;
    }
    for (uint32_t i = 0u; i < config->unit_scale_count; ++i) {
        if (unit_id != config->alternate_unit_ids[i]) continue;
        uint32_t numerator = config->conversion_numerators[i];
        uint32_t denominator = config->conversion_denominators[i];
        if (numerator == 0u || denominator == 0u) break;
        int64_t scaled = (int64_t)*candidate * (int64_t)numerator;
        if (scaled % (int64_t)denominator != 0) break;
        int64_t converted = scaled / (int64_t)denominator;
        if (converted < INT32_MIN || converted > INT32_MAX) break;
        *candidate = (int32_t)converted;
        return true;
    }
    *faults |= LATCH_FAULT_UNIT;
    return false;
}

static bool gov_apply_rate_bucket(const latch_manifest_governor_t *config,
                                  gov_gate_state_t *state,
                                  governor_rung_t rung,
                                  int32_t theta,
                                  int32_t *candidate,
                                  uint16_t *faults) {
    if (config->rate_enabled == 0u) return true;
    uint32_t refill = config->rate_refill_per_tick;
    if (rung == GOVERNOR_RUNG_SLOW) {
        uint64_t slow_refill = ((uint64_t)refill * config->slow_scale_pct) / 100u;
        refill = slow_refill == 0u ? 1u : (uint32_t)slow_refill;
    }
    state->rate_tokens = sat_add_u32(state->rate_tokens, refill);
    if (state->rate_tokens > config->rate_burst_tokens) {
        state->rate_tokens = config->rate_burst_tokens;
    }

    int64_t delta = (int64_t)*candidate - theta;
    uint64_t distance = (uint64_t)abs64(delta);
    uint64_t sustain = config->rate_sustain_per_tick;
    uint64_t cost = distance > sustain ? distance - sustain : 0u;
    if (cost <= state->rate_tokens) {
        state->rate_tokens -= (uint32_t)cost;
        return true;
    }

    *faults |= LATCH_FAULT_RATE;
    if (rung != GOVERNOR_RUNG_CLAMP && rung != GOVERNOR_RUNG_SLOW) {
        state->rate_tokens = 0u;
        return false;
    }
    uint64_t allowed = sustain + state->rate_tokens;
    int64_t shaped = (int64_t)theta + (delta < 0 ? -(int64_t)allowed : (int64_t)allowed);
    *candidate = clamp_i32_from64(shaped);
    state->rate_tokens = 0u;
    return true;
}

gov_gate_result_t gov_gate_precheck(const latch_manifest_t *manifest,
                                    const latch_manifest_governor_t *config,
                                    gov_gate_state_t *state,
                                    const gov_gate_input_t *input) {
    gov_gate_result_t result;
    memset(&result, 0, sizeof(result));
    result.candidate = input != NULL ? input->candidate : 0;
    result.effective_v_max = manifest != NULL ? manifest->envelope.v_max : 0;
    result.effective_a_max = manifest != NULL ? manifest->envelope.a_max : 0;
    result.normalized_target = input != NULL ? input->candidate : 0;

    if (manifest == NULL || config == NULL || state == NULL || input == NULL ||
        config->enabled != 1u || input->rung < GOVERNOR_RUNG_HP ||
        input->rung > GOVERNOR_RUNG_LATCH || input->has_v2_metadata > 1u) {
        result.faults = LATCH_FAULT_MAGIC;
        return result;
    }

    /*
     * HOMEOSTAT velocity ceiling (CONTRACTING ONLY).
     *
     * `base_v_max` is the signed manifest limit, possibly lowered by the
     * HOMEOSTAT outer loop. A homeostat_v_max of 0 means "not applied", which
     * leaves base_v_max equal to the manifest value and reproduces the
     * pre-HOMEOSTAT behaviour bit-for-bit. A positive homeostat_v_max can
     * only lower the ceiling -- there is no code path here that raises it.
     */
    int32_t base_v_max = manifest->envelope.v_max;
    if (input->homeostat_v_max > 0 && input->homeostat_v_max < base_v_max) {
        base_v_max = input->homeostat_v_max;
    }
    result.effective_v_max = base_v_max;

    if (input->kind == GOVERNOR_WIRE_HEARTBEAT) {
        result.message_only = 1u;
        result.command_valid = 1u;
        return result;
    }
    if (input->kind == GOVERNOR_WIRE_SHRINK_REQ) {
        if (input->candidate <= 0 || input->candidate > result.effective_v_max ||
            input->confidence_q8 == 0u ||
            (state->shrink_active != 0u &&
             ((uint32_t)input->candidate > state->shrink_v ||
              input->confidence_q8 > state->shrink_scale_q8))) {
            result.faults |= LATCH_FAULT_WIDEN;
            result.command_valid = 0u;
            result.message_only = 1u;
            return result;
        }
        state->shrink_v = (uint32_t)input->candidate;
        state->shrink_scale_q8 = input->confidence_q8;
        state->shrink_active = 1u;
        result.message_only = 1u;
        result.command_valid = 1u;
        return result;
    }
    if (input->kind != GOVERNOR_WIRE_CMD && input->kind != GOVERNOR_WIRE_CMD_V2) {
        result.faults = LATCH_FAULT_MAGIC;
        return result;
    }

    int32_t candidate = input->candidate;
    if (!gov_apply_unit_policy(config, input->unit_id,
                               &candidate, &result.faults)) {
        result.candidate = candidate;
        result.normalized_target = candidate;
        return result;
    }
    result.normalized_target = candidate;

    if (input->kind == GOVERNOR_WIRE_CMD_V2) {
        if (input->has_v2_metadata == 0u) {
            result.faults |= LATCH_FAULT_RESERVED;
            return result;
        }
        uint32_t floor_q8 = config->min_confidence_q8;
        if (floor_q8 > 255u) floor_q8 = 255u; /* Q8 bound; manifests validate 1..255 */
        uint32_t scale_q8 = input->confidence_q8 < floor_q8 ? floor_q8 : input->confidence_q8;
        if (state->shrink_active != 0u && state->shrink_scale_q8 < scale_q8) {
            scale_q8 = state->shrink_scale_q8;
        }
        uint32_t v_eff = q8_scale((uint32_t)base_v_max, scale_q8);
        uint32_t a_eff = q8_scale((uint32_t)manifest->envelope.a_max, scale_q8);
        if (state->shrink_active != 0u && state->shrink_v < v_eff) v_eff = state->shrink_v;
        result.effective_v_max = (int32_t)v_eff;
        result.effective_a_max = (int32_t)a_eff;
        int64_t lo_step = -(int64_t)v_eff;
        int64_t hi_step = (int64_t)v_eff;
        int64_t lo_accel = (int64_t)input->velocity - (int64_t)a_eff;
        int64_t hi_accel = (int64_t)input->velocity + (int64_t)a_eff;
        if (lo_accel > lo_step) lo_step = lo_accel;
        if (hi_accel < hi_step) hi_step = hi_accel;
        if (lo_step > hi_step) {
            result.faults |= LATCH_FAULT_RATE;
            result.candidate = candidate;
            return result;
        }
        int64_t step = clamp64((int64_t)candidate - input->theta, lo_step, hi_step);
        candidate = clamp_i32_from64((int64_t)input->theta + step);
    }

    if (input->rung == GOVERNOR_RUNG_CLAMP || input->rung == GOVERNOR_RUNG_SLOW) {
        uint64_t step_limit = config->clamp_max_step;
        if (input->rung == GOVERNOR_RUNG_SLOW) {
            step_limit = (step_limit * config->slow_scale_pct) / 100u;
            if (step_limit == 0u) step_limit = 1u;
        }
        int64_t delta = (int64_t)candidate - input->theta;
        if ((uint64_t)abs64(delta) > step_limit) {
            result.faults |= LATCH_FAULT_DOSE;
        }
        candidate = clamp_i32_from64((int64_t)input->theta +
                                     clamp64(delta, -(int64_t)step_limit,
                                             (int64_t)step_limit));
    } else if (input->rung == GOVERNOR_RUNG_HP || input->rung == GOVERNOR_RUNG_ADVISE) {
        int64_t delta = (int64_t)candidate - input->theta;
        if ((uint64_t)abs64(delta) > (uint64_t)base_v_max) {
            result.faults |= (LATCH_FAULT_DOSE | LATCH_FAULT_RATE);
        }
    }

    if (!gov_apply_rate_bucket(config, state, input->rung, input->theta,
                               &candidate, &result.faults)) {
        result.candidate = candidate;
        return result;
    }
    result.candidate = candidate;
    result.command_valid = 1u;
    return result;
}
