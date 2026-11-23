#include "gov_homeostat.h"

#include <limits.h>
#include <string.h>

#define GOV_HOMEOSTAT_Q8_ONE 256u

static uint64_t sat_add_u64(uint64_t a, uint64_t b) {
    return UINT64_MAX - a < b ? UINT64_MAX : a + b;
}

static uint32_t fraction_q8(uint64_t numerator, uint64_t denominator) {
    if (denominator == 0u || numerator == 0u) return 0u;
    if (numerator >= denominator) return GOV_HOMEOSTAT_Q8_ONE;
    uint32_t q = 0u;
    uint64_t rem = numerator;
    for (unsigned int i = 0u; i < 8u; ++i) {
        q <<= 1;
        if (rem >= denominator - rem) {
            rem -= denominator - rem;
            q++;
        } else {
            rem += rem;
        }
    }
    return q;
}

void gov_homeostat_init(gov_homeostat_state_t *state) {
    if (state == NULL) return;
    memset(state, 0, sizeof(*state));
    state->scale_q8 = GOV_HOMEOSTAT_Q8_ONE;
    state->latency_min_ns = UINT32_MAX;
}

int gov_homeostat_observe(const gov_homeostat_config_t *config,
                          gov_homeostat_state_t *state,
                          const gov_homeostat_sample_t *sample) {
    if (config == NULL || state == NULL || sample == NULL ||
        config->epoch_ticks == 0u || config->floor_q8 > GOV_HOMEOSTAT_Q8_ONE ||
        config->contraction_q8 == 0u || config->recovery_q8 == 0u) return 0;
    if (config->enabled == 0u) {
        state->scale_q8 = GOV_HOMEOSTAT_Q8_ONE;
        return 0;
    }

    if (sample->proposal_present) {
        if (state->proposals < UINT32_MAX) state->proposals++;
        if (!sample->proposal_accepted && state->rejected < UINT32_MAX) state->rejected++;
        state->proposed_motion = sat_add_u64(state->proposed_motion, sample->proposed_motion);
        uint32_t applied = sample->applied_motion > sample->proposed_motion
                               ? sample->proposed_motion : sample->applied_motion;
        state->applied_motion = sat_add_u64(state->applied_motion, applied);
    }
    if (sample->coherence_anomaly && state->coherence_anomalies < UINT32_MAX)
        state->coherence_anomalies++;
    if (sample->latency_ns < state->latency_min_ns) state->latency_min_ns = sample->latency_ns;
    if (sample->latency_ns > state->latency_max_ns) state->latency_max_ns = sample->latency_ns;
    if (state->epoch_ticks < UINT32_MAX) state->epoch_ticks++;
    if (state->epoch_ticks < config->epoch_ticks) return 0;

    uint32_t reject_q8 = state->proposals == 0u ? 0u :
        (uint32_t)(((uint64_t)state->rejected * GOV_HOMEOSTAT_Q8_ONE) / state->proposals);
    uint32_t clamp_q8 = state->proposed_motion == 0u ? 0u :
        fraction_q8(state->proposed_motion - state->applied_motion,
                    state->proposed_motion);
    uint32_t spread = state->latency_max_ns >= state->latency_min_ns
                          ? state->latency_max_ns - state->latency_min_ns : 0u;
    state->last_reject_ratio_q8 = reject_q8;
    state->last_clamp_fraction_q8 = clamp_q8;
    state->last_latency_spread_ns = spread;
    state->last_coherence_anomalies = state->coherence_anomalies;

    int stressed = (config->reject_threshold_q8 != 0u && reject_q8 >= config->reject_threshold_q8) ||
                   (config->latency_spread_threshold_ns != 0u &&
                    spread >= config->latency_spread_threshold_ns) ||
                   (config->clamp_threshold_q8 != 0u && clamp_q8 >= config->clamp_threshold_q8) ||
                   (config->coherence_anomaly_threshold != 0u &&
                    state->coherence_anomalies >= config->coherence_anomaly_threshold);
    if (stressed) {
        state->scale_q8 = state->scale_q8 > config->floor_q8 &&
                          state->scale_q8 - config->floor_q8 > config->contraction_q8
                              ? state->scale_q8 - config->contraction_q8 : config->floor_q8;
        if (state->scale_q8 < config->floor_q8) state->scale_q8 = config->floor_q8;
        if (state->stress_epochs < UINT32_MAX) state->stress_epochs++;
    } else if (state->proposals != 0u) {
        uint64_t recovered = (uint64_t)state->scale_q8 + config->recovery_q8;
        state->scale_q8 = recovered > GOV_HOMEOSTAT_Q8_ONE
                              ? GOV_HOMEOSTAT_Q8_ONE : (uint32_t)recovered;
        if (state->recovery_epochs < UINT32_MAX) state->recovery_epochs++;
    }

    state->epoch_ticks = state->proposals = state->rejected = state->coherence_anomalies = 0u;
    state->proposed_motion = state->applied_motion = 0u;
    state->latency_min_ns = UINT32_MAX;
    state->latency_max_ns = 0u;
    return 1;
}

uint32_t gov_homeostat_effective_vmax(uint32_t manifest_vmax,
                                      uint32_t homeostat_scale_q8,
                                      uint32_t agent_scale_q8) {
    uint64_t h = ((uint64_t)manifest_vmax * homeostat_scale_q8) / GOV_HOMEOSTAT_Q8_ONE;
    uint64_t a = ((uint64_t)manifest_vmax * agent_scale_q8) / GOV_HOMEOSTAT_Q8_ONE;
    uint64_t result = manifest_vmax;
    if (h < result) result = h;
    if (a < result) result = a;
    return (uint32_t)result;
}
