#ifndef GOV_HOMEOSTAT_H_
#define GOV_HOMEOSTAT_H_

#include <stdint.h>

/* Bounded, integer-only supervisor-owned adaptive velocity scale. */
typedef struct gov_homeostat_config {
    uint32_t enabled;
    uint32_t epoch_ticks;
    uint32_t reject_threshold_q8;
    uint32_t latency_spread_threshold_ns;
    uint32_t clamp_threshold_q8;
    uint32_t coherence_anomaly_threshold;
    uint32_t contraction_q8;
    uint32_t recovery_q8;
    uint32_t floor_q8;
} gov_homeostat_config_t;

typedef struct gov_homeostat_state {
    uint32_t scale_q8;
    uint32_t epoch_ticks;
    uint32_t proposals;
    uint32_t rejected;
    uint32_t coherence_anomalies;
    uint64_t proposed_motion;
    uint64_t applied_motion;
    uint32_t latency_min_ns;
    uint32_t latency_max_ns;
    uint32_t last_reject_ratio_q8;
    uint32_t last_clamp_fraction_q8;
    uint32_t last_latency_spread_ns;
    uint32_t last_coherence_anomalies;
    uint32_t stress_epochs;
    uint32_t recovery_epochs;
} gov_homeostat_state_t;

typedef struct gov_homeostat_sample {
    uint8_t proposal_present;
    uint8_t proposal_accepted;
    uint8_t coherence_anomaly;
    uint32_t latency_ns;
    uint32_t proposed_motion;
    uint32_t applied_motion;
} gov_homeostat_sample_t;

void gov_homeostat_init(gov_homeostat_state_t *state);
/* Returns 1 when an epoch closes, 0 otherwise. No heap, floating point, or I/O. */
int gov_homeostat_observe(const gov_homeostat_config_t *config,
                          gov_homeostat_state_t *state,
                          const gov_homeostat_sample_t *sample);
uint32_t gov_homeostat_effective_vmax(uint32_t manifest_vmax,
                                      uint32_t homeostat_scale_q8,
                                      uint32_t agent_scale_q8);

#endif
