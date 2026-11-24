/*
 * qnx/latch_manifest.h
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Zero-Hardcoding Manifest Engine:
 * Defines generic multi-axis plant configuration, kinematic envelope limits,
 * disjoint keep-out intervals, real-time timing & watchdog budgets, hardware
 * bus paths, and PCA9685 PWM calibration loaded from `latch.manifest`.
 */

#ifndef LATCH_MANIFEST_H_
#define LATCH_MANIFEST_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LATCH_MANIFEST_SCHEMA_VERSION  2u
#define LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION 3u
#define LATCH_MAX_AXES                4u
#define LATCH_MAX_KEEPOUTS            8u
#define LATCH_MANIFEST_MAX_TAPE_CAPACITY 4096u

typedef struct latch_axis {
    uint32_t id;
    char     kind[16];   /* "angular", "linear", "rate" */
    char     unit[16];   /* "mrad", "mm", "mrad_s"      */
    int32_t  min;
    int32_t  max;
    int32_t  fullscale_counts_span;
} latch_axis_t;

typedef struct latch_keepout_interval {
    int32_t lo_mrad;
    int32_t hi_mrad;
    char    label[32];
} latch_keepout_interval_t;

typedef struct latch_manifest_envelope {
    int32_t                  theta_min_mrad;
    int32_t                  theta_max_mrad;
    int32_t                  home_mrad;
    uint32_t                 num_keepouts;
    latch_keepout_interval_t keepout[LATCH_MAX_KEEPOUTS];
    int32_t                  v_max;
    int32_t                  a_max;
    int32_t                  j_max;
    int32_t                  v_home;
    uint32_t                 lookahead_ticks;
} latch_manifest_envelope_t;

typedef struct latch_manifest_timing {
    uint32_t period_us;
    uint32_t watchdog_ticks;
    uint32_t wcet_budget_us;
    uint32_t max_backlog_ticks;
} latch_manifest_timing_t;

typedef struct latch_manifest_recovery {
    uint32_t hysteresis_clean_frames;
    uint32_t hold_to_home_ticks;
} latch_manifest_recovery_t;

typedef struct latch_manifest_decision {
    uint32_t cpu;
    uint32_t priority;
    uint32_t pulse_priority;
} latch_manifest_decision_t;

typedef struct latch_manifest_ingest {
    uint32_t cpu;
    char     delivery[16];   /* "queued" or "latest" */
    uint32_t queue_depth;    /* bounded ring buffer capacity */
} latch_manifest_ingest_t;

typedef struct latch_manifest_paths {
    char proposal[128];
    char actuator[128];
    char ability[128];
    char i2c_bus[128];
} latch_manifest_paths_t;

typedef struct latch_manifest_actuator {
    char     type[32];
    uint32_t addr;
    uint32_t freq_hz;
    uint32_t prescale;
    int32_t  pwm_center;
    int32_t  pwm_min;
    int32_t  pwm_max;
    uint32_t retries;
    uint32_t init_delay_us;
    bool     required;
} latch_manifest_actuator_t;

typedef struct latch_manifest_tape {
    uint32_t capacity;
    char     log_path[128];  /* Where the evidence logger persists the CSV */
} latch_manifest_tape_t;

typedef struct latch_manifest_protocol {
    char     magic[8];
    uint32_t version;
    char     crc[16];
    uint32_t coverage;
} latch_manifest_protocol_t;

typedef struct latch_manifest_governor {
    uint32_t enabled;
    uint32_t advise_fault_mask;
    uint32_t clamp_max_step;
    uint32_t slow_scale_pct;
    uint32_t safe_stop_decel;
    uint32_t demote_faults_per_rung;
    uint32_t promote_clean_frames;
    uint32_t lease_ticks;
    uint32_t coherence_max_gap;
    uint32_t warmup_heartbeats;
    uint32_t units_enabled;
    uint32_t canonical_unit_id;
    uint32_t alternate_unit_ids[4];
    uint32_t conversion_numerators[4];
    uint32_t conversion_denominators[4];
    uint32_t unit_scale_count;
    uint32_t rate_enabled;
    uint32_t rate_burst_tokens;
    uint32_t rate_refill_per_tick;
    uint32_t rate_sustain_per_tick;
    uint32_t min_confidence_q8;
} latch_manifest_governor_t;

typedef struct latch_manifest_medical {
    char     drug_name[64];
    uint32_t drug_id;
    uint32_t concentration_uL_per_unit;
    uint32_t max_bolus_uL;
    uint32_t min_bolus_interval_ticks;
    uint32_t cumulative_dose_window_ticks;
    uint32_t max_cumulative_dose_uL;
} latch_manifest_medical_t;

/*
 * HOMEOSTAT (Ashby ultrastability) outer-loop configuration.
 *
 * This is an OPTIONAL, schema-3, DEFAULT-OFF section. An absent section
 * means `homeostat_present == false`, `homeostat.enabled == 0`, and the
 * supervisor behaves bit-identically to a build without the module. That
 * property is asserted by the host-sim evidence signature gate.
 *
 * The loop is CONTRACTING ONLY: it may lower the effective velocity ceiling
 * below the signed manifest limit, never raise it. `floor_q8` is the lowest
 * scale the loop may reach (Q8, so 256 == 1.0).
 */
typedef struct latch_manifest_homeostat {
    uint32_t enabled;
    uint32_t epoch_ticks;
    uint32_t reject_threshold_q8;
    uint32_t latency_spread_threshold_ns;
    uint32_t clamp_threshold_q8;
    uint32_t coherence_anomaly_threshold;
    uint32_t contraction_q8;
    uint32_t recovery_q8;
    uint32_t floor_q8;
} latch_manifest_homeostat_t;

typedef struct latch_manifest {
    uint32_t                  schema_version;
    char                      plant_name[64];
    uint32_t                  num_axes;
    latch_axis_t              axes[LATCH_MAX_AXES];
    latch_manifest_envelope_t envelope;
    latch_manifest_timing_t   timing;
    latch_manifest_recovery_t recovery;
    latch_manifest_decision_t decision;
    latch_manifest_ingest_t   ingest;
    latch_manifest_paths_t    paths;
    latch_manifest_actuator_t actuator;
    latch_manifest_tape_t     tape;
    latch_manifest_protocol_t protocol;
    latch_manifest_governor_t governor;
    bool                      governor_present;
    latch_manifest_medical_t  medical;
    bool                      medical_present;
    latch_manifest_homeostat_t homeostat;
    bool                      homeostat_present;
    uint8_t                   sha256[32];
    char                      sha256_hex[65];
} latch_manifest_t;

typedef enum latch_admissibility {
    LATCH_ADMIT_UNRESOLVED = 0,  /* Missing required JSON keys, I/O failure, schema != 1, zero timing */
    LATCH_ADMIT_SATISFIED  = 1,  /* All prerequisites and topological/kinematic invariants hold */
    LATCH_ADMIT_VIOLATED   = 2   /* Topological/kinematic invariant violated */
} latch_admissibility_t;

/* DEPRECATED: not called anywhere. Strict defaults come from schema-3
 * manifest load; schema-1/2 have first-match-wins duplicate/unknown key
 * behavior (known limitation). Re-add with caller+test if needed. */
void latch_manifest_init_defaults(latch_manifest_t *m);

/* Load and validate latch.manifest JSON from file. Returns 0 on success, <0 on failure. */
int latch_manifest_load(const char *path, latch_manifest_t *out_m, char *err_buf, size_t err_len);

/* Load and validate manifest with explicit sidecar enforcement policy. */
int latch_manifest_load_opts(const char *path, latch_manifest_t *out_m, bool require_sidecar,
                             char *err_buf, size_t err_len);

/* Three-valued evidence-grounded manifest admissibility validator */
latch_admissibility_t latch_manifest_validate(const latch_manifest_t *m, char *err_buf, size_t err_len);

/* Verify sidecar file (<manifest_path>.sha256) matches computed hex digest. Returns 0 on success, <0 on mismatch or missing when required */
int latch_manifest_verify_sidecar(const char *manifest_path, const char *computed_hex,
                                  bool require_sidecar, char *err_buf, size_t err_len);

/* Compute SHA-256 digest of a manifest file. Returns 0 on success, <0 on failure. */
int latch_manifest_compute_sha256(const char *path, uint8_t hash_out[32], char hex_out[65]);

/* Self-test SHA-256 implementation against NIST FIPS 180-2 vectors. Returns 0 on pass. */
int latch_manifest_selftest_sha256(void);

/* Check if a candidate angle violates any configured keep-out interval */
bool latch_manifest_in_keepout(const latch_manifest_t *m, int32_t theta_mrad);

/* Check if a transition between theta_a and theta_b enters or crosses any keep-out interval */
bool latch_manifest_crossed_keepout(const latch_manifest_t *m, int32_t theta_a, int32_t theta_b);

#ifdef __cplusplus
}
#endif

#endif /* LATCH_MANIFEST_H_ */

