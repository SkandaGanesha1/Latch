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

#define LATCH_MANIFEST_SCHEMA_VERSION  1u
#define LATCH_MAX_AXES                4u
#define LATCH_MAX_KEEPOUTS            8u

typedef struct latch_axis {
    uint32_t id;
    char     kind[16];   /* "angular", "linear", "rate" */
    char     unit[16];   /* "mrad", "mm", "mrad_s"      */
    int32_t  min;
    int32_t  max;
} latch_axis_t;

typedef struct latch_keepout_interval {
    int32_t lo_mrad;
    int32_t hi_mrad;
    char    label[32];
} latch_keepout_interval_t;

typedef struct latch_manifest_envelope {
    int32_t                  theta_min_mrad;
    int32_t                  theta_max_mrad;
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
} latch_manifest_actuator_t;

typedef struct latch_manifest_tape {
    uint32_t capacity;
} latch_manifest_tape_t;

typedef struct latch_manifest_protocol {
    char     magic[8];
    uint32_t version;
    char     crc[16];
    uint32_t coverage;
} latch_manifest_protocol_t;

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
    uint8_t                   sha256[32];
    char                      sha256_hex[65];
} latch_manifest_t;

/* Initialize manifest with conservative defaults matching the reference plant */
void latch_manifest_init_defaults(latch_manifest_t *m);

/* Load and validate latch.manifest JSON from file. Returns 0 on success, <0 on failure. */
int latch_manifest_load(const char *path, latch_manifest_t *out_m, char *err_buf, size_t err_len);

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

