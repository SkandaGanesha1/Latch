/*
 * qnx/latch_manifest_test.c
 *
 * LATCH — manifest parser unit tests.
 *
 * The manifest is the SAFETY FRONT DOOR: every plant limit, every timing
 * budget and every calibration constant enters the supervisor through this
 * parser, and a parser that silently accepts a malformed document is a
 * safety defect, not a convenience. This test therefore asserts two things
 * for every case:
 *
 *   1. a WELL-FORMED document loads and yields the expected values, and
 *   2. a MALFORMED document is REJECTED (fail closed) with a non-zero rc --
 *      never silently defaulted, never clamped.
 *
 * The HOMEOSTAT section is optional and DEFAULT-OFF, so it gets the most
 * attention here: absent means off, present means strictly parsed, and an
 * out-of-range safety parameter is a LOAD REJECTION rather than a runtime
 * clamp.
 */

#include "latch_manifest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

/* A minimal, complete schema-3 manifest with the GOVERNOR section enabled.
 * The HOMEOSTAT section is appended by the caller. */
static const char *BASE_SCHEMA3 =
    "{\n"
    "  \"schema_version\": 3,\n"
    "  \"plant\": {\"name\": \"servo-horn-1d\", \"axes\": [{\"id\": 0, \"kind\": \"angular\","
    " \"unit\": \"mrad\", \"min\": -1000, \"max\": 1000}]},\n"
    "  \"envelope\": {\"theta_min_mrad\": -1000, \"theta_max_mrad\": 1000, \"home_mrad\": 0,\n"
    "    \"keepout\": [{\"lo_mrad\": 250, \"hi_mrad\": 650, \"label\": \"PERSON\"}],\n"
    "    \"v_max\": 25, \"a_max\": 10, \"j_max\": 20, \"v_home\": 10, \"lookahead_ticks\": 10},\n"
    "  \"timing\": {\"period_us\": 1000, \"watchdog_ticks\": 2, \"wcet_budget_us\": 100,\n"
    "    \"max_backlog_ticks\": 256},\n"
    "  \"recovery\": {\"hysteresis_clean_frames\": 25, \"hold_to_home_ticks\": 50},\n"
    "  \"decision\": {\"cpu\": 0, \"priority\": 63, \"pulse_priority\": 63},\n"
    "  \"ingest\": {\"cpu\": 1, \"delivery\": \"queued\", \"queue_depth\": 256},\n"
    "  \"paths\": {\"proposal\": \"/dev/latch/proposal\", \"actuator\": \"/dev/latch/actuator\",\n"
    "    \"ability\": \"latch/actuator\", \"i2c_bus\": \"/dev/i2c1\"},\n"
    "  \"actuator\": {\"type\": \"pca9685\", \"addr\": 64, \"freq_hz\": 50, \"prescale\": 121,\n"
    "    \"pwm_center\": 307, \"pwm_min\": 205, \"pwm_max\": 410, \"retries\": 1,\n"
    "    \"init_delay_us\": 600, \"required\": false},\n"
    "  \"tape\": {\"capacity\": 4096, \"log_path\": \"/dev/shmem/latch_tape.csv\"},\n"
    "  \"protocol\": {\"magic\": \"LATH\", \"version\": 2, \"crc\": \"ieee32-v2\", \"coverage\": 28},\n"
    "  \"governor\": {\n"
    "    \"enabled\": 1,\n"
    "    \"ladder\": {\"advise_fault_mask\": 4096, \"clamp_max_step\": 5, \"slow_scale_pct\": 25,\n"
    "      \"safe_stop_decel\": 10, \"demote_faults_per_rung\": 3, \"promote_clean_frames\": 25,\n"
    "      \"min_confidence_q8\": 128},\n"
    "    \"deadman\": {\"lease_ticks\": 100, \"coherence_max_gap\": 3, \"warmup_heartbeats\": 4},\n"
    "    \"units\": {\"enabled\": 1, \"canonical_unit_id\": 1, \"alternate_unit_ids\": [2, 3],\n"
    "      \"conversion_numerators\": [1, 1], \"conversion_denominators\": [57, 1000]},\n"
    "    \"rate\": {\"enabled\": 1, \"burst_tokens\": 40, \"refill_per_tick\": 2, \"sustain_per_tick\": 25}\n"
    "  }\n"
    "}\n";

/* The HOMEOSTAT section with every value legal. */
static const char *HOMEOSTAT_SECTION =
    ",\n"
    "  \"homeostat\": {\n"
    "    \"enabled\": 1,\n"
    "    \"epoch_ticks\": 100,\n"
    "    \"reject_threshold_q8\": 64,\n"
    "    \"latency_spread_threshold_ns\": 100000,\n"
    "    \"clamp_threshold_q8\": 64,\n"
    "    \"coherence_anomaly_threshold\": 4,\n"
    "    \"contraction_q8\": 8,\n"
    "    \"recovery_q8\": 2,\n"
    "    \"floor_q8\": 26\n"
    "  }\n";

/*
 * Writes `body` to a temporary manifest, generates the matching SHA-256
 * sidecar (the loader REQUIRES it), and loads it.
 *
 * Returns the loader's rc; *out is only meaningful on success.
 */
static int load_body(const char *body, latch_manifest_t *out, char *err, size_t err_len) {
    static char path[192];
    static char sidecar[256];
    const char *dir = getenv("TMPDIR");
    if (dir == NULL || dir[0] == '\0') dir = "/tmp";
    snprintf(path, sizeof(path), "%s/latch_manifest_test_%d.manifest", dir, (int)getpid());
    snprintf(sidecar, sizeof(sidecar), "%s.sha256", path);

    FILE *f = fopen(path, "wb");
    if (f == NULL) return -EIO;
    size_t len = strlen(body);
    if (fwrite(body, 1, len, f) != len) {
        fclose(f);
        return -EIO;
    }
    fclose(f);

    /* The sidecar must match the file's SHA-256 exactly. */
    unsigned char digest[32];
    char hex[65];
    if (latch_manifest_compute_sha256(path, digest, hex) != 0) {
        remove(path);
        return -EIO;
    }
    f = fopen(sidecar, "wb");
    if (f == NULL) {
        remove(path);
        return -EIO;
    }
    fprintf(f, "%s  %s\n", hex, "latch_manifest_test.manifest");
    fclose(f);

    int rc = latch_manifest_load(path, out, err, err_len);
    remove(path);
    remove(sidecar);
    return rc;
}

static void expect_rejected(const char *label, const char *body) {
    checks++;
    latch_manifest_t m;
    char err[512] = {0};
    memset(&m, 0, sizeof(m));
    int rc = load_body(body, &m, err, sizeof(err));
    if (rc == 0) {
        fprintf(stderr, "FAIL: %s should have been REJECTED but loaded\n", label);
        failures++;
    }
}

static char *with_homeostat(const char *section) {
    /* BASE_SCHEMA3 ends with "}\n"; splice the extra section in before the
     * closing brace. */
    static char buffer[8192];
    const char *tail = strrchr(BASE_SCHEMA3, '}');
    if (tail == NULL) return NULL;
    size_t head = (size_t)(tail - BASE_SCHEMA3);
    snprintf(buffer, sizeof(buffer), "%.*s%s%s", (int)head, BASE_SCHEMA3, section, tail);
    return buffer;
}

int main(void) {
    char err[512] = {0};

    /* ------------------------------------------------------------------
     * 1. The baseline schema-3 manifest loads, and HOMEOSTAT is OFF.
     * ------------------------------------------------------------------ */
    {
        checks++;
        latch_manifest_t m;
        memset(&m, 0, sizeof(m));
        int rc = load_body(BASE_SCHEMA3, &m, err, sizeof(err));
        if (rc != 0) {
            fprintf(stderr, "FAIL: the baseline schema-3 manifest was rejected: %s\n", err);
            failures++;
        } else if (m.homeostat_present || m.homeostat.enabled != 0u) {
            fprintf(stderr, "FAIL: HOMEOSTAT was active without a manifest section\n");
            failures++;
        } else if (m.governor_present != true || m.envelope.v_max != 25) {
            fprintf(stderr, "FAIL: the baseline manifest decoded the wrong values\n");
            failures++;
        }
    }

    /* ------------------------------------------------------------------
     * 2. A VALID homeostat section is parsed and its values survive.
     * ------------------------------------------------------------------ */
    {
        checks++;
        latch_manifest_t m;
        memset(&m, 0, sizeof(m));
        int rc = load_body(with_homeostat(HOMEOSTAT_SECTION), &m, err, sizeof(err));
        if (rc != 0) {
            fprintf(stderr, "FAIL: a valid homeostat section was rejected: %s\n", err);
            failures++;
        } else if (!m.homeostat_present) {
            fprintf(stderr, "FAIL: a valid homeostat section was not detected\n");
            failures++;
        } else if (m.homeostat.enabled != 1u || m.homeostat.epoch_ticks != 100u ||
                   m.homeostat.reject_threshold_q8 != 64u ||
                   m.homeostat.latency_spread_threshold_ns != 100000u ||
                   m.homeostat.clamp_threshold_q8 != 64u ||
                   m.homeostat.coherence_anomaly_threshold != 4u ||
                   m.homeostat.contraction_q8 != 8u || m.homeostat.recovery_q8 != 2u ||
                   m.homeostat.floor_q8 != 26u) {
            fprintf(stderr, "FAIL: the homeostat section decoded the wrong values\n");
            failures++;
        }
    }

    /* ------------------------------------------------------------------
     * 3. A homeostat section with `enabled: 0` parses, and stays OFF.
     * ------------------------------------------------------------------ */
    {
        checks++;
        latch_manifest_t m;
        memset(&m, 0, sizeof(m));
        const char *section =
            ",\n  \"homeostat\": {\"enabled\": 0, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n";
        int rc = load_body(with_homeostat(section), &m, err, sizeof(err));
        if (rc != 0) {
            fprintf(stderr, "FAIL: a disabled homeostat section was rejected: %s\n", err);
            failures++;
        } else if (!m.homeostat_present || m.homeostat.enabled != 0u) {
            fprintf(stderr, "FAIL: a disabled homeostat section was not honoured\n");
            failures++;
        }
    }

    /* ------------------------------------------------------------------
     * 4. STRUCTURAL rejections: unknown key, duplicate key, missing key,
     *    non-integer value.
     * ------------------------------------------------------------------ */
    expect_rejected("homeostat with an unknown key",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26,"
            " \"surprise\": 1}\n"));

    expect_rejected("homeostat with a duplicate key",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"epoch_ticks\": 200,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with a missing key",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2}\n"));

    expect_rejected("homeostat with a non-integer value",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": \"100\","
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with a negative value",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": -1,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    /* ------------------------------------------------------------------
     * 5. RANGE rejections: every out-of-range safety parameter must be a
     *    LOAD REJECTION, never a silent runtime clamp.
     * ------------------------------------------------------------------ */
    expect_rejected("homeostat with enabled = 2",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 2, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with epoch_ticks = 0",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 0,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with floor_q8 = 0",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 0}\n"));

    expect_rejected("homeostat with floor_q8 = 257",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 257}\n"));

    expect_rejected("homeostat with contraction_q8 = 0",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 0, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with recovery_q8 = 0",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 0, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with reject_threshold_q8 = 257",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 257, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 64, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    expect_rejected("homeostat with clamp_threshold_q8 = 257",
        with_homeostat(",\n  \"homeostat\": {\"enabled\": 1, \"epoch_ticks\": 100,"
            " \"reject_threshold_q8\": 64, \"latency_spread_threshold_ns\": 100000,"
            " \"clamp_threshold_q8\": 257, \"coherence_anomaly_threshold\": 4,"
            " \"contraction_q8\": 8, \"recovery_q8\": 2, \"floor_q8\": 26}\n"));

    /* ------------------------------------------------------------------
     * 6. The section is SCHEMA-3 ONLY.
     * ------------------------------------------------------------------ */
    {
        checks++;
        latch_manifest_t m;
        memset(&m, 0, sizeof(m));
        char body[8192];
        /* Take the schema-2 baseline and append a homeostat section. */
        const char *schema2 =
            "{\n"
            "  \"schema_version\": 2,\n"
            "  \"plant\": {\"name\": \"servo-horn-1d\", \"axes\": [{\"id\": 0, \"kind\": \"angular\","
            " \"unit\": \"mrad\", \"min\": -1000, \"max\": 1000}]},\n"
            "  \"envelope\": {\"theta_min_mrad\": -1000, \"theta_max_mrad\": 1000, \"home_mrad\": 0,\n"
            "    \"v_max\": 25, \"a_max\": 10, \"j_max\": 20, \"v_home\": 10, \"lookahead_ticks\": 10},\n"
            "  \"timing\": {\"period_us\": 1000, \"watchdog_ticks\": 2, \"wcet_budget_us\": 100,\n"
            "    \"max_backlog_ticks\": 256},\n"
            "  \"recovery\": {\"hysteresis_clean_frames\": 25, \"hold_to_home_ticks\": 50},\n"
            "  \"decision\": {\"cpu\": 0, \"priority\": 63, \"pulse_priority\": 63},\n"
            "  \"ingest\": {\"cpu\": 1, \"delivery\": \"queued\", \"queue_depth\": 16},\n"
            "  \"paths\": {\"proposal\": \"/dev/latch/proposal\", \"actuator\": \"/dev/latch/actuator\",\n"
            "    \"ability\": \"latch/actuator\", \"i2c_bus\": \"/dev/i2c1\"},\n"
            "  \"actuator\": {\"type\": \"pca9685\", \"addr\": 64, \"freq_hz\": 50, \"prescale\": 121,\n"
            "    \"pwm_center\": 307, \"pwm_min\": 205, \"pwm_max\": 410, \"retries\": 1,\n"
            "    \"init_delay_us\": 600, \"required\": false},\n"
            "  \"tape\": {\"capacity\": 4096, \"log_path\": \"/dev/shmem/latch_tape.csv\"},\n"
            "  \"protocol\": {\"magic\": \"LATH\", \"version\": 1, \"crc\": \"ieee32\", \"coverage\": 16}\n"
            "}\n";
        const char *tail = strrchr(schema2, '}');
        snprintf(body, sizeof(body), "%.*s%s%s", (int)(tail - schema2), schema2,
                 HOMEOSTAT_SECTION, tail);
        int rc = load_body(body, &m, err, sizeof(err));
        if (rc == 0) {
            fprintf(stderr, "FAIL: a homeostat section was accepted in schema 2\n");
            failures++;
        }
    }

    /* ------------------------------------------------------------------
     * 7. The malformed-document fail-closed behaviour of the loader as a
     *    whole: a truncated document and a missing sidecar are rejected.
     * ------------------------------------------------------------------ */
    expect_rejected("a truncated manifest", "{\"schema_version\": 3, \"plant\":");

    {
        checks++;
        latch_manifest_t m;
        memset(&m, 0, sizeof(m));
        const char *dir = getenv("TMPDIR");
        if (dir == NULL || dir[0] == '\0') dir = "/tmp";
        char path[256];
        snprintf(path, sizeof(path), "%s/latch_manifest_nosidecar_%d.manifest", dir, (int)getpid());
        FILE *f = fopen(path, "wb");
        if (f != NULL) {
            fputs(BASE_SCHEMA3, f);
            fclose(f);
            int rc = latch_manifest_load(path, &m, err, sizeof(err));
            remove(path);
            if (rc == 0) {
                fprintf(stderr, "FAIL: a manifest without a SHA-256 sidecar was accepted\n");
                failures++;
            }
        }
    }

    if (failures != 0) {
        fprintf(stderr, "[LATCH_MANIFEST] FAIL: %d of %d checks failed\n", failures, checks);
        return 1;
    }
    printf("[LATCH_MANIFEST] PASS: %d checks -- strict homeostat parsing, range "
           "fail-closed, default-off, schema-3-only and sidecar enforcement\n", checks);
    return 0;
}
