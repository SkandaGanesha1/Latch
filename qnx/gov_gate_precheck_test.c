#include "gov_gate_precheck.h"

#include <stdio.h>
#include <string.h>

static latch_manifest_t fixture_manifest(void) {
    latch_manifest_t m;
    memset(&m, 0, sizeof(m));
    m.envelope.theta_min_mrad = -1000;
    m.envelope.theta_max_mrad = 1000;
    m.envelope.v_max = 25;
    m.envelope.a_max = 10;
    m.envelope.num_keepouts = 1u;
    m.envelope.keepout[0].lo_mrad = 250;
    m.envelope.keepout[0].hi_mrad = 650;
    return m;
}

static latch_manifest_governor_t fixture_config(void) {
    latch_manifest_governor_t c;
    memset(&c, 0, sizeof(c));
    c.enabled = 1u;
    c.clamp_max_step = 5u;
    c.slow_scale_pct = 25u;
    c.min_confidence_q8 = 128u;
    c.units_enabled = 1u;
    c.canonical_unit_id = 1u;
    c.unit_scale_count = 2u;
    c.alternate_unit_ids[0] = 2u;
    c.alternate_unit_ids[1] = 3u;
    c.conversion_numerators[0] = 1u;
    c.conversion_numerators[1] = 1u;
    c.conversion_denominators[0] = 57u;
    c.conversion_denominators[1] = 1000u;
    c.rate_enabled = 1u;
    c.rate_burst_tokens = 40u;
    c.rate_refill_per_tick = 2u;
    c.rate_sustain_per_tick = 25u;
    return c;
}

static gov_gate_input_t command_input(governor_rung_t rung, uint8_t kind,
                                      int32_t theta, int32_t target, uint8_t confidence) {
    gov_gate_input_t input;
    memset(&input, 0, sizeof(input));
    input.rung = rung;
    input.kind = kind;
    input.confidence_q8 = confidence;
    input.unit_id = (kind == GOVERNOR_WIRE_CMD_V2 || kind == GOVERNOR_WIRE_CMD) ? 1u : 0u;
    input.has_v2_metadata = 1u;
    input.theta = theta;
    input.candidate = target;
    return input;
}

int main(void) {
    latch_manifest_t manifest = fixture_manifest();
    latch_manifest_governor_t config = fixture_config();
    gov_gate_state_t state;
    gov_gate_result_t result;
    int failures = 0;

    gov_gate_init(&config, &state);
    gov_gate_input_t input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2,
                                           0, 100, 200u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 7 || result.effective_v_max != 19 ||
        result.effective_a_max != 7) {
        fprintf(stderr, "FAIL: confidence Q8 clamp did not constrain the candidate\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 100, 127u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 5 || result.effective_v_max != 12 ||
        result.effective_a_max != 5) {
        fprintf(stderr, "FAIL: low confidence floor did not apply integer half-scale\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 100, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.effective_v_max != 24 || result.effective_a_max != 9) {
        fprintf(stderr, "FAIL: Q0.8 maximum 255/256 boundary changed\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_SHRINK_REQ, 0, 10, 128u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.message_only != 1u || state.shrink_v != 10u) {
        fprintf(stderr, "FAIL: shrink-only request was not recorded as message-only\n");
        failures++;
    }
    input.candidate = 11;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_WIDEN) == 0u || result.command_valid != 0u) {
        fprintf(stderr, "FAIL: widening request was not rejected\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 220, 225000, 0u);
    input.unit_id = 999u;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_UNIT) == 0u || result.command_valid != 0u) {
        fprintf(stderr, "FAIL: unknown unit ID was not rejected at HP\n");
        failures++;
    }
    input.rung = GOVERNOR_RUNG_CLAMP;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_UNIT) == 0u || result.command_valid) {
        fprintf(stderr, "FAIL: unknown unit ID was guessed at CLAMP\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_CLAMP, GOVERNOR_WIRE_CMD_V2, 25, 37000, 255u);
    input.unit_id = 3u;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 30 ||
        (result.faults & LATCH_FAULT_UNIT) != 0u) {
        fprintf(stderr, "FAIL: manifest-declared rational unit conversion was not applied exactly\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_CLAMP, GOVERNOR_WIRE_CMD_V2, 25, 100, 255u);
    input.unit_id = 2u;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (result.command_valid || (result.faults & LATCH_FAULT_UNIT) == 0u) {
        fprintf(stderr, "FAIL: non-integral rational unit conversion was not rejected\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD, 0, 100, 0u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (result.command_valid || (result.faults & LATCH_FAULT_RATE) == 0u) {
        fprintf(stderr, "FAIL: HP rate excess did not fail closed\n");
        failures++;
    }

    /*
     * HOMEOSTAT velocity ceiling (CONTRACTING ONLY).
     *
     * homeostat_v_max == 0 means "not applied" and must reproduce the
     * pre-HOMEOSTAT result EXACTLY. A positive ceiling can only LOWER the
     * limit. The ceiling composes with the agent confidence scale: a
     * ceiling of 8 with confidence 255/256 gives 8 * 255 / 256 = 7.
     *
     * Note the candidate is bounded by the ACCELERATION limit as well: with
     * v_max 25 / a_max 10 and confidence 255/256 the effective limits are
     * 24 and 9, so the step (and therefore the candidate) saturates at 9.
     */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 100, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.effective_v_max != 24 ||
        result.effective_a_max != 9 || result.candidate != 9) {
        fprintf(stderr, "FAIL: the unadapted ceiling changed (expected v_max 24, a_max 9)\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 100, 255u);
    input.homeostat_v_max = 8;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.effective_v_max != 7 ||
        result.candidate != 7) {
        fprintf(stderr, "FAIL: the HOMEOSTAT ceiling did not constrain the candidate\n");
        failures++;
    }

    /* A ceiling ABOVE the manifest limit must NOT raise it. */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 100, 255u);
    input.homeostat_v_max = 1000;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.effective_v_max != 24) {
        fprintf(stderr, "FAIL: the HOMEOSTAT ceiling was allowed to RAISE the limit\n");
        failures++;
    }

    /* The contracting ceiling also bounds the HP rate check: a step that the
     * manifest limit would accept is a RATE fault once HOMEOSTAT has
     * contracted the ceiling below it. The gate reports the fault; the
     * caller decides whether to fail the frame closed. */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD, 0, 20, 0u);
    input.homeostat_v_max = 5;
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_RATE) == 0u) {
        fprintf(stderr, "FAIL: the contracted ceiling did not bound the HP rate check\n");
        failures++;
    }
    /* And the SAME step is NOT a rate fault without the contracted ceiling. */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD, 0, 20, 0u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_RATE) != 0u) {
        fprintf(stderr, "FAIL: the unadapted ceiling raised a spurious rate fault\n");
        failures++;
    }

    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_CLAMP, GOVERNOR_WIRE_HEARTBEAT, 0, 100, 0u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.message_only != 1u || result.candidate != 100) {
        fprintf(stderr, "FAIL: heartbeat was treated as an actuator command\n");
        failures++;
    }

    /* DOSE Fault evaluation in CLAMP rung: excessive rate raises DOSE and clamps candidate */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_CLAMP, GOVERNOR_WIRE_CMD_V2, 0, 20, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 5 ||
        (result.faults & LATCH_FAULT_DOSE) == 0u) {
        fprintf(stderr, "FAIL: CLAMP excessive dose rate did not raise LATCH_FAULT_DOSE or clamp candidate\n");
        failures++;
    }

    /* DOSE Fault recovery in CLAMP rung: proposed step within clamp_max_step raises no fault */
    input = command_input(GOVERNOR_RUNG_CLAMP, GOVERNOR_WIRE_CMD_V2, 5, 8, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 8 ||
        (result.faults & LATCH_FAULT_DOSE) != 0u) {
        fprintf(stderr, "FAIL: CLAMP compliant dose rate raised unexpected DOSE fault\n");
        failures++;
    }

    /* DOSE Fault evaluation in SLOW rung: scaled limit (5 * 25% = 1u) */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_SLOW, GOVERNOR_WIRE_CMD_V2, 0, 10, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 1 ||
        (result.faults & LATCH_FAULT_DOSE) == 0u) {
        fprintf(stderr, "FAIL: SLOW excessive dose rate did not raise LATCH_FAULT_DOSE or clamp candidate to scaled limit\n");
        failures++;
    }

    /* DOSE Fault recovery in SLOW rung: compliant step (1u) raises no fault */
    input = command_input(GOVERNOR_RUNG_SLOW, GOVERNOR_WIRE_CMD_V2, 1, 2, 255u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if (!result.command_valid || result.candidate != 2 ||
        (result.faults & LATCH_FAULT_DOSE) != 0u) {
        fprintf(stderr, "FAIL: SLOW compliant dose rate raised unexpected DOSE fault\n");
        failures++;
    }

    /* DOSE and RATE fault in HP rung when proposed rate exceeds manifest v_max */
    gov_gate_init(&config, &state);
    input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD, 0, 50, 0u);
    result = gov_gate_precheck(&manifest, &config, &state, &input);
    if ((result.faults & LATCH_FAULT_DOSE) == 0u || (result.faults & LATCH_FAULT_RATE) == 0u) {
        fprintf(stderr, "FAIL: HP rate exceeding v_max did not raise DOSE and RATE faults\n");
        failures++;
    }

    /* Sliding window tracks only supervisor-committed positive motion. */
    {
        latch_manifest_t m = manifest;
        m.medical_present = true;
        m.medical.max_bolus_uL = 100u;
        m.medical.max_cumulative_dose_uL = 150u;
        m.medical.cumulative_dose_window_ticks = 10u;
        m.medical.min_bolus_interval_ticks = 0u;
        gov_gate_init(&config, &state);
        if (gov_medical_check(&m, &state, 1, 0, 50) != 0u || state.cumulative_window_dose_uL != 0u) failures++;
        if (gov_medical_check(&m, &state, 2, 0, 50) != 0u || state.cumulative_window_dose_uL != 0u) failures++;
        gov_medical_commit(&state, 2, 0, 50);
        if (gov_medical_check(&m, &state, 5, 50, 150) != 0u) failures++;
        gov_medical_commit(&state, 5, 50, 150);
        if (gov_medical_check(&m, &state, 11, 150, 160) != LATCH_FAULT_DOSE) failures++;
        if (gov_medical_check(&m, &state, 12, 150, 200) != 0u || state.cumulative_window_dose_uL != 100u) failures++;
        gov_medical_commit(&state, 12, 150, 200);
        if (gov_medical_check(&m, &state, 11, 200, 201) != LATCH_FAULT_DOSE) failures++;
        m.medical.min_bolus_interval_ticks = 4u;
        if (gov_medical_check(&m, &state, 13, 200, 201) != LATCH_FAULT_DOSE || gov_medical_check(&m, &state, 16, 200, 201) != 0u) failures++;
        gov_gate_init(&config, &state);
        m.medical.min_bolus_interval_ticks = 0u;
        m.medical.max_cumulative_dose_uL = 10000u;
        m.medical.cumulative_dose_window_ticks = 10000u;
        for (uint32_t i = 1; i <= GOV_DOSE_HISTORY_CAPACITY; i++) {
            if (gov_medical_check(&m, &state, i, 0, 1) != 0u) failures++;
            gov_medical_commit(&state, i, 0, 1);
        }
        if (gov_medical_check(&m, &state, 257, 0, 1) != LATCH_FAULT_DOSE || gov_medical_check(&m, &state, 10001, 0, 1) != 0u) failures++;
    }

    if (failures != 0) return 1;
    puts("[GOV_GATE] PASS: metadata-driven unit, rate, confidence and shrink prechecks");
    return 0;
}
