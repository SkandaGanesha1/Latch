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

    /* Cumulative dose window tracking and clamping */
    {
        latch_manifest_t med_manifest = manifest;
        med_manifest.medical_present = true;
        strncpy(med_manifest.medical.drug_name, "insulin-lispro", sizeof(med_manifest.medical.drug_name) - 1);
        med_manifest.medical.drug_id = 1u;
        med_manifest.medical.concentration_uL_per_unit = 10u;
        med_manifest.medical.max_bolus_uL = 100u;
        med_manifest.medical.min_bolus_interval_ticks = 0u;
        med_manifest.medical.cumulative_dose_window_ticks = 1000u;
        med_manifest.medical.max_cumulative_dose_uL = 150u;
        med_manifest.envelope.v_max = 100;
        med_manifest.envelope.a_max = 100;

        latch_manifest_governor_t med_config = config;
        med_config.rate_burst_tokens = 500u;
        med_config.rate_refill_per_tick = 100u;
        med_config.rate_sustain_per_tick = 100u;

        gov_gate_init(&med_config, &state);

        /* Step 1: 50 uL at tick 1 (within limit) */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 50, 255u);
        input.tick = 1u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 50 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.cumulative_window_dose_uL != 50u) {
            fprintf(stderr, "FAIL: cumulative dose step 1 not accepted\n");
            failures++;
        }

        /* Step 2: +50 uL at tick 2 (within limit, cumulative = 100) */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 50, 100, 255u);
        input.tick = 2u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 100 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.cumulative_window_dose_uL != 100u) {
            fprintf(stderr, "FAIL: cumulative dose step 2 not accepted\n");
            failures++;
        }

        /* Step 3: +50 uL at tick 3 (within limit, cumulative = 150) */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 100, 150, 255u);
        input.tick = 3u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 150 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.cumulative_window_dose_uL != 150u) {
            fprintf(stderr, "FAIL: cumulative dose step 3 not accepted\n");
            failures++;
        }

        /* Step 4: +10 uL at tick 4 (exceeds 150 max_cumulative_dose_uL) -> assert DOSE fault and clamp step to 0 */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 150, 160, 255u);
        input.tick = 4u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if ((result.faults & LATCH_FAULT_DOSE) == 0u || result.candidate != 150) {
            fprintf(stderr, "FAIL: cumulative dose exceedance did not raise LATCH_FAULT_DOSE or clamp step to 0\n");
            failures++;
        }

        /* Step 5: window expiration at tick 1005 (after 1000 ticks) -> resets window and accepts step */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 150, 160, 255u);
        input.tick = 1005u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 160 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.cumulative_window_dose_uL != 10u) {
            fprintf(stderr, "FAIL: cumulative dose window expiration did not reset window\n");
            failures++;
        }

        /* Step 6: Defensive hardening — window tick wrap guard near UINT64_MAX */
        state.window_start_tick = UINT64_MAX - 500u;
        state.cumulative_window_dose_uL = 100u;
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 100, 150, 255u);
        input.tick = UINT64_MAX - 200u; /* elapsed = 300 < 1000, must NOT reset window */
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || (result.faults & LATCH_FAULT_DOSE) != 0u ||
            state.window_start_tick != UINT64_MAX - 500u || state.cumulative_window_dose_uL != 150u) {
            fprintf(stderr, "FAIL: window tick wrap guard prematurely reset window\n");
            failures++;
        }

        /* Step 7: Defensive hardening — cumulative dose counter addition wrap guard */
        state.cumulative_window_dose_uL = UINT64_MAX;
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 100, 110, 255u);
        input.tick = UINT64_MAX - 100u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if ((result.faults & LATCH_FAULT_DOSE) == 0u || result.candidate != 100) {
            fprintf(stderr, "FAIL: cumulative dose counter addition wrap guard failed to raise DOSE fault or clamp\n");
            failures++;
    
        /* Step 8: Medical lockout interval — min_bolus_interval_ticks enforcement */
        med_manifest.medical.min_bolus_interval_ticks = 10u;
        gov_gate_init(&med_config, &state);

        /* 8a: First bolus at tick 1: accepted */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 0, 20, 255u);
        input.tick = 1u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 20 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.last_bolus_tick != 1u) {
            fprintf(stderr, "FAIL: Step 8a initial bolus not accepted\n");
            failures++;
        }

        /* 8b: Rapid bolus attempt at tick 5 (elapsed 4 < 10): lockout violation */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 20, 30, 255u);
        input.tick = 5u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if ((result.faults & LATCH_FAULT_DOSE) == 0u || result.candidate != 20) {
            fprintf(stderr, "FAIL: Step 8b rapid bolus before min_bolus_interval did not raise DOSE fault or clamp\n");
            failures++;
        }

        /* 8c: Bolus attempt at tick 12 (elapsed 11 >= 10): lockout expired, accepted */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 20, 30, 255u);
        input.tick = 12u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if (!result.command_valid || result.candidate != 30 ||
            (result.faults & LATCH_FAULT_DOSE) != 0u || state.last_bolus_tick != 12u) {
            fprintf(stderr, "FAIL: Step 8c bolus after min_bolus_interval not accepted\n");
            failures++;
        }

        /* 8d: Out-of-order / non-monotonic tick at tick 8 (last_bolus_tick=12): rejected fail-closed */
        input = command_input(GOVERNOR_RUNG_HP, GOVERNOR_WIRE_CMD_V2, 30, 40, 255u);
        input.tick = 8u;
        result = gov_gate_precheck(&med_manifest, &med_config, &state, &input);
        if ((result.faults & LATCH_FAULT_DOSE) == 0u || result.candidate != 30) {
            fprintf(stderr, "FAIL: Step 8d out-of-order tick did not raise DOSE fault or clamp\n");
            failures++;
        }
    }
    }

    if (failures != 0) return 1;
    puts("[GOV_GATE] PASS: metadata-driven unit, rate, confidence and shrink prechecks");
    return 0;
}
