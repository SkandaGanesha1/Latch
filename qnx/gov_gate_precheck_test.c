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

    if (failures != 0) return 1;
    puts("[GOV_GATE] PASS: metadata-driven unit, rate, confidence and shrink prechecks");
    return 0;
}
