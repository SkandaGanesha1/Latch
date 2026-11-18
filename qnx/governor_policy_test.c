#include "governor_policy.h"

#include <stdio.h>

static int expect(governor_policy_config_t config, governor_policy_input_t input,
                  governor_advice_t advice, uint32_t reasons) {
    governor_policy_result_t result = governor_policy_evaluate(&config, &input);
    if (result.advice != advice || result.reasons != reasons) {
        fprintf(stderr, "FAIL: advice=%u reasons=0x%x expected=%u/0x%x\n",
                (unsigned int)result.advice, result.reasons,
                (unsigned int)advice, reasons);
        return 1;
    }
    return 0;
}

int main(void) {
    const governor_policy_config_t enabled = { 1u, 128u, 2u };
    const governor_policy_config_t disabled = { 0u, 128u, 2u };
    const governor_policy_input_t nominal = { 200u, 0u, 1u, 0u };
    const governor_policy_input_t low_confidence = { 127u, 0u, 1u, 0u };
    const governor_policy_input_t stale = { 200u, 3u, 1u, 0u };
    const governor_policy_input_t hard_fault = { 0u, 3u, 1u, 1u };
    const governor_policy_input_t missing_metadata = { 255u, 0u, 0u, 0u };
    const governor_policy_config_t invalid_config = { 2u, 0u, 2u };
    int failures = 0;

    failures += expect(enabled, nominal, GOVERNOR_ADVICE_NOMINAL, GOVERNOR_REASON_NONE);
    failures += expect(enabled, low_confidence, GOVERNOR_ADVICE_REDUCE, GOVERNOR_REASON_CONFIDENCE);
    failures += expect(enabled, stale, GOVERNOR_ADVICE_REDUCE, GOVERNOR_REASON_COHERENCE);
    failures += expect(enabled, hard_fault, GOVERNOR_ADVICE_SAFE_STOP, GOVERNOR_REASON_HARD_FAULT);
    failures += expect(enabled, missing_metadata, GOVERNOR_ADVICE_INVALID, GOVERNOR_REASON_METADATA);
    failures += expect(disabled, missing_metadata, GOVERNOR_ADVICE_NOMINAL, GOVERNOR_REASON_NONE);
    failures += expect(invalid_config, nominal, GOVERNOR_ADVICE_INVALID, GOVERNOR_REASON_METADATA);
    if (governor_policy_config_validate(&enabled) != 0 ||
        governor_policy_config_validate(0) == 0) {
        fprintf(stderr, "FAIL: policy configuration validation\n");
        failures++;
    }

    {
        const governor_ladder_config_t ladder = { 1u, 0x01u, 2u, 3u };
        governor_ladder_config_t bad_ladder = { 1u, 0x01u, 0u, 3u };
        governor_ladder_state_t state;
        governor_ladder_input_t input = { 0u, 1u, 1u, 1u, 0u, 0u, 0u };
        governor_ladder_result_t result;

        if (governor_ladder_config_validate(&ladder) != 0 ||
            governor_ladder_config_validate(&bad_ladder) == 0) {
            fprintf(stderr, "FAIL: ladder configuration validation\n");
            failures++;
        }

        governor_ladder_init(&state);
        input.fault_bits = 0x01u;
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_ADVISE || state.advisory_fault_streak != 0u) {
            fprintf(stderr, "FAIL: first advisory fault did not enter ADVISE\n");
            failures++;
        }
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_ADVISE || state.advisory_fault_streak != 1u) {
            fprintf(stderr, "FAIL: advisory dwell threshold advanced early\n");
            failures++;
        }
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_CLAMP || result.changed == 0u) {
            fprintf(stderr, "FAIL: repeated advisory faults did not demote one rung\n");
            failures++;
        }

        input.fault_bits = 0u;
        for (unsigned int i = 0u; i < ladder.clean_frames_per_promotion; ++i) {
            result = governor_ladder_step(&ladder, &state, &input);
            if (i + 1u < ladder.clean_frames_per_promotion) {
                uint32_t streak = state.clean_frame_streak;
                input.frame_present = 0u;
                input.frame_accepted = 0u;
                input.coherent = 0u;
                (void)governor_ladder_step(&ladder, &state, &input);
                if (state.clean_frame_streak != streak) {
                    fprintf(stderr, "FAIL: idle supervisor tick discarded clean-frame recovery credit\n");
                    failures++;
                }
                input.frame_present = 1u;
                input.frame_accepted = 1u;
                input.coherent = 1u;
            }
        }
        if (result.rung_after != GOVERNOR_RUNG_ADVISE || result.changed == 0u) {
            fprintf(stderr, "FAIL: clean frames did not promote CLAMP to ADVISE\n");
            failures++;
        }
        for (unsigned int i = 0u; i < ladder.clean_frames_per_promotion; ++i) {
            result = governor_ladder_step(&ladder, &state, &input);
        }
        if (result.rung_after != GOVERNOR_RUNG_HP || result.changed == 0u) {
            fprintf(stderr, "FAIL: clean coherent frames did not promote ADVISE to HP\n");
            failures++;
        }

        input.frame_present = 1u;
        (void)governor_ladder_step(&ladder, &state, &input);
        if (state.clean_frame_streak != 1u) {
            fprintf(stderr, "FAIL: accepted clean command did not earn recovery credit\n");
            failures++;
        }
        input.frame_accepted = 0u;
        input.coherent = 1u;
        (void)governor_ladder_step(&ladder, &state, &input);
        if (state.clean_frame_streak != 0u) {
            fprintf(stderr, "FAIL: heartbeat-only frame retained clean-command recovery credit\n");
            failures++;
        }
        input.frame_accepted = 1u;

        input.immediate_demotion = 1u;
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_ADVISE || result.hard_fault != 0u) {
            fprintf(stderr, "FAIL: lease expiry did not demote exactly one rung\n");
            failures++;
        }
        input.immediate_demotion = 0u;
        input.fault_bits = 0x02u;
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_LATCH || result.hard_fault == 0u) {
            fprintf(stderr, "FAIL: unclassified fault did not take hard-fault path\n");
            failures++;
        }

        input.fault_bits = 0u;
        input.operator_release = 1u;
        result = governor_ladder_step(&ladder, &state, &input);
        input.operator_release = 0u;
        for (unsigned int i = 1u; i < ladder.clean_frames_per_promotion; ++i) {
            result = governor_ladder_step(&ladder, &state, &input);
        }
        if (result.rung_after != GOVERNOR_RUNG_SAFE_STOP || result.changed == 0u) {
            fprintf(stderr, "FAIL: one-shot operator release did not arm clean recovery\n");
            failures++;
        }

        input.operator_release = 0u;
        input.safe_stop_complete = 0u;
        for (unsigned int i = 0u; i < ladder.clean_frames_per_promotion; ++i) {
            result = governor_ladder_step(&ladder, &state, &input);
        }
        if (result.rung_after != GOVERNOR_RUNG_SAFE_STOP) {
            fprintf(stderr, "FAIL: SAFE_STOP promoted before stop completion\n");
            failures++;
        }
        input.safe_stop_complete = 1u;
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_SLOW || result.changed == 0u) {
            fprintf(stderr, "FAIL: completed SAFE_STOP did not recover one rung\n");
            failures++;
        }
        input.immediate_demotion = 1u;
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_SAFE_STOP) {
            fprintf(stderr, "FAIL: SLOW lease expiry did not return to SAFE_STOP\n");
            failures++;
        }
        result = governor_ladder_step(&ladder, &state, &input);
        if (result.rung_after != GOVERNOR_RUNG_LATCH) {
            fprintf(stderr, "FAIL: repeated lease expiry at SAFE_STOP did not latch\n");
            failures++;
        }
    }

    if (failures != 0) return 1;
    puts("[GOVERNOR_POLICY] PASS: policy classification and ladder transitions");
    return 0;
}
