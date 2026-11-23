#include "gov_homeostat.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static gov_homeostat_config_t config(void) {
    gov_homeostat_config_t c = {1u, 4u, 64u, 1000u, 64u, 4u, 8u, 2u, 26u};
    return c;
}

static int epoch(gov_homeostat_config_t *c, gov_homeostat_state_t *s,
                 gov_homeostat_sample_t sample) {
    int closed = 0;
    for (unsigned int i = 0; i < c->epoch_ticks; ++i)
        closed += gov_homeostat_observe(c, s, &sample);
    return closed;
}

int main(void) {
    gov_homeostat_config_t c = config();
    gov_homeostat_state_t s;
    gov_homeostat_init(&s);
    int failures = 0;
    gov_homeostat_sample_t bad = {1u, 0u, 0u, 100u, 1000u, 0u};
    for (unsigned int i = 0; i < 40u; ++i) (void)epoch(&c, &s, bad);
    if (s.scale_q8 != c.floor_q8 || s.stress_epochs != 40u) {
        fprintf(stderr, "FAIL: sustained stress did not contract to floor\n"); failures++;
    }

    gov_homeostat_sample_t empty = {0u, 0u, 0u, 100u, 0u, 0u};
    (void)epoch(&c, &s, empty);
    if (s.scale_q8 != c.floor_q8 || s.recovery_epochs != 0u) {
        fprintf(stderr, "FAIL: empty epoch recovered scale\n"); failures++;
    }

    gov_homeostat_sample_t clean = {1u, 1u, 0u, 100u, 1000u, 1000u};
    for (unsigned int i = 0; i < 200u; ++i) (void)epoch(&c, &s, clean);
    if (s.scale_q8 != 256u || s.recovery_epochs < 100u) {
        fprintf(stderr, "FAIL: recovery did not saturate at Q8 unity\n"); failures++;
    }

    gov_homeostat_init(&s);
    gov_homeostat_sample_t clamp = {1u, 1u, 0u, 100u, 1000u, 500u};
    (void)epoch(&c, &s, clamp);
    if (s.last_clamp_fraction_q8 != 128u || s.scale_q8 != 248u) {
        fprintf(stderr, "FAIL: clamp fraction or contraction incorrect (%u/%u)\n",
                s.last_clamp_fraction_q8, s.scale_q8); failures++;
    }
    if (gov_homeostat_effective_vmax(25u, 128u, 64u) != 6u ||
        gov_homeostat_effective_vmax(25u, 300u, 300u) != 25u ||
        gov_homeostat_effective_vmax(25u, 256u, 128u) != 12u) {
        fprintf(stderr, "FAIL: min-composition or saturation invariant\n"); failures++;
    }

    gov_homeostat_init(&s);
    s.proposed_motion = UINT64_MAX - 10u;
    s.applied_motion = 0u;
    gov_homeostat_sample_t overflow = {1u, 1u, 0u, 1u, 100u, 50u};
    (void)epoch(&c, &s, overflow);
    if (s.last_clamp_fraction_q8 != 255u && s.last_clamp_fraction_q8 != 256u) {
        fprintf(stderr, "FAIL: overflow-safe saturated motion accounting (%u)\n",
                s.last_clamp_fraction_q8); failures++;
    }

    gov_homeostat_init(&s);
    gov_homeostat_config_t disabled = c;
    disabled.enabled = 0u;
    (void)epoch(&disabled, &s, bad);
    if (s.scale_q8 != 256u || s.epoch_ticks != 0u) {
        fprintf(stderr, "FAIL: disabled HOMEOSTAT modified state\n"); failures++;
    }
    if (failures != 0) return 1;
    puts("[GOV_HOMEOSTAT] PASS: contraction, recovery, empty epoch, Q8 bounds, saturating accounting, min composition");
    return 0;
}
