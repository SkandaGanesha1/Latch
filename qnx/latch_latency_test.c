/*
 * qnx/latch_latency_test.c
 *
 * THE HOST-SIM TEST FOR THE DECISION-LATENCY HISTOGRAM'S BUCKET SCHEME
 * ======================================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * The supervisor samples its own per-tick decision latency into a 112-bucket
 * histogram.  Buckets 0..63 are EXACT cycle counts; above that, every
 * octave of the cycle count is split into THREE sub-buckets, so the
 * resolution inside an octave is 25 %:
 *
 *     octave k covers [1.00, 1.25), [1.25, 1.50) and [1.50, 2.00) times 2^k
 *
 * The scheme is expressed TWICE, on purpose: `latch_latency_bucket()` maps
 * a cycle count to a bucket INDEX, and `latch_latency_bucket_range()` maps a
 * bucket index back to the range of cycle counts it stands for.  The reader
 * (latchctl) uses the second; the supervisor (latchd) uses the first.  A
 * percentile is reported as a RANGE, so the two MUST agree -- and nothing in
 * the code checked that they did.
 *
 * THE DEFECT THIS TEST EXISTS FOR
 * -------------------------------
 * The index used to be
 *
 *     sub = ((cycles >> (k - 2)) & 3) - 4
 *
 * `& 3` yields 0..3 and the subtraction is UNSIGNED, so it WRAPS: every
 * sample of 64 cycles or more landed FOUR buckets low.  The archived
 * percentiles were therefore understated by about 2.5x, and the defect was
 * invisible because the range function -- the half a reader actually sees --
 * was CORRECT all along.  Two correct-looking halves of one scheme, and
 * nobody compared them.
 *
 * The property that binds them is the ROUND TRIP:
 *
 *     latch_latency_bucket_range(latch_latency_bucket(c)).lo <= c < .hi
 *
 * for every cycle count the histogram can represent.  That is what this
 * test checks, over the WHOLE domain, derived from the bucket count rather
 * than written down.
 *
 * IT IS PROVED NON-VACUOUS
 * ------------------------
 * The test carries the OLD, BROKEN index next to the shipped one and checks
 * that the old one FAILS the round trip.  Without that, a test that swept
 * the wrong domain -- or checked the wrong thing -- would still be green.
 *
 * It runs on the host, so it is part of `make check-governor` and it runs
 * in CI.
 */

#include "latch_protocol.h"

#include <stdio.h>
#include <stdint.h>

static int g_checks = 0;
static int g_failures = 0;

static void check(int ok, const char *what) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        printf("  FAIL: %s\n", what);
    }
}

/*
 * THE OLD, BROKEN INDEX.  Carried here so the test can prove it has teeth:
 * this is the exact expression the shipped code used to have, and it is the
 * defect the audit found.
 */
static unsigned broken_latency_bucket(uint64_t cycles) {
    if (cycles < (uint64_t)LATCH_LATENCY_EXACT) {
        return (unsigned)cycles;
    }
    unsigned k = 63u - (unsigned)__builtin_clzll(cycles);
    unsigned sub = (unsigned)((cycles >> (k - 2u)) & 3u) - 4u;  /* WRAPS */
    unsigned idx = LATCH_LATENCY_EXACT + 3u * (k - 6u) + sub;
    if (idx >= LATCH_LATENCY_BUCKETS) {
        idx = LATCH_LATENCY_BUCKETS - 1u;
    }
    return idx;
}

/* Does `bucket` stand for a range that CONTAINS `cycles`? */
static int bucket_contains(unsigned bucket, uint64_t cycles) {
    uint64_t lo = 0u;
    uint64_t hi = 0u;
    latch_latency_bucket_range(bucket, &lo, &hi);
    return (lo <= cycles) && (cycles < hi);
}

/*
 * THE ROUND TRIP, OVER THE WHOLE DOMAIN.
 *
 * The domain is the header's DERIVED constant: every octave above the exact
 * range carries three buckets, so the number of octaves follows from the
 * bucket count and the top of the table follows from that.  Nothing here is
 * a literal that could drift away from the scheme.
 */
static void test_round_trip_over_the_whole_domain(void) {
    uint64_t cycles = 0u;
    uint64_t first_bad = 0u;
    unsigned bad = 0u;

    for (cycles = 0u; cycles < LATCH_LATENCY_DOMAIN_CYCLES; ++cycles) {
        const unsigned bucket = latch_latency_bucket(cycles);
        if (!bucket_contains(bucket, cycles)) {
            if (bad == 0u) {
                first_bad = cycles;
            }
            ++bad;
            if (bad > 4u) {
                break;      /* enough: one counter-example is a defect */
            }
        }
    }

    if (bad != 0u) {
        printf("    first counter-example: cycles=%llu -> bucket %u, whose "
               "range does not contain it\n",
               (unsigned long long)first_bad,
               (unsigned)latch_latency_bucket(first_bad));
    }
    check(bad == 0u,
          "every cycle count in the derived domain lands in a bucket whose "
          "range CONTAINS it (the index and the range are one scheme)");
}

/*
 * THE EXACT BUCKETS.  Below the exact range, the bucket IS the cycle count.
 */
static void test_the_exact_buckets_are_exact(void) {
    int ok = 1;
    uint64_t cycles;
    for (cycles = 0u; cycles < (uint64_t)LATCH_LATENCY_EXACT; ++cycles) {
        if (latch_latency_bucket(cycles) != (unsigned)cycles) {
            ok = 0;
            break;
        }
    }
    check(ok, "the first 64 buckets are EXACT cycle counts");
}

/*
 * MONOTONICITY.  A larger latency can never land in a LOWER bucket: a
 * histogram whose index moves backwards is a histogram that cannot be read
 * as a distribution at all.
 */
static void test_the_bucket_index_is_monotonic(void) {
    int ok = 1;
    uint64_t cycles;
    unsigned previous = latch_latency_bucket(0u);

    for (cycles = 1u; cycles < LATCH_LATENCY_DOMAIN_CYCLES; ++cycles) {
        const unsigned bucket = latch_latency_bucket(cycles);
        if (bucket < previous) {
            printf("    non-monotonic at cycles=%llu: bucket %u after %u\n",
                   (unsigned long long)cycles, (unsigned)bucket,
                   (unsigned)previous);
            ok = 0;
            break;
        }
        previous = bucket;
    }
    check(ok, "the bucket index never moves BACKWARDS as the latency grows");
}

/*
 * THE BUCKET TABLE IS CONTIGUOUS AND COMPLETE.
 *
 * Every bucket has a non-empty range, consecutive buckets abut, and the
 * table as a whole covers the whole domain with nothing missing and
 * nothing overlapping.  A scheme whose range function had a hole would
 * report a percentile that no sample could ever fall into.
 */
static void test_the_bucket_table_is_contiguous(void) {
    int nonempty = 1;
    int abut = 1;
    uint64_t expected_lo = 0u;
    unsigned bucket;

    for (bucket = 0u; bucket < LATCH_LATENCY_BUCKETS; ++bucket) {
        uint64_t lo = 0u;
        uint64_t hi = 0u;
        latch_latency_bucket_range(bucket, &lo, &hi);

        if (hi <= lo) {
            nonempty = 0;
            break;
        }
        if (lo != expected_lo) {
            abut = 0;
            break;
        }
        expected_lo = hi;
    }

    check(nonempty, "every bucket has a non-empty range");
    check(abut, "consecutive buckets abut exactly, so no cycle count falls "
                "between two buckets");
    check(expected_lo == LATCH_LATENCY_DOMAIN_CYCLES,
          "the bucket table covers the whole derived domain, to the cycle");
}

/*
 * THE INDEX AGREES WITH THE RANGE AT THE BUCKET'S OWN LOWER BOUND.
 *
 * For each bucket, the cycle count at the bottom of its range must map
 * BACK to that bucket.  This is the round trip in its other direction, and
 * it is the check that a saturated top quarter cannot slip through: the
 * top quarter of an octave has to land in the LAST sub-bucket, and this is
 * where that shows up.
 */
static void test_the_index_agrees_at_every_lower_bound(void) {
    int ok = 1;
    unsigned bucket;

    for (bucket = 0u; bucket < LATCH_LATENCY_BUCKETS; ++bucket) {
        uint64_t lo = 0u;
        uint64_t hi = 0u;
        latch_latency_bucket_range(bucket, &lo, &hi);
        if (latch_latency_bucket(lo) != bucket) {
            printf("    bucket %u starts at %llu cycles, but that cycle "
                   "count maps to bucket %u\n",
                   (unsigned)bucket, (unsigned long long)lo,
                   (unsigned)latch_latency_bucket(lo));
            ok = 0;
            break;
        }
        if (hi > lo && latch_latency_bucket(hi - 1u) != bucket) {
            printf("    bucket %u ends before %llu cycles, but that cycle "
                   "count maps to bucket %u\n",
                   (unsigned)bucket, (unsigned long long)(hi - 1u),
                   (unsigned)latch_latency_bucket(hi - 1u));
            ok = 0;
            break;
        }
    }
    check(ok, "each bucket's own first and last cycle count map back to "
              "that bucket");
}

/*
 * SATURATION ABOVE THE DOMAIN.
 *
 * A cycle count the histogram cannot represent is SATURATED into the last
 * bucket.  It is never reported as belonging to a bucket whose range does
 * not contain it, and it never wraps around into a low bucket.
 */
static void test_saturation_above_the_domain(void) {
    const unsigned last = LATCH_LATENCY_BUCKETS - 1u;
    const uint64_t probes[] = {
        LATCH_LATENCY_DOMAIN_CYCLES,
        LATCH_LATENCY_DOMAIN_CYCLES + 1ULL,
        LATCH_LATENCY_DOMAIN_CYCLES * 2ULL,
        0xffffffffffffffffULL,
    };
    size_t i;
    int ok = 1;

    for (i = 0u; i < sizeof(probes) / sizeof(probes[0]); ++i) {
        if (latch_latency_bucket(probes[i]) != last) {
            printf("    cycles=%llu did not saturate into the last bucket\n",
                   (unsigned long long)probes[i]);
            ok = 0;
            break;
        }
    }
    check(ok, "a cycle count above the domain SATURATES into the last bucket "
              "instead of wrapping into a low one");
}

/*
 * THE TEST HAS TEETH: THE OLD INDEX FAILS THE ROUND TRIP.
 *
 * If the old expression ever satisfied the round trip, this sweep would
 * stop discriminating and the checks above would be proving nothing.
 */
static void test_the_old_index_would_have_failed(void) {
    uint64_t cycles = 0u;
    unsigned wrong = 0u;

    for (cycles = 0u; cycles < LATCH_LATENCY_DOMAIN_CYCLES; ++cycles) {
        const unsigned bucket = broken_latency_bucket(cycles);
        if (!bucket_contains(bucket, cycles)) {
            ++wrong;
            if (wrong >= 1u) {
                break;
            }
        }
    }
    check(wrong != 0u,
          "the OLD index (the unsigned subtraction) FAILS the round trip, so "
          "this test really discriminates between the two schemes");

    /*
     * And the old index really did put samples LOW -- the shape of the
     * defect, so the reason it is called "four buckets" is checkable
     * rather than remembered.
     *
     * The offset is FOUR buckets for the three quarter indices that map to
     * a sub-bucket of their own, and THREE for the top quarter, because
     * the shipped scheme collapses that quarter into the last sub-bucket.
     * So the general property is "the old index is never HIGHER", and the
     * exact magnitude is checked on a sample whose quarter index is 0.
     */
    int never_higher = 1;
    uint64_t scan = 0u;
    for (scan = (uint64_t)LATCH_LATENCY_EXACT;
         scan < LATCH_LATENCY_DOMAIN_CYCLES; ++scan) {
        if (broken_latency_bucket(scan) > latch_latency_bucket(scan)) {
            never_higher = 0;
            break;
        }
    }
    check(never_higher,
          "the old index never landed HIGHER than the shipped one, so it "
          "understated the latency rather than exaggerating it");

    const unsigned fixed = latch_latency_bucket(512u);
    const unsigned broken = broken_latency_bucket(512u);
    check(broken + 4u == fixed,
          "the old index put a sample FOUR buckets low, which is the "
          "magnitude of the defect the audit found");
}

int main(void) {
    printf("[LATCH_LATENCY] the histogram's bucket index and bucket range "
           "must be ONE scheme\n");

    test_the_exact_buckets_are_exact();
    test_round_trip_over_the_whole_domain();
    test_the_bucket_index_is_monotonic();
    test_the_bucket_table_is_contiguous();
    test_the_index_agrees_at_every_lower_bound();
    test_saturation_above_the_domain();
    test_the_old_index_would_have_failed();

    if (g_failures == 0) {
        printf("[LATCH_LATENCY] PASS: %d checks, 0 failures -- every cycle "
               "count in [0, %llu) lands in the bucket whose range contains "
               "it\n",
               g_checks, (unsigned long long)LATCH_LATENCY_DOMAIN_CYCLES);
        return 0;
    }
    printf("[LATCH_LATENCY] FAIL: %d checks, %d failure(s)\n",
           g_checks, g_failures);
    return 1;
}
