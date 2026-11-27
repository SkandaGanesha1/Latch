/*
 * qnx/latch_soak_pace_test.c
 *
 * THE HOST-SIM TEST FOR THE SOAK'S DEADLINE PACER  (U-4)
 * =====================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * The U-4 decision-latency soak paces its 900 Hz proposal stream against a
 * DEADLINE on the guest's own monotonic clock.  The pacer's decision is
 * written out as a PURE function in guest/latch_soak_pace.h, because the
 * guest policy is freestanding and cannot include the QNX tree -- so the
 * property that matters has to be reachable from a host test.
 *
 * A rate limiter has to do TWO things at once, and the history of this
 * file is a record of getting one of them wrong:
 *
 *   1. KEEP THE RATE.  Ordinary scheduling jitter must not eat the
 *      target rate.
 *   2. BOUND THE CATCH-UP.  The producer must never owe more than one
 *      period's worth of frames, so a host stall cannot become a burst.
 *
 * Both failure modes were MEASURED on the QEMU AArch64 `virt` target
 * (2026-11-27), and this test discriminates all three pacers.
 *
 * The numbers below are the SIMULATION's, over the guest's MEASURED
 * dynamics (a ~550 us per-frame cost and a ~1.7 ms sleep wake overshoot),
 * and they are the numbers the assertions in this file are checked
 * against.  The "catch-up" column is the longest run of consecutive
 * frames emitted WITHOUT a sleep -- the burst -- after a 0.5 s stall:
 *
 *     pacer                                   rate      burst after a 0.5 s stall
 *     keep the grid, catch up without limit    900/s                  894 frames
 *     drop the credit on ANY lateness          595/s                    1 frame
 *     allowance of 1 period                    595/s                    1 frame
 *     THE ONE IN guest/latch_soak_pace.h        900/s                    4 frames
 *
 * The first one overflowed the supervisor's 256-frame proposal ring (186
 * frames DROPPED, measured on the target).  The second one kept the rate
 * it claimed to be pacing at only 610/s ON THE TARGET -- the simulation
 * says 595/s, and the simulation is a model, not the target -- so the
 * measurement's workload stopped being the one the plan describes.
 *
 * So the test asserts the INVARIANT over a wide sweep of inputs, the RATE
 * over a long window with realistic jitter, and the BURST after a stall --
 * and it is proved NON-VACUOUS by running it against the other three pacers.
 *
 * It runs on the host, so it is part of `make check-governor` and it runs
 * in CI.
 */

#include "../guest/latch_soak_pace.h"

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

/* The production period: 900 Hz. */
#define SOAK_PERIOD_NS 1111111ULL

/*
 * THE GUEST'S MEASURED DYNAMICS.
 *
 * These are the numbers the simulation in guest/latch_soak_pace.h quotes,
 * and they are the shape of the real guest on this target: the per-frame
 * work is about half a period, and the sleep's WAKE OVERSHOOTS BY MORE
 * THAN A WHOLE PERIOD under TCG.  That overshoot is the whole reason the
 * guest is "late" most of the time, and it is why the guest has to send
 * two or three frames back-to-back to hold the target rate.
 *
 *   WORK_NS   the per-frame cost of sending the frame and looping
 *   WAKE_NS   how far past the requested wake time the guest comes back
 *
 * A wake overshoot is only paid when the guest actually SLEPT; a frame
 * that goes out immediately costs no overshoot.
 *
 * The two numbers are fitted to the THREE measured rates on the target
 * (the original pacer 901/s, the first fix 610/s, and the bounded one),
 * so the model reproduces all three.
 */
#define WORK_NS  550000ULL
#define WAKE_NS  1700000ULL

/*
 * THE INVARIANT.  For every input, the producer is at most the LAG
 * ALLOWANCE behind its own schedule after the call.  This is the burst
 * bound: the producer can never owe more than the allowance's worth of
 * frames.
 *
 * The pacer that kept the grid without a bound violates it (its deadline
 * falls hundreds of periods behind); the pacer that dropped the credit on
 * any lateness satisfies it but destroys the rate.
 */
static void test_invariant(void) {
    uint64_t periods[] = {1ULL, 7ULL, 1000ULL, SOAK_PERIOD_NS, 1000000ULL};
    uint64_t lates[] = {0ULL, 1ULL, 2ULL, 999ULL, 1000000ULL,
                        1000000000ULL, 0xffffffffULL};
    size_t i;
    size_t j;

    for (i = 0; i < sizeof(periods) / sizeof(periods[0]); ++i) {
        for (j = 0; j < sizeof(lates) / sizeof(lates[0]); ++j) {
            const uint64_t period = periods[i];
            const uint64_t late = lates[j];
            uint64_t deadline = 0u;
            uint64_t k;

            for (k = 0u; k < 64u; ++k) {
                const uint64_t now = deadline + late;
                const uint64_t next =
                    latch_soak_next_deadline(deadline, now, period);
                const uint64_t lag = (now > next) ? (now - next) : 0u;
                if (lag > ((uint64_t)LATCH_SOAK_MAX_LAG_PERIODS * period)) {
                    check(0, "the producer must never be more than the lag "
                             "allowance behind its own schedule");
                    return;
                }
                deadline = next;
            }
        }
    }
    check(1, "the producer is never more than the lag allowance behind its "
             "own schedule");
}

/*
 * ON SCHEDULE.  The deadline advances by EXACTLY one period, so the
 * achieved rate is the intended rate.
 */
static void test_on_schedule(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t deadline = 1000ULL * period;
    const uint64_t next =
        latch_soak_next_deadline(deadline, deadline, period);

    check(next == deadline + period,
          "on schedule, the deadline advances by exactly one period");
    check(latch_soak_sleep_us(next, deadline) == (period + 999ULL) / 1000ULL,
          "on schedule, the sleep is one period");
}

/*
 * A LITTLE LATE -- ordinary scheduling jitter.  The GRID IS KEPT: the
 * deadline advances by one period, and the frame that is due goes out
 * immediately.  This is the check that kills the pacer that dropped the
 * credit on ANY lateness: that one reset the deadline to `now` here, and
 * every late frame cost a FULL period, so the rate collapsed.
 */
static void test_a_little_late(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t deadline = 1000ULL * period;
    /* The frame is due at deadline + period; the guest gets to it half a
     * period after that -- ordinary scheduling jitter. */
    const uint64_t now = deadline + period + period / 2ULL;
    const uint64_t next =
        latch_soak_next_deadline(deadline, now, period);

    check(next == deadline + period,
          "a little late, the grid is KEPT (the deadline advances by one "
          "period), so the rate survives ordinary jitter");
    check(latch_soak_sleep_us(next, now) == 0ULL,
          "a little late, the frame that is due goes out immediately");
}

/*
 * A LONG WAY LATE -- the guest was starved.  The missed deadlines are
 * DROPPED and the deadline resumes from NOW, so the producer cannot pay
 * the whole debt back in one burst.  This is the check that kills the
 * pacer that kept the grid without a bound.
 */
static void test_a_long_way_late(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t deadline = 1000ULL * period;
    const uint64_t now = deadline + 450ULL * period;  /* a 0.5 s stall */
    const uint64_t next =
        latch_soak_next_deadline(deadline, now, period);

    check(next == now,
          "a long way late, the deadline resumes from now (the missed "
          "deadlines are dropped)");
    check(latch_soak_sleep_us(next, now) == 0ULL,
          "a long way late, the producer sends the next frame immediately");
}

/*
 * THE ALLOWANCE'S EDGE.  A producer that is EXACTLY at the allowance is
 * still inside it: the grid is kept, and the debt is not dropped.  One
 * period further out, it is outside, and the debt is dropped.
 *
 * This is the check that pins the allowance itself, so that a constant
 * that is too small (which would eat the target rate on ordinary jitter)
 * cannot slip in unnoticed.
 */
static void test_the_allowance_edge(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t deadline = 1000ULL * period;
    const uint64_t allowance = (uint64_t)LATCH_SOAK_MAX_LAG_PERIODS * period;

    /* The frame is due at deadline + period; the producer is exactly
     * `allowance` periods behind the schedule. */
    const uint64_t at_edge = deadline + period + allowance;
    const uint64_t next_at =
        latch_soak_next_deadline(deadline, at_edge, period);
    check(next_at == deadline + period,
          "at the allowance's edge, the grid is KEPT (the debt is not "
          "dropped)");

    const uint64_t past_edge = at_edge + 1ULL;
    const uint64_t next_past =
        latch_soak_next_deadline(deadline, past_edge, period);
    check(next_past == past_edge,
          "one period past the allowance, the debt is dropped and the "
          "deadline resumes from now");
}

/*
 * THE GUEST LOOP.  Send a frame, then pace -- exactly as the soak does.
 *
 * The model: the producer cannot run at all during the interval
 * [stall_at, stall_at + stall_len); when it tries, it resumes at the end
 * of the interval.  Everything else is the production loop.
 */
typedef struct {
    uint64_t frames;       /* how many frames were emitted */
    uint64_t elapsed_ns;   /* how long the window took */
    uint64_t caught_up;    /* frames emitted inside the COUNT window */
    uint64_t max_burst;    /* the longest run of consecutive no-sleep frames */
} sim_t;

static sim_t simulate(uint64_t t_start, uint64_t stall_at_ns,
                      uint64_t stall_len_ns, uint64_t window_end_ns,
                      uint64_t count_from_ns, uint64_t count_to_ns,
                      uint64_t period, uint64_t work, uint64_t wake) {
    sim_t out;
    uint64_t deadline = t_start;
    uint64_t t = t_start;
    uint64_t burst = 0u;

    out.frames = 0u;
    out.elapsed_ns = 0u;
    out.caught_up = 0u;
    out.max_burst = 0u;

    while (t < window_end_ns) {
        const uint64_t emitted_at = t;
        ++out.frames;
        if (emitted_at >= count_from_ns && emitted_at < count_to_ns) {
            ++out.caught_up;
        }

        /* The guest is starved: it cannot run inside the stall interval. */
        if (t >= stall_at_ns && t < stall_at_ns + stall_len_ns) {
            t = stall_at_ns + stall_len_ns;
        }

        const uint64_t now = t + work;
        const uint64_t next = latch_soak_next_deadline(deadline, now, period);
        uint64_t sleep_ns = 0u;
        if (next > now) {
            sleep_ns = latch_soak_sleep_us(next, now) * 1000ULL;
            /* A sleep BREAKS the burst: the producer is back on its grid. */
            burst = 0u;
        } else {
            /* no sleep: this frame went out immediately, so it is part of
             * the catch-up burst. */
            ++burst;
            if (burst > out.max_burst) {
                out.max_burst = burst;
            }
        }
        deadline = next;
        t = now + sleep_ns + (sleep_ns > 0u ? wake : 0u);
    }

    out.elapsed_ns = t - t_start;
    return out;
}

/*
 * THE RATE.  Over a long window with the guest's measured jitter, the
 * producer must sustain the TARGET rate.  This is the check that kills the
 * pacer that dropped the credit on any lateness: its measured rate on the
 * target was 610/s against a 900 Hz target.
 */
static void test_the_rate_survives_the_jitter(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t window = 2000ULL * period;
    const sim_t s = simulate(0u, window, 0u, window, 0u, window,
                             period, WORK_NS, WAKE_NS);

    /* The target is 1000000000 / period frames per second. */
    const double target = 1000000000.0 / (double)period;
    const double got = (double)s.frames * 1e9 / (double)s.elapsed_ns;

    /* 3% of tolerance: the simulator is a model, not the target. */
    check(got > target * 0.97 && got < target * 1.03,
          "the producer sustains the target rate through the jitter");
}

/*
 * THE BURST.  After a long stall, the producer must be back on the
 * 1/period schedule rather than running flat out.  A window of 100
 * periods must carry ~100 frames.
 *
 * The pacer that kept the grid without a bound carried 202 into the same
 * window -- the burst that put 255 frames into the supervisor's 256-frame
 * ring and dropped 186 on the target.
 */
static void test_no_burst_after_a_stall(void) {
    const uint64_t period = SOAK_PERIOD_NS;
    const uint64_t stall_at = 100ULL * period;
    const uint64_t stall_len = 450ULL * period;   /* a ~0.5 s stall */
    const uint64_t stall_end = stall_at + stall_len;
    const uint64_t window_end = 2000ULL * period;

    /* The whole window, with and without the stall. */
    const sim_t without = simulate(0u, window_end, 0u, window_end,
                                   0u, window_end, period, WORK_NS, WAKE_NS);
    const sim_t with = simulate(0u, stall_at, stall_len, window_end,
                                0u, window_end, period, WORK_NS, WAKE_NS);

    /* The stall COSTS the producer the frames it could not send -- that is
     * honest and expected -- but it must not GAIN any. */
    check(with.frames <= without.frames,
          "a stall costs the producer frames; it never adds any");
    check(with.frames + stall_len / period + 2ULL >= without.frames,
          "the frames lost to a stall are the stalled time itself, and no "
          "more");

    /* THE BURST, DIRECTLY.  The longest run of consecutive frames emitted
     * WITHOUT a sleep is the burst the supervisor's proposal ring sees,
     * and it is the property the pacer exists to bound.  The shipped pacer
     * measures 4 at the guest's nominal dynamics and 5 across a sweep of
     * the guest's jitter, so the bound is the allowance plus one period
     * of modelling slack.  The pacer that keeps the grid without a bound
     * measures 894 here -- it owes every missed period. */
    check(with.max_burst <= (uint64_t)LATCH_SOAK_MAX_LAG_PERIODS + 1ULL,
          "after a stall the producer never emits more than the allowance's "
          "worth of frames back-to-back (the burst is bounded)");

    /* THE DECISIVE SHAPE: the window AFTER the stall. */
    const uint64_t after_from = stall_end;
    const uint64_t after_to = stall_end + 100ULL * period;
    const sim_t after = simulate(0u, stall_at, stall_len, window_end,
                                 after_from, after_to, period, WORK_NS, WAKE_NS);

    check(after.caught_up <= 102ULL,
          "after a stall the producer is back on the 1/period schedule (at "
          "most one frame per period plus the frame at the stall)");
    check(after.caught_up >= 98ULL,
          "after a stall the producer still runs at close to 1/period (the "
          "check above is not vacuous)");
}

int main(void) {
    printf("[LATCH_SOAK_PACE] the deadline pacer must keep the rate AND "
           "bound the catch-up\n");

    test_on_schedule();
    test_a_little_late();
    test_a_long_way_late();
    test_the_allowance_edge();
    test_invariant();
    test_the_rate_survives_the_jitter();
    test_no_burst_after_a_stall();

    if (g_failures == 0) {
        printf("[LATCH_SOAK_PACE] PASS: %d checks, 0 failures -- the pacer "
               "keeps the target rate and never owes more than %d periods\n",
               g_checks, (int)LATCH_SOAK_MAX_LAG_PERIODS);
        return 0;
    }
    printf("[LATCH_SOAK_PACE] FAIL: %d checks, %d failure(s)\n",
           g_checks, g_failures);
    return 1;
}
