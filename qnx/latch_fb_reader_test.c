/*
 * latch_fb_reader_test.c -- THE FIRST-READER DECISION, PROVEN ON THE HOST.
 *
 * `qnx/latch_fb_sink.c` is a QNX resource manager: it needs resmgr, the
 * iofunc library and a QNX sysroot, so it cannot be built or run on the
 * build host.  The decision it makes about "is this open the first
 * READER, and must the backlog be discarded" lives in
 * `qnx/latch_fb_reader.h`, and THIS test proves the property on the
 * host -- against the same function the resource manager calls.
 *
 * THE PROPERTY, IN ONE LINE
 * =========================
 * The backlog is discarded for the first open that was GRANTED read
 * access -- and for no other open.  A probe (an open with the access
 * bits cleared, which is how QNX's `waitfor` tests that the node exists)
 * and a refused open (read AND write on the read-only node) are not
 * readers, and neither of them may consume the first-reader slot.
 *
 * WHY IT MATTERS
 * ==============
 * The defect this test was written from was measured on the QEMU AArch64
 * target: the `waitfor` probe consumed the first-reader slot, the real
 * reader's backlog was never dropped, `dropped_on_open` stayed at 0
 * across a whole run in which 120 frames had been published, and the
 * guest's first read was a STALE verdict -- a decision made for an
 * earlier proposal.  The measurement is in `qnx/latch_fb_sink.c`'s own
 * comment; the proof that the defect cannot come back is here.
 */

#include <stdio.h>
#include <string.h>

#include "latch_fb_reader.h"

static int failures;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            printf("  FAIL: ");                                              \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
            failures++;                                                       \
        }                                                                     \
    } while (0)

/* The measured access bits of the three kinds of open the node sees. */
#define OPEN_PROBE  (0u)      /* `waitfor`: neither bit (measured 0x8880) */
#define OPEN_READ   (1u)      /* _IO_FLAG_RD */
#define OPEN_WRITE  (2u)      /* _IO_FLAG_WR */
#define OPEN_READWRITE (OPEN_READ | OPEN_WRITE)

static void test_probe_is_not_a_reader(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    /* A `waitfor` probe opens with NO access bits.  It must not be
     * counted, and it must not be told that it is the first reader. */
    CHECK(latch_fb_reader_account(&st, OPEN_PROBE, OPEN_PROBE) == 0,
          "the waitfor probe must not be reported as the first reader");
    CHECK(st.opens == 0u,
          "the waitfor probe must not consume the first-reader slot "
          "(opens=%llu, expected 0)", (unsigned long long)st.opens);
}

static void test_first_real_reader_is_the_first(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    /* After the probe, the first open that asks for READ access is the
     * first reader -- and it is the one that discards the backlog. */
    CHECK(latch_fb_reader_account(&st, OPEN_PROBE, OPEN_PROBE) == 0,
          "the probe before the reader must not consume the slot");
    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 1,
          "the first open with READ access must be reported as the first reader");
    CHECK(st.opens == 1u,
          "exactly one reader must be counted (opens=%llu, expected 1)",
          (unsigned long long)st.opens);
}

static void test_second_reader_is_not_the_first(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 1,
          "the first reader must be reported");
    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 0,
          "the SECOND reader must not be reported as the first reader");
    CHECK(st.opens == 2u,
          "both readers must be counted (opens=%llu, expected 2)",
          (unsigned long long)st.opens);
}

static void test_refused_open_is_not_a_reader(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    /* READ+WRITE on the read-only node is refused with EACCES.  A
     * refused open is not a reader: it must not consume the slot, or the
     * real reader would lose the discard -- the same defect as the
     * probe, arrived at from the other side. */
    CHECK(latch_fb_reader_account(&st, OPEN_READWRITE, OPEN_READWRITE) == 0,
          "a refused READ+WRITE open must not be reported as the first reader");
    CHECK(st.opens == 0u,
          "a refused open must not consume the first-reader slot "
          "(opens=%llu, expected 0)", (unsigned long long)st.opens);
    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 1,
          "the first GRANTED reader after a refusal must still be the first reader");
}

static void test_probe_between_readers_is_inert(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 1,
          "the first reader must be reported");
    CHECK(latch_fb_reader_account(&st, OPEN_PROBE, OPEN_PROBE) == 0,
          "a probe after the first reader must not be reported as a reader");
    CHECK(latch_fb_reader_account(&st, OPEN_READ, OPEN_PROBE) == 0,
          "the second reader must not be reported as the first reader");
    CHECK(st.opens == 2u,
          "only the granted readers are counted (opens=%llu, expected 2)",
          (unsigned long long)st.opens);
}

static void test_write_only_open_is_not_a_reader(void)
{
    latch_fb_reader_t st;
    memset(&st, 0, sizeof(st));

    CHECK(latch_fb_reader_account(&st, OPEN_PROBE, OPEN_WRITE) == 0,
          "a write-only open must not be reported as the first reader");
    CHECK(st.opens == 0u,
          "a write-only open must not consume the first-reader slot "
          "(opens=%llu, expected 0)", (unsigned long long)st.opens);
}

static void test_null_state_is_safe(void)
{
    CHECK(latch_fb_reader_account(NULL, OPEN_READ, OPEN_PROBE) == 0,
          "a null accounting state must not report a first reader");
}

int main(void)
{
    printf("=== latch_fb_reader_test: the first-reader decision ===\n");
    test_probe_is_not_a_reader();
    test_first_real_reader_is_the_first();
    test_second_reader_is_not_the_first();
    test_refused_open_is_not_a_reader();
    test_probe_between_readers_is_inert();
    test_write_only_open_is_not_a_reader();
    test_null_state_is_safe();

    if (failures != 0) {
        printf("=== latch_fb_reader_test: %d CHECK(s) FAILED ===\n", failures);
        return 1;
    }
    printf("=== latch_fb_reader_test: all checks PASSED ===\n");
    return 0;
}
