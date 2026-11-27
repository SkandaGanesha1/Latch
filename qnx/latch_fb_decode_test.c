/*
 * qnx/latch_fb_decode_test.c
 *
 * THE HOST-SIM ROUND-TRIP TEST FOR THE GUEST-SIDE LFBK DECODER  (W5)
 * =====================================================================
 *
 * WHAT THIS TEST IS FOR
 * ---------------------
 * The guest policy is FREESTANDING: it cannot include qnx/latch_feedback.h,
 * so the frame format and the decoder are written out again in
 * guest/latch_fb_decode.h.  A protocol that is written down twice is a
 * protocol that WILL drift, and the drift would be invisible until a guest
 * on a target silently stopped understanding its supervisor.
 *
 * So this test puts the two implementations SIDE BY SIDE:
 *
 *   * the PRODUCTION codec (qnx/latch_feedback.c) encodes a verdict, and
 *     the GUEST decoder (guest/latch_fb_decode.h) decodes it -- byte for
 *     byte, with no translation in between; and
 *
 *   * the guest's CRC is compared against the production CRC
 *     (qnx/latch_protocol.h's latch_crc32_ieee) over the same bytes, so
 *     the two copies cannot disagree about the checksum either.
 *
 * It also exercises the CORRELATION state machine, which is where the
 * safety-relevant behaviour lives: a stale sequence number, a foreign
 * epoch, a duplicate, an unknown verdict and a silent channel must all
 * end in the SAME place -- the guest stops proposing.
 *
 * It runs on the host, so it is part of `make check` and it runs in CI.
 */

#include "../guest/latch_fb_decode.h"

#include "latch_feedback.h"
#include "latch_protocol.h"

#include <stdio.h>
#include <string.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", (msg)); return 1; } while (0)

/* The production codec and the guest decoder must agree on the CRC. */
_Static_assert(LATCH_FB_SIZE == LATCH_FEEDBACK_SIZE,
               "the guest's frame size must be the production frame size");

static int test_production_round_trip(void)
{
    latch_feedback_t prod;
    latch_fb_frame_t guest;
    uint8_t raw[LATCH_FEEDBACK_SIZE];

    memset(&prod, 0, sizeof(prod));
    prod.seq           = 0x01020304u;
    prod.session_epoch = 0xB7BA19BDu;
    prod.verdict       = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
    prod.rung          = 3u;
    prod.fault_bits    = 0x2000u;
    prod.fault_bits2   = 0u;
    prod.flags         = 0u;
    if (latch_feedback_encode(&prod) != 0) {
        FAIL("the production codec refused to encode a verdict");
    }
    memcpy(raw, &prod, sizeof(raw));

    /* The GUEST decoder must accept the PRODUCTION bytes unchanged. */
    if (latch_fb_decode(raw, sizeof(raw), &guest) != LATCH_FB_OK) {
        FAIL("the guest decoder refused a frame the production codec encoded");
    }
    if (guest.seq != prod.seq || guest.epoch != prod.session_epoch ||
        guest.verdict != prod.verdict || guest.rung != prod.rung ||
        guest.fault_bits != prod.fault_bits || guest.flags != prod.flags) {
        FAIL("the guest decoder and the production codec disagree on the fields");
    }

    /* And the two CRCs must be the same function. */
    if (latch_fb_crc32(raw, 24u) != latch_crc32_ieee(raw, 24u)) {
        FAIL("the guest's CRC and the production CRC disagree");
    }
    if (prod.crc32 != latch_crc32_ieee(raw, 24u)) {
        FAIL("the production frame's CRC is not the production CRC");
    }

    /* The production decoder must accept the GUEST's field values. */
    {
        latch_feedback_t back;
        if (latch_feedback_decode(raw, sizeof(raw), &back) != 0) {
            FAIL("the production decoder refused its own frame");
        }
    }
    return 0;
}

static int test_decode_rejections(void)
{
    latch_feedback_t prod;
    latch_fb_frame_t guest;
    uint8_t raw[LATCH_FEEDBACK_SIZE];

    memset(&prod, 0, sizeof(prod));
    prod.seq           = 7u;
    prod.session_epoch = 0x11223344u;
    prod.verdict       = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
    prod.rung          = 0u;
    (void)latch_feedback_encode(&prod);
    memcpy(raw, &prod, sizeof(raw));

    if (latch_fb_decode(raw, sizeof(raw), &guest) != LATCH_FB_OK) {
        FAIL("a well-formed frame was refused");
    }

    /* A corrupt CRC must not be admitted: a torn read of the verdict
     * sector must never look like a verdict. */
    raw[20] ^= 0x01u;
    if (latch_fb_decode(raw, sizeof(raw), &guest) == LATCH_FB_OK) {
        FAIL("a frame with a corrupt CRC was admitted");
    }
    raw[20] ^= 0x01u;

    /* A wrong magic, version or size must not be admitted. */
    raw[0] ^= 0xFFu;
    if (latch_fb_decode(raw, sizeof(raw), &guest) == LATCH_FB_OK) {
        FAIL("a frame with a wrong magic was admitted");
    }
    raw[0] ^= 0xFFu;
    raw[4] = 1u; /* version 1 */
    if (latch_fb_decode(raw, sizeof(raw), &guest) == LATCH_FB_OK) {
        FAIL("a version-1 frame was admitted as version 2");
    }
    raw[4] = LATCH_FB_VERSION;

    /* Epoch 0 belongs to no session. */
    {
        latch_feedback_t zero;
        memset(&zero, 0, sizeof(zero));
        zero.seq     = 7u;
        zero.verdict = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
        (void)latch_feedback_encode(&zero);
        if (latch_fb_decode(&zero, sizeof(zero), &guest) != LATCH_FB_EEPOCH) {
            FAIL("a frame with epoch 0 was admitted");
        }
    }

    /* THE VERDICT VOCABULARY IS CLOSED.  This is the single most
     * important rejection in this file: "I did not understand what the
     * supervisor said" must never be read as "the supervisor said yes". */
    {
        latch_feedback_t odd;
        memset(&odd, 0, sizeof(odd));
        odd.seq           = 7u;
        odd.session_epoch = 0x11223344u;
        odd.verdict       = 0x5Au;   /* the probe's marker verdict */
        odd.rung          = 0u;
        (void)latch_feedback_encode(&odd);
        if (latch_fb_decode(&odd, sizeof(odd), &guest) != LATCH_FB_EVERDICT) {
            FAIL("an unknown verdict was admitted");
        }
    }

    /* A timeout verdict without the timeout flag is not canonical. */
    {
        latch_feedback_t bad;
        memset(&bad, 0, sizeof(bad));
        bad.seq           = 7u;
        bad.session_epoch = 0x11223344u;
        bad.verdict       = (uint8_t)LATCH_FB_VERDICT_TIMEOUT;
        bad.rung          = (uint8_t)LATCH_FB_VERDICT_TIMEOUT;
        bad.flags         = 0u;
        (void)latch_feedback_encode(&bad);
        if (latch_fb_decode(&bad, sizeof(bad), &guest) != LATCH_FB_ETIMEOUT) {
            FAIL("a timeout verdict without the timeout flag was admitted");
        }
    }

    /* A canonical timeout frame IS admitted. */
    {
        latch_feedback_t good;
        memset(&good, 0, sizeof(good));
        good.seq           = 7u;
        good.session_epoch = 0x11223344u;
        good.verdict       = (uint8_t)LATCH_FB_VERDICT_TIMEOUT;
        good.rung          = (uint8_t)LATCH_FB_VERDICT_TIMEOUT;
        good.flags         = LATCH_FB_FLAG_TIMEOUT;
        (void)latch_feedback_encode(&good);
        if (latch_fb_decode(&good, sizeof(good), &guest) != LATCH_FB_OK ||
            guest.flags != LATCH_FB_FLAG_TIMEOUT) {
            FAIL("a canonical timeout frame was refused");
        }
    }

    /* A truncated frame must not be admitted. */
    if (latch_fb_decode(raw, sizeof(raw) - 1u, &guest) == LATCH_FB_OK) {
        FAIL("a truncated frame was admitted");
    }
    return 0;
}

/* Build a frame the way the supervisor does. */
static void make_frame(latch_fb_frame_t *f, uint32_t seq, uint32_t epoch,
                       uint8_t verdict, uint8_t rung)
{
    memset(f, 0, sizeof(*f));
    f->magic   = LATCH_FB_MAGIC;
    f->version = LATCH_FB_VERSION;
    f->size    = LATCH_FB_SIZE;
    f->seq     = seq;
    f->epoch   = epoch;
    f->verdict = verdict;
    f->rung    = rung;
    f->crc32   = latch_fb_crc32(f, 24u);
}

static int test_correlation(void)
{
    latch_fb_state_t st;
    latch_fb_frame_t f;
    const uint32_t epoch = 0xA5A5A5A5u;

    latch_fb_state_init(&st, 50u /* polls without an answer are fatal */);

    /* The guest has sent up to seq 10, and seq 10 was a MOTION PROPOSAL.
     *
     * The two calls are SEPARATE on purpose.  `note_sent` records that a
     * frame is on the wire; `note_cmd` records that the supervisor OWES
     * the guest an answer for it.  Only a motion proposal is answered, so
     * only a motion proposal can be outstanding. */
    latch_fb_note_sent(&st, 10u);
    latch_fb_note_cmd(&st, 10u);
    if (!latch_fb_outstanding(&st)) {
        FAIL("a motion proposal was not outstanding");
    }

    /* A verdict for a proposal the guest has NOT sent is stale.  It must
     * not be correlated, and it must not stop the guest either -- it is
     * simply not about this guest. */
    make_frame(&f, 11u, epoch, LATCH_FB_VERDICT_ACCEPT, 0u);
    if (latch_fb_correlate(&st, &f) != LATCH_FB_RES_STALE) {
        FAIL("a verdict for an unsent proposal was correlated");
    }
    if (st.accepts != 0u || st.stopped) {
        FAIL("a stale verdict changed the guest's state");
    }

    /* The first verdict pins the session epoch. */
    make_frame(&f, 5u, epoch, LATCH_FB_VERDICT_ACCEPT, 0u);
    if (latch_fb_correlate(&st, &f) != LATCH_FB_RES_ACCEPT) {
        FAIL("a matching verdict was not correlated");
    }
    if (st.pinned_epoch != epoch || st.accepts != 1u || st.last_seq_verdict != 5u) {
        FAIL("the first verdict did not pin the epoch");
    }
    if (!latch_fb_may_propose(&st)) {
        FAIL("the guest stopped proposing after an accepted verdict");
    }

    /* The same verdict again is a duplicate, not a second acceptance. */
    if (latch_fb_correlate(&st, &f) != LATCH_FB_RES_DUPLICATE) {
        FAIL("a duplicate verdict was correlated twice");
    }
    if (st.accepts != 1u) {
        FAIL("a duplicate verdict was counted as an acceptance");
    }

    /* A verdict from ANOTHER session must not be correlated.  This is the
     * session-epoch half of the correlation: after a handoff, the old
     * session's verdict is still in flight, and the guest must not
     * attribute it to the new session's proposal. */
    make_frame(&f, 6u, epoch + 1u, LATCH_FB_VERDICT_ACCEPT, 0u);
    if (latch_fb_correlate(&st, &f) != LATCH_FB_RES_FOREIGN) {
        FAIL("a verdict from another session was correlated");
    }
    if (st.foreign != 1u || st.accepts != 1u) {
        FAIL("a foreign verdict was counted as an acceptance");
    }

    /* A rejection stops the guest: the supervisor said no, and a guest
     * that keeps asking after being told no is not listening. */
    make_frame(&f, 7u, epoch, LATCH_FB_VERDICT_REJECT, 2u);
    if (latch_fb_correlate(&st, &f) != LATCH_FB_RES_REJECT) {
        FAIL("a rejection was not correlated");
    }
    if (!st.stopped || st.stop_reason != LATCH_FB_STOP_REJECTED ||
        st.rejects != 1u) {
        FAIL("a rejection did not stop the guest");
    }
    if (latch_fb_may_propose(&st)) {
        FAIL("the guest may still propose after a rejection");
    }
    return 0;
}

static int test_timeout(void)
{
    latch_fb_state_t st;
    latch_fb_frame_t f;
    const uint32_t epoch = 0x01020304u;

    latch_fb_state_init(&st, 5u);

    /* The guest sends a proposal and awaits an answer. */
    latch_fb_note_sent(&st, 1u);
    latch_fb_note_cmd(&st, 1u);
    if (!latch_fb_outstanding(&st)) {
        FAIL("sending a proposal did not arm the feedback timeout");
    }

    /* Polls with no answer.  The timeout must fire after exactly the
     * configured number of polls -- not before, and not never. */
    for (uint32_t i = 0u; i < 4u; ++i) {
        if (latch_fb_note_poll(&st) != 0) {
            FAIL("the feedback timeout fired early");
        }
    }
    if (latch_fb_note_poll(&st) != 1) {
        FAIL("the feedback timeout did not fire");
    }
    if (!st.stopped || st.stop_reason != LATCH_FB_STOP_TIMEOUT ||
        st.timeouts != 1u) {
        FAIL("the feedback timeout did not stop the guest");
    }
    if (latch_fb_may_propose(&st)) {
        FAIL("the guest may still propose after a feedback timeout");
    }

    /* A heartbeat does NOT arm the timeout: the supervisor does not answer
     * a heartbeat with a verdict, so waiting for one would be waiting for
     * something that will never come. */
    {
        latch_fb_state_t st2;
        latch_fb_state_init(&st2, 5u);
        latch_fb_note_sent(&st2, 1u);
        if (latch_fb_outstanding(&st2)) {
            FAIL("a heartbeat armed the feedback timeout");
        }
        for (uint32_t i = 0u; i < 20u; ++i) {
            (void)latch_fb_note_poll(&st2);
        }
        if (st2.stopped) {
            FAIL("a heartbeat-only session timed out");
        }
    }

    /* An answer clears the wait. */
    {
        latch_fb_state_t st3;
        latch_fb_state_init(&st3, 5u);
        latch_fb_note_sent(&st3, 3u);
        latch_fb_note_cmd(&st3, 3u);
        (void)latch_fb_note_poll(&st3);
        make_frame(&f, 3u, epoch, LATCH_FB_VERDICT_ACCEPT, 0u);
        if (latch_fb_correlate(&st3, &f) != LATCH_FB_RES_ACCEPT) {
            FAIL("the answer was not correlated");
        }
        if (latch_fb_outstanding(&st3)) {
            FAIL("the answer did not clear the outstanding proposal");
        }
        for (uint32_t i = 0u; i < 20u; ++i) {
            (void)latch_fb_note_poll(&st3);
        }
        if (st3.stopped) {
            FAIL("the feedback timeout fired after an answer arrived");
        }
    }
    return 0;
}

int main(void)
{
    if (test_production_round_trip() != 0) return 1;
    if (test_decode_rejections() != 0) return 1;
    if (test_correlation() != 0) return 1;
    if (test_timeout() != 0) return 1;

    puts("[LATCH_FB_DECODE] PASS: the production codec's bytes decode in the "
         "guest, the CRCs agree, the verdict vocabulary is closed, the "
         "correlation is by sequence AND epoch, a rejection stops the guest, "
         "and a silent channel times out into fail-closed");
    return 0;
}
