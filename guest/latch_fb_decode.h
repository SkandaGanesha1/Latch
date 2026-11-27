/*
 * guest/latch_fb_decode.h
 *
 * THE GUEST-SIDE LFBK DECODER AND CORRELATOR  (W5)
 * ===============================================
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The guest policy is FREESTANDING: it has no libc, no printf and no
 * dependency on the QNX tree, so it cannot include qnx/latch_feedback.h.
 * But the LFBK frame format is a PROTOCOL, and a protocol that is written
 * down twice is a protocol that will drift.
 *
 * So the guest's decoder lives HERE, in a header that is:
 *
 *   * self-contained -- it needs only <stdint.h> and <stddef.h>, both of
 *     which are freestanding-safe; and
 *   * shared -- the host-sim test (qnx/latch_fb_decode_test.c) includes the
 *     SAME header, so the decoder that runs inside the untrusted guest is
 *     the decoder that is unit-tested on the host.
 *
 * `tools/consistency_check.py` checks that the constants here agree with
 * the production header (qnx/latch_feedback.h), so there is exactly ONE
 * feedback frame format in the tree and the two copies cannot drift.
 *
 * WHAT THE DECODER DOES
 * ---------------------
 * 1. RE-SYNCHRONISES on the frame's magic and validates the version, the
 *    size and the CRC.  A sector that was read while the host was
 *    rewriting it therefore cannot produce a false "it worked".
 *
 * 2. CORRELATES the verdict with the proposal it answers, by BOTH the
 *    sequence number and the session epoch.
 *
 * 3. COUNTS what it could not use -- a stale sequence number, a foreign
 *    epoch, a duplicate, a frame that failed the structural checks -- so
 *    that the report distinguishes "the channel is silent" from "the
 *    channel is carrying somebody else's frames".
 *
 * WHAT THE CORRELATION DOES *NOT* CLAIM
 * -------------------------------------
 * The epoch is bound by the INGEST on the trusted side (RT-02), so the
 * guest does not CHOOSE it: it LEARNS it from the first verdict it
 * accepts and then refuses any frame that names a different session.  A
 * verdict that arrives with an unfamiliar epoch is therefore not
 * correlated -- it is counted as foreign and ignored.  The cost of that
 * strictness is that a legitimate session handoff leaves the guest unable
 * to correlate (the guest's own process restarts with the session, and a
 * fresh guest starts with a fresh state), and the benefit is that a guest
 * can never attribute one session's verdict to another session's
 * proposal.
 *
 * THE FAIL-CLOSED DIRECTION
 * --------------------------
 * A verdict the guest does not understand is a REJECTION, never an
 * acceptance: "I did not understand what the supervisor said" is not "the
 * supervisor said yes".  And a verdict that does not arrive at all is a
 * TIMEOUT, which stops the guest's proposing.  Both directions close.
 */

#ifndef LATCH_FB_DECODE_H_
#define LATCH_FB_DECODE_H_

#include <stddef.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * THE WIRE FORMAT (qnx/latch_feedback.h)
 * ------------------------------------------------------------------------ */
#define LATCH_FB_MAGIC        0x4B42464Cu /* little-endian "LFBK" */
#define LATCH_FB_VERSION      2u
#define LATCH_FB_SIZE         28u
#define LATCH_FB_FLAG_TIMEOUT 0x0001u

/* THE VERDICT VOCABULARY.  It is closed: see qnx/latch_feedback.h. */
#define LATCH_FB_VERDICT_ACCEPT  0x01u
#define LATCH_FB_VERDICT_REJECT  0x02u
#define LATCH_FB_VERDICT_TIMEOUT 0xFFu

/* The governor rung the decision was taken at (qnx/governor_policy.h). */
#define LATCH_FB_RUNG_MIN 0u
#define LATCH_FB_RUNG_MAX 5u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t seq;
    uint32_t epoch;
    uint8_t  verdict;
    uint8_t  rung;
    uint16_t fault_bits;
    uint16_t fault_bits2;
    uint16_t flags;
    uint32_t crc32;
} latch_fb_frame_t;

_Static_assert(sizeof(latch_fb_frame_t) == LATCH_FB_SIZE,
               "the LFBK frame must be a fixed 28-byte frame");
_Static_assert(offsetof(latch_fb_frame_t, epoch) == 12u,
               "the session epoch must sit beside the sequence number");
_Static_assert(offsetof(latch_fb_frame_t, crc32) == 24u,
               "the LFBK CRC must cover the first 24 bytes");

/* --------------------------------------------------------------------------
 * THE DECODE
 * ------------------------------------------------------------------------ */

/* The decode outcomes.  They are NEGATIVE so that 0 can mean "fine". */
#define LATCH_FB_OK          0
#define LATCH_FB_EFRAME   (-1)  /* magic, version, size or CRC          */
#define LATCH_FB_EEPOCH   (-2)  /* epoch 0: the frame belongs to no session */
#define LATCH_FB_EVERDICT (-3)  /* the verdict vocabulary is closed       */
#define LATCH_FB_ETIMEOUT (-4)  /* a non-canonical timeout frame          */

/* The reflected IEEE 802.3 CRC-32 (polynomial 0xEDB88320).  It is the
 * same function as qnx/latch_protocol.h's latch_crc32_ieee(), written out
 * here because the guest policy must not pull a header out of the QNX
 * tree.  tools/consistency_check.py checks that the two agree. */
static inline uint32_t latch_fb_crc32(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= (uint32_t)bytes[i];
        for (unsigned int bit = 0; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)0u - (crc & 1u);
            crc = (crc >> 1u) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

/*
 * Validate one frame.
 *
 * Returns LATCH_FB_OK and fills `out`, or one of the negative codes above.
 */
static inline int latch_fb_decode(const void *bytes, size_t size,
                                  latch_fb_frame_t *out) {
    latch_fb_frame_t f;
    const uint8_t *b = (const uint8_t *)bytes;

    if (bytes == NULL || out == NULL || size != LATCH_FB_SIZE) {
        return LATCH_FB_EFRAME;
    }
    for (size_t i = 0; i < sizeof(f); ++i) {
        ((uint8_t *)&f)[i] = b[i];
    }
    if (f.magic != LATCH_FB_MAGIC ||
        f.version != LATCH_FB_VERSION ||
        f.size != LATCH_FB_SIZE) {
        return LATCH_FB_EFRAME;
    }
    if (f.crc32 != latch_fb_crc32(b, 24u)) {
        return LATCH_FB_EFRAME;
    }
    /* The epoch is never 0: a frame that names no session cannot be
     * attributed to one. */
    if (f.epoch == 0u) {
        return LATCH_FB_EEPOCH;
    }
    /* The verdict vocabulary is CLOSED.  An unknown verdict is refused
     * rather than guessed at, because the one thing this channel must not
     * do is turn "I did not understand" into "yes". */
    if (f.verdict != (uint8_t)LATCH_FB_VERDICT_ACCEPT &&
        f.verdict != (uint8_t)LATCH_FB_VERDICT_REJECT &&
        f.verdict != (uint8_t)LATCH_FB_VERDICT_TIMEOUT) {
        return LATCH_FB_EVERDICT;
    }
    /* The timeout verdict is the absence of a verdict, so it is only legal
     * with the timeout flag, and it carries no rung and no faults. */
    if ((f.flags & LATCH_FB_FLAG_TIMEOUT) != 0u) {
        if (f.verdict != (uint8_t)LATCH_FB_VERDICT_TIMEOUT ||
            f.rung != (uint8_t)LATCH_FB_VERDICT_TIMEOUT ||
            f.fault_bits != 0u || f.fault_bits2 != 0u) {
            return LATCH_FB_ETIMEOUT;
        }
    } else if (f.verdict == (uint8_t)LATCH_FB_VERDICT_TIMEOUT) {
        return LATCH_FB_ETIMEOUT;
    }
    *out = f;
    return LATCH_FB_OK;
}

/* --------------------------------------------------------------------------
 * THE CORRELATION
 * ------------------------------------------------------------------------ */

/* What happened to one frame. */
#define LATCH_FB_RES_ACCEPT    0  /* correlated: the supervisor accepted it  */
#define LATCH_FB_RES_REJECT    1  /* correlated: the supervisor rejected it  */
#define LATCH_FB_RES_BAD       2  /* the frame failed the structural checks  */
#define LATCH_FB_RES_STALE     3  /* the sequence number is not one we sent  */
#define LATCH_FB_RES_FOREIGN   4  /* the epoch is not this session's epoch    */
#define LATCH_FB_RES_DUPLICATE 5  /* already correlated                       */

/* WHY THE GUEST STOPPED PROPOSING. */
#define LATCH_FB_STOP_NONE     0u
#define LATCH_FB_STOP_REJECTED 1u
#define LATCH_FB_STOP_TIMEOUT  2u

/*
 * THE CORRELATION STATE
 * ----------------------
 * There is exactly ONE writer of this state: the verdict watcher.  The
 * main thread never touches it -- it publishes what it sent through two
 * volatile words, and the watcher folds them in.  That is not a style
 * choice: a state that two threads mutate needs a lock, and a freestanding
 * policy has no lock.
 *
 * The state is therefore a PURE FUNCTION of the sequence of events the
 * watcher observes:
 *
 *   note_sent(seq)     the guest put seq on the wire (any kind of frame)
 *   note_cmd(seq)      the guest put a MOTION PROPOSAL on the wire
 *   note_poll()        the watcher looked at the verdict sector
 *   correlate(frame)   a decoded frame arrived
 *
 * "IS A PROPOSAL STILL UNANSWERED?" is DERIVED, not stored:
 *
 *      outstanding  <=>  last_cmd_seq != 0  &&  last_cmd_seq > last_seq_verdict
 *
 * A derived predicate cannot go stale, and it cannot disagree with itself:
 * there is no "awaiting" flag that a lost update could leave behind.
 */
typedef struct {
    /* The session epoch, learned from the first accepted verdict. */
    uint32_t pinned_epoch;
    /* The highest sequence number the guest has put on the wire. */
    uint32_t last_seq_sent;
    /* The highest sequence number of a MOTION PROPOSAL the guest sent.
     * Only a motion proposal is answered by the supervisor, so only a
     * motion proposal can be outstanding. */
    uint32_t last_cmd_seq;
    /* The highest sequence number correlated with a verdict. */
    uint32_t last_seq_verdict;
    /* The poll counter, and the value it had when the guest last sent a
     * proposal.  The timeout is measured in POLLS rather than in
     * milliseconds because the guest policy has no clock: a poll is a
     * fixed-cost action, so "N polls without an answer" is a duration
     * that does not depend on a clock the guest does not have. */
    uint32_t polls;
    uint32_t await_since_poll;
    uint32_t timeout_polls;
    /* The worst observed round trip, in polls: how long the supervisor's
     * answer took to come back.  It is the measurement that says whether
     * the timeout budget is sane. */
    uint32_t max_round_trip_polls;
    int      stopped;       /* the guest must stop proposing            */
    uint32_t stop_reason;
    /* The census. */
    uint32_t accepts;
    uint32_t rejects;
    uint32_t foreign;
    uint32_t stale;
    uint32_t duplicates;
    uint32_t bad;
    uint32_t timeouts;
} latch_fb_state_t;

/* A fresh state.  `timeout_polls` is the number of polls without a
 * correlated verdict that is fatal; 0 disables the timeout. */
static inline void latch_fb_state_init(latch_fb_state_t *st,
                                        uint32_t timeout_polls) {
    for (size_t i = 0; i < sizeof(*st); ++i) {
        ((uint8_t *)st)[i] = 0u;
    }
    st->timeout_polls = timeout_polls;
}

/* The guest put a frame on the wire.
 *
 * The sequence number is recorded for EVERY frame, so a verdict that
 * arrives for an EARLIER frame is not mistaken for one the guest has not
 * reached yet.  A heartbeat does not ARM anything: the supervisor
 * publishes a verdict for a motion proposal and for nothing else, so
 * waiting for an answer to a heartbeat would be waiting for something that
 * is never going to come.
 */
static inline void latch_fb_note_sent(latch_fb_state_t *st, uint32_t seq) {
    if (seq > st->last_seq_sent) {
        st->last_seq_sent = seq;
    }
}

/* The guest put a MOTION PROPOSAL on the wire.
 *
 * This ARMS the feedback timeout: the supervisor owes the guest an answer
 * for this proposal, and a proposal that is never answered is a supervisor
 * that has stopped listening -- which the guest must fail closed on.
 */
static inline void latch_fb_note_cmd(latch_fb_state_t *st, uint32_t seq) {
    if (seq > st->last_cmd_seq) {
        st->last_cmd_seq = seq;
        st->await_since_poll = st->polls;
    }
}

/* Is a motion proposal still unanswered? */
static inline int latch_fb_outstanding(const latch_fb_state_t *st) {
    return (st->last_cmd_seq != 0u &&
            st->last_cmd_seq > st->last_seq_verdict) ? 1 : 0;
}

/* A poll happened.  Returns 1 when the guest must STOP. */
static inline int latch_fb_note_poll(latch_fb_state_t *st) {
    st->polls++;
    if (st->stop_reason != LATCH_FB_STOP_NONE) {
        return st->stopped;
    }
    if (!latch_fb_outstanding(st)) {
        return 0;
    }
    if (st->timeout_polls != 0u &&
        (st->polls - st->await_since_poll) >= st->timeout_polls) {
        st->timeouts++;
        st->stopped = 1;
        st->stop_reason = LATCH_FB_STOP_TIMEOUT;
        return 1;
    }
    return 0;
}

/*
 * Correlate one decoded frame.
 *
 * The sequence number says WHICH proposal the verdict answers; the epoch
 * says WHICH SESSION it belongs to.  Both must match, and a frame that
 * fails either test is counted and ignored -- never guessed at.
 */
static inline int latch_fb_correlate(latch_fb_state_t *st,
                                     const latch_fb_frame_t *f) {
    if (f == NULL) {
        st->bad++;
        return LATCH_FB_RES_BAD;
    }
    /* A sequence number of 0 belongs to no proposal, and a sequence number
     * the guest has not reached yet is a frame from the future -- either
     * way it is not an answer to anything the guest asked. */
    if (f->seq == 0u || f->seq > st->last_seq_sent) {
        st->stale++;
        return LATCH_FB_RES_STALE;
    }
    if (st->pinned_epoch == 0u) {
        /* The first verdict NAMES the session. */
        st->pinned_epoch = f->epoch;
    } else if (f->epoch != st->pinned_epoch) {
        /* A different session's verdict.  It is counted, so the report can
         * say "the channel carried somebody else's frames" rather than
         * "the channel was silent", and it is NOT correlated. */
        st->foreign++;
        return LATCH_FB_RES_FOREIGN;
    }
    if (f->seq <= st->last_seq_verdict) {
        st->duplicates++;
        return LATCH_FB_RES_DUPLICATE;
    }

    st->last_seq_verdict = f->seq;
    /* The round trip, in polls.  It is the measurement that says whether
     * the timeout budget is sane: a budget below the observed round trip
     * would fail closed on a supervisor that is working perfectly. */
    if (st->polls >= st->await_since_poll) {
        uint32_t trip = st->polls - st->await_since_poll;
        if (trip > st->max_round_trip_polls) {
            st->max_round_trip_polls = trip;
        }
    }

    if (f->verdict == (uint8_t)LATCH_FB_VERDICT_ACCEPT) {
        st->accepts++;
        return LATCH_FB_RES_ACCEPT;
    }
    /* A REJECTION, a TIMEOUT, and anything else the vocabulary does not
     * contain are all "no".  The guest's response to "no" is to STOP
     * asking: the supervisor is the authority, and a guest that keeps
     * asking after being told no is a guest that is not listening. */
    st->rejects++;
    st->stopped = 1;
    if (st->stop_reason == LATCH_FB_STOP_NONE) {
        st->stop_reason = LATCH_FB_STOP_REJECTED;
    }
    return LATCH_FB_RES_REJECT;
}

/* May the guest keep proposing? */
static inline int latch_fb_may_propose(const latch_fb_state_t *st) {
    return st->stop_reason == LATCH_FB_STOP_NONE ? 1 : 0;
}

#endif /* LATCH_FB_DECODE_H_ */
