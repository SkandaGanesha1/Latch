/*
 * latch_fb_reader.h -- THE "FIRST READER" DECISION, AS A PURE FUNCTION.
 *
 * WHY THIS FILE EXISTS
 * ====================
 * The feedback sink's READ node must hand its FIRST reader a FRESH frame.
 * A verdict published before the reader was ready is STALE: the guest
 * would act on a decision that was made for an earlier proposal.  The
 * transport therefore discards the backlog when a reader arrives, so the
 * reader's first frame is the first frame published from then on.
 *
 * "WHEN A READER ARRIVES" is the part that is easy to get wrong, and it
 * was wrong.  TWO measured facts move the trigger away from "the first
 * open of the READ node":
 *
 * 1. QNX's `waitfor` probes a path by OPENING it with the access bits
 *    CLEARED.  The measured ioflag was 0x8880 -- no read bit, no write
 *    bit -- and that probe is the FIRST open the read node ever sees.
 *    Keying the discard on "the first open of any kind" therefore let the
 *    probe consume the first-reader slot: the real reader's backlog was
 *    never dropped, and the measured `dropped_on_open` stayed at 0 across
 *    a whole run in which 120 frames had been published.  The guest's
 *    first read was then a stale verdict.
 *
 * 2. An open that asks for READ *and* WRITE on the read-only node is
 *    REFUSED (EACCES).  A refused open is not a reader, and if it
 *    consumed the first-reader slot the real reader would lose the
 *    discard for exactly the same reason as (1).
 *
 * So the decision has THREE inputs -- the read access bit, the write
 * access bit, and how many readers have already been granted -- and it is
 * a PURE FUNCTION of them.
 *
 * WHY IT IS A HEADER AND NOT A FUNCTION IN THE RESOURCE MANAGER
 * ===============================================================
 * `qnx/latch_fb_sink.c` is a QNX resource manager: it needs resmgr, the
 * iofunc library and a QNX sysroot, so it CANNOT be built or run on the
 * build host.  A decision that only lives there is a decision with no
 * test.  Putting it here means the shipped resource manager and a HOST
 * test call the SAME function, and the test can prove the property that
 * the measurement exposed -- that a probe does not consume the slot and
 * that a refused open does not consume it either.
 *
 * `tools/consistency_check.py` proves that the resource manager really
 * calls this function, so the host test cannot drift away from the code
 * that ships.
 *
 * THE INPUTS ARE THE ALREADY-DERIVED BOOLEANS, NOT THE RAW FLAGS.
 * `_IO_FLAG_RD` (0x1) and `_IO_FLAG_WR` (0x2) come from QNX's
 * <sys/iomsg.h>, and this header must stay free of QNX headers so the
 * host test can compile it.  The resource manager derives the booleans
 * from the flags with the QNX macros and passes them in.
 */

#ifndef LATCH_FB_READER_H
#define LATCH_FB_READER_H

#include <stdint.h>

/*
 * The READ node's reader accounting.
 *
 * `opens` counts the opens that were GRANTED read access -- the readers,
 * not the probes and not the refusals.  It is the counter the
 * first-reader decision is made against.
 */
typedef struct {
    uint64_t opens;    /* opens that were granted read access */
} latch_fb_reader_t;

/*
 * Account one open against the READ node's reader accounting.
 *
 * Returns 1 if THIS open is the first reader, and the caller must
 * therefore discard the backlog; returns 0 otherwise.
 *
 * The caller must hold the lock that protects the accounting: the
 * decision and the increment have to be ATOMIC with each other, or two
 * concurrent opens could both see "no readers yet" and both believe they
 * were first.
 *
 * rd -- the open asked for read access (the QNX `_IO_FLAG_RD` bit).
 * wr -- the open asked for write access (the QNX `_IO_FLAG_WR` bit).
 */
static inline int latch_fb_reader_account(latch_fb_reader_t *st,
                                           unsigned rd,
                                           unsigned wr)
{
    int first;

    if (st == NULL) {
        return 0;
    }
    /* NOT A READER: the open asked for no access at all (the `waitfor`
     * probe), or it asked for read access on a node that also asked for
     * write access and is therefore refused. */
    if (rd == 0u || wr != 0u) {
        return 0;
    }
    first = (st->opens == 0u);
    st->opens++;
    return first;
}

#endif /* LATCH_FB_READER_H */
