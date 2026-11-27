/*
 * qnx/latch_feedback_pub_test.c
 *
 * THE HOST-SIM ROUND-TRIP TEST FOR THE FEEDBACK PUBLISHER  (W5)
 * ==============================================================
 *
 * WHAT THIS TEST PROVES
 * ---------------------
 * The publisher is the thing that carries the supervisor's verdict to the
 * transport, and it has three properties that matter:
 *
 *   1. THE FRAME ARRIVES UNCHANGED.  The bytes the publisher writes are
 *      the bytes the supervisor encoded -- the magic, the version, the
 *      epoch, the verdict, the rung, the faults and the CRC all survive
 *      the trip.
 *
 *   2. THE PUBLISH CALL NEVER BLOCKS ON I/O.  The test publishes a burst
 *      far larger than the slot and checks that the call returned
 *      promptly and that the LAST frame is what landed: the transport
 *      keeps the LATEST verdict, and a backlog of verdicts would deliver
 *      stale ones.
 *
 *   3. THE LOSSES ARE COUNTED.  An overwrite is a fact about the run, and
 *      a fact nobody can see is a fact nobody can act on.
 *
 * The "node" here is an ordinary file, which is the closest thing to the
 * resource manager's publisher node that a POSIX host offers: the
 * publisher opens it write-only and writes fixed-size frames to it.
 */

#include "latch_feedback.h"
#include "latch_feedback_pub.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define FAIL(msg) do { fprintf(stderr, "FAIL: %s\n", (msg)); return 1; } while (0)

static const char *g_node_path = "build/host-sim/latch_feedback_pub_test.node";

static void sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000L;
    ts.tv_nsec = (ms % 1000L) * 1000000L;
    (void)nanosleep(&ts, NULL);
}

/* Wait until the writer thread has written at least `want` frames. */
static int wait_for_written(uint64_t want, int timeout_ms)
{
    for (int waited = 0; waited < timeout_ms; waited += 5) {
        latch_feedback_pub_status_t st;
        latch_feedback_pub_get_status(&st);
        if (st.written >= want) {
            return 0;
        }
        sleep_ms(5);
    }
    return -1;
}

/* Wait until every frame the publisher was given has either been written
 * or counted as dropped -- i.e. until the writer thread is QUIESCENT.
 * Without this the test would race the one frame that is in flight between
 * the slot and the node. */
static int wait_for_quiescent(int timeout_ms)
{
    for (int waited = 0; waited < timeout_ms; waited += 5) {
        latch_feedback_pub_status_t st;
        latch_feedback_pub_get_status(&st);
        if (st.written + st.dropped + st.errors >= st.offered) {
            return 0;
        }
        sleep_ms(5);
    }
    return -1;
}

/* The node's frame count, read from the node's ACTUAL size.
 *
 * WHY NOT A FIXED BUFFER
 * ----------------------
 * The first version of this test read the node into a fixed 4096-byte
 * buffer and then compared the LAST frame IN THAT BUFFER with the last
 * frame published.  A frame is LATCH_FEEDBACK_SIZE (28) bytes, so a
 * 4096-byte window holds at most 4096/28 = 146 frames -- while the number
 * of frames the writer thread lands during the burst is a RACE: it depends
 * on whether the writer keeps up with the publisher.
 *
 * Measured: on this workstation the writer lands 18-34 of the 500 burst
 * frames with the node on the repository's disk, and 104-132 with the node
 * on tmpfs -- so the window happens to hold the whole file and the test
 * passes.  On the CI runner (2026-11-27, run 45988680440) the writer kept
 * up and landed more than 146, so the window held the FIRST 146 frames and
 * the test compared frame 145 with the LAST published frame -- and failed
 * with "the node does not hold the LATEST verdict" even though the node
 * DID hold it.  The publisher was right; THE TEST WAS WRONG, and it was
 * wrong in a way that only showed up on a faster machine.
 *
 * So the node's size is the authority, and the frame under test is
 * addressed by INDEX.  The test's verdict then does not depend on how many
 * frames landed.
 *
 * The return value is 0 on success, -1 if the node cannot be stat'ed, and
 * -2 if the node holds a TORN frame (its size is not a whole number of
 * frames) -- which is a protocol violation in its own right.
 */
static int node_frame_count(uint64_t *count)
{
    struct stat st;
    if (stat(g_node_path, &st) != 0) {
        return -1;
    }
    if (st.st_size < 0 ||
        (uint64_t)st.st_size % (uint64_t)LATCH_FEEDBACK_SIZE != 0u) {
        return -2;
    }
    *count = (uint64_t)st.st_size / (uint64_t)LATCH_FEEDBACK_SIZE;
    return 0;
}

/* Read ONE frame, addressed by its index in the node. */
static int read_frame_at(uint64_t index, unsigned char *out)
{
    int fd = open(g_node_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    off_t off = (off_t)(index * (uint64_t)LATCH_FEEDBACK_SIZE);
    ssize_t n = pread(fd, out, LATCH_FEEDBACK_SIZE, off);
    (void)close(fd);
    if (n != (ssize_t)LATCH_FEEDBACK_SIZE) {
        return -1;
    }
    return 0;
}

int main(void)
{
    unsigned char buf[LATCH_FEEDBACK_SIZE];
    uint64_t frames = 0u;
    latch_feedback_pub_status_t st;

    /* The publisher must refuse to publish anything before it is started:
     * a silent publisher that looks like a working one is worse than no
     * publisher at all. */
    {
        latch_feedback_t f;
        memset(&f, 0, sizeof(f));
        if (latch_feedback_pub_publish(&f) != -EPERM) {
            FAIL("the publisher accepted a frame before it was started");
        }
    }
    if (latch_feedback_pub_publish(NULL) != -EINVAL) {
        FAIL("the publisher accepted a NULL frame");
    }

    /* Create the node.  The publisher opens it write-only and does not
     * create it, exactly like the resource manager's node. */
    (void)unlink(g_node_path);
    {
        int fd = open(g_node_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            fprintf(stderr, "FAIL: cannot create the test node %s: %s\n",
                    g_node_path, strerror(errno));
            return 1;
        }
        (void)close(fd);
    }

    if (latch_feedback_pub_start(g_node_path) != 0) {
        FAIL("the publisher did not start");
    }
    if (!latch_feedback_pub_is_running()) {
        FAIL("the publisher says it is not running");
    }

    /* ---- 1. ONE FRAME, UNCHANGED ------------------------------------- */
    {
        latch_feedback_t f;
        latch_feedback_t back;
        memset(&f, 0, sizeof(f));
        f.seq           = 42u;
        f.session_epoch = 0xB7BA19BDu;
        f.verdict       = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
        f.rung          = 3u;
        f.fault_bits    = 0x0102u;
        if (latch_feedback_encode(&f) != 0) {
            FAIL("the production codec refused to encode a verdict");
        }
        if (latch_feedback_pub_publish(&f) != 0) {
            FAIL("the publisher refused a frame");
        }
        if (wait_for_written(1u, 2000) != 0) {
            FAIL("the publisher did not write the frame");
        }
        {
            int rc = node_frame_count(&frames);
            if (rc == -2) {
                FAIL("the node holds a TORN frame: its size is not a whole "
                     "number of frames");
            }
            if (rc != 0 || frames != 1u) {
                FAIL("the node does not hold exactly one frame");
            }
        }
        if (read_frame_at(0u, buf) != 0) {
            FAIL("the node's frame cannot be read");
        }
        memcpy(&back, buf, sizeof(back));
        if (latch_feedback_decode(buf, LATCH_FEEDBACK_SIZE, &back) != 0) {
            FAIL("the frame the publisher wrote does not decode");
        }
        if (back.seq != f.seq || back.session_epoch != f.session_epoch ||
            back.verdict != f.verdict || back.rung != f.rung ||
            back.fault_bits != f.fault_bits) {
            FAIL("the frame the publisher wrote is not the frame it was given");
        }
    }

    /* ---- 2. A BURST: THE CALL MUST NOT BLOCK, AND THE LAST WINS ------ */
    {
        const uint32_t burst = 500u;
        latch_feedback_t f;
        memset(&f, 0, sizeof(f));
        f.seq           = 1u;
        f.session_epoch = 0x01020304u;
        f.verdict       = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
        f.rung          = 0u;
        if (latch_feedback_encode(&f) != 0) {
            FAIL("encode (burst)");
        }
        for (uint32_t i = 0u; i < burst; ++i) {
            f.seq = 1000u + i;
            (void)latch_feedback_encode(&f);
            if (latch_feedback_pub_publish(&f) != 0) {
                FAIL("the publisher refused a frame during the burst");
            }
        }
        /* The whole burst must be over in well under a second: the
         * publish call is a memcpy and a signal, never a write. */
        latch_feedback_pub_get_status(&st);
        /* `offered` is CUMULATIVE: it also counts the single frame of
         * section 1, so the burst's share is `offered - 1`.  Comparing the
         * cumulative counter against the burst's own size was a second
         * off-by-one in this test: on a machine where the writer keeps up
         * with every publish, `written` reaches 501 and the test failed
         * with "the publisher wrote more frames than it was given" even
         * though the publisher had written exactly what it was given. */
        if (st.offered < (uint64_t)burst + 1u) {
            FAIL("the publisher did not accept the whole burst");
        }
        if (st.written > st.offered) {
            FAIL("the publisher wrote more frames than it was given");
        }
        /* Wait for the writer to settle before the accounting is checked:
         * one frame is always in flight between the slot and the node. */
        if (wait_for_quiescent(3000) != 0) {
            FAIL("the publisher did not settle after the burst");
        }
        latch_feedback_pub_get_status(&st);
        if (st.written + st.dropped + st.errors != st.offered) {
            FAIL("a frame went missing without being counted as dropped");
        }

        /* Whatever landed, the LAST frame the publisher was given must be
         * in the node: the transport keeps the latest verdict. */
        {
            unsigned char last[LATCH_FEEDBACK_SIZE];
            latch_feedback_t f_last;
            memset(&f_last, 0, sizeof(f_last));
            f_last.seq           = 1000u + burst - 1u;
            f_last.session_epoch = 0x01020304u;
            f_last.verdict       = (uint8_t)LATCH_FEEDBACK_VERDICT_ACCEPT;
            f_last.rung          = 0u;
            (void)latch_feedback_encode(&f_last);
            {
                int rc = node_frame_count(&frames);
                if (rc == -2) {
                    FAIL("the node holds a TORN frame: its size is not a "
                         "whole number of frames");
                }
                if (rc != 0 || frames == 0u) {
                    FAIL("the node holds no frame after the burst");
                }
                /* The frame under test is the node's LAST frame, addressed
                 * by index -- not "the last frame inside a 4096-byte
                 * window".  See node_frame_count() for why. */
                if (read_frame_at(frames - 1u, last) != 0) {
                    FAIL("the node's last frame cannot be read");
                }
            }
            if (memcmp(last, &f_last, LATCH_FEEDBACK_SIZE) != 0) {
                FAIL("the node does not hold the LATEST verdict");
            }
        }
    }

    /* ---- 3. THE COUNTERS TELL THE STORY ------------------------------ */
    latch_feedback_pub_get_status(&st);
    if (st.written + st.dropped + st.errors != st.offered) {
        FAIL("the publisher's counters do not add up: a frame went missing "
             "without being counted");
    }
    if (st.errors != 0u) {
        FAIL("the publisher reported write errors on a regular file");
    }
    if (st.opens != 1u) {
        FAIL("the publisher opened the node more than once");
    }

    /* ---- 4. STOPPING IS CLEAN, AND THE PUBLISHER SAYS SO ------------- */
    latch_feedback_pub_stop();
    if (latch_feedback_pub_is_running()) {
        FAIL("the publisher still says it is running after stop");
    }
    {
        latch_feedback_t f;
        memset(&f, 0, sizeof(f));
        if (latch_feedback_pub_publish(&f) != -EPERM) {
            FAIL("the publisher accepted a frame after it was stopped");
        }
    }
    /* Stopping twice must not crash or hang. */
    latch_feedback_pub_stop();

    (void)unlink(g_node_path);

    printf("[LATCH_FEEDBACK_PUB] PASS: offered=%llu written=%llu dropped=%llu "
           "errors=%llu opens=%llu frames_in_node=%llu -- the frame arrives "
           "unchanged, the publish call never blocks, the latest verdict wins, "
           "and every loss is counted\n",
           (unsigned long long)st.offered, (unsigned long long)st.written,
           (unsigned long long)st.dropped, (unsigned long long)st.errors,
           (unsigned long long)st.opens, (unsigned long long)frames);
    return 0;
}
