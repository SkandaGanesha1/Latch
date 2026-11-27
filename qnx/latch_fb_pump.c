/*
 * latch_fb_pump.c -- the host side of the LATCH feedback (LFBK) channel.
 *
 * WHAT THIS IS
 * ------------
 * The LATCH feedback channel carries the trusted supervisor's VERDICT on a
 * guest's proposal, back to the guest.  The guest is untrusted, so the
 * channel is advisory for the guest's own planning loop only; the safety
 * envelope is enforced exclusively by the QNX supervisor.  A missing or
 * stale verdict therefore cannot make the plant unsafe -- it can only make
 * the guest stop proposing, which the supervisor's dead-man lease turns into
 * a fail-closed LATCH.  That is the property this channel is designed
 * around: LOSS IS SAFE, SILENCE IS FATAL.
 *
 * This program is the PUBLISHER: it writes feedback frames into the
 * mailbox that `latch_fb_sink` owns.
 *
 * THE TRANSPORT, AND WHY IT IS A MAILBOX
 * --------------------------------------
 * The guest is a Linux VM inside the QNX Hypervisor.  Its only routes to the
 * host are the hypervisor's virtual devices, and each `vdev` has exactly
 * ONE `hostdev` endpoint in ONE direction:
 *
 *     hostdev ><path>   the hypervisor WRITES to <path>  (guest -> host)
 *     hostdev <<path>   the hypervisor READS from <path>  (host -> guest)
 *
 * The existing black channel is `hostdev >"|cmd"` -- a pipe into
 * `latch-ingest`.  A second `vdev virtio-console` was tried for the
 * feedback and is REJECTED BY MEASUREMENT: it corrupted the frame channel
 * (26 of 84 frames delivered, the wire-fault count tripled --
 * docs/evidence/resolution/05-rejected-2nd-virtio-console.txt).  A second
 * PL011 is a DIFFERENT driver on a DIFFERENT interrupt, so it cannot
 * perturb the virtio-console frame path.
 *
 * The host endpoint has to be something the hypervisor can BLOCK on.  The
 * hypervisor's character-device layer reads it with QNX's `readcond()`,
 * which blocks until data arrives; that is why a message-passing endpoint
 * is required and a plain file is not (a regular file is at EOF, and the
 * read returns immediately with nothing).
 *
 * A QNX pseudo-terminal was tried first and is REJECTED BY MEASUREMENT (see
 * THE PTY FLOW PROBE below and AGENTS.md section 4c).  The endpoint is now a
 * purpose-built QNX resource manager, `latch_fb_sink`, with TWO nodes:
 *
 *     /dev/latch/feedback       READ side.  The hypervisor's PL011 vdev
 *                                opens this and reads the frames.
 *     /dev/latch/feedback_pub   WRITE side.  This program opens this and
 *                                writes the frames.
 *
 * Two nodes, so that the security statement has one sentence:
 *
 *     THE HYPERVISOR CAN READ THE FEEDBACK CHANNEL AND CANNOT WRITE IT.
 *     THE SUPERVISOR CAN WRITE THE FEEDBACK CHANNEL AND CANNOT READ IT.
 *
 * The guest side is a SECOND PL011.  ITS DEVICE NAME IS NOT UNDER THE
 * GUEST'S CONTROL: the Linux PL011 driver takes each port's index from the
 * guest device tree's `serial` alias when there is one and from the
 * driver's PROBE ORDER when there is not, and neither is in the guest's
 * hands.  Measured on the QEMU AArch64 target (2026-11-26), with the
 * console PL011 declared FIRST in the qvmconf, the driver published
 *
 *     1c0b0000.uart: ttyAMA0 at MMIO 0x1c0b0000   (the FEEDBACK port)
 *     1c090000.uart: ttyAMA1 at MMIO 0x1c090000   (the CONSOLE port)
 *
 * -- the REVERSE of the declaration order.  So the guest-side probe tries
 * EVERY candidate port and lets the DATA decide which one carries the
 * channel.
 *
 * BACKPRESSURE
 * ------------
 * The publisher's node is opened O_NONBLOCK.  A full mailbox makes
 * `write()` fail with EAGAIN; this program then DROPS the frame and counts
 * it.  It never blocks, because the publisher must not be able to stall the
 * safety core.  A dropped verdict is caught by the guest's feedback
 * TIMEOUT, which stops the guest's planning loop -> the supervisor's
 * dead-man expires -> LATCH.  Dropping is therefore the fail-closed choice.
 *
 * MODES
 * -----
 *   latch_fb_pump -d <device> [-n <count>] [-i <interval_ms>]
 *       Writes feedback frames to <device>.  A count of 0 (the default)
 *       writes them CONTINUOUSLY, so the measurement does not depend on
 *       when the guest opens its port.
 *   latch_fb_pump --pty-flow-probe <writer_dev> <reader_dev>
 *       The MEASUREMENT that rejected the pseudo-terminal.  It is kept so
 *       that the negative result stays reproducible; it is never run by
 *       the fbprobe image.
 *
 * THE FRAME
 * ---------
 * The frames are the PRODUCTION LFBK frames of qnx/latch_feedback.h: the
 * same 28-byte layout, the same magic, the same version, the same CRC
 * rule.  The transport test therefore exercises the real wire format, and
 * there is exactly ONE feedback frame format in the tree.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* The PRODUCTION LFBK wire format (qnx/latch_feedback.h).  It is repeated
 * here rather than included because this binary is built in the QNX tree
 * and the header is a plain freestanding-safe header, but the constant
 * values are checked against it by tools/consistency_check.py. */
#define LFBK_MAGIC   0x4B42464Cu /* little-endian "LFBK" */
#define LFBK_VERSION 2u
#define LFBK_SIZE    28u
#define LFBK_FLAG_TIMEOUT 0x0001u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t seq;
    uint32_t session_epoch;
    uint8_t  verdict;
    uint8_t  rung;
    uint16_t fault_bits;
    uint16_t fault_bits2;
    uint16_t flags;
    uint32_t crc32;
} lfbk_frame_t;

_Static_assert(sizeof(lfbk_frame_t) == LFBK_SIZE,
               "lfbk_frame_t must be a fixed 28-byte frame");
_Static_assert(offsetof(lfbk_frame_t, crc32) == 24u,
               "the LFBK CRC must cover the first 24 bytes");

static uint32_t crc32_ieee(const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= p[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return ~crc;
}

static void sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* Read from `fd` for up to `timeout_ms`, returning the byte count. */
static long drain_read(int fd, unsigned char *buf, size_t cap, int timeout_ms)
{
    long total = 0;
    for (int waited = 0; waited < timeout_ms; waited += 10) {
        ssize_t n = read(fd, buf + total, cap - (size_t)total);
        if (n > 0) {
            total += (long)n;
            if ((size_t)total >= cap) {
                break;
            }
            continue;
        }
        if (n == 0) {
            break;      /* EOF */
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            break;
        }
        sleep_ms(10);
    }
    return total;
}

/*
 * THE PTY FLOW PROBE -- the measurement that rejected the pseudo-terminal.
 *
 * Everything about that transport had to be MEASURED, because the
 * documentation and the platform disagree.  Two measurements on the QNX
 * AArch64 target (2026-11-26) settled the shape of the problem:
 *
 *  1. The documented direction does not deliver.  QNX's System
 *     Architecture chapter `char_PTY.html` says "anything written on the
 *     master device is given to the worker device as input", and
 *     `devc-pty` names the master the CONTROLLER (/dev/ptyp0).  Writing
 *     "CTRLMARK01" to /dev/ptyp0 and reading /dev/ttyp0 yielded 0 bytes,
 *     while writing "PEERMARK02" to /dev/ttyp0 and reading /dev/ptyp0
 *     yielded the marker.  So the direction that delivered was
 *     WORKER -> CONTROLLER.
 *
 *  2. io-char's EXCLUSIVITY decides whether the pair can be used at
 *     all.  A client that holds the pair blocks a later O_RDONLY open of
 *     the CONTROLLER with EBUSY ("Resource busy"), while the WORKER
 *     accepts an O_RDONLY open.  The hypervisor's own message was
 *     `qvmconf:164] Unable to open '/dev/ptyp0': Resource busy`.
 *
 * Neither measurement settles the question that matters -- does the data
 * cross between two PROCESSES, one holding each end, in the exact
 * topology the deployment uses?  A single-process test cannot: the same
 * process holds both ends, and the pty's behaviour differs when the two
 * ends have different owners.
 *
 * So the probe FORKS: the parent holds the writing end and the child
 * holds the reading end, which is the deployment's shape exactly.  It
 * runs both directions and reports what crossed.
 */
static void pty_flow_probe(const char *writer_dev, const char *reader_dev,
                           const char *tag)
{
    static const unsigned char marker[] = "FLOWMARK01";
    const size_t marker_len = sizeof(marker) - 1u;

    int wfd = open(writer_dev, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (wfd < 0) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: open(%s) for writing "
                "failed: %s\n", tag, writer_dev, strerror(errno));
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: fork failed: %s\n",
                tag, strerror(errno));
        close(wfd);
        return;
    }
    if (pid == 0) {
        /* The child is the READER.  It must not inherit the writer's
         * descriptor: in the deployment the two ends have different
         * owners, and an inherited descriptor would change the pty's
         * behaviour.
         *
         * The reader is NON-BLOCKING with an explicit deadline.  A
         * blocking read() here would hang the probe forever when the data
         * does not cross -- and a hung probe reports nothing, which is
         * indistinguishable from a probe that was never run. */
        close(wfd);
        int rfd = open(reader_dev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
        if (rfd < 0) {
            fprintf(stderr, "[latch_fb_pump] pty-flow %s: child open(%s) for "
                    "reading failed: %s\n", tag, reader_dev, strerror(errno));
            _exit(3);
        }
        unsigned char buf[64];
        long n = drain_read(rfd, buf, sizeof(buf), 2000);
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: reader(%s) got %ld "
                "byte(s):", tag, reader_dev, n);
        for (long i = 0; i < n && i < 24; ++i) {
            fprintf(stderr, " %02x", buf[i]);
        }
        fprintf(stderr, "\n");
        close(rfd);
        _exit(0);
    }

    /* The parent is the WRITER.  Give the child time to open its end. */
    sleep_ms(300);
    errno = 0;
    ssize_t w = write(wfd, marker, marker_len);
    fprintf(stderr, "[latch_fb_pump] pty-flow %s: writer(%s) wrote %ld byte(s)"
            "%s%s\n", tag, writer_dev, (long)w,
            (w < 0) ? " errno=" : "",
            (w < 0) ? strerror(errno) : "");

    int status = 0;
    (void)waitpid(pid, &status, 0);
    close(wfd);
}

/*
 * The READER-FIRST flow probe.
 *
 * This is the DEPLOYMENT'S ACTUAL ORDER, and it is the opposite of the
 * probe above.  The hypervisor opens the host endpoint at qvm start --
 * `open(path, O_RDONLY|O_NOCTTY|O_NONBLOCK)` -- and only afterwards does
 * the publisher want to open its end.  So the question is whether the
 * pair tolerates a reader that was there FIRST, and a writer that comes
 * SECOND.
 *
 * The reader is opened in the child, and the child signals readiness
 * through a pipe before the parent opens the writer.  That ordering is
 * the whole point of the test: without the handshake the parent could
 * open its end first and the measurement would be the other experiment.
 */
static void pty_flow_probe_reader_first(const char *writer_dev,
                                        const char *reader_dev,
                                        const char *tag)
{
    static const unsigned char marker[] = "FLOWMARK01";
    const size_t marker_len = sizeof(marker) - 1u;

    int ready[2];
    if (pipe(ready) < 0) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: pipe failed: %s\n",
                tag, strerror(errno));
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: fork failed: %s\n",
                tag, strerror(errno));
        close(ready[0]);
        close(ready[1]);
        return;
    }
    if (pid == 0) {
        /* The child is the READER and it goes FIRST. */
        close(ready[0]);
        int rfd = open(reader_dev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
        if (rfd < 0) {
            fprintf(stderr, "[latch_fb_pump] pty-flow %s: child open(%s) for "
                    "reading failed: %s\n", tag, reader_dev, strerror(errno));
            close(ready[1]);
            _exit(3);
        }
        /* Tell the parent the reader is open. */
        (void)write(ready[1], "R", 1);
        close(ready[1]);

        unsigned char buf[64];
        long n = drain_read(rfd, buf, sizeof(buf), 3000);
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: reader(%s) got %ld "
                "byte(s):", tag, reader_dev, n);
        for (long i = 0; i < n && i < 24; ++i) {
            fprintf(stderr, " %02x", buf[i]);
        }
        fprintf(stderr, "\n");
        close(rfd);
        _exit(0);
    }

    /* The parent is the WRITER and it goes SECOND. */
    close(ready[1]);
    char c = 0;
    ssize_t rn = read(ready[0], &c, 1);   /* the child always writes or exits */
    close(ready[0]);
    if (rn != 1) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: the reader never became "
                "ready\n", tag);
        (void)waitpid(pid, NULL, 0);
        return;
    }

    int wfd = open(writer_dev, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (wfd < 0) {
        fprintf(stderr, "[latch_fb_pump] pty-flow %s: writer open(%s) failed: "
                "%s\n", tag, writer_dev, strerror(errno));
        (void)waitpid(pid, NULL, 0);
        return;
    }
    sleep_ms(300);
    errno = 0;
    ssize_t w = write(wfd, marker, marker_len);
    fprintf(stderr, "[latch_fb_pump] pty-flow %s: writer(%s) wrote %ld byte(s)"
            "%s%s\n", tag, writer_dev, (long)w,
            (w < 0) ? " errno=" : "",
            (w < 0) ? strerror(errno) : "");
    (void)waitpid(pid, NULL, 0);
    close(wfd);
}

static int pty_selftest(const char *publisher, const char *consumer)
{
    /* The deployment's two shapes, one per direction. */
    pty_flow_probe(publisher, consumer, "publisher->consumer");
    pty_flow_probe(consumer, publisher, "consumer->publisher");
    /* And the deployment's ACTUAL open order: the reader (the hypervisor)
     * first, the writer (the publisher) second. */
    pty_flow_probe_reader_first(publisher, consumer, "reader-first publisher->consumer");
    pty_flow_probe_reader_first(consumer, publisher, "reader-first consumer->publisher");
    return 0;
}

/*
 * THE READCOND SELF-TEST.
 *
 * This is the MEASUREMENT that separates two hypotheses that look identical
 * from the outside:
 *
 *   H1: the resource manager's readcond() contract is wrong, so the
 *       hypervisor's readcond() never gets a byte;
 *   H2: the contract is right and the hypervisor's trigger path is the
 *       thing that is not firing.
 *
 * The self-test answers H1 DIRECTLY, with the same client library the
 * hypervisor uses: it publishes one frame on the WRITE node, opens the
 * READ node, and readcond()s it.  A frame that comes back with the right
 * magic and the right CRC proves the resource manager's side of the
 * contract -- the reply is the DATA ONLY at offset 0 and the byte count
 * travels in the message status -- end to end.
 *
 * It runs BEFORE the hypervisor is involved, so its result cannot be
 * confused with the hypervisor's behaviour.
 */
static int read_selftest(const char *read_dev, const char *pub_dev)
{
    lfbk_frame_t f;
    unsigned char buf[64];
    int wfd;
    int rfd;
    ssize_t w;
    int n;

    memset(&f, 0, sizeof(f));
    f.magic = LFBK_MAGIC;
    f.version = LFBK_VERSION;
    f.size = LFBK_SIZE;
    f.seq = 1u;
    f.session_epoch = 0xA5A5A5A5u;
    f.verdict = 0x5Au;
    f.rung = 0x7Bu;
    f.fault_bits = 0x1234u;
    f.fault_bits2 = 0x5678u;
    f.flags = 0u;
    f.crc32 = crc32_ieee(&f, offsetof(lfbk_frame_t, crc32));

    wfd = open(pub_dev, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (wfd < 0) {
        fprintf(stderr, "[latch_fb_pump] read-selftest: cannot open the WRITE "
                "node %s: %s\n", pub_dev, strerror(errno));
        return 1;
    }
    w = write(wfd, &f, sizeof(f));
    if (w != (ssize_t)sizeof(f)) {
        fprintf(stderr, "[latch_fb_pump] read-selftest: write to %s returned "
                "%ld: %s\n", pub_dev, (long)w, strerror(errno));
        close(wfd);
        return 1;
    }
    close(wfd);

    rfd = open(read_dev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
    if (rfd < 0) {
        fprintf(stderr, "[latch_fb_pump] read-selftest: cannot open the READ "
                "node %s: %s\n", read_dev, strerror(errno));
        return 1;
    }
    errno = 0;
    n = readcond(rfd, buf, (int)sizeof(buf), 0, 0, 0);
    if (n < 0) {
        fprintf(stderr, "[latch_fb_pump] read-selftest: readcond(%s) failed: "
                "%s\n", read_dev, strerror(errno));
        close(rfd);
        return 1;
    }
    printf("[latch_fb_pump] read-selftest: readcond(%s) returned %d byte(s)\n",
           read_dev, n);
    if (n != (int)sizeof(f)) {
        fprintf(stderr, "[latch_fb_pump] read-selftest: expected %d byte(s)\n",
                (int)sizeof(f));
        close(rfd);
        return 1;
    }
    {
        lfbk_frame_t got;
        memcpy(&got, buf, sizeof(got));
        if (got.magic != LFBK_MAGIC || got.version != LFBK_VERSION ||
            got.size != LFBK_SIZE ||
            got.crc32 != crc32_ieee(buf, offsetof(lfbk_frame_t, crc32))) {
            fprintf(stderr, "[latch_fb_pump] read-selftest: the frame that came "
                    "back is NOT a valid LFBK frame (magic=0x%08x version=%u "
                    "size=%u crc=0x%08x)\n", got.magic, got.version, got.size,
                    got.crc32);
            close(rfd);
            return 1;
        }
    }
    printf("[latch_fb_pump] read-selftest: PASS -- the resource manager's "
           "readcond() contract works end to end (the reply is the DATA ONLY "
           "at offset 0 and the CRC is intact)\n");
    fflush(stdout);
    close(rfd);
    return 0;
}

/*
 * The publisher.
 *
 * The frames are the PRODUCTION LFBK frames, so the transport test
 * exercises the real wire format.  The payload is a self-describing
 * pattern so that a guest (or a human reading the transcript) can tell a
 * transport probe from a real supervisor verdict:
 *
 *     verdict  = 'Z'  (0x5A)   "this came from the probe"
 *     rung     = 'u'  (0x7B)
 *     epoch    = 0xA5A5A5A5    a fixed, obviously-fake session epoch
 *     fault_bits = the low 16 bits of the sequence number
 */
static int publish_loop(const char *device, long count, long interval_ms)
{
    /* O_WRONLY: the mailbox's publisher node is WRITE-ONLY, and the
     * resource manager refuses a read access on it.  That is the point of
     * the two-node design: the publisher cannot read the channel back.
     *
     * O_NONBLOCK: the publisher must NEVER be able to stall the safety
     * core.  A full mailbox is a dropped frame, not a blocked writer. */
    int fd = open(device, O_WRONLY | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        fprintf(stderr, "latch_fb_pump: cannot open %s: %s\n",
                device, strerror(errno));
        return 1;
    }

    uint32_t seq = 0u;
    uint64_t sent = 0u;
    uint64_t refused = 0u;
    uint64_t errors = 0u;

    for (;;) {
        if (count > 0 && (long)sent >= count) {
            break;
        }
        lfbk_frame_t f;
        memset(&f, 0, sizeof(f));
        f.magic = LFBK_MAGIC;
        f.version = LFBK_VERSION;
        f.size = LFBK_SIZE;
        f.seq = ++seq;
        f.session_epoch = 0xA5A5A5A5u;
        f.verdict = 0x5Au;   /* 'Z' -- "this came from the probe" */
        f.rung = 0x7Bu;      /* 'u' */
        f.fault_bits = (uint16_t)(seq & 0xFFFFu);
        f.fault_bits2 = 0x1234u;
        f.flags = 0u;
        f.crc32 = crc32_ieee(&f, offsetof(lfbk_frame_t, crc32));

        ssize_t w = write(fd, &f, sizeof(f));
        if (w == (ssize_t)sizeof(f)) {
            sent++;
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            /* The mailbox is full: the frame is DROPPED and counted. */
            refused++;
        } else {
            errors++;
            fprintf(stderr, "latch_fb_pump: write failed: %s\n",
                    strerror(errno));
        }

        if ((sent + refused + errors) % 64u == 0u) {
            fprintf(stderr, "[latch_fb_pump] sent=%llu refused=%llu errors=%llu "
                    "seq=%u\n",
                    (unsigned long long)sent, (unsigned long long)refused,
                    (unsigned long long)errors, (unsigned)seq);
        }
        sleep_ms(interval_ms);
    }
    fprintf(stderr, "[latch_fb_pump] done: sent=%llu refused=%llu errors=%llu\n",
            (unsigned long long)sent, (unsigned long long)refused,
            (unsigned long long)errors);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    const char *device = NULL;
    long count = 0;            /* 0 = unlimited (the default) */
    long interval_ms = 250;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            device = argv[++i];
        } else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            count = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            interval_ms = strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--pty-flow-probe") == 0 && i + 2 < argc) {
            /* The measurement that rejected the pseudo-terminal.  Kept so
             * the negative result stays reproducible. */
            return pty_selftest(argv[i + 1], argv[i + 2]);
        } else if (strcmp(argv[i], "--read-selftest") == 0 && i + 2 < argc) {
            /* The measurement that proves the resource manager's readcond()
             * contract, independently of the hypervisor. */
            return read_selftest(argv[i + 1], argv[i + 2]);
        } else {
            fprintf(stderr, "latch_fb_pump: unknown argument '%s'\n", argv[i]);
            return 2;
        }
    }
    if (device == NULL) {
        fprintf(stderr, "usage: latch_fb_pump -d <device> [-n <count>] "
                        "[-i <interval_ms>]\n"
                        "       latch_fb_pump --pty-flow-probe <writer> <reader>\n"
                        "       latch_fb_pump --read-selftest <read_node> <write_node>\n");
        return 2;
    }

    return publish_loop(device, count, interval_ms);
}
