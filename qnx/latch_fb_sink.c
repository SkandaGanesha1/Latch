/*
 * latch_fb_sink.c -- the HOST END of the LATCH feedback (LFBK) channel.
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
 * This program is the HOST ENDPOINT of that channel: a small QNX resource
 * manager that owns a fixed-frame MAILBOX.
 *
 *     /dev/latch/feedback       READ side.  The QNX Hypervisor opens this
 *                                path for its feedback PL011 vdev and reads
 *                                the frames with readcond().
 *     /dev/latch/feedback_pub   WRITE side.  The trusted supervisor (latchd)
 *                                writes one frame per proposal.
 *
 * TWO NODES, NOT ONE
 * ------------------
 * The read side and the write side are SEPARATE device nodes, and that is
 * deliberate.  A single node would have to be opened for reading by the
 * hypervisor and for writing by the publisher at the same time, and whether
 * that is permitted depends on the resource manager's open semantics.  Two
 * nodes make the question disappear -- there is no shared open state at all
 * -- and they give the security boundary a shape that can be stated in one
 * sentence:
 *
 *     THE HYPERVISOR CAN READ THE FEEDBACK CHANNEL AND CANNOT WRITE IT.
 *     THE SUPERVISOR CAN WRITE THE FEEDBACK CHANNEL AND CANNOT READ IT.
 *
 * Only the trusted supervisor holds the `latch_fb_sink_t` connect ability,
 * so no untrusted process can inject a fake verdict into the channel.
 *
 * WHY A RESOURCE MANAGER AND NOT A PSEUDO-TERMINAL
 * -------------------------------------------------
 * A QNX `devc-pty` pair was tried first, and it was MEASURED on the QEMU
 * AArch64 target (2026-11-26).  The pty carries bytes between two
 * processes, but its open semantics make it unusable here:
 *
 *   1. The documented direction does not deliver.  QNX's System
 *      Architecture chapter `char_PTY.html` says "anything written on the
 *      master device is given to the worker device as input", and
 *      `devc-pty` names the master the CONTROLLER (/dev/ptyp0).  Writing
 *      "CTRLMARK01" to /dev/ptyp0 and reading /dev/ttyp0 yielded 0 bytes;
 *      writing "PEERMARK02" to /dev/ttyp0 and reading /dev/ptyp0 yielded
 *      the marker.  So the direction that delivers is WORKER -> CONTROLLER.
 *
 *   2. The open ORDER decides whether the pair can be used at all.  With
 *      the reader opening FIRST, 10 bytes crossed between two processes
 *      ("FLOWMARK01", measured).  With the writer opening FIRST, the
 *      reader's open was refused with EBUSY ("Resource busy").  Since the
 *      hypervisor opens its host endpoint at qvm start -- and a hostdev
 *      that cannot be opened is FATAL to the VM start -- the publisher
 *      would have to guess when the hypervisor had opened its end.  A
 *      publisher that opens first kills the guest; a publisher that opens
 *      second needs a race-free way to know the hypervisor is ready.  The
 *      pty offers neither.
 *
 *   3. A pty is a BYTE PIPE that any process with the right ability may
 *      write.  That is the wrong security property for a channel whose
 *      entire value is "this verdict came from the trusted supervisor".
 *
 * A resource manager gives all three properties that the channel needs:
 * a deterministic open, a byte-exact framing contract, and a writer set
 * that the security policy pins to one type.
 *
 * THE HYPERVISOR'S CONTRACT
 * -------------------------
 * The PL011 vdev (`vdev-pl011.so`) is the client.  Disassembling the
 * installed `qvm` (target/qnx/aarch64le/sbin/qvm.sym) shows exactly what
 * it does with the host endpoint:
 *
 *     fd = open(hostdev, O_RDONLY | O_NOCTTY | O_NONBLOCK);
 *     ...
 *     n = readcond(fd, buf, len, 0, 0, 0);
 *     if (n <= 0 || (n == -1 && errno == EAGAIN))
 *         activate_notify(...);            // ionotify()
 *
 * and that a zero-byte read is NOT an end-of-file: the vdev arms the
 * notification and retries when the pulse arrives.  So the endpoint must:
 *
 *   - open read-only, non-blocking, without a controlling terminal;
 *   - answer readcond() with whatever is available and return 0 when
 *     nothing is (readcond with min=0, time=0, timeout=0 means "return
 *     immediately with as many bytes as are available");
 *   - support ionotify(), so the vdev learns that data has arrived.
 *
 * The POSIX layer's readcond() sends an `_IO_XTYPE_READCOND` message, and
 * ionotify() sends `_IO_NOTIFY`; both are handled here.  The handlers are
 * the ones QNX documents in "Writing a Resource Manager" (the
 * `_IO_NOTIFY` sample), because they are the canonical way to give a
 * resource manager an input notification.
 *
 * THE REPLY LAYOUT
 * ----------------
 * The reply to a read is the DATA ONLY, at offset 0, and the byte count
 * travels in the message status via `_IO_SET_READ_NBYTES()`.  That is not
 * a guess: QNX's own `_IO_NOTIFY` sample does exactly
 *
 *     _IO_SET_READ_NBYTES (ctp, nbytes);
 *     resmgr_msgwrite (ctp, item->data, nbytes, 0);
 *
 * and the QNX C Library's `readcond()` sends the reply straight into the
 * caller's buffer and returns its length.  The 28-byte request the client
 * sends is `_io_read` (16 bytes, xtype = _IO_XTYPE_READCOND, combine_len
 * = 28) followed by `struct _xtype_readcond` (min, time, timeout).
 *
 * FAIL CLOSED
 * -----------
 * The mailbox is BOUNDED.  When it is full, the write is REFUSED with
 * EAGAIN rather than blocking: the supervisor must never be stalled by
 * the advisory channel.  A refused frame is a lost verdict, which the
 * guest's feedback timeout turns into "stop proposing", which the
 * supervisor's dead-man turns into a LATCH.  Silence is fatal; loss is
 * safe.
 */

#include <sys/iofunc.h>      /* FIRST: RESMGR_OCB_T must be the iofunc OCB */
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* THE FIRST-READER DECISION.  It is in a header of its own so a HOST
 * test can prove it: this resource manager needs resmgr, the iofunc
 * library and a QNX sysroot, so it cannot be built on the build host,
 * and a decision that cannot be built there is a decision with no test. */
#include "latch_fb_reader.h"

/* THE RESOURCE MANAGER'S ATTRIBUTE LOCK.  Every iofunc entry point this
 * resource manager calls goes through the wrappers in this header, so
 * the iofunc call is made while the device's SHARED attribute (the
 * file-use count, the reader and writer counts) is locked.  This channel
 * runs TWO dispatch threads with `DISPATCH_FLAG_NOLOCK`, so two opens of
 * the same node really can be in flight at the same time -- and the
 * iofunc library updates those counters with a NON-ATOMIC 16-bit
 * read-modify-write. */
#include "latch_rm_attr.h"

/* THE RESOURCE MANAGER'S NOTIFICATION-LIST LOCK.  The iofunc library's
 * notification lists are SHARED mutable state: `iofunc_notify()` links a
 * new event into the list, `iofunc_notify_trigger()` walks it and
 * unlinks the events it fires, and `iofunc_notify_remove()` walks it
 * and FREES the events -- and NONE of them takes a mutex (measured on
 * the installed SDP 8.0 library).  This channel runs TWO dispatch
 * threads with `DISPATCH_FLAG_NOLOCK`, and the WRITE handler that
 * triggers a notification and the READ/close handlers that arm and
 * remove one run on DIFFERENT threads, so the trigger and the remove
 * really can walk the same list at the same time -- which is a
 * use-after-free, not a lost count. */
#include "latch_rm_notify.h"

/* The fixed frame size of the LFBK wire format (qnx/latch_feedback.h).
 * The mailbox is FRAME-ORIENTED: a write is either exactly one frame or
 * it is refused with EINVAL.  A transport that could deliver half a frame
 * would push the framing problem onto the guest, and the guest is the
 * untrusted side. */
#define FB_FRAME_SIZE 28u

/* The mailbox depth, in bytes.  It is 146 WHOLE frames (146 * 28 = 4088):
 * enough to ride out a scheduling hiccup, small enough that a stale backlog
 * is detected (and dropped) rather than replayed into a later session.
 *
 * IT IS A WHOLE NUMBER OF FRAMES, AND THAT IS A SAFETY PROPERTY, NOT A
 * ROUNDING CONVENIENCE.
 *
 * MEASURED on the QEMU AArch64 target (2026-11-26): with a 4096-byte ring
 * (4096 = 146 * 28 + 8) the tail reached 4088 on the 147th frame and the
 * frame copy -- which wrote the frame in one memcpy, with no wrap -- ran
 * 20 bytes PAST the end of the ring.  Those 20 bytes landed exactly on
 * `head` (4), `tail` (4), `count` (4), the alignment padding (4) and the
 * low half of `published` (4), so the mailbox's own bookkeeping was
 * overwritten by the frame's bytes: `count` became a frame field, every
 * later write was refused, and the transport stopped updating.  The status
 * line showed `published=3323619266` and `queued=9599862` -- and both
 * numbers were, byte for byte, the frame's CRC and one of its fields.
 *
 * With the depth a whole number of frames, the tail can only ever point at
 * a frame boundary and `tail + FB_FRAME_SIZE <= FB_RING_BYTES` holds for
 * every possible tail, so the copy is in bounds BY CONSTRUCTION.  The
 * assertion below makes that a compile-time property: change the frame
 * size and the build stops. */
#define FB_RING_BYTES (146u * FB_FRAME_SIZE)
_Static_assert((FB_RING_BYTES % FB_FRAME_SIZE) == 0u,
               "the mailbox must hold a whole number of frames, or the frame "
               "copy can run past the end of the ring");

/* The most bytes one read returns.  Four frames: enough to amortise the
 * message round trip, small enough that the reader's buffer stays on the
 * stack. */
#define FB_READ_MAX (FB_FRAME_SIZE * 4u)

#define FB_READ_PATH_DEFAULT "/dev/latch/feedback"
#define FB_PUB_PATH_DEFAULT  "/dev/latch/feedback_pub"
#define FB_OUT_PATH_DEFAULT  "/dev/latch/feedback_out"

/*
 * THE VERDICT FILE -- the host endpoint of the WORKING transport.
 *
 * MEASURED on the QEMU AArch64 target (2026-11-26): the PL011 vdev's
 * host->guest injection does NOT deliver (the bytes reach the hypervisor's
 * own buffer and stop there), and the virtio-console vdev's host->guest
 * input direction does NOT deliver either (its `receive_host_data` is
 * reachable only through a flag that an unreachable error-recovery path
 * sets).  The ONLY surviving host->guest data path on this platform is
 * `vdev virtio-blk`, which serves a HOST FILE to the guest.
 *
 * So the verdict channel is a FILE: this resource manager writes every
 * accepted frame into the first sector of a small backing file, and the
 * hypervisor serves that file to the guest READ-ONLY (`hostdev <`).  The
 * guest polls the sector; the frame's sequence number and session epoch
 * tell it whether the verdict it is looking at is the one it asked for.
 *
 * The file is written by EXACTLY ONE process -- this resource manager --
 * and this resource manager accepts a frame only on its WRITE node, which
 * the security policy pins to one type.  The hypervisor opens the file
 * read-only, so the guest can never put a byte into the channel.
 *
 * The file I/O happens on a DEDICATED THREAD.  The writer's critical path
 * (the trusted supervisor's, in the deployment) must never wait for a
 * filesystem write: the feedback channel is advisory, and an advisory
 * channel that can stall the safety core is a defect.
 */
#define FB_BLOCK_PATH_DEFAULT "/dev/shmem/latch_feedback.img"

/* The size of the backing file.  One mebibyte: 2048 sectors, so the guest
 * sees an ordinary small disk, and the file is big enough that the guest's
 * read of sector 0 can never run off the end. */
#define FB_BLOCK_BYTES (1024u * 1024u)

/* The frame's offset inside the backing file.  Sector 0. */
#define FB_BLOCK_FRAME_OFFSET ((off_t)0)

/*
 * The combined readcond() REQUEST.  The QNX "Writing a Resource Manager"
 * chapter ("Handling readcond()") defines this structure in its sample,
 * but the SDP headers do not, so it is declared here exactly as the
 * documentation shows it: the _io_read header followed by the
 * _xtype_readcond arguments (min, time, timeout).
 */
typedef struct {
    struct _io_read        read;
    struct _xtype_readcond cond;
} fb_readcond_t;

/*
 * The device-specific attribute structure.  It must start with the
 * iofunc_attr_t, because that is what the resource-manager library puts
 * in the OCB.
 */
typedef enum {
    FB_NODE_READ = 0,   /* the guest-facing READ node: the hypervisor reads it */
    FB_NODE_PUB  = 1,   /* the publisher's WRITE node: the supervisor writes it */
    FB_NODE_OUT  = 2    /* the guest's UART OUTPUT direction: bytes are DISCARDED */
} fb_node_kind_t;

typedef struct fb_node_s {
    iofunc_attr_t    attr;
    latch_rm_notify_t notify;   /* the notification lists AND their lock */
    fb_node_kind_t   kind;
} fb_node_t;

static struct {
    fb_node_t        read_node;
    fb_node_t        pub_node;
    fb_node_t        out_node;
    unsigned char    ring[FB_RING_BYTES];
    unsigned         head;       /* the next byte to hand to the reader */
    unsigned         tail;       /* the next free byte */
    unsigned         count;      /* bytes queued */
    uint64_t         published;  /* frames published to the TRANSPORT (the file) */
    uint64_t         dropped;    /* frames the MAILBOX mirror could not take */
    uint64_t         delivered;  /* frames handed to the reader */
    uint64_t         read_opens; /* opens of the READ node */
    latch_fb_reader_t reader;    /* opens of the READ node that were GRANTED read access */
    uint64_t         pub_opens;  /* opens of the WRITE node */
    uint64_t         read_calls; /* readcond()/read() calls served */
    uint64_t         write_calls;/* write() calls served */
    uint64_t         read_refused;/* opens of the READ node that were refused */
    uint64_t         pub_refused; /* opens of the WRITE node that were refused */
    uint64_t         out_opens;  /* opens of the DISCARD node */
    uint64_t         out_bytes;  /* bytes the guest wrote towards the host */
    uint64_t         dropped_on_open; /* frames discarded when a reader arrived */
    uint64_t         notify_calls;/* _IO_NOTIFY messages served */
    uint64_t         triggers;    /* iofunc_notify_trigger() deliveries attempted */
    unsigned         last_read_ioflag; /* the io_open flags of the last READ open */
    unsigned         last_pub_ioflag;  /* ... of the last WRITE open */
    int              last_notify_rc;   /* the return value of the last iofunc_notify() */
    int              last_notify_action;
    /* The verdict file (see FB_BLOCK_PATH_DEFAULT). */
    int              block_fd;         /* the backing file, opened O_RDWR */
    unsigned char    block_frame[FB_FRAME_SIZE]; /* the frame waiting to be written */
    int              block_pending;    /* a frame is waiting for the writer thread */
    uint64_t         block_writes;     /* frames written into the file */
    uint64_t         block_errors;     /* failed file writes */
    pthread_cond_t   block_cond;
    pthread_mutex_t  lock;
} g_fb;

static const char *g_read_path = FB_READ_PATH_DEFAULT;
static const char *g_pub_path  = FB_PUB_PATH_DEFAULT;
static const char *g_out_path  = FB_OUT_PATH_DEFAULT;
static const char *g_block_path = FB_BLOCK_PATH_DEFAULT;

/* ------------------------------------------------------------------ */
/* The mailbox itself.                                                  */
/* ------------------------------------------------------------------ */

/*
 * Queue one frame in the MAILBOX MIRROR.  Returns 0 on success, EAGAIN
 * when the mailbox is full.
 *
 * The notification is triggered OUTSIDE the mailbox lock:
 * iofunc_notify_trigger() delivers a pulse, and a pulse delivery must
 * not be holding the mailbox lock.
 *
 * It IS taken under the NOTIFICATION-LIST lock, which is a different
 * lock: the library's trigger WALKS the armed-event list and unlinks
 * the events it fires, and the library's remove walks the SAME list and
 * frees the events, and neither takes a mutex of its own.  The WRITE
 * handler that triggers and the READ/close handlers that arm and remove
 * run on DIFFERENT dispatch threads, so the trigger and the remove can
 * be in flight at the same time.
 *
 * This is the MIRROR, not the transport.  Nothing reads the mailbox any
 * more (the guest reads the verdict file through the hypervisor's
 * read-only virtio-blk device), so the mirror fills up within a fraction
 * of a second and then DROPS.  A drop is counted, not returned as a
 * failure: the verdict has already reached the transport by the time this
 * runs, and reporting a failed publish would make the supervisor believe
 * its own verdict was lost.
 */
static int fb_enqueue(const unsigned char *frame)
{
    unsigned bytes = 0u;
    int fired = 0;
    int rc;

    pthread_mutex_lock(&g_fb.lock);
    if (g_fb.count + FB_FRAME_SIZE > FB_RING_BYTES) {
        g_fb.dropped++;
        pthread_mutex_unlock(&g_fb.lock);
        return EAGAIN;
    }
    memcpy(&g_fb.ring[g_fb.tail], frame, FB_FRAME_SIZE);
    g_fb.tail = (g_fb.tail + FB_FRAME_SIZE) % FB_RING_BYTES;
    g_fb.count += FB_FRAME_SIZE;
    bytes = g_fb.count;
    pthread_mutex_unlock(&g_fb.lock);

    /* Tell the reader that data is available.  The count is the number of
     * bytes waiting, which is what the client's notification trigger value
     * is compared against.  The armed-count CHECK and the trigger that
     * follows it are ONE critical section, so a notification cannot be
     * armed between them. */
    rc = latch_rm_notify_input_fire(&g_fb.read_node.notify, (int)bytes,
                                    &fired);
    if (fired) {
        pthread_mutex_lock(&g_fb.lock);
        g_fb.triggers++;
        pthread_mutex_unlock(&g_fb.lock);
    }
    if (rc != EOK) {
        /* The trigger was REFUSED -- the list's lock could not be taken,
         * so the armed event was NOT walked and NOT delivered.  The
         * reader waits for the next trigger, which is the safe
         * direction, but a refusal that is not PRINTED is a silent one,
         * and a silent one is a lie. */
        printf("latch_fb_sink: notify trigger refused rc=%d\n", rc);
        fflush(stdout);
    }
    return 0;
}

/* The number of whole frames currently queued. */
static unsigned fb_pending_units(void)
{
    unsigned units;
    pthread_mutex_lock(&g_fb.lock);
    units = g_fb.count / FB_FRAME_SIZE;
    pthread_mutex_unlock(&g_fb.lock);
    return units;
}

/* ------------------------------------------------------------------ */
/* The verdict file.                                                    */
/* ------------------------------------------------------------------ */

/*
 * Create (or open) the backing file and make it exactly FB_BLOCK_BYTES
 * long.
 *
 * The size matters: the `vdev virtio-blk` reads the file's length through
 * fstat() and turns it into the disk's capacity, so a file that is too
 * short would give the guest a disk that ends in the middle of a sector.
 *
 * The file is created 0600 and owned by root, and this resource manager is
 * the ONLY process that writes it.
 */
static int fb_open_block_file(void)
{
    int fd = open(g_block_path, O_RDWR | O_CREAT | O_NOCTTY, 0600);
    if (fd < 0) {
        return -1;
    }
    if (ftruncate(fd, (off_t)FB_BLOCK_BYTES) != 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

/*
 * Hand a frame to the writer thread.
 *
 * The frame is COPIED and the writer thread does the file I/O, so the
 * caller -- in the deployment, the trusted supervisor -- returns as soon
 * as the frame has been accepted.  That is the property the channel needs:
 * an advisory channel must never be able to stall the safety core.
 *
 * Only the LATEST frame is kept: the channel carries the newest verdict,
 * and a verdict that is overwritten before the guest polls it is a lost
 * verdict, which the guest's feedback timeout turns into "stop proposing",
 * which the supervisor's dead-man turns into a fail-closed LATCH.  Loss is
 * safe; silence is fatal.
 */
static void fb_publish_to_block(const unsigned char *frame)
{
    pthread_mutex_lock(&g_fb.lock);
    memcpy(g_fb.block_frame, frame, FB_FRAME_SIZE);
    g_fb.block_pending = 1;
    pthread_cond_signal(&g_fb.block_cond);
    pthread_mutex_unlock(&g_fb.lock);
}

/*
 * The writer thread.
 *
 * It waits for a frame and writes it into sector 0 of the backing file.
 * The write is a positioned write (pwrite), so it never depends on the
 * file offset, and it never truncates: the guest may be reading the file
 * at the very moment.
 */
static void *fb_block_writer_thread(void *arg)
{
    (void)arg;
    for (;;) {
        unsigned char frame[FB_FRAME_SIZE];
        int have = 0;

        pthread_mutex_lock(&g_fb.lock);
        while (!g_fb.block_pending) {
            pthread_cond_wait(&g_fb.block_cond, &g_fb.lock);
        }
        memcpy(frame, g_fb.block_frame, FB_FRAME_SIZE);
        g_fb.block_pending = 0;
        have = 1;
        pthread_mutex_unlock(&g_fb.lock);

        if (!have) {
            continue;
        }
        if (g_fb.block_fd >= 0) {
            ssize_t w = pwrite(g_fb.block_fd, frame, sizeof(frame),
                               FB_BLOCK_FRAME_OFFSET);
            pthread_mutex_lock(&g_fb.lock);
            if (w == (ssize_t)sizeof(frame)) {
                g_fb.block_writes++;
            } else {
                g_fb.block_errors++;
            }
            pthread_mutex_unlock(&g_fb.lock);
        } else {
            pthread_mutex_lock(&g_fb.lock);
            g_fb.block_errors++;
            pthread_mutex_unlock(&g_fb.lock);
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* The I/O handlers.                                                    */
/* ------------------------------------------------------------------ */

/*
 * The READ side: the hypervisor's readcond().
 *
 * The handler NEVER blocks.  The vdev's readcond() uses min=0, time=0,
 * timeout=0, which means "return immediately with as many bytes as are
 * currently available"; the vdev arms ionotify() when it gets nothing
 * and reads again when the pulse arrives.  That is exactly the model
 * implemented here.
 *
 * A readcond() that asks for a BLOCKING wait (min > 0) is answered with
 * EAGAIN rather than a wait.  The vdev never asks for one -- it opens the
 * endpoint O_NONBLOCK and uses the notification -- and a blocking read in
 * this resource manager would stall the publisher's write, which would put
 * the supervisor's critical path at the mercy of the advisory channel.
 * EAGAIN is the safe answer: the vdev treats it exactly like an empty
 * read and arms the notification.
 */
static int fb_io_read(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb)
{
    fb_node_t *node = (fb_node_t *)ocb->attr;
    unsigned char buf[FB_READ_MAX];
    size_t want;
    size_t n = 0u;

    if (node->kind != FB_NODE_READ) {
        return EBADF;   /* only the read node can be read */
    }
    pthread_mutex_lock(&g_fb.lock);
    g_fb.read_calls++;
    pthread_mutex_unlock(&g_fb.lock);
    printf("latch_fb_sink: read nbytes=%u xtype=0x%x\n",
           (unsigned)msg->i.nbytes, (unsigned)(msg->i.xtype & _IO_XTYPE_MASK));
    fflush(stdout);

    /* Accept a plain read() and a readcond(); refuse anything else.
     *
     * The QNX C Library's readcond() has NO fallback: it sends the
     * _IO_XTYPE_READCOND message once and returns whatever the resource
     * manager answers, so a resource manager that answers ENOSYS makes
     * the vdev's readcond() fail with ENOSYS instead of falling back to a
     * plain read.  The extended type therefore has to be implemented. */
    if ((msg->i.xtype & _IO_XTYPE_MASK) == _IO_XTYPE_READCOND) {
        const fb_readcond_t *rc = (const fb_readcond_t *)msg;
        if (rc->cond.min > 0 || rc->cond.time > 0 || rc->cond.timeout > 0) {
            return EAGAIN;   /* a blocking wait: refuse, never stall */
        }
    } else if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }

    {
        /* The exact errno matters: EBADF means "this descriptor was not
         * opened for reading", which is a bug in the CALLER and must be
         * reported as itself, not flattened into EIO. */
        int status = latch_rm_read_verify(ctp, msg, ocb, NULL);
        if (status != EOK) {
            return status;
        }
    }

    want = msg->i.nbytes;
    if (want > sizeof(buf)) {
        want = sizeof(buf);
    }

    pthread_mutex_lock(&g_fb.lock);
    n = (want < (size_t)g_fb.count) ? want : (size_t)g_fb.count;
    for (size_t i = 0u; i < n; ++i) {
        buf[i] = g_fb.ring[(g_fb.head + i) % FB_RING_BYTES];
    }
    g_fb.head = (unsigned)((g_fb.head + n) % FB_RING_BYTES);
    g_fb.count -= (unsigned)n;
    g_fb.delivered += (uint64_t)(n / FB_FRAME_SIZE);
    pthread_mutex_unlock(&g_fb.lock);

    /* The reply is the DATA ONLY, at offset 0; the byte count travels in
     * the message status.  See the header comment. */
    _IO_SET_READ_NBYTES(ctp, (int)n);
    if (n > 0u) {
        (void)resmgr_msgwrite(ctp, buf, n, 0);
    }
    return EOK;
}

/*
 * The WRITE side: the supervisor publishes one frame.
 *
 * The write is refused (EINVAL) when it is not exactly one frame.  It never
 * blocks, and it never depends on the mailbox having room: the verdict file
 * -- the transport the guest actually reads -- is written first, and the
 * mailbox is only a mirror (see fb_enqueue()).
 */
static int fb_io_write(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb)
{
    fb_node_t *node = (fb_node_t *)ocb->attr;
    unsigned char frame[FB_FRAME_SIZE];

    if (node->kind == FB_NODE_READ) {
        return EBADF;   /* the guest-facing node is read-only */
    }
    if (node->kind == FB_NODE_OUT) {
        /* The guest's UART OUTPUT direction.  The hypervisor writes here
         * whatever the guest sends towards the host.  Those bytes are
         * DISCARDED: the feedback channel is one-way, and a byte the guest
         * sends must never be able to look like a verdict.  They are
         * counted, because "the guest wrote N bytes and none of them
         * reached the mailbox" is evidence, not a detail. */
        size_t got = 0u;
        pthread_mutex_lock(&g_fb.lock);
        g_fb.write_calls++;
        pthread_mutex_unlock(&g_fb.lock);
        if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
            return ENOSYS;
        }
        {
            int status = latch_rm_write_verify(ctp, msg, ocb, NULL);
            if (status != EOK) {
                return status;
            }
        }
        got = msg->i.nbytes;
        if (got > 0u) {
            /* Drain the message payload so the sender's buffer is released. */
            unsigned char sink[256];
            while (got > 0u) {
                size_t chunk = (got < sizeof(sink)) ? got : sizeof(sink);
                ssize_t n = resmgr_msgget(ctp, sink, chunk, sizeof(msg->i));
                if (n <= 0) {
                    break;
                }
                got -= (size_t)n;
            }
        }
        pthread_mutex_lock(&g_fb.lock);
        g_fb.out_bytes += msg->i.nbytes;
        pthread_mutex_unlock(&g_fb.lock);
        _IO_SET_WRITE_NBYTES(ctp, (int)msg->i.nbytes);
        return EOK;
    }
    pthread_mutex_lock(&g_fb.lock);
    g_fb.write_calls++;
    pthread_mutex_unlock(&g_fb.lock);
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) {
        return ENOSYS;
    }
    {
        int status = latch_rm_write_verify(ctp, msg, ocb, NULL);
        if (status != EOK) {
            return status;
        }
    }
    if (msg->i.nbytes != FB_FRAME_SIZE) {
        return EINVAL;  /* the mailbox is frame-oriented */
    }
    if (resmgr_msgget(ctp, frame, sizeof(frame), sizeof(msg->i)) !=
        (ssize_t)sizeof(frame)) {
        return EIO;     /* a short frame would corrupt the stream */
    }

    /* THE TRANSPORT IS THE VERDICT FILE, AND IT IS WRITTEN FIRST.
     *
     * MEASURED on the QEMU AArch64 target (2026-11-26): when the file
     * write was conditional on the mailbox accepting the frame, a full
     * mailbox starved the transport.  The mailbox holds 146 frames and
     * NOTHING reads it any more (the guest reads the file through the
     * hypervisor's read-only virtio-blk device), so after 146 verdicts
     * the file stopped changing while the publisher kept writing: the
     * measured `file_writes` froze at 147 and never moved again.  The
     * transport must not depend on the mailbox's state, so the file is
     * written FIRST and the mailbox is only a mirror. */
    fb_publish_to_block(frame);
    pthread_mutex_lock(&g_fb.lock);
    g_fb.published++;
    pthread_mutex_unlock(&g_fb.lock);

    /* The mirror.  It is bounded and it drops rather than blocks, but a
     * drop is not a failed publish -- the verdict is already in the
     * transport -- so the write still succeeds. */
    (void)fb_enqueue(frame);

    _IO_SET_WRITE_NBYTES(ctp, (int)msg->i.nbytes);
    return EOK;
}

/*
 * The io_notify() handler: the client arms a notification for "input is
 * available".  iofunc_notify() does the bookkeeping and answers
 * immediately if the condition is already met.
 *
 * The wrapper takes the node's notification-list lock around the call:
 * iofunc_notify() LINKS a new event into the shared list, and the
 * WRITE handler's trigger walks the same list on another thread.
 */
static int fb_io_notify(resmgr_context_t *ctp, io_notify_t *msg, RESMGR_OCB_T *ocb)
{
    fb_node_t *node = (fb_node_t *)ocb->attr;
    int trig = 0;
    int rc;

    if (node->kind == FB_NODE_READ) {
        if (fb_pending_units() > 0u) {
            trig |= _NOTIFY_COND_INPUT;
        }
    } else {
        /* The publisher may always write: a full mailbox is signalled by
         * the EAGAIN on the write itself, not by a notification. */
        trig |= _NOTIFY_COND_OUTPUT;
    }
    rc = latch_rm_notify_arm(ctp, msg, &node->notify, trig);
    pthread_mutex_lock(&g_fb.lock);
    g_fb.notify_calls++;
    g_fb.last_notify_rc = rc;
    g_fb.last_notify_action = msg->i.action;
    pthread_mutex_unlock(&g_fb.lock);
    printf("latch_fb_sink: notify %s action=%d trig=0x%x rc=%d pending=%u\n",
           (node->kind == FB_NODE_READ) ? "READ" : "WRITE", msg->i.action,
           (unsigned)trig, rc, fb_pending_units());
    fflush(stdout);
    return rc;
}

/* A client closed its descriptor: drop its notification.
 *
 * Every one of these four calls WALKS the armed-event list -- the
 * triggers unlink the events they fire and the remove frees the rest --
 * and the library takes no mutex of its own, so each one goes through
 * the locked wrapper.  The attribute lock is a DIFFERENT lock, and it
 * is taken only by the close wrapper below, AFTER the notification lock
 * has been released: the two are never held at the same time.
 */
static int fb_io_close_dup(resmgr_context_t *ctp, io_close_t *msg, RESMGR_OCB_T *ocb)
{
    fb_node_t *node = (fb_node_t *)ocb->attr;

    (void)latch_rm_notify_trigger_strict(ctp, &node->notify, INT_MAX,
                                         IOFUNC_NOTIFY_INPUT);
    (void)latch_rm_notify_trigger_strict(ctp, &node->notify, INT_MAX,
                                         IOFUNC_NOTIFY_OUTPUT);
    (void)latch_rm_notify_trigger_strict(ctp, &node->notify, INT_MAX,
                                         IOFUNC_NOTIFY_OBAND);
    (void)latch_rm_notify_remove(ctp, &node->notify);

    /* The close DETACHES the OCB, which decrements the node's shared
     * file-use count.  The wrapper takes the node's attribute lock
     * around the call, so two concurrent closes cannot lose a
     * decrement. */
    return latch_rm_close_dup_default(ctp, msg, ocb);
}

/*
 * The OPEN handler: the nodes are one-sided, and the security statement
 * depends on it.  The read node accepts only a read access and the two
 * write nodes only a write access, so "the hypervisor cannot write the
 * verdict channel" and "the supervisor cannot read it" are enforced by the
 * resource manager itself and not only by the security policy.
 *
 * The hypervisor opens the guest's UART OUTPUT direction with
 * O_WRONLY|O_CREAT|O_TRUNC (it is opening a PATH, and a path may be a file
 * it creates).  Neither flag means anything for a character device, and
 * iofunc_open_default() is entitled to refuse them, so they are cleared
 * before the default handler runs.  The permission bits -- the only ones
 * this handler cares about -- are left exactly as the client sent them.
 */
static int fb_io_open(resmgr_context_t *ctp,
                      io_open_t *msg,
                      RESMGR_HANDLE_T *handle,
                      void *extra)
{
    fb_node_t *node = (fb_node_t *)handle;
    unsigned rd = (msg->connect.ioflag & _IO_FLAG_RD) ? 1u : 0u;
    unsigned wr = (msg->connect.ioflag & _IO_FLAG_WR) ? 1u : 0u;
    int first_reader = 0;
    uint64_t dropped_frames = 0;

    if (node == NULL) {
        return EIO;
    }
    pthread_mutex_lock(&g_fb.lock);
    if (node->kind == FB_NODE_READ) {
        g_fb.read_opens++;
        g_fb.last_read_ioflag = msg->connect.ioflag;
        /* THE FIRST-READER DECISION, AND THE BACKLOG DISCARD, ARE ONE
         * ATOMIC STEP.
         *
         * The decision lives in `latch_fb_reader.h` because it is a
         * property that a HOST test can prove and this resource manager
         * cannot be built on the build host.  Two things have to happen
         * together here, and both of them have to be inside this ONE
         * critical section:
         *
         *   - the reader accounting is incremented, and
         *   - the backlog is discarded.
         *
         * The channel runs TWO dispatch threads with
         * `DISPATCH_FLAG_NOLOCK`, so two opens can be in flight at the
         * same time.  If the increment and the check were separate
         * critical sections, BOTH opens could see "no readers yet" and
         * both would believe they were the first -- and neither would
         * discard the backlog. */
        first_reader = latch_fb_reader_account(&g_fb.reader, rd, wr);
        if (first_reader) {
            dropped_frames = (uint64_t)(g_fb.count / FB_FRAME_SIZE);
            g_fb.dropped_on_open += dropped_frames;
            g_fb.count = 0u;
            g_fb.head = 0u;
            g_fb.tail = 0u;
        }
    } else if (node->kind == FB_NODE_PUB) {
        g_fb.pub_opens++;
        g_fb.last_pub_ioflag = msg->connect.ioflag;
    } else {
        g_fb.out_opens++;
    }
    pthread_mutex_unlock(&g_fb.lock);
    /* Report EVERY open with its flags.  The hypervisor's open flags are the
     * measurement that decides the transport's shape: the PL011 vdev opens
     * its host endpoint O_RDWR when the input and the output path are the
     * SAME string, and one-sided nodes refuse that. */
    printf("latch_fb_sink: open %s ioflag=0x%x (%s%s)\n",
           (node->kind == FB_NODE_READ) ? "READ" :
           ((node->kind == FB_NODE_PUB) ? "WRITE" : "DISCARD"),
           msg->connect.ioflag,
           (msg->connect.ioflag & _IO_FLAG_RD) ? "RD" : "--",
           (msg->connect.ioflag & _IO_FLAG_WR) ? "WR" : "--");
    fflush(stdout);
    if (node->kind == FB_NODE_READ) {
        /* The mailbox is EMPTY when a READER arrives.
         *
         * A frame that was published before the reader was ready is a
         * STALE verdict: the guest would act on a decision that was made
         * for an earlier proposal.  The frame format carries the session
         * epoch and the sequence number so the guest can reject a stale
         * frame, but the transport must not hand it out in the first
         * place -- "the mailbox was full of old verdicts when the guest
         * opened it" is a state in which the guest's first read is
         * guaranteed to be wrong.
         *
         * So the backlog is discarded when the read node is opened, and
         * the reader's first frame is the first frame published after it
         * was ready.  The discard is counted and logged: it is a fact
         * about the run, not a detail.
         *
         * THE TRIGGER IS "AN OPEN THAT WAS GRANTED READ ACCESS", NOT
         * "THE FIRST OPEN" AND NOT "ANY OPEN".
         *
         * MEASURED on the QEMU AArch64 target (2026-11-26): QNX's `waitfor`
         * probes a path by OPENING it with the access bits CLEARED (the
         * measured ioflag was 0x8880 -- no read bit, no write bit), and that
         * probe is the FIRST open the read node ever sees.  Keying the
         * drop on "the first open of any kind" therefore let the waitfor
         * probe consume the first-reader slot, and the real reader's
         * backlog was never dropped (the measured `dropped_on_open` stayed
         * at 0 across a whole run in which 120 frames had been published).
         *
         * The counter that decided this was `read_opens`, which counts
         * EVERY open of the READ node -- including the probe.  So the
         * condition `read_opens == 1` was FALSE for the real reader
         * (the probe had already made it 2), and the backlog was never
         * discarded.  The fix is a counter of READERS, not of opens.
         *
         * A REFUSED open is not a reader either: an open that asks for
         * READ *and* WRITE on this read-only node is refused with EACCES,
         * and it must not consume the slot for the same reason the probe
         * must not.
         *
         * The decision is `latch_fb_reader_account()` in
         * `qnx/latch_fb_reader.h`, and `qnx/latch_fb_reader_test.c` proves
         * it on the host -- this resource manager cannot be built there. */
        if (first_reader) {
            printf("latch_fb_sink: the read node was opened: the backlog was "
                   "discarded (%llu frame(s)), the first delivered frame is the "
                   "first frame published from now on\n",
                   (unsigned long long)dropped_frames);
            fflush(stdout);
        }
        if (wr != 0u) {
            pthread_mutex_lock(&g_fb.lock);
            g_fb.read_refused++;
            pthread_mutex_unlock(&g_fb.lock);
            return EACCES;   /* the read node is read-only */
        }
    } else {
        if (rd != 0u) {
            pthread_mutex_lock(&g_fb.lock);
            g_fb.pub_refused++;
            pthread_mutex_unlock(&g_fb.lock);
            return EACCES;   /* the write nodes are write-only */
        }
    }
    /* O_CREAT and O_TRUNC mean nothing for a character device. */
    msg->connect.ioflag &= ~((unsigned)(O_CREAT | O_TRUNC));
    /* The open ATTACHES an OCB, which increments the node's shared
     * file-use count.  The wrapper takes the node's attribute lock
     * around the call, so two concurrent opens cannot lose an
     * increment. */
    return latch_rm_open_default(ctp, msg, handle, extra);
}

/* ------------------------------------------------------------------ */
/* The server.                                                          */
/* ------------------------------------------------------------------ */

static void *fb_dispatch_thread(void *arg)
{
    dispatch_context_t *ctp = (dispatch_context_t *)arg;

    for (;;) {
        if (dispatch_block(ctp) == NULL) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        (void)dispatch_handler(ctp);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    dispatch_t *dpp;
    resmgr_connect_funcs_t connect_funcs;
    resmgr_io_funcs_t io_funcs;
    resmgr_attr_t rattr;
    int id_read;
    int id_pub;
    int id_out;
    pthread_t tid[2];
    pthread_t block_tid;

    if (argc > 1) {
        g_read_path = argv[1];
    }
    if (argc > 2) {
        g_pub_path = argv[2];
    }
    if (argc > 3) {
        g_out_path = argv[3];
    }
    if (argc > 4) {
        g_block_path = argv[4];
    }

    pthread_mutex_init(&g_fb.lock, NULL);
    pthread_cond_init(&g_fb.block_cond, NULL);

    /* THE VERDICT FILE IS CREATED BEFORE THE NODES ARE REGISTERED.
     *
     * The ordering is the contract: the hypervisor opens the backing file
     * at qvm start, and a hostdev that cannot be opened is FATAL to the VM
     * start.  The buildfile waits for the read node before it launches the
     * hypervisor, so "the node exists" has to imply "the file exists and
     * has its final size" -- otherwise the hypervisor could find a
     * half-created file.  Creating the file first makes the node the
     * LATER event, which is the safe direction. */
    g_fb.block_fd = fb_open_block_file();
    if (g_fb.block_fd < 0) {
        fprintf(stderr, "latch_fb_sink: cannot create the verdict file %s: %s\n",
                g_block_path, strerror(errno));
        return EXIT_FAILURE;
    }
    printf("latch_fb_sink: the verdict file %s is ready (%u bytes)\n",
           g_block_path, (unsigned)FB_BLOCK_BYTES);
    fflush(stdout);

    dpp = dispatch_create_channel(-1, DISPATCH_FLAG_NOLOCK);
    if (dpp == NULL) {
        perror("latch_fb_sink: dispatch_create_channel");
        return EXIT_FAILURE;
    }

    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &connect_funcs,
                     _RESMGR_IO_NFUNCS, &io_funcs);
    connect_funcs.open = fb_io_open;
    io_funcs.read      = fb_io_read;
    io_funcs.write     = fb_io_write;
    io_funcs.notify    = fb_io_notify;
    io_funcs.close_dup = fb_io_close_dup;

    iofunc_attr_init(&g_fb.read_node.attr, S_IFCHR | 0666, NULL, NULL);
    g_fb.read_node.kind = FB_NODE_READ;
    if (latch_rm_notify_init(&g_fb.read_node.notify) != EOK) {
        fprintf(stderr, "latch_fb_sink: cannot initialise the READ node's "
                "notification list\n");
        return EXIT_FAILURE;
    }

    iofunc_attr_init(&g_fb.pub_node.attr, S_IFCHR | 0666, NULL, NULL);
    g_fb.pub_node.kind = FB_NODE_PUB;
    if (latch_rm_notify_init(&g_fb.pub_node.notify) != EOK) {
        fprintf(stderr, "latch_fb_sink: cannot initialise the WRITE node's "
                "notification list\n");
        return EXIT_FAILURE;
    }

    iofunc_attr_init(&g_fb.out_node.attr, S_IFCHR | 0666, NULL, NULL);
    g_fb.out_node.kind = FB_NODE_OUT;
    if (latch_rm_notify_init(&g_fb.out_node.notify) != EOK) {
        fprintf(stderr, "latch_fb_sink: cannot initialise the DISCARD node's "
                "notification list\n");
        return EXIT_FAILURE;
    }

    memset(&rattr, 0, sizeof(rattr));
    rattr.nparts_max   = 1;
    rattr.msg_max_size = 1024u;

    id_read = resmgr_attach(dpp, &rattr, g_read_path,
                             _FTYPE_ANY, 0, &connect_funcs,
                             &io_funcs, &g_fb.read_node.attr);
    if (id_read == -1) {
        perror("latch_fb_sink: resmgr_attach(read)");
        return EXIT_FAILURE;
    }
    id_pub = resmgr_attach(dpp, &rattr, g_pub_path,
                            _FTYPE_ANY, 0, &connect_funcs,
                            &io_funcs, &g_fb.pub_node.attr);
    if (id_pub == -1) {
        perror("latch_fb_sink: resmgr_attach(pub)");
        return EXIT_FAILURE;
    }
    id_out = resmgr_attach(dpp, &rattr, g_out_path,
                            _FTYPE_ANY, 0, &connect_funcs,
                            &io_funcs, &g_fb.out_node.attr);
    if (id_out == -1) {
        perror("latch_fb_sink: resmgr_attach(out)");
        return EXIT_FAILURE;
    }

    printf("latch_fb_sink: serving %s (read), %s (write) and %s (discard), "
           "frame=%u bytes, verdict file %s\n",
           g_read_path, g_pub_path, g_out_path, (unsigned)FB_FRAME_SIZE,
           g_block_path);
    fflush(stdout);

    /* THE VERDICT-FILE WRITER THREAD.  It is started BEFORE the dispatch
     * threads, so a frame that arrives immediately is never left waiting. */
    if (pthread_create(&block_tid, NULL, fb_block_writer_thread, NULL) != 0) {
        perror("latch_fb_sink: pthread_create(block writer)");
        return EXIT_FAILURE;
    }

    /* TWO dispatch threads, so that a slow client can never delay the
     * publisher's write.  The mailbox itself is protected by a mutex. */
    for (int i = 0; i < 2; ++i) {
        dispatch_context_t *ctp = dispatch_context_alloc(dpp);
        if (ctp == NULL) {
            perror("latch_fb_sink: dispatch_context_alloc");
            return EXIT_FAILURE;
        }
        if (pthread_create(&tid[i], NULL, fb_dispatch_thread, ctp) != 0) {
            perror("latch_fb_sink: pthread_create");
            return EXIT_FAILURE;
        }
    }

    for (;;) {
        uint64_t published, delivered, dropped;
        uint64_t read_opens, pub_opens, read_calls, write_calls;
        uint64_t reader_opens;
        uint64_t read_refused, pub_refused, out_opens, out_bytes;
        uint64_t dropped_on_open, notify_calls, triggers;
        uint64_t block_writes, block_errors;
        unsigned queued, last_read_ioflag, last_pub_ioflag;
        int last_notify_rc, last_notify_action;

        sleep(30);
        /* THE COUNTERS ARE SNAPSHOTTED UNDER THE LOCK.
         *
         * A status line that reads the counters unlocked can print a
         * half-updated value, and a status line that lies is worse than
         * no status line: it is the evidence a reader uses to decide
         * whether the transport is alive. */
        pthread_mutex_lock(&g_fb.lock);
        published = g_fb.published;
        delivered = g_fb.delivered;
        dropped = g_fb.dropped;
        queued = g_fb.count;
        read_opens = g_fb.read_opens;
        reader_opens = g_fb.reader.opens;
        pub_opens = g_fb.pub_opens;
        read_calls = g_fb.read_calls;
        write_calls = g_fb.write_calls;
        read_refused = g_fb.read_refused;
        pub_refused = g_fb.pub_refused;
        last_read_ioflag = g_fb.last_read_ioflag;
        last_pub_ioflag = g_fb.last_pub_ioflag;
        out_opens = g_fb.out_opens;
        out_bytes = g_fb.out_bytes;
        dropped_on_open = g_fb.dropped_on_open;
        notify_calls = g_fb.notify_calls;
        triggers = g_fb.triggers;
        last_notify_action = g_fb.last_notify_action;
        last_notify_rc = g_fb.last_notify_rc;
        block_writes = g_fb.block_writes;
        block_errors = g_fb.block_errors;
        pthread_mutex_unlock(&g_fb.lock);

        printf("latch_fb_sink: published=%llu delivered=%llu dropped=%llu queued=%u bytes "
               "| read_opens=%llu reader_opens=%llu pub_opens=%llu read_calls=%llu write_calls=%llu "
               "| read_refused=%llu pub_refused=%llu last_read_ioflag=0x%x "
               "last_pub_ioflag=0x%x | out_opens=%llu out_bytes=%llu "
               "dropped_on_open=%llu "
               "| notify_calls=%llu triggers=%llu "
               "last_notify_action=%d last_notify_rc=%d "
               "| file_writes=%llu file_errors=%llu\n",
               (unsigned long long)published,
               (unsigned long long)delivered,
               (unsigned long long)dropped,
               queued,
               (unsigned long long)read_opens,
               (unsigned long long)reader_opens,
               (unsigned long long)pub_opens,
               (unsigned long long)read_calls,
               (unsigned long long)write_calls,
               (unsigned long long)read_refused,
               (unsigned long long)pub_refused,
               last_read_ioflag,
               last_pub_ioflag,
               (unsigned long long)out_opens,
               (unsigned long long)out_bytes,
               (unsigned long long)dropped_on_open,
               (unsigned long long)notify_calls,
               (unsigned long long)triggers,
               last_notify_action,
               last_notify_rc,
               (unsigned long long)block_writes,
               (unsigned long long)block_errors);
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}
