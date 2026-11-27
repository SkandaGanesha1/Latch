/*
 * guest/latch_fb_transport.h
 *
 * THE POLLED VERDICT SECTOR -- THE SHARED HOST->GUEST TRANSPORT  (W4 + W5)
 * =======================================================================
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The LFBK verdict channel is a POLLED BLOCK DEVICE.  The hypervisor opens
 * a host file READ-ONLY (`hostdev </dev/shmem/latch_feedback.img`) and
 * serves it to the guest as `/dev/vda`; the guest polls sector 0 with
 * `pread64`.
 *
 * Two guest profiles use it:
 *
 *   * W4 (`-DLATCH_GOVERNOR_FEEDBACK`)      -- the transport PROBE.  It
 *     answers the question "does a host-side verdict reach a freestanding
 *     guest policy at all?", and it reports what it saw ONCE, before the
 *     session opens.
 *
 *   * W5 (`-DLATCH_GOVERNOR_FEEDBACK_VERDICT`) -- the verdict WATCHER.  It
 *     decodes the supervisor's verdict on every proposal, correlates it
 *     with the proposal it answers, and stops the guest when the
 *     supervisor says no.
 *
 * They share ONE copy of the transport, and that is not a convenience:
 *
 *   * THE FRESHNESS MECHANISM IS LOAD-BEARING.  A guest that reads the
 *     same sector through its page cache sees the SAME bytes forever, and
 *     a channel that cannot show a change is not a channel.  Two copies of
 *     the freshness rule would drift, and the drift would be invisible
 *     until a guest on a target silently stopped seeing its supervisor.
 *   * THE DEVICE DISCOVERY IS LOAD-BEARING TOO.  The guest does NOT
 *     control which `/dev/vd*` node carries the channel: the Linux
 *     virtio-blk driver names its devices in its own probe order.  A
 *     profile that guessed a name would report a false negative -- which
 *     is EXACTLY what happened to the serial form of the probe (see
 *     AGENTS.md §4c: the PL011 driver published `ttyAMA0` for the
 *     FEEDBACK port even though the console port was declared first).
 *
 * So the candidates are all opened and the DATA decides which one carries
 * the channel.
 *
 * WHY THE HEADER IS GUEST-SIDE AND NOT QNX-SIDE
 * ---------------------------------------------
 * The guest policy is FREESTANDING: it has no libc and must not pull a
 * header out of the QNX tree.  This header therefore needs only
 * <stdint.h>/<stddef.h> plus the handful of raw-syscall wrappers that
 * `latch_guest_init.c` has already defined above the include point
 * (`sys_open`, `sys_close`, `sys_sleep_ms`, `sys_pread64`,
 * `sys_fadvise64`) and the two constants it has already defined
 * (`O_DIRECT`, `POSIX_FADV_DONTNEED`).
 *
 * WHAT THE PROFILES DIFFER IN
 * ----------------------------
 * Only the POLICY: what the guest does with a frame it has read.  The
 * transport underneath -- which device, how fresh, how many bytes -- is
 * identical, and that is the point of this file.
 */

#ifndef LATCH_FB_TRANSPORT_H_
#define LATCH_FB_TRANSPORT_H_

#include <stddef.h>
#include <stdint.h>

/* --------------------------------------------------------------------------
 * THE BOUNDED REPORT FORMATTERS
 *
 * The guest policy has no printf, so a report is built by hand into a
 * fixed-size buffer.  These three helpers are the ONLY way a feedback
 * profile writes a number, and they live here so that the W4 probe's
 * report and the W5 watcher's report cannot drift apart in their format.
 *
 * Every one of them is BOUNDED: nothing is written past `cap`, and the
 * returned offset is where the next piece starts.  A truncated report is
 * a short report, never a buffer overrun.
 * ------------------------------------------------------------------------ */
static size_t fb_append_str(char *dst, size_t cap, size_t at, const char *s) {
    while (*s != '\0' && at + 1u < cap) {
        dst[at++] = *s++;
    }
    return at;
}

static size_t fb_append_u32(char *dst, size_t cap, size_t at, uint32_t v) {
    char tmp[10];
    int n = 0;
    if (v == 0u) {
        tmp[n++] = '0';
    } else {
        while (v > 0u && n < (int)sizeof(tmp)) {
            tmp[n++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
    }
    while (n > 0 && at + 1u < cap) {
        dst[at++] = tmp[--n];
    }
    return at;
}

static size_t fb_append_hex8(char *dst, size_t cap, size_t at, uint32_t v) {
    static const char hex[] = "0123456789abcdef";
    for (int shift = 28; shift >= 0; shift -= 4) {
        if (at + 1u >= cap) {
            break;
        }
        dst[at++] = hex[(v >> (uint32_t)shift) & 0xFu];
    }
    return at;
}

/* --------------------------------------------------------------------------
 * THE CANDIDATE BLOCK DEVICES
 *
 * The guest MUST NOT assume which node carries the verdict.  The Linux
 * virtio-blk driver names its devices in its own probe order, and the guest
 * does not control that order -- exactly the trap the serial form of this
 * probe fell into (measured on the target: the PL011 driver published
 * `ttyAMA0` for the FEEDBACK port even though the console port was
 * declared first, so a probe that trusted a name opened the wrong port and
 * reported a false negative).
 *
 * So a profile opens EVERY candidate and lets the DATA decide which one
 * carries the channel: only the verdict device ever contains a frame with
 * the LFBK magic and a valid CRC.
 * ------------------------------------------------------------------------ */
#define LATCH_FB_BLOCK_MAX 3

/* THE READ SIZE IS ONE PAGE, NOT ONE SECTOR.
 *
 * A DIRECT read has to satisfy TWO alignment rules at once: the COUNT has
 * to be a whole number of the device's LOGICAL blocks (512 bytes for
 * virtio-blk) and the buffer has to satisfy the device's DMA alignment,
 * which is the REQUEST QUEUE's alignment and is not necessarily 512.
 * The Linux 6.12 block layer checks both (`blkdev_dio_invalid()` ->
 * `bdev_iter_is_aligned()` -> `iov_iter_is_aligned()`), and a 512-byte
 * read is rejected by the second rule on a queue whose DMA alignment is
 * 4096 -- with EINVAL, at READ time, long after the open succeeded.
 *
 * A 4096-byte read is a whole number of 512-byte blocks AND a whole number
 * of 4096-byte pages, so it satisfies both rules whatever the queue's
 * alignment is, and the frame -- which lives in the first 28 bytes -- is
 * unaffected by the larger read. */
#define LATCH_FB_READ_BYTES   4096u

/* The DIRECT read's buffer has to be aligned to the device's DMA
 * alignment, which is at most a page on every block device this guest can
 * have. */
#define LATCH_FB_BUFFER_ALIGN 4096u

/* The guest's errno values (asm-generic/errno.h).  The policy has no libc,
 * so the few it needs are named here rather than invented. */
#define LATCH_FB_ENOENT   2
#define LATCH_FB_EINVAL  22
#define LATCH_FB_ENOTSUP 95

/* The per-candidate telemetry.  It is the same structure for both
 * profiles, so a report can say WHICH device carried the channel, which
 * one could not be opened and WHY, and whether the reads bypassed the
 * page cache. */
typedef struct {
    int      fd;
    int      open_errno;
    int      direct;        /* the descriptor bypasses the page cache */
    int      direct_errno;  /* why the O_DIRECT open was refused */
    int      advise_errno;  /* why the DONTNEED advice was refused */
    int      read_errno;    /* why the last read was refused */
    uint32_t reads;
    uint32_t valid;
    uint32_t bad;
    uint32_t changes;
    uint32_t first_seq;
    uint32_t last_seq;
    uint32_t epoch;
    uint32_t verdict;
    uint32_t rung;
    uint32_t faults;
} fb_blk_t;

static const char *fb_block_candidates[LATCH_FB_BLOCK_MAX] = {
    "/dev/vda",
    "/dev/vdb",
    "/dev/vdc"
};

/*
 * Open one candidate block device.
 *
 * The node is NEVER created by hand.  A hand-made node would have to guess
 * the minor, and the minor follows the driver's probe order -- so a guess
 * can name the wrong device, which is exactly the failure this transport
 * exists to rule out.  The guest reads the nodes devtmpfs published.
 *
 * The open is retried, because PID 1 may run before the guest's block
 * layer has probed every device.
 *
 * O_DIRECT IS NOT A DETAIL, IT IS THE TRANSPORT.
 *
 * MEASURED on the QEMU AArch64 target (2026-11-26): with a plain
 * O_RDONLY the guest's own page cache answered every poll from the FIRST
 * read, so 600 polls over 12 s saw one unchanged frame (seq 74 -> 74)
 * while the host wrote dozens of verdicts into the very same sector.  The
 * device was right, the address was right and the frame was valid -- only
 * the FRESHNESS was missing, and a channel that cannot show a change is
 * not a channel.
 *
 * So the transport asks for a view that reaches the device:
 *
 *   * O_DIRECT, when the kernel accepts it -- the read then bypasses the
 *     cache by construction; and
 *   * POSIX_FADV_DONTNEED before every buffered read, which drops the
 *     cached pages so the read goes back to the device.  This is the
 *     standard way to poll a file for changes: POSIX has no "poll this
 *     file" call, and the page cache is exactly what makes a repeated
 *     read return the SAME bytes.
 *
 * The report says which of the two was used (`dir=`, `derr=`, `ferr=`), so
 * a freshness failure is attributable rather than mysterious.
 */
static int fb_open_block(const char *device, int *last_errno, int *direct,
                               int *direct_errno) {
    int err = 0;
    int fd = -1;

    *direct = 0;
    *direct_errno = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        long ret = sys_open(device, O_RDONLY);
        if (ret >= 0) {
            fd = (int)ret;
            break;
        }
        /* The raw syscall returns -errno on failure, so the reason the
         * device could not be opened is available -- and a report that
         * cannot say WHY a candidate failed to open is a report that
         * cannot be acted on. */
        err = (int)(-ret);
        sys_sleep_ms(250);
    }
    if (fd < 0) {
        if (last_errno != NULL) {
            *last_errno = err;
        }
        return -1;
    }

    /* The device is there.  Now ask for the view that bypasses the page
     * cache.  A single attempt: this is a property of the DEVICE, not of
     * the boot's timing, so retrying it would only add delay.  The reason
     * a refusal is KEPT, because "O_DIRECT was refused and I do not know
     * why" is a different fault from "O_DIRECT was refused with EINVAL". */
    {
        long ret = sys_open(device, O_RDONLY | O_DIRECT);
        if (ret >= 0) {
            sys_close(fd);
            *direct = 1;
            return (int)ret;
        }
        *direct_errno = (int)(-ret);
    }
    return fd;
}

/*
 * THE FRESHNESS RULE -- ONE COPY, FOR EVERY PROFILE.
 *
 * DROP THE CACHED PAGES BEFORE EVERY BUFFERED READ.
 *
 * Without this the guest's page cache answers the poll from the FIRST
 * read, and a profile measures its own cache instead of the transport.  A
 * DIRECT descriptor does not need the advice -- it never caches.
 *
 * The advice's refusal is recorded, because a silently ineffective advice
 * would look exactly like a transport that never changes.
 *
 * WHY IT IS A MACRO AND NOT A FUNCTION
 * -----------------------------------
 * A `static inline` function was tried first, and it CHANGED the W4
 * guest's compiled binary: the inliner's own version of the advice block
 * is not instruction-for-instruction the block that was written by hand.
 * That matters here, because the W4 profile's initrd SHA-256 is the
 * zero-regression witness for the transport work: as long as the W4
 * binary is byte-for-byte the one that was measured GREEN on the QEMU
 * AArch64 target, nobody has to take anybody's word for the fact that the
 * transport refactor did not touch it.
 *
 * A macro expands to the hand-written text, so both profiles compile the
 * SAME instructions from the SAME source.  One copy of the rule, and a
 * byte-identical W4 binary -- which is the best of both.
 */
#define LATCH_FB_DROP_CACHE(b)                                                   \
    do {                                                                         \
        if ((b)->direct == 0) {                                                  \
            long adv = sys_fadvise64((b)->fd, 0, 0, POSIX_FADV_DONTNEED);       \
            if (adv < 0) {                                                       \
                (b)->advise_errno = (int)(-adv);                                 \
            }                                                                    \
        }                                                                        \
    } while (0)

#endif /* LATCH_FB_TRANSPORT_H_ */
