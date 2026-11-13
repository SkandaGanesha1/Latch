/*
 * guest/latch_guest_init.c
 *
 * Freestanding static AArch64 Linux /init for the QNX Hypervisor 8.0 (qvm) guest.
 *
 * Zero libc dependencies: direct AArch64 Linux syscalls (`svc #0`).
 * Mounts proc/sysfs/devtmpfs, creates /dev/hvc0 (229:0) & /dev/console (5:1),
 * prints status to /dev/kmsg, and streams an 84-frame LATH wire-frame fault
 * suite to /dev/hvc0.
 *
 * THE GUEST POLICY IS THIS BINARY.
 * guest/liar.py is a WORKSTATION-ONLY generator used by `make check` through a
 * POSIX pipe. It never runs inside qvm: there is no Python, no libc and no
 * shell in the cpio archive that `make guest-initrd` builds. Do not describe
 * liar.py as the in-guest policy in the README, the codelab or the video.
 *
 * Fault classes, in order. Each phase prints a marker on /dev/console (the
 * guest's DEBUG console, not the black channel) so a judge can narrate it,
 * and the host-side evidence tape shows the corresponding state transition.
 *
 * PACING -- WHY THERE IS NO PAUSE BETWEEN PHASES:
 *   The host's watchdog is `watchdog_ticks = 2`, i.e. 2 ms of host time at
 *   1 kHz. If the guest stops sending for longer than that, the host sees a
 *   genuine gap, fails closed into HA-HOLD, then retracts to HA-HOME -- which
 *   moves `theta` away from the value the next phase proposes, so every
 *   frame of that next phase is then vetoed as a RATE fault. A pause between
 *   phases therefore corrupts the very safety story it is meant to
 *   dramatise: measured on QEMU, even a 1 ms guest pause produced 16 host
 *   ticks of starvation and 48 spurious envelope vetoes instead of 7.
 *
 *   So the guest emits ONE CONTINUOUS byte stream with no gap at all, and
 *   it produces FASTER than the host consumes: 4 frames (128 bytes) every
 *   200 us is about 20 frames/ms against the supervisor's 1 kHz tick. The
 *   backlog that builds up is what keeps the supervisor's decision loop fed
 *   and its watchdog from ever firing spuriously. There is NO artificial
 *   pacing anywhere in the path -- `latch-ingest` hands each frame over as
 *   fast as the transport delivers it. The guest's frame
 *   ORDER is what the safety envelope sees, and order is preserved by the
 *   host's 256-slot queue.
 *
 *   The phase markers still go to /dev/console (the guest's DEBUG console,
 *   not the black channel), so a judge can narrate each phase, and the host's
 *   evidence tape shows the corresponding state transition in order.
 *
 *   The ONE deliberate silence is phase 9, and it is a REAL silence.
 *   1. Legal ramp            (frames  1..25)  -> host tracks in HP
 *   2. Keep-out violation    (frames 26..32)  -> host vetoes, HA-HOLD
 *   3. Clean recovery        (frames 33..57)  -> host returns to HP
 *   4. Step to hold angle    (frames 58..62)
 *   5. CRC bit-flip          (frames 63..66)  -> host rejects (wire fault)
 *   6. NaN sentinel          (frames 67..70)  -> host rejects (NaN fault)
 *   7. Valid frames          (frames 71..80)
 *   8. Sequence replay       (frames 81..84)  -> host rejects (SEQ fault)
 *   9. REAL SILENCE          (the silence phase) -> NO BYTES AT ALL.
 *
 * Step 9 is the important one. A previous revision sent LATCH_WIRE_FLAG_SILENCE
 * frames for the "silence" phase. The host does NOT treat that flag as
 * silence -- guest flags are ignored for safety -- so those frames were
 * counted as sequence REPLAYS, and the watchdog never actually fired. This
 * revision simply STOPS WRITING, so the host sees a genuine gap on the
 * channel, trips LATCH_FAULT_WATCHDOG (0x0100) after watchdog_ticks, latches
 * HA-HOLD, and retracts to HA-HOME after hold_to_home_ticks.
 *
 * PID 1 is this binary, so there is no separate policy process to `kill -9`.
 * The honest on-camera statement is: "the guest stops sending; the host's 1 kHz
 * loop does not stop." The demo script must say that, not "we killed the
 * policy in the guest".
 */

#include <stddef.h>
#include <stdint.h>

#define AT_FDCWD        (-100)
#define O_WRONLY        1
#define O_RDWR          2
#define O_NOCTTY        0400
#define S_IFCHR         0020000

#define SYS_dup3        24
#define SYS_ioctl       29
#define SYS_mknodat     33
#define SYS_mkdirat     34
#define SYS_mount       40
#define SYS_openat      56
#define SYS_close       57
#define SYS_write       64
#define SYS_exit        93
#define SYS_nanosleep   101

#define LATCH_WIRE_MAGIC        0x4C415448u   /* "LATH" */
#define LATCH_WIRE_VERSION      1u
#define LATCH_WIRE_JOINT        0u
#define LATCH_NAN_MRAD          ((int32_t)0x80000000)
#define LATCH_WIRE_FLAG_NONE    0x00u
#define LATCH_WIRE_FLAG_SILENCE 0x80u

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint16_t version;
    uint8_t  joint;
    uint8_t  flags;
    uint32_t seq;
    int32_t  u_mrad;
    uint32_t crc32;
    uint8_t  reserved[12];
} lath_frame_t;

typedef struct {
    long tv_sec;
    long tv_nsec;
} ktimespec_t;

static inline long sys6(long num, long a0, long a1, long a2, long a3, long a4, long a5) {
    register long x8 __asm__("x8") = num;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    register long x4 __asm__("x4") = a4;
    register long x5 __asm__("x5") = a5;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

static inline long sys_mkdir(const char *path, int mode) {
    return sys6(SYS_mkdirat, AT_FDCWD, (long)path, mode, 0, 0, 0);
}

static inline long sys_mount(const char *src, const char *tgt, const char *fstype) {
    return sys6(SYS_mount, (long)src, (long)tgt, (long)fstype, 0, 0, 0);
}

static inline long sys_mknod(const char *path, int mode, uint64_t dev) {
    return sys6(SYS_mknodat, AT_FDCWD, (long)path, mode, (long)dev, 0, 0);
}

static inline long sys_open(const char *path, int flags) {
    return sys6(SYS_openat, AT_FDCWD, (long)path, flags, 0, 0, 0);
}

static inline long sys_close(int fd) {
    return sys6(SYS_close, fd, 0, 0, 0, 0, 0);
}

static inline long sys_write(int fd, const void *buf, size_t len) {
    return sys6(SYS_write, fd, (long)buf, (long)len, 0, 0, 0);
}

static inline long sys_dup2(int oldfd, int newfd) {
    return sys6(SYS_dup3, oldfd, newfd, 0, 0, 0, 0);
}

static void set_tty_raw(int fd) {
    /* Linux AArch64 struct termios: c_iflag, c_oflag, c_cflag, c_lflag (4x u32) + c_line + c_cc[19] + speeds */
    struct {
        uint32_t c_iflag;
        uint32_t c_oflag;
        uint32_t c_cflag;
        uint32_t c_lflag;
        uint8_t  c_line;
        uint8_t  c_cc[19];
        uint32_t c_ispeed;
        uint32_t c_ospeed;
    } tio;
    if (sys6(SYS_ioctl, fd, 0x5401L /* TCGETS */, (long)&tio, 0, 0, 0) == 0) {
        tio.c_iflag &= ~(0x0001u | 0x0002u | 0x0008u | 0x0020u | 0x0040u | 0x0080u | 0x0100u | 0x0400u);
        tio.c_oflag &= ~0x0001u; /* Clear OPOST (prevents ONLCR 0x0A -> 0x0D 0x0A!) */
        tio.c_lflag &= ~(0x0001u | 0x0002u | 0x0008u | 0x8000u); /* Clear ISIG | ICANON | ECHO | IEXTEN */
        tio.c_cflag |= 0x0030u; /* CS8 */
        sys6(SYS_ioctl, fd, 0x5402L /* TCSETS */, (long)&tio, 0, 0, 0);
    }
}

static inline void sys_sleep_ms(long ms) {
    ktimespec_t ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    sys6(SYS_nanosleep, (long)&ts, 0, 0, 0, 0, 0);
}

/* Sub-millisecond sleep, in microseconds. */
static inline void sys_sleep_us(long us) {
    ktimespec_t ts;
    ts.tv_sec  = us / 1000000L;
    ts.tv_nsec = (us % 1000000L) * 1000L;
    sys6(SYS_nanosleep, (long)&ts, 0, 0, 0, 0, 0);
}

static inline uint64_t mkdev(uint32_t maj, uint32_t min) {
    return (((uint64_t)(maj & 0xfffu)) << 8) | ((uint64_t)(min & 0xffu));
}

/*
 * PHASE MARKERS GO TO /dev/kmsg, NOT /dev/console.
 *
 * The guest's debug console is the PL011 (ttyAMA0), and QNX's own
 * hypervisor documentation says about that device: "The PL011 serial
 * device is slow and has slow output because it interacts a lot with the
 * virtualized serial port." A blocking write() to /dev/console therefore
 * stalls the GUEST for tens of milliseconds -- measured on QEMU TCG, each
 * phase marker stalled the guest ~24 ms.
 *
 * That stall is fatal to the demonstration: the guest stopped producing
 * frames long enough for the supervisor's 2-tick watchdog to fire, the
 * supervisor failed closed into HA-HOLD -> HA-HOME, retracted theta, and
 * every later frame became a spurious RATE veto (48 envelope vetoes where
 * 7 are correct).
 *
 * /dev/kmsg writes into the kernel's log RING BUFFER and return
 * immediately; the console driver prints them out asynchronously. The
 * markers still appear in the guest console log -- they just no longer
 * stall the policy. The black channel (/dev/hvc0) is never used for
 * messages: it carries only LATH frames.
 */
static int g_kmsg_fd  = -1;
static int g_marker_fd = -1;

static void kputs(int fd, const char *s) {
    size_t len = 0;
    while (s[len] != '\0') ++len;
    sys_write(fd, s, len);
}

/*
 * Write a phase marker.
 *
 * The marker path must be NON-BLOCKING. A blocking write to the PL011 console
 * stalled the guest for tens of milliseconds per marker, which starved the
 * supervisor's 2-tick watchdog: it failed closed into HA-HOLD -> HA-HOME,
 * retracted theta, and turned every later frame into a spurious RATE veto
 * (48 envelope vetoes where 7 are correct).
 *
 * Primary path: the kernel log (/dev/kmsg) -- a ring buffer, so the write
 * returns immediately. The kernel's console driver may drop entries under
 * load, so the markers are a diagnostic aid, not the evidence: the host's
 * evidence tape is.
 *
 * A dedicated marker port is used if the platform offers one.
 */
static void phase_marker(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') ++len;

    if (g_marker_fd >= 0) {
        sys_write(g_marker_fd, s, len);
        sys_write(g_marker_fd, "\n", 1);
        return;
    }
    if (g_kmsg_fd >= 0) {
        /* /dev/kmsg expects "<level>" as the first bytes; 6 = informational. */
        sys_write(g_kmsg_fd, "<6>", 3);
        sys_write(g_kmsg_fd, s, len);
        sys_write(g_kmsg_fd, "\n", 1);
        return;
    }
    kputs(1, s);
}

static uint32_t ieee_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= buf[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 1u) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
        }
    }
    return ~crc;
}

static void pack_frame(lath_frame_t *f, uint32_t seq, int32_t u_mrad,
                       uint8_t flags, int corrupt_bit) {
    uint8_t *p = (uint8_t *)f;
    for (size_t i = 0; i < sizeof(*f); ++i) p[i] = 0;
    f->magic   = LATCH_WIRE_MAGIC;
    f->version = LATCH_WIRE_VERSION;
    f->joint   = LATCH_WIRE_JOINT;
    f->flags   = flags;
    f->seq     = seq;
    f->u_mrad  = u_mrad;
    f->crc32   = ieee_crc32((const uint8_t *)f, 16u);
    if (corrupt_bit) {
        f->u_mrad ^= 0x00000100;
    }
}

/*
 * TRANSPORT PACING -- the guest produces FASTER than the host consumes.
 *
 * The supervisor's 1 kHz loop drains exactly ONE proposal per tick from a
 * ring bounded by the manifest's `ingest.queue_depth`. The guest therefore
 * runs FASTER than 1 frame/ms (here: 4 frames every 200 us = 20 frames/ms),
 * so the ring always holds a backlog and the supervisor's watchdog never
 * fires spuriously. 20 frames/ms of production against 1 frame/ms of
 * consumption is a 20x margin, and the ring absorbs the difference.
 *
 * The writes are deliberately SMALL (4 frames = 128 bytes). A previous
 * revision wrote each phase as one 800-byte burst. That outran the QNX
 * virtio-console vdev's forwarding: the guest's virtqueue filled, the Linux
 * virtio-console driver spun waiting for the vdev to acknowledge, and the
 * next phase's frames arrived 12-21 supervisor ticks late. The supervisor's
 * 2-tick watchdog fired in each of those gaps, failed closed into
 * HA-HOLD -> HA-HOME, retracted theta, and turned every later frame into a
 * spurious RATE veto (48 envelope vetoes where 7 are correct).
 *
 * Small writes keep the vdev's queue short so it forwards continuously, and
 * the 200 us gap between writes is two orders of magnitude below the
 * supervisor's 2 ms watchdog -- so even a jittery forward cannot starve it.
 *
 * The safety story is the ORDER of the frames, and order is preserved
 * end-to-end: virtio-console -> QNX pipe -> latch-ingest -> the ring.
 */
#define LATCH_GUEST_FLUSH_FRAMES 4u
#define LATCH_GUEST_PACE_US      200u

/*
 * Total number of frames this policy emits (9 phases). The guest can run
 * ahead of the host's 1 kHz consumption, so the supervisor's ring must be
 * able to hold the WHOLE suite: `ingest.queue_depth >= LATCH_GUEST_SUITE_FRAMES`.
 * tools/consistency_check.py asserts that cross-file invariant.
 */
#define LATCH_GUEST_SUITE_FRAMES 84u

static uint8_t tx_buf[1024];
static size_t  tx_len = 0;
static uint32_t tx_frames = 0;

static void flush_frames(int hvc_fd) {
    const uint8_t *p = tx_buf;
    size_t rem = tx_len;
    while (rem > 0) {
        long n = sys_write(hvc_fd, p, rem);
        if (n < 0) {
            if (n == -4 || n == -11) { /* -EINTR / -EAGAIN */
                sys_sleep_us(100);
                continue;
            }
            break;
        }
        p += (size_t)n;
        rem -= (size_t)n;
    }
    tx_len = 0;
    tx_frames = 0;
}

static void send_frame(int hvc_fd, const lath_frame_t *f) {
    if (tx_len + sizeof(*f) > sizeof(tx_buf)) {
        flush_frames(hvc_fd);
    }
    const uint8_t *src = (const uint8_t *)f;
    for (size_t i = 0; i < sizeof(*f); ++i) {
        tx_buf[tx_len + i] = src[i];
    }
    tx_len += sizeof(*f);
    tx_frames++;

    /* Push the batch out and pace, so the vdev's queue never backs up. */
    if (tx_frames >= LATCH_GUEST_FLUSH_FRAMES) {
        flush_frames(hvc_fd);
        sys_sleep_us(LATCH_GUEST_PACE_US);
    }
}

void _start(void) {
    sys_mkdir("/proc", 0555);
    sys_mkdir("/sys", 0555);
    sys_mkdir("/dev", 0755);

    sys_mount("proc", "/proc", "proc");
    sys_mount("sysfs", "/sys", "sysfs");
    sys_mount("devtmpfs", "/dev", "devtmpfs");

    sys_mknod("/dev/console", S_IFCHR | 0600, mkdev(5, 1));
    sys_mknod("/dev/hvc0", S_IFCHR | 0660, mkdev(229, 0));
    sys_mknod("/dev/null", S_IFCHR | 0666, mkdev(1, 3));
    sys_mknod("/dev/kmsg", S_IFCHR | 0600, mkdev(1, 11));

    /* The kernel log ring buffer: non-blocking, unlike the slow PL011 path. */
    g_kmsg_fd = (int)sys_open("/dev/kmsg", O_WRONLY);

    /* An optional dedicated marker port. With the single-virtio-console
     * configuration there is no hvc1, and this open simply fails: the guest
     * then uses the kernel log, which is non-blocking. (A second virtio-console
     * vdev was tried here and REJECTED: it corrupted the frame channel on the
     * black channel -- the guest then delivered 26 of 84 frames.) */
    g_marker_fd = (int)sys_open("/dev/hvc1", O_WRONLY | O_NOCTTY);

    int cfd = (int)sys_open("/dev/console", O_RDWR);
    if (cfd >= 0) {
        sys_dup2(cfd, 0);
        sys_dup2(cfd, 1);
        sys_dup2(cfd, 2);
        if (cfd > 2) sys_close(cfd);
    }

    phase_marker("\n=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===\n");
    phase_marker("[guest] PID 1 = this binary. The in-guest policy IS /init.\n");

    int hvc_fd = -1;
    for (int attempt = 0; attempt < 20; ++attempt) {
        hvc_fd = (int)sys_open("/dev/hvc0", O_WRONLY | O_NOCTTY);
        if (hvc_fd >= 0) break;
        phase_marker("[guest] waiting for /dev/hvc0...\n");
        sys_sleep_ms(100);
    }

    if (hvc_fd < 0) {
        phase_marker("[guest] FATAL: cannot open /dev/hvc0\n");
        for (;;) sys_sleep_ms(10000);
    }

    phase_marker("[guest] /dev/hvc0 opened! Configuring raw mode & streaming the 84-frame LATH suite...\n");
    set_tty_raw(hvc_fd);

    uint32_t seq = 1u;
    int32_t theta = 0;
    lath_frame_t f;

    /* ---- Fault class 1: legal ramp (host stays in HP) ---- */
    phase_marker("[guest] phase 1/9: legal ramp (-10 mrad steps) -> host HP\n");
    for (int t = 1; t <= 25; ++t) {
        if (theta > -150) theta -= 10;
        pack_frame(&f, seq++, theta, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 2: keep-out violation (host vetoes -> HA-HOLD) ---- */
    phase_marker("[guest] phase 2/9: keep-out violation (+450 mrad, inside PERSON box) -> host VETO\n");
    for (int t = 26; t <= 32; ++t) {
        pack_frame(&f, seq++, 450, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 3: clean recovery (host returns to HP) ---- */
    phase_marker("[guest] phase 3/9: clean recovery (-150 mrad) -> host back to HP\n");
    for (int t = 33; t <= 57; ++t) {
        pack_frame(&f, seq++, -150, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 4: step down to the hold angle ---- */
    phase_marker("[guest] phase 4/9: step to hold angle (-180 mrad)\n");
    for (int t = 58; t <= 62; ++t) {
        if (theta > -180) theta -= 10;
        pack_frame(&f, seq++, theta, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 5: CRC bit-flip (host drops the payload) ---- */
    phase_marker("[guest] phase 5/9: CRC bit-flip -> host wire fault\n");
    for (int t = 63; t <= 66; ++t) {
        pack_frame(&f, seq++, -180, LATCH_WIRE_FLAG_NONE, 1);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 6: NaN sentinel (host drops the payload) ---- */
    phase_marker("[guest] phase 6/9: NaN sentinel (INT32_MIN) -> host NaN fault\n");
    for (int t = 67; t <= 70; ++t) {
        pack_frame(&f, seq++, LATCH_NAN_MRAD, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 7: valid frames ---- */
    phase_marker("[guest] phase 7/9: valid frames\n");
    uint32_t last_good_seq = seq;
    for (int t = 71; t <= 80; ++t) {
        last_good_seq = seq;
        pack_frame(&f, seq++, -180, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 8: sequence replay ---- */
    phase_marker("[guest] phase 8/9: sequence replay -> host SEQ fault\n");
    for (int t = 81; t <= 84; ++t) {
        pack_frame(&f, last_good_seq, -180, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    /* ---- Fault class 9: REAL SILENCE ----
     * NO BYTES ARE WRITTEN. The host sees a genuine gap on the channel,
     * trips LATCH_FAULT_WATCHDOG after watchdog_ticks, latches HA-HOLD and
     * retracts to HA-HOME after hold_to_home_ticks. A previous revision
     * sent LATCH_WIRE_FLAG_SILENCE frames here; the host ignores guest
     * flags for safety, so those were counted as replays and the watchdog
     * never fired. */
    phase_marker("[guest] phase 9/9: REAL SILENCE -- sending NO bytes -> host WATCHDOG -> HA-HOME\n");
    /* This long pause is the point of the demo: the host must see a REAL gap.
     * 400 ms comfortably covers watchdog_ticks (2) + hold_to_home_ticks (50)
     * plus the HA-HOME travel time, measured in HOST ticks -- and it also
     * covers the time latch-ingest needs to drain the frames still queued
     * from the phases above. */
    sys_sleep_ms(400);

    phase_marker("[guest] 84-frame LATH suite complete. Guest is now silent. Entering idle sleep.\n");
    sys_close(hvc_fd);

    for (;;) {
        sys_sleep_ms(60000);
    }
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}