/*
 * guest/latch_guest_init.c
 *
 * Freestanding static AArch64 Linux /init for the QNX Hypervisor 8.0 (qvm) guest.
 *
 * Zero libc dependencies: direct AArch64 Linux syscalls (`svc #0`).
 * Mounts proc/sysfs/devtmpfs, creates /dev/hvc0 (229:0) & /dev/console (5:1),
 * prints status to /dev/kmsg, and streams either the legacy 84-frame LATH
 * fault suite or (when built with LATCH_GOVERNOR_V2) the 235-frame GOVERNOR
 * lease/recovery scenario to /dev/hvc0.
 *
 * THE GUEST POLICY IS THIS BINARY.
 * guest/liar.py is a WORKSTATION-ONLY generator used by `make check` through a
 * POSIX pipe. It never runs inside qvm: there is no Python, no libc and no
 * shell in the cpio archive that `make guest-initrd` builds. Do not describe
 * liar.py as the in-guest policy in the README, the codelab or the video.
 *
 * The legacy v1 mode below retains its established fault-suite pacing and
 * sequence. GOVERNOR mode has its own A4 lease/recovery sequence, selected at
 * compile time; neither mode introduces a second policy process.
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
 * frames for the "silence" phase. The host DOES honor LATCH_WIRE_FLAG_SILENCE
 * as an idle tick (latchd.c:831-833) -- but that counts as a frame, not a gap.
 * This revision simply STOPS WRITING, so the host sees a genuine gap on the
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

#if defined(LATCH_GOVERNOR_INFER) && !defined(LATCH_GOVERNOR_V2)
#error "LATCH_GOVERNOR_INFER requires LATCH_GOVERNOR_V2 (the wire-v2 profile)"
#endif

#if defined(LATCH_GOVERNOR_LATENCY_SOAK) && !defined(LATCH_GOVERNOR_V2)
#error "LATCH_GOVERNOR_LATENCY_SOAK requires LATCH_GOVERNOR_V2 (the wire-v2 profile)"
#endif

/* The U-4 latency soak is a STANDALONE profile.  It is the scripted GOVERNOR
 * policy with the scenario replaced by a sustained frame stream, and it must
 * not be combined with the feedback-transport probe, the verdict watcher or
 * the inference relay: each of those has its own scenario, its own console
 * discipline and its own meaning, and mixing them would make the soak's
 * numbers describe a workload nobody can reproduce. */
#if defined(LATCH_GOVERNOR_LATENCY_SOAK) && \
    (defined(LATCH_GOVERNOR_FEEDBACK) || defined(LATCH_GOVERNOR_FEEDBACK_VERDICT) || \
     defined(LATCH_GOVERNOR_INFER))
#error "LATCH_GOVERNOR_LATENCY_SOAK is a standalone profile: it cannot be combined with the feedback probe, the verdict watcher or the inference relay"
#endif

#define AT_FDCWD        (-100)
#define O_RDONLY        0
#define O_WRONLY        1
#define O_RDWR          2
#define O_NOCTTY        0400
#define O_NONBLOCK      04000
/* O_DIRECT (asm-generic/fcntl.h): 00040000 octal.  See fb_open_block() --
 * a buffered read of a block device is served from the GUEST's page cache
 * after the first read, and a page cache is a correct implementation of a
 * file and a wrong implementation of a channel. */
#define O_DIRECT        00040000
#define O_CLOEXEC       02000000
#define S_IFCHR         0020000

#define SYS_dup3        24
#define SYS_ioctl       29
#define SYS_mknodat     33
#define SYS_mkdirat     34
#define SYS_mount       40
#define SYS_openat      56
#define SYS_pipe2       59
#define SYS_close       57
#define SYS_read        63
#define SYS_write       64
#define SYS_exit        93
#define SYS_exit_group  94
#define SYS_nanosleep   101
#define SYS_clock_gettime 113
#define SYS_clone       220
#define SYS_execve      221
#define SYS_wait4       260
#define SYS_ppoll       73
#define SYS_fcntl       25
#define SYS_pread64     67
/* fadvise64 (asm-generic/unistd.h: __NR3264_fadvise64 = 223, and arm64
 * has only the 64-bit-offset variant, so 223 is its fadvise64). */
#define SYS_fadvise64   223

/* POSIX_FADV_DONTNEED (include/uapi/linux/fcntl.h): drop the page cache
 * for the range, so the next read goes to the device. */
#define POSIX_FADV_DONTNEED 4

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

/*
 * A POSITIONED READ.
 *
 * AArch64's `pread64` is syscall 67 and takes (fd, buf, count, offset) with
 * a 64-bit offset in x3 -- arm64's `off_t` is 64 bits, so there is no
 * 32-bit-offset variant to fall back to.
 *
 * This is what the feedback-transport profile uses to read the verdict
 * sector of the hypervisor's virtio-blk device: the verdict file is
 * served to the guest as a block device, and the guest polls ONE sector of
 * it.
 */
static inline long sys_pread64(int fd, void *buf, size_t len, long long offset) {
    return sys6(SYS_pread64, fd, (long)buf, (long)len, (long)offset, 0, 0);
}

/*
 * A DROP-THE-PAGE-CACHE ADVICE.
 *
 * `fadvise64(fd, 0, 0, POSIX_FADV_DONTNEED)` asks the kernel to discard the
 * cached pages of the whole file, so the NEXT read goes back to the device.
 * It is the standard way to poll a file for changes: POSIX has no
 * "poll this file" call, and the page cache is what makes a repeated read
 * return the SAME bytes.
 *
 * The return value is the number of pages discarded, or -errno.  The caller
 * records the error, because a silently ineffective advice would look
 * exactly like a transport that never changes.
 */
static inline long sys_fadvise64(int fd, long long offset, long long len, int advice) {
    return sys6(SYS_fadvise64, fd, (long)offset, (long)len, (long)advice, 0, 0);
}

static inline long sys_dup2(int oldfd, int newfd) {
    return sys6(SYS_dup3, oldfd, newfd, 0, 0, 0, 0);
}

static inline long sys_mount_ext(const char *src, const char *tgt,
                                 const char *fstype, unsigned long flags) {
    return sys6(SYS_mount, (long)src, (long)tgt, (long)fstype,
                (long)flags, 0, 0);
}

/* ------------------------------------------------------------------------
 * READ / POLL -- shared by the EXPERIMENTAL profiles.
 *
 * AArch64 has NO plain `poll` syscall (7 on x86_64); the only poll-family
 * syscall is `ppoll` (73).  These live OUTSIDE the inference block because
 * the feedback-transport profile needs them too.
 * ------------------------------------------------------------------------ */
#define POLLIN         0x0001
#define POLLERR        0x0008
#define POLLHUP        0x0010
#define POLLNVAL       0x0020

typedef struct {
    int   fd;
    short events;
    short revents;
} latch_pollfd_t;

static inline long sys_read(int fd, void *buf, size_t len) {
    return sys6(SYS_read, fd, (long)buf, (long)len, 0, 0, 0);
}

static inline long sys_ppoll(latch_pollfd_t *fds, unsigned long nfds,
                              const ktimespec_t *timeout) {
    return sys6(SYS_ppoll, (long)fds, (long)nfds, (long)timeout, 0, 0, 0);
}

#ifdef LATCH_GOVERNOR_INFER

/* ------------------------------------------------------------------------
 * SYSCALLS FOR THE INFERENCE RELAY
 *
 * The numbers are the AArch64 (asm-generic) ones, read out of the
 * cross-sysroot's asm-generic/unistd.h -- not from memory:
 *
 *     pipe2      59   READ  (AArch64 has NO plain `pipe` syscall)
 *     read       63
 *     ppoll      73   READ  (AArch64 has NO plain `poll` syscall either:
 *                           `poll` is 7 on x86_64, but on arm64 the only
 *                           poll-family syscall is `ppoll`.)
 *     clone     220   READ  (the fork-like form: SIGCHLD only)
 *     execve    221
 *     wait4     260
 *     fcntl      25
 *
 * `pipe2` and `ppoll` matter: a policy that used `pipe` or `poll`
 * because every other architecture has them would fail with ENOSYS on
 * the guest and the failure would look like "the guest is quiet".
 * ------------------------------------------------------------------------ */
#define F_SETFD        2
#define FD_CLOEXEC     1
#define LATCH_MS_RDONLY 1
#define SIGCHLD        17
#define WNOHANG        1

static inline long sys_pipe2(int *fds, int flags) {
    return sys6(SYS_pipe2, (long)fds, flags, 0, 0, 0, 0);
}

/*
 * clone() in the fork-like form.
 *
 * WHY THE STACK ARGUMENT IS ZERO
 * ------------------------------
 * The Linux arm64 kernel's copy_thread() (arch/arm64/kernel/process.c)
 * does:
 *
 *     if (stack_start) {
 *         childregs->sp = stack_start;
 *     }
 *
 * and otherwise leaves the child's SP at the parent's SP.  Passing 0
 * therefore gives EXACT fork() semantics: the child runs on a
 * copy-on-write copy of the parent's address space, continuing on the
 * (copied) parent stack.
 *
 * Passing a separate child stack would be the other textbook approach,
 * but it is UNSAFE in a freestanding binary written in C: the child's SP
 * would be the new stack, while the compiler's function epilogue pops
 * the saved frame pointer and the return address from THAT stack --
 * memory nobody ever wrote.  The child would return to a garbage
 * address.  glibc avoids this by making its clone() wrapper's child
 * path non-returning in assembly; passing 0 avoids the problem
 * entirely, because the stack the epilogue reads is the parent's
 * copy, which is valid.
 *
 * `SIGCHLD` alone (no CLONE_VM) gives the child its own address space:
 * this is a fork, not a thread.  The child immediately execve()s, so it
 * never shares memory with the policy.
 */
static inline long sys_clone_fork(void) {
    return sys6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
}

static inline long sys_execve(const char *path, const char *const argv[],
                              const char *const envp[]) {
    return sys6(SYS_execve, (long)path, (long)argv, (long)envp, 0, 0, 0);
}

static inline long sys_fcntl(int fd, int cmd, long arg) {
    return sys6(SYS_fcntl, fd, cmd, arg, 0, 0, 0);
}

static inline long sys_wait4(int pid, int *status, int options) {
    return sys6(SYS_wait4, pid, (long)status, options, 0, 0, 0);
}

static inline void sys_exit_group(int code) {
    sys6(SYS_exit_group, code, 0, 0, 0, 0, 0);
    for (;;) { }
}

#endif /* LATCH_GOVERNOR_INFER */

/* Linux AArch64 struct termios: c_iflag, c_oflag, c_cflag, c_lflag (4x u32)
 * + c_line + c_cc[19] + the two speed fields. */
typedef struct {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_cflag;
    uint32_t c_lflag;
    uint8_t  c_line;
    uint8_t  c_cc[19];
    uint32_t c_ispeed;
    uint32_t c_ospeed;
} latch_termios_t;

/*
 * THE SERIAL FORM OF THE FEEDBACK TRANSPORT WAS REJECTED BY MEASUREMENT.
 *
 * The first version of this channel put the verdict stream on a second
 * PL011, so the guest's side of it needed a line discipline: canonical
 * mode would hold every read until a newline arrived, and a binary frame
 * never contains one.  The termios helpers below implemented that.
 *
 * They are GONE, because the serial form does not work on this platform:
 *
 *   - the PL011 vdev's host->guest injection never delivers (the bytes
 *     reach the hypervisor's own buffer and stop there), and
 *   - the virtio-console vdev's host->guest input direction never
 *     delivers either (its `receive_host_data` is reachable only through
 *     a flag that an unreachable error-recovery path sets).
 *
 * The transport that DOES work is a POLLED BLOCK DEVICE, which has no
 * line discipline at all.  See `run_feedback_probe()` below and AGENTS.md
 * section 4c for the measurements.
 */

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

/*
 * THE GUEST'S OWN MONOTONIC CLOCK.
 *
 * clock_gettime(CLOCK_MONOTONIC) is syscall 113 on AArch64
 * (asm-generic/unistd.h: __NR_clock_gettime = 113) and CLOCK_MONOTONIC is
 * 1.  The guest reads it for ONE reason: the U-4 latency soak paces itself
 * against a DEADLINE on this clock instead of sleeping for a fixed time.
 *
 * WHY A DEADLINE AND NOT A FIXED SLEEP.  A fixed sleep accumulates every
 * scheduling hiccup: a soak of 1.5 million frames would drift by the sum
 * of 1.5 million jitter terms, and the frame rate the supervisor actually
 * saw would be a function of the host's load rather than of the guest's
 * intent.  A deadline is self-correcting: the target time of frame N is
 * `start + N * period`, so the ACHIEVED RATE is the target rate as long as
 * the guest can produce that fast, and the achieved rate is the guest's own
 * maximum when it cannot.
 *
 * The clock is read through the raw syscall because this binary is
 * freestanding: there is no libc here to wrap it.
 */
#define CLOCK_MONOTONIC 1

static inline uint64_t guest_now_ns(void) {
    ktimespec_t ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = 0;
    if (sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&ts, 0, 0, 0, 0) != 0) {
        return 0u;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
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
 *
 * ONE WRITE PER MARKER
 * --------------------
 * `/dev/kmsg` treats EVERY write() as ONE record: the kernel parses the
 * "<level>" prefix from the start of the buffer and takes the REST of the
 * buffer as the message.  Writing the prefix, the message and the newline
 * as three separate write() calls therefore produces THREE records --
 * an empty one, the message, and another empty one -- and burns three
 * units of the userspace rate-limit budget for one marker.
 *
 * That budget is real: `/proc/sys/kernel/printk_devkmsg` defaults to
 * "ratelimit", which allows 10 messages per 5 seconds PER PROCESS
 * (`DEFAULT_RATELIMIT_BURST` = 10, `DEFAULT_RATELIMIT_INTERVAL` = 5*HZ
 * in `include/linux/ratelimit_types.h`; the check is in
 * `devkmsg_write()` in `kernel/printk/printk.c`).
 *
 * Measured on the QEMU AArch64 target (2026-11-26): with three writes per
 * marker, the first three markers of the in-guest inference profile
 * consumed the whole budget and EVERY LATER MARKER WAS SILENTLY DROPPED.
 * The guest console showed the model's own decisions but none of the
 * policy's `[INFER] ...` markers, which looked like a missing feature and
 * was in fact a rate limit.
 *
 * So the record is assembled in one buffer and written ONCE, and the
 * policy turns the rate limit off for this guest (see
 * `enable_devkmsg_log()`).  The policy emits a bounded number of markers
 * -- one per phase -- so there is no flood risk to turn off.
 */
static char g_marker_buf[256];

static void phase_marker(const char *s) {
    size_t len = 0;
    while (s[len] != '\0') ++len;

    if (g_marker_fd >= 0) {
        sys_write(g_marker_fd, s, len);
        sys_write(g_marker_fd, "\n", 1);
        return;
    }
    if (g_kmsg_fd >= 0) {
        /* "<6>" + message + "\n", as ONE record.  6 = informational. */
        if (len + 5u > sizeof(g_marker_buf)) {
            return;             /* never truncate a marker silently */
        }
        g_marker_buf[0] = '<';
        g_marker_buf[1] = '6';
        g_marker_buf[2] = '>';
        for (size_t i = 0u; i < len; ++i) {
            g_marker_buf[3u + i] = s[i];
        }
        g_marker_buf[3u + len] = '\n';
        sys_write(g_kmsg_fd, g_marker_buf, len + 4u);
        return;
    }
    kputs(1, s);
}

/*
 * Turn OFF the /dev/kmsg userspace rate limit for this guest.
 *
 * `/proc/sys/kernel/printk_devkmsg` accepts "on" (no rate limit), "off"
 * (ignore userspace messages entirely) and "ratelimit" (the default: 10
 * messages per 5 seconds per process).  The policy wants "on": it emits
 * one marker per phase, and a marker that is silently dropped is worse
 * than useless -- it makes the evidence look like the feature is missing.
 *
 * The write is best-effort: if the sysctl is absent or read-only the
 * markers still work, they are just rate limited.  A failure here is NOT
 * a safety event, so it is not reported as one.
 */
static void enable_devkmsg_log(void) {
    int fd = (int)sys_open("/proc/sys/kernel/printk_devkmsg", O_WRONLY);
    if (fd < 0) {
        return;
    }
    sys_write(fd, "on\n", 3);
    sys_close(fd);
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

#ifndef LATCH_GOVERNOR_V2
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
#endif

/*
 * LEGACY V1 TRANSPORT PACING -- the guest produces FASTER than the host consumes.
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
 * Total number of frames the legacy v1 policy emits (9 phases). The guest can run
 * ahead of the host's 1 kHz consumption, so the supervisor's ring must be
 * able to hold the WHOLE suite: `ingest.queue_depth >= LATCH_GUEST_SUITE_FRAMES`.
 * tools/consistency_check.py asserts that cross-file invariant.
 */
#define LATCH_GUEST_SUITE_FRAMES 84u
#define LATCH_GOVERNOR_SUITE_FRAMES 235u
#define LATCH_GOVERNOR_DEMO_LEASE_TICKS 100u
#define LATCH_GOVERNOR_A4_DELAY_MS 110u
#define LATCH_GOVERNOR_HEARTBEAT_HOLD_MS 1u
#define LATCH_GOVERNOR_FINAL_SILENCE_MS 600u

/*
 * THE CONSOLE-DRAIN WAIT.
 *
 * A /dev/kmsg write returns as soon as the record is in the kernel's
 * ring buffer, but the kernel's console thread then pushes it out
 * through the PL011 at ~1.3-1.8 ms PER CHARACTER.  The guest has
 * therefore finished "printing" the scenario plan while the HOST is
 * still busy serving it -- and that host-side drain lands on the wrong
 * side of the lease if the session opens immediately.
 *
 * Measured on the QEMU AArch64 target (2026-11-26), with the plan
 * printed and the session opened immediately:
 *
 *     the guest's own clock:  sleep(110) = 111.66 ms, write = 0.97 ms
 *     the supervisor's view:  268 TICKS of silence, TWO lease
 *                            expiries, ADVISE -> CLAMP, and the A4
 *                            command REJECTED with DOSE (0x8000)
 *
 * i.e. the host's tick index advanced 268 for an event the guest
 * measured as 112.6 ms -- a 2.4x skew.  The deadman counted the
 * console drain as guest silence and demoted the ladder TWICE for a
 * silence that was meant to expire the lease ONCE.
 *
 * The wait below lets the console go quiet BEFORE the session opens,
 * while the deadman is not yet running.  It is deliberately generous:
 * it is longer than the measured cost of the whole plan (8 lines,
 * ~480 characters, at the measured 1.3-1.8 ms per character), and
 * tools/consistency_check.py FAILS THE BUILD if the plan grows
 * without this wait growing with it.
 *
 * It also has to cover the W4 feedback probe's report, which the
 * FEEDBACK profile prints BEFORE the plan (the console is FIFO, so the
 * plan's drain has to empty that traffic too).  The probe's report is
 * built in a 256-byte buffer, so the worst case is 256 characters plus
 * the kernel's ~15-character timestamp prefix -- 271 characters, about
 * 488 ms at the measured upper bound of 1.8 ms/char.  Added to the
 * plan's own 619 characters that is 890 characters and a required
 * drain of 1602 ms, so the wait is 1700 ms.
 */
#define LATCH_GOVERNOR_CONSOLE_DRAIN_MS 1700u
#define LATCH_GOVERNOR_WARMUP_HEARTBEATS 4u
#define LATCH_GOVERNOR_A4_RESUME_COMMANDS 1u
#define LATCH_GOVERNOR_HEARTBEAT_HOLD_FRAMES 150u
#define LATCH_GOVERNOR_RECOVERY_COMMANDS 25u
#define LATCH_GOVERNOR_NOMINAL_COMMANDS 50u
#define LATCH_GOVERNOR_POLICY_SAMPLE_FRAMES 5u

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

#ifdef LATCH_GOVERNOR_V2
enum {
    GOV_WIRE_HEARTBEAT = 1u,
    GOV_WIRE_CMD_V2 = 2u,
    GOV_WIRE_SHRINK_REQ = 3u
};

static void store_le16(uint8_t *p, uint16_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void store_le24(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
}

static void store_le32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

/* Keep this byte layout aligned with docs/GOVERNOR_PROTOCOL_V2.md. */
static void pack_governor_frame(lath_frame_t *frame, uint8_t kind, uint32_t seq,
                                uint32_t coherence, int32_t value,
                                uint8_t confidence_q8, uint8_t agent_state,
                                uint32_t unit_id) {
    uint8_t *p = (uint8_t *)frame;
    uint8_t crc_input[28];
    for (size_t i = 0; i < sizeof(*frame); ++i) p[i] = 0;
    store_le32(p + 0, LATCH_WIRE_MAGIC);
    store_le16(p + 4, 2u);
    p[6] = LATCH_WIRE_JOINT;
    p[7] = kind;
    store_le32(p + 8, seq);
    store_le32(p + 12, (uint32_t)value);
    store_le32(p + 20, confidence_q8);
    p[24] = agent_state;
    store_le24(p + 25, coherence);
    store_le32(p + 28, unit_id);
    for (size_t i = 0; i < 16u; ++i) crc_input[i] = p[i];
    for (size_t i = 0; i < 12u; ++i) crc_input[16u + i] = p[20u + i];
    store_le32(p + 16, ieee_crc32(crc_input, sizeof(crc_input)));
}

static void send_governor_frame(int hvc_fd, lath_frame_t *frame, uint8_t kind,
                                uint32_t *seq, uint32_t *coherence, int32_t value,
                                uint8_t confidence_q8, uint32_t unit_id) {
    pack_governor_frame(frame, kind, (*seq)++, ++(*coherence), value,
                        confidence_q8, 1u, unit_id);
    send_frame(hvc_fd, frame);
}

#ifdef LATCH_GOVERNOR_INFER

#include "latch_action.h"

/* ------------------------------------------------------------------------
 * THE IN-GUEST INFERENCE RELAY
 *
 * WHAT THIS IS
 * ------------
 * The experimental profile runs a language model INSIDE the guest:
 *
 *     PID 1 (this binary, freestanding)  --owns-->  /dev/hvc0
 *        |
 *        |  pipe carrying 32-byte wire-v2 frames
 *        v
 *     latch_infer  (a static AArch64 C++ binary: llama.cpp + the action
 *                   schema validator)
 *
 * The model runs in the UNTRUSTED guest, so the split is deliberate:
 *
 *   * the model may only PROPOSE.  Its output passes a GBNF grammar
 *     (inside latch_infer) and an INDEPENDENT JSON validator (also
 *     inside latch_infer) before it becomes a frame at all;
 *   * the policy re-checks the frame's magic, version, joint and CRC
 *     before it relays it, and DROPS anything that fails;
 *   * the policy is the ONLY writer on the virtio-console.  The child
 *     cannot write to it: the descriptor is marked close-on-exec
 *     before the fork, and the child closes it explicitly as well;
 *   * the policy owns the wire's sequence number and coherence counter
 *     and re-stamps them on the way out (see latch_wire_v2_restamp);
 *   * if the child dies, the pipe closes, the policy stops writing, and
 *     the supervisor's deadman expires the lease -> HA-HOLD -> HA-HOME.
 *     That is the fail-closed path, and it is the SAME observable
 *     behaviour as the guest going silent.
 *
 * WHAT THE POLICY DOES NOT DO
 * ---------------------------
 * It does not know the safety envelope.  The keep-out box, the rate
 * limit, the unit whitelist and the lease live in the SIGNED MANIFEST
 * and are enforced by the trusted QNX supervisor.  A safety parameter
 * duplicated in the untrusted guest would be an untrusted copy of a
 * safety parameter -- patchable by whoever controls the guest -- so it
 * could not be relied upon even if it were signed.
 *
 * WHY THE POLICY SENDS HEARTBEATS
 * -------------------------------
 * The supervisor's deadman requires `warmup_heartbeats` heartbeats
 * before the first command is admissible, and it rejects a frame whose
 * coherence counter jumps by more than `coherence_max_gap`.  A language
 * model takes SECONDS to think; the supervisor's lease is measured in
 * MILLISECONDS.  So the policy keeps the lease alive with heartbeats
 * while the model thinks, and re-stamps the model's command so the
 * coherence sequence stays contiguous.
 * ------------------------------------------------------------------------ */

#define LATCH_INFER_MODEL_PATH   "/model/latch_model.gguf"
#define LATCH_INFER_BIN_PATH     "/model/latch_infer"
#define LATCH_INFER_OUT_FD       3

/*
 * THE HEARTBEAT CADENCE IS DERIVED FROM THE SIGNED CONTRACT, NOT CHOSEN.
 *
 * The supervisor's deadman lease is `governor.deadman.lease_ticks` ticks
 * of `timing.period_us` -- in the signed `governor_servo.manifest` that
 * is 100 ticks at 1000 us, i.e. a 100 ms lease.  The lease is decremented
 * once per supervisor tick and is renewed only by a frame that the
 * OWNER sent and that was accepted as coherent.
 *
 * So the heartbeat period MUST be comfortably shorter than the lease.
 * A 200 ms period (an earlier value in this file) would have let the
 * lease EXPIRE between two heartbeats -- the supervisor would have
 * latched LATCH_FAULT_HEARTBEAT, declared the session dead and failed
 * closed into HA-HOLD, and the experiment would have looked like "the
 * model is unreliable" when the cause was a too-slow heartbeat.
 *
 * 10 ms gives a 10x margin against the 100 ms lease, and it is also
 * faster than the supervisor's 1 kHz decision tick, so the lease is
 * always renewed before it can run down.
 *
 * The lease cannot simply be lengthened instead: the manifest loader
 * caps `lease_ticks` at 100 (`qnx/latch_manifest.c`, the "Schema 3
 * governor values are invalid or outside the supported range" check),
 * and that cap is a deliberate safety bound -- it bounds how long the
 * trusted host waits for a producer before failing closed.  Raising it
 * for the experiment would mean the experiment is judged by a DIFFERENT
 * contract than the scripted profile.  It is not.
 *
 * Heartbeats are free of the rate limiter: the rate bucket is charged
 * only for commands, so the heartbeat stream costs the supervisor
 * nothing in envelope terms.
 */
#define LATCH_INFER_HEARTBEAT_MS 10

/*
 * The mount is retried while the block device appears, which is not
 * ordered against PID 1's startup.  The session is NOT open yet at this
 * point (the READY handshake comes later), so a wait here costs nothing:
 * the deadman is not running.  250 x 20 ms is the same 5 s of patience
 * as the original 50 x 100 ms, at a tenth of the gap between retries.
 */
#define LATCH_INFER_MOUNT_TRIES    250
#define LATCH_INFER_MOUNT_SLEEP_MS 20
#define LATCH_INFER_RX_BUFSZ       256

/*
 * The readiness byte the inference child sends once the model and the
 * context exist.  The policy opens its session on this byte and not
 * before, so the supervisor's deadman measures the producer's LIVENESS
 * rather than its STARTUP.
 */
#define LATCH_INFER_READY_BYTE    0xA5u

static const char *const g_infer_argv[] = {
    "latch_infer",
    "--model", LATCH_INFER_MODEL_PATH,
    "--out-fd", "3",
    /*
     * ONE THREAD, ON PURPOSE.
     *
     * The guest has TWO vCPUs (`cluster _cpu-2,_cpu-3` in the qvmconf).
     * With two inference threads, BOTH vCPUs are saturated by the
     * model's compute and the POLICY -- the process that owns the
     * lease -- has to compete with them for a CPU.  The measured
     * consequence on the QEMU AArch64 target (2026-11-26) was that the
     * policy's heartbeat interval stretched from 11 ms to as much as
     * 82 ms against a 100-tick lease: the producer was alive, but it
     * was alive at the edge of its budget.
     *
     * With one thread, the compute has a vCPU to itself and the policy
     * has the other.  The compute takes about twice as long, which
     * costs the experiment a minute and buys the lease its margin.
     * This is a SCHEDULING decision, not a safety parameter: the
     * signed contract is untouched, and the supervisor cannot tell
     * the difference.
     */
    "--n-threads", "1",
    (const char *)0
};

static const char *const g_infer_envp[] = {
    "LATCH_GUEST=1",
    (const char *)0
};

static int g_infer_pipe_w = -1;
static int g_infer_hvc_fd = -1;

/*
 * Stop sending, permanently.  The host sees a genuine gap on the
 * channel, the supervisor's deadman expires the lease, and the system
 * fails closed into HA-HOLD -> HA-HOME.  Nothing here is a "best
 * effort" continuation: once the policy cannot produce valid frames,
 * it produces NO frames.
 */
static void guest_fail_closed_msg(int hvc_fd, const char *reason) {
    /* CLOSE THE WIRE FIRST.
     *
     * The session is over the moment the wire is closed, and a console
     * write costs 57-88 ms of guest time on this platform -- roughly
     * 1.3-1.8 ms per character -- which is most of the signed 100-tick
     * lease.  So the order is: stop sending, THEN report.  Writing the
     * marker first would put a hole in a session that is still live.
     *
     * The marker itself is written to /dev/kmsg, not to the wire, so
     * closing the wire does not silence it.
     */
    if (hvc_fd >= 0) {
        sys_close(hvc_fd);
    }
    phase_marker(reason);
    for (;;) sys_sleep_ms(60000);
}

static void guest_fail_closed(int hvc_fd) {
    guest_fail_closed_msg(hvc_fd,
        "[INFER] FAIL CLOSED: this guest will send no further frames\n");
}

/*
 * The child's continuation.  It NEVER returns: it either execve()s the
 * inference binary or exits.  The parent's clone() call cannot unwind
 * through this frame -- see sys_clone_fork() for why that is safe.
 */
static void latch_infer_child_main(void) {
    /* Put the pipe's write end on fd 3, which is where the inference
     * program writes its frames.  dup3() clears FD_CLOEXEC on the new
     * descriptor, so fd 3 SURVIVES the execve() while the original
     * pipe descriptors (which are close-on-exec) do not. */
    sys6(SYS_dup3, g_infer_pipe_w, LATCH_INFER_OUT_FD, 0, 0, 0, 0);
    sys_execve(LATCH_INFER_BIN_PATH, g_infer_argv, g_infer_envp);
    sys_exit_group(127);
}

/*
 * A marker on the relay path, BRACKETED BY HEARTBEATS.
 *
 * The relay path writes nothing to the console in the ordinary case --
 * see the ordering note at the fork and at the warm-up.  A dropped
 * frame is worth reporting, though, and a console write costs 57-88 ms
 * of guest time on this platform, which is most of the 100-tick lease.
 *
 * So the lease is renewed on BOTH sides of the report: the gap the
 * supervisor sees is one marker's cost (57-88 ms), which fits inside
 * the 100-tick lease, and it is the ONLY console write the steady-state
 * relay path can make.
 *
 * If a marker ever costs MORE than the lease, the supervisor will fail
 * closed and demote itself.  That is the correct behaviour for a
 * producer that stopped speaking, and it is the right answer even when
 * the reason is the policy's own diagnostics -- which is exactly why
 * there are so few of them.
 */
static void relay_note(int hvc_fd, lath_frame_t *frame, uint32_t *seq,
                       uint32_t *coherence, const char *msg) {
    send_governor_frame(hvc_fd, frame, GOV_WIRE_HEARTBEAT, seq, coherence, 0, 0u, 0u);
    flush_frames(hvc_fd);
    phase_marker(msg);
    send_governor_frame(hvc_fd, frame, GOV_WIRE_HEARTBEAT, seq, coherence, 0, 0u, 0u);
    flush_frames(hvc_fd);
}

static void run_infer_profile(int hvc_fd) {
    lath_frame_t frame;
    uint32_t seq = 1u;
    uint32_t coherence = 0u;
    uint8_t rx[LATCH_INFER_RX_BUFSZ];
    size_t rx_len = 0u;
    int fds[2];

    g_infer_hvc_fd = hvc_fd;

    /* ---- 1. The asset disk -----------------------------------------
     * The model AND the inference program arrive on a read-only
     * virtio-blk disk (the hypervisor's `hostdev <` form makes the
     * backing file read-only to the guest), and are mounted as ext4.
     *
     * The mount is READ-ONLY (MS_RDONLY).  The device is already
     * read-only -- that is the hypervisor's doing, not the guest's --
     * but mounting it read-only as well means the guest's own attempt to
     * write gets refused by the kernel before it ever reaches the
     * device.  Two independent mechanisms, one property.
     *
     * The mount is retried because the block device appears when the
     * guest kernel probes the virtio device, which is not ordered
     * against PID 1's startup.
     *
     * WHY THE ASSETS ARE NOT IN THE INITRAMFS
     * ---------------------------------------
     * Because qvm cannot put them there.  Measured on the QEMU AArch64
     * target: an initramfs of 8.9 MiB reached the guest kernel as a
     * buffer that was NOT the gzip archive ("Initramfs unpacking failed:
     * invalid magic at start of compressed archive"), while the scripted
     * profile's 3.3 KiB initramfs works.  qvm's load_blob() copies a
     * small blob straight into guest memory but transfers a large one in
     * 64 KiB message-block chunks that the GUEST has to service -- and
     * that service code lives in the QNX guest BSP, not in upstream
     * Linux.  The assets therefore travel over the virtio protocol,
     * which does not go through qvm's blob loader at all. */
    sys_mkdir("/model", 0755);
    phase_marker("[INFER] mounting the asset disk at /model...\n");
    int mounted = 0;
    for (int i = 0; i < LATCH_INFER_MOUNT_TRIES; ++i) {
        if (sys_mount_ext("/dev/vda", "/model", "ext4", LATCH_MS_RDONLY) == 0) {
            mounted = 1;
            break;
        }
        /* The lease is NOT running yet -- the session opens only when the
         * producer is ready to produce (see the READY handshake below).
         * So a wait here costs nothing. */
        sys_sleep_ms(LATCH_INFER_MOUNT_SLEEP_MS);
    }
    if (!mounted) {
        phase_marker("[INFER] FATAL: cannot mount /dev/vda -- there are no assets\n");
        guest_fail_closed(hvc_fd);
    }
    phase_marker("[INFER] asset disk mounted read-only\n");

    /* ---- 3. The pipe ----------------------------------------------- */
    if (sys_pipe2(fds, O_CLOEXEC) != 0) {
        phase_marker("[INFER] FATAL: pipe2 failed\n");
        guest_fail_closed(hvc_fd);
    }

    /* ---- 4. Close-on-exec the descriptors the child must not keep ---
     * The wire is the safety-relevant channel.  The child must not be
     * able to write to it, so the descriptor is marked close-on-exec
     * BEFORE the fork: execve() then closes it in the child.  The
     * child also closes it explicitly before the exec, so there is no
     * window in which it holds the descriptor. */
    sys_fcntl(hvc_fd, F_SETFD, FD_CLOEXEC);
    if (g_kmsg_fd >= 0) sys_fcntl(g_kmsg_fd, F_SETFD, FD_CLOEXEC);
    if (g_marker_fd >= 0) sys_fcntl(g_marker_fd, F_SETFD, FD_CLOEXEC);

    /* ---- 5. Fork the inference child --------------------------------
     *
     * The console markers around the fork are cheap NOW, because the
     * session has not been opened yet: the supervisor's deadman only
     * runs once the producer has started producing.
     */
    phase_marker("[INFER] starting the inference child...\n");
    g_infer_pipe_w = fds[1];
    long pid = sys_clone_fork();
    if (pid < 0) {
        phase_marker("[INFER] FATAL: clone failed\n");
        guest_fail_closed(hvc_fd);
    }
    if (pid == 0) {
        /* The child.  It never returns to the parent's code path. */
        sys_close(fds[0]);
        if (g_infer_hvc_fd >= 0) sys_close(g_infer_hvc_fd);
        latch_infer_child_main();
        sys_exit_group(127);
    }
    /* The parent keeps only the read end, so the pipe reaches EOF the
     * moment the child is gone. */
    sys_close(fds[1]);

    /* ---- 6. Wait for the producer to become ready ---------------------
     *
     * THE SESSION OPENS HERE, NOT BEFORE.  The supervisor's deadman
     * starts counting when the first frame arrives, so the moment the
     * session opens is the moment the producer has to be ready to
     * produce.
     *
     * Two measured defects on the QEMU AArch64 target (2026-11-26)
     * shaped this handshake, and both of them are about the same thing:
     * the supervised window must contain NOTHING that can stall it.
     *
     * DEFECT 1 -- THE SESSION OPENED BEFORE THE MODEL WAS LOADED.
     * Loading the model reads 168 MB from the hypervisor's block
     * device, and while that I/O is in flight the host is busy enough
     * that the virtio-console forwarding stalls for hundreds of
     * milliseconds -- far longer than the signed 100-tick lease.
     *
     *   guest-t  7.997  the warm-up heartbeats went out
     *   guest-t  8.049  the asset-disk mount started
     *   guest-t  8.386  the mount finished        (337 ms, one syscall)
     *   guest-t  8.579  the first relay heartbeat write started
     *   guest-t  8.653  the write returned        (73 ms, BLOCKED)
     *
     * The host saw a 594-tick hole in the frame stream, the deadman
     * fired five times and the supervisor demoted itself HP -> ADVISE
     * -> CLAMP -> SLOW -> SAFE_STOP -> LATCH before the model had said
     * a word.  The supervisor was RIGHT to: a producer that goes silent
     * for longer than the lease must not keep full authority.  The
     * producer was wrong to open its session before it could produce.
     *
     * DEFECT 2 -- THE MODEL'S OWN ANNOUNCEMENT WAS INSIDE THE WINDOW.
     * A console line on this platform is not free: a `/dev/kmsg` write
     * becomes a printk, and the guest's PL011 console is slow.  Measured
     * on the target: 57-88 ms of GUEST TIME per line, at roughly
     * 1.3-1.8 ms per CHARACTER.  The model's decision line is 119
     * characters, so announcing it inside the supervised window cost
     * about 153 ticks -- more than the 100-tick lease.  The guest was
     * alive; the guest's own diagnostics had eaten the lease.
     *
     * So the child signals readiness (one byte, 0xA5) once it has a
     * PROPOSAL ready -- the model has been loaded, the first decision
     * has been made, and the decision has been announced (which is
     * free, because no lease is running yet).  Only then does the
     * policy open the session.  From that point the model only
     * COMPUTES and relays SILENTLY, which is CPU-bound rather than
     * I/O-bound, so the host's forwarding stays prompt and the lease
     * is held.
     *
     * If the child dies instead of signalling, the pipe reaches EOF and
     * the policy fails closed without ever opening a session -- there
     * is nothing for the deadman to catch, because nothing was ever
     * commanded.
     */
    phase_marker("[INFER] waiting for the model's first proposal...\n");
    {
        uint8_t ready = 0u;
        long got = 0;
        while (got < 1) {
            long r = sys_read(fds[0], &ready, 1u);
            if (r == 1) {
                got = 1;
                break;
            }
            if (r == 0) {
                phase_marker("[INFER] FATAL: the inference child exited before "
                             "the model was ready\n");
                guest_fail_closed(hvc_fd);
            }
            if (r == -4) {
                continue;          /* -EINTR */
            }
            phase_marker("[INFER] FATAL: cannot read the readiness signal\n");
            guest_fail_closed(hvc_fd);
        }
        if (ready != LATCH_INFER_READY_BYTE) {
            phase_marker("[INFER] FATAL: the readiness signal is not the expected "
                         "byte\n");
            guest_fail_closed(hvc_fd);
        }
    }
    phase_marker("[INFER] the model has a proposal: opening the session\n");

    /* ---- 7. The warm-up heartbeats, and then the relay ---------------
     *
     * The supervisor's contract says a command is admitted only after
     * `warmup_heartbeats` heartbeats have been seen, so these go out
     * first, and from now on the policy renews the lease every
     * LATCH_INFER_HEARTBEAT_MS.
     *
     * EVERY MARKER BELOW IS BEFORE THE FIRST FRAME GOES OUT.  Not one
     * console write is allowed to happen between the first frame and
     * the steady-state heartbeat stream, and the reason is measured:
     *
     * MEASURED DEFECT, QEMU AArch64 target, 2026-11-26
     * ---------------------------------------------------
     * A marker on this platform is a printk, and a printk has to take
     * the console lock and then push the line out of the PL011.  That
     * costs 57-88 ms of GUEST TIME per line on this machine -- the
     * signed lease is 100 ticks, and 100 ticks is roughly 100 ms, so a
     * SINGLE marker is most of the lease.
     *
     * With three markers between the warm-up and the first relay
     * heartbeat, the guest's own clock showed
     *
     *     guest-t 11.031  the warm-up frames went out
     *     guest-t 11.087  the "relaying" marker was formatted  (+57 ms)
     *     guest-t 11.175  the "write starting" marker         (+88 ms)
     *     guest-t 11.246  the "write returned" marker          (+70 ms)
     *
     * -- 78 + 10 + 70 = 158 ms, which is the 161-tick hole the
     * supervisor saw, and it cost the producer its full authority:
     * the deadman fired and the supervisor demoted itself out of HP.
     *
     * The fix is not a shorter marker; it is NO marker.  The policy's
     * diagnostics belong where they cost nothing: before the session
     * is open, or on a fault path that is bracketed by heartbeats
     * (relay_note()).  The event ring on the host side is the
     * authority on timing anyway -- it carries the supervisor's own
     * tick for every frame.
     */
    phase_marker("[INFER] warm-up heartbeats...\n");
    phase_marker("[INFER] relaying: the policy is the sole writer on the wire\n");
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_WARMUP_HEARTBEATS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq,
                            &coherence, 0, 0u, 0u);
    }
    flush_frames(hvc_fd);

    for (;;) {
        latch_pollfd_t pfd;
        ktimespec_t tmo;
        long n;

        pfd.fd = fds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        tmo.tv_sec = 0;
        tmo.tv_nsec = (long)LATCH_INFER_HEARTBEAT_MS * 1000000L;

        n = sys_ppoll(&pfd, 1u, &tmo);
        if (n < 0) {
            if (n == -4) continue;   /* -EINTR */
            break;
        }
        if (n == 0) {
            /* The model is still thinking.  Renew the lease.
             *
             * NOTHING HERE MAY TOUCH THE CONSOLE.  See the note above
             * the warm-up: a console write costs 57-88 ms of guest time
             * on this platform, and the lease is 100 ticks. */
            send_governor_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq,
                                &coherence, 0, 0u, 0u);
            flush_frames(hvc_fd);
            continue;
        }
        if ((pfd.revents & (POLLERR | POLLNVAL)) != 0) {
            break;
        }
        if ((pfd.revents & POLLIN) != 0) {
            long r = sys_read(fds[0], rx + rx_len, sizeof(rx) - rx_len);
            if (r == 0) {
                /* The child is gone.  Close the wire FIRST and report
                 * afterwards -- see guest_fail_closed_msg(). */
                guest_fail_closed_msg(hvc_fd,
                    "[INFER] the inference child closed the pipe; this guest will "
                    "send no further frames\n");
            }
            if (r < 0) {
                if (r == -4) continue;   /* -EINTR */
                break;
            }
            rx_len += (size_t)r;

            while (rx_len >= LATCH_WIRE_V2_SIZE) {
                uint8_t *f = rx;
                if (latch_wire_v2_check(f, LATCH_WIRE_V2_SIZE) != 0) {
                    relay_note(hvc_fd, &frame, &seq, &coherence,
                               "[INFER] dropped a frame: structural check failed\n");
                } else if (f[7] != GOV_WIRE_CMD_V2) {
                    relay_note(hvc_fd, &frame, &seq, &coherence,
                               "[INFER] dropped a frame: not a command\n");
                } else {
                    /* Re-stamp the sequence number and the coherence
                     * counter, and recompute the CRC.  The payload --
                     * the value, the confidence, the agent state and the
                     * unit id -- is relayed EXACTLY as the model
                     * produced it. */
                    latch_wire_v2_restamp(f, seq, coherence + 1u);
                    seq++;
                    coherence++;
                    send_frame(hvc_fd, (const lath_frame_t *)f);
                }
                for (size_t i = 0u; i + LATCH_WIRE_V2_SIZE < rx_len; ++i) {
                    rx[i] = rx[i + LATCH_WIRE_V2_SIZE];
                }
                rx_len -= LATCH_WIRE_V2_SIZE;
            }
            flush_frames(hvc_fd);
        }

        /* Reap the child if it exited, so PID 1 does not accumulate
         * zombies. */
        sys_wait4(-1, 0, WNOHANG);
    }

    /* The child is gone: the guest stops sending.  The supervisor's
     * deadman turns that into HA-HOLD -> HA-HOME. */
    guest_fail_closed(hvc_fd);
}

#else /* !LATCH_GOVERNOR_INFER */

/*
 * The 235-frame scripted scenario belongs to the W4 (transport PROBE)
 * profile and to the plain GOVERNOR profile.
 *
 * The W5 (verdict WATCHER) profile has its OWN scenario --
 * `run_governor_verdict_demo()` -- and this function would be dead code
 * there, which `-Wunused-function` (and `-Werror`) refuses.  The two
 * profiles are therefore mutually exclusive HERE, at the source, rather
 * than by a linker flag.
 */
#if !defined(LATCH_GOVERNOR_FEEDBACK_VERDICT) && !defined(LATCH_GOVERNOR_LATENCY_SOAK)
static void run_governor_demo(int hvc_fd) {
    lath_frame_t frame;
    uint32_t seq = 1u;
    uint32_t coherence = 0u;

    /* ---- THE SCENARIO PLAN --------------------------------------------
     *
     * EVERY annotation for the whole scenario is printed HERE, before
     * the session opens.  That is a measured requirement, not a style
     * choice.
     *
     * A console line costs ~70 ms of GUEST TIME on this platform: the
     * guest's PL011 under QEMU TCG costs roughly one host MMIO exit
     * per character, and the kernel's own timestamp prefix adds ~15
     * characters to every line.  Measured on the QEMU AArch64 target
     * on 2026-11-26 from the guest's own kernel timestamps:
     *
     *     guest-t 7.857  [GOVERNOR] v2 demo: four liveness heartbeats
     *     guest-t 7.940  [A4] guest CPU spinner, then 110 ms delay   (+83 ms)
     *     guest-t 8.128  [A4] one command renews lease              (+188 ms)
     *
     * and the signed lease is 100 ticks = 100 ms.
     *
     * The A4 scenario is a DEADMAN test.  The guest must go silent
     * for a scripted 110 ms: long enough to expire the 100-tick lease
     * ONCE and demote the ladder exactly one rung, and short enough
     * that it cannot expire it twice.  A console write inside that
     * window adds ~70 ms per line, and two of them turn one expiry
     * into two or three: the ladder ratchets HP -> ADVISE -> CLAMP ->
     * SLOW -> LATCH and the scenario is measuring THE CONSOLE instead
     * of the deadman.
     *
     * That is not hypothetical; it is exactly what happened.  The
     * /dev/kmsg userspace rate limit used to SILENTLY DROP these
     * annotations, so they cost the guest nothing and the A4 window
     * was the scripted 110 ms.  When the rate limit was lifted -- so
     * that a marker can no longer vanish without anyone noticing --
     * every annotation became visible, the A4 window grew to ~250 ms,
     * and the on-target verifier failed with the ladder at LATCH.
     *
     * The fix is not to drop the annotations again.  It is to print
     * them where they cost nothing: BEFORE the session opens, while
     * the supervisor's deadman is not yet running.  From the warm-up
     * flush onwards the guest writes NOTHING to the console, and the
     * supervisor's event ring -- which carries the supervisor's own
     * tick for every frame -- is the authority on what happened.
     *
     * The annotations therefore read as the PLAN the guest is about to
     * execute, and that is exactly what they are.
     *
     * ---- AND THEN LET THE CONSOLE DRAIN ------------------------------
     *
     * Printing them before the session opens is necessary but NOT
     * sufficient: a /dev/kmsg write returns as soon as the record is in
     * the kernel's ring buffer, but the kernel's console thread then
     * pushes it out through the PL011 at ~1.3-1.8 ms PER CHARACTER.  The
     * guest has therefore finished "printing" the plan while the HOST is
     * still busy serving it.
     *
     * That host-side drain is not free, and it lands on the wrong side
     * of the lease.  Measured on the QEMU AArch64 target (2026-11-26),
     * with the plan printed and the session opened immediately:
     *
     *     the guest's own clock:  sleep(110) = 111.66 ms, write = 0.97 ms
     *     the supervisor's view:  268 TICKS of silence, TWO lease
     *                            expiries, ADVISE -> CLAMP, and the A4
     *                            command REJECTED with DOSE (0x8000)
     *
     * i.e. the host's tick index advanced 268 for an event the guest
     * measured as 112.6 ms -- a 2.4x skew.  The guest's clock and the
     * supervisor's tick index agreed 1:1 during the busy phases on
     * either side, so the skew was confined to the window in which the
     * console burst was still draining.  The deadman then counted the
     * console drain as guest silence and demoted the ladder TWICE for a
     * silence that was meant to expire the lease ONCE.
     *
     * The fix is to let the console go quiet BEFORE the session opens,
     * while the deadman is not yet running.  The wait is deliberately
     * generous: it is longer than the measured cost of the whole plan
     * (8 lines, ~480 characters, ~1.3-1.8 ms per character), and
     * tools/consistency_check.py FAILS THE BUILD if the plan grows
     * without the wait growing with it.
     */
    phase_marker("[GOVERNOR] v2 demo: four liveness heartbeats, then commands\n");
    phase_marker("[A4] guest CPU spinner, then scripted 110 ms heartbeat delay\n");
    phase_marker("[A4] one command renews lease; heartbeat-only traffic must not recover rung\n");
    phase_marker("[GOVERNOR] 25 coherent commands recover the lease demotion\n");
    phase_marker("[GOVERNOR] recovered rung accepts fresh canonical commands\n");
    phase_marker("[GOVERNOR] low-confidence command and explicit milli-unit conversion\n");
    phase_marker("[GOVERNOR] unknown unit rejected; tighten request accepted\n");
    phase_marker("[GOVERNOR] widening request vetoed; guest stops sending\n");
    sys_sleep_ms(LATCH_GOVERNOR_CONSOLE_DRAIN_MS);

    for (uint32_t i = 0u; i < LATCH_GOVERNOR_WARMUP_HEARTBEATS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq,
                            &coherence, 0, 0u, 0u);
    }
    flush_frames(hvc_fd);

    /* ---- THE A4 SILENT WINDOW ----------------------------------------
     *
     * The spinner and the scripted delay, and NOTHING ELSE.  No
     * console write, no extra frame, nothing that can extend the
     * silence past the scripted 110 ms.  The lease must expire ONCE.
     */
    volatile uint32_t spin_state = 0xA4u;
    for (uint32_t i = 0u; i < 1000u; ++i) {
        spin_state = (spin_state * 1664525u) + 1013904223u;
    }
    (void)spin_state;
    sys_sleep_ms(LATCH_GOVERNOR_A4_DELAY_MS);

    /* One command renews the lease.  Heartbeat-only traffic after it
     * must NOT recover the rung. */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_A4_RESUME_COMMANDS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, 100, 255u, 1u);
    }
    flush_frames(hvc_fd);
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_HEARTBEAT_HOLD_FRAMES; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq,
                            &coherence, 0, 0u, 0u);
        /* Hold the scenario open for external QNX status sampling. The
         * heartbeat keeps the lease alive but cannot earn recovery credit. */
        sys_sleep_ms(LATCH_GOVERNOR_HEARTBEAT_HOLD_MS);
    }
    flush_frames(hvc_fd);

    /* 25 coherent commands recover the lease demotion. */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_RECOVERY_COMMANDS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, 100, 255u, 1u);
        sys_sleep_ms(1);
    }
    flush_frames(hvc_fd);

    /* The recovered rung accepts fresh canonical commands. */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_NOMINAL_COMMANDS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, 100, 255u, 1u);
        sys_sleep_ms(1);
    }
    flush_frames(hvc_fd);

    /* A low-confidence command and an explicit milli-unit conversion. */
    send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                        &coherence, 120, 96u, 1u);
    send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                        &coherence, 37000, 255u, 3u);
    flush_frames(hvc_fd);

    /* An unknown unit is rejected; a tighten request is accepted. */
    send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                        &coherence, 120, 255u, 999u);
    send_governor_frame(hvc_fd, &frame, GOV_WIRE_SHRINK_REQ, &seq,
                        &coherence, 12, 128u, 0u);
    flush_frames(hvc_fd);

    /* A widening request is vetoed; the guest then stops sending. */
    send_governor_frame(hvc_fd, &frame, GOV_WIRE_SHRINK_REQ, &seq,
                        &coherence, 13, 150u, 0u);
    flush_frames(hvc_fd);
    /* LATCH_GOVERNOR_SUITE_FRAMES is cross-checked against the components
     * above, the selected manifest lease, and the QVM ring by consistency_check. */
    /* The trusted host owns lease time. Silence demonstrates expiry. */
    sys_sleep_ms(LATCH_GOVERNOR_FINAL_SILENCE_MS);
    sys_close(hvc_fd);
    for (;;) sys_sleep_ms(60000);
}
#endif /* !LATCH_GOVERNOR_FEEDBACK_VERDICT && !LATCH_GOVERNOR_LATENCY_SOAK */

#if defined(LATCH_GOVERNOR_LATENCY_SOAK)
/* =========================================================================
 * THE DECISION-LATENCY SOAK  (U-4)
 *
 * WHAT THIS IS
 * ------------
 * The project's latency record used to carry a "bounded WCET" of 61 us that
 * came from a generator which INSERTED FIXED VALUES.  That number was
 * withdrawn, and this profile exists to replace it with a MEASUREMENT: the
 * trusted QNX supervisor's own per-tick decision latency, sampled once per
 * tick, over at least a million ticks, aggregated on the target and read
 * back over an output-only devctl (`latchctl latency`).
 *
 * WHY THE GUEST HAS TO BE THE PRODUCER
 * ------------------------------------
 * The measurement is of the SUPERVISOR, but the supervisor only does the
 * interesting work when it has something to decide.  A supervisor with an
 * empty queue measures the idle path, and the idle path is not the thing
 * the record is about.  So the guest has to keep proposing, at a rate the
 * supervisor can actually consume.
 *
 * THE RATE, AND WHY IT IS NOT "ONE FRAME PER TICK"
 * -------------------------------------------------
 * The supervisor consumes EXACTLY ONE proposal per tick, so its view of the
 * frame stream is capped at 1000 frames/s -- and the signed contract's
 * `timing.period_us` is 1000, so the supervisor ticks at 1 kHz.  A producer
 * paced at exactly one frame per tick is a coin flip (the measured jitter
 * is larger than 1 ms), and a producer paced FASTER than the supervisor
 * consumes fills the 256-slot ring and starts dropping frames.
 *
 * So the soak targets 900 frames/s: BELOW the consumption rate, so the ring
 * never fills and the telemetry stays clean, and ABOVE the rate at which
 * the queue would starve.  The consequence is honest and is reported: some
 * ticks find the queue empty, and the supervisor separates those samples
 * from the decision-path samples in the histogram.
 *
 * THE DEADLINE PACER
 * ------------------
 * The pace is a DEADLINE on the guest's own monotonic clock, not a fixed
 * sleep, so the achieved rate is the target rate and does not drift with
 * the host's load.  See guest_now_ns().
 *
 * THE CONSOLE
 * -----------
 * The whole plan is printed BEFORE the session opens and the console is
 * left QUIET for the whole soak.  A console line costs ~70 ms of guest
 * time on this platform, and the signed lease is 100 ticks (~100 ms), so a
 * marker inside the supervised window would be counted by the dead-man as
 * guest silence.  The rule from the scripted profile applies unchanged.
 *
 * THE SETTLING STAIRCASE, AND WHY THE SOAK NEEDS ONE
 * ---------------------------------------------------
 * The measured phase asks the plant to HOLD a position.  To get there, the
 * plant has to MOVE, and the supervisor's kinematic model has three
 * quantities: the position, the velocity (the last applied step) and the
 * acceleration (the change of the velocity).  Its JERK limit
 * (`envelope.j_max` = 20 mrad/tick^3) is checked against the difference of
 * two consecutive accelerations.
 *
 * Now consider what happens when a tick finds the proposal queue EMPTY
 * while the plant is moving.  The supervisor applies no motion that tick,
 * so the applied velocity is 0 and the acceleration becomes -v.  The NEXT
 * command then has to satisfy
 *
 *     jerk = a_step - a_cur = a_step + v  <=  j_max
 *
 * and with v at the envelope's v_max (25 mrad/tick) and a_step up to the
 * governor's own acceleration limit (9 mrad/tick), the jerk reaches 34 --
 * beyond j_max.  The supervisor refuses the command, LATCHES the RATE
 * fault, drops into HOLD and the governor ladder ratchets all the way to
 * LATCH.  Measured on the QEMU AArch64 target (2026-11-27): a soak that
 * jumped straight to 100 mrad tripped exactly this, intermittently, and
 * the fault was a property of the WORKLOAD, not of the supervisor.
 *
 * The fix is in the WORKLOAD, because the supervisor's behaviour here is
 * fail-closed and correct: the soak must not ask the plant to accelerate
 * harder than the jerk limit allows.  So the plant is walked to its
 * measurement position on a STAIRCASE: each command advances the target by
 * `SETTLE_STEP_MRAD` (5 mrad), and the commands are sent at the SAME rate
 * as the measured window, with no gap at all.  That gives
 *
 *   * the target is never more than one step ahead of the plant, so the
 *     plant's velocity never exceeds the step (5 mrad/tick),
 *   * the acceleration is the change of that velocity, so it too stays
 *     inside the step, and
 *   * the jerk is therefore at most 2 x the step (10), comfortably inside
 *     the envelope's j_max of 20 -- WHETHER OR NOT a tick finds the queue
 *     empty, because an empty tick drops the velocity to zero and the
 *     acceleration to -v, and the worst-case jerk after that is still
 *     step + step = 10.
 *
 * THE STAIRCASE HAS NO GAP, AND THAT IS THE POINT
 * ------------------------------------------------
 * The obvious way to let the plant settle between the steps is to pause
 * and send heartbeats.  That pause is a SILENCE, and the signed lease is
 * 100 ticks (about 100 ms), so the pause has to stay inside it -- and a
 * guest's sleep is only as accurate as the host's scheduler, which under
 * TCG is not a promise.  Sending the steps back to back at the measured
 * rate removes the question entirely: there is no gap for the dead-man to
 * count, and the plant still comes to rest (the HOLD commands that follow
 * the staircase stop it within two ticks).
 *
 * After the staircase the plant HOLDS its position: the target equals the
 * plant's position, so every measured command asks for no motion, the
 * plant's velocity stays zero, and an empty queue is harmless.
 * ========================================================================= */

/* The pacing decision lives in a shared, host-testable header: see
 * guest/latch_soak_pace.h for the defect it prevents (a rate limiter that
 * accumulates credit bursts to catch up after a host stall, and the burst
 * overflows the supervisor's proposal ring). */
#include "latch_soak_pace.h"

/* The target frame rate, in frames per second.  See the note above: it has
 * to sit below the supervisor's 1 kHz consumption rate so the ring never
 * fills, and high enough that the decision path is the dominant workload. */
#ifndef LATCH_GOVERNOR_SOAK_TARGET_HZ
#define LATCH_GOVERNOR_SOAK_TARGET_HZ 900
#endif

/* How long the soak runs.  The supervisor samples ONE latency per tick at
 * 1 kHz, so 2,100,000 ms is ~2.1 million ticks -- comfortably past the
 * million-tick floor, with room for the boot, the warm-up and a starved
 * TCG host whose tick rate falls below 1 kHz. */
#ifndef LATCH_GOVERNOR_SOAK_DURATION_MS
#define LATCH_GOVERNOR_SOAK_DURATION_MS 2100000
#endif

/* The settling staircase (see the note above).  The step is well inside the
 * governor's own acceleration limit, so the plant's velocity and
 * acceleration are bounded by the step and the jerk by twice it. */
#define LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD 5
#define LATCH_GOVERNOR_SOAK_SETTLE_TARGET_MRAD 100
/* The frames the plant is allowed to come to REST on the measurement
 * position before the measured window opens.  Two HOLD commands are enough
 * (the first stops the plant, the second zeroes the acceleration), and the
 * rest of the frames are margin: they are ordinary HOLD commands, so they
 * are the same kind of sample the measured window collects. */
#define LATCH_GOVERNOR_SOAK_SETTLE_FRAMES 200

/*
 * STRINGIFY A COMPILE-TIME CONSTANT.
 *
 * The soak's plan marker has to state the rate and the duration the binary
 * was ACTUALLY BUILT with.  A hand-written "900 Hz ... 2100 s" in the
 * marker is a claim about the build, and a build that overrides either
 * knob would then print a LIE -- and the marker is the only thing that
 * tells the harness which workload it is looking at.  So the numbers are
 * stringified out of the macros themselves.
 *
 * The macros therefore carry NO `u` suffix: the suffix would show up in the
 * printed text ("900u Hz"), and every use of them is explicitly cast.
 */
#define LATCH_STR_(x) #x
#define LATCH_STR(x) LATCH_STR_(x)

/*
 * THE PACER.
 *
 * One deadline, advanced by exactly one period per frame, and the guest
 * sleeps until it.  The achieved rate is therefore the TARGET rate as long
 * as the guest can produce that fast, and the guest's own maximum when it
 * cannot -- and it is the guest's own CLOCK that decides, so the rate does
 * not drift with the host's load.
 *
 * The sleep is rounded UP to a whole microsecond, so the pacer never
 * undersleeps and the rate cannot creep upward.
 */
/*
 * THE PACER.  See guest/latch_soak_pace.h for why the decision lives in a
 * shared, host-testable header.
 *
 * THE RULE, IN ONE LINE: the producer may fall at most the LAG ALLOWANCE
 * behind its own schedule, and it keeps its grid.
 *
 * A rate limiter has to do two things at once, and every failure mode
 * here was MEASURED on the QEMU AArch64 `virt` target (2026-11-27):
 *
 *   * "keep the grid, catch up without limit" sustained the target rate
 *     (901/s) but a ~0.5 s host stall made it pay the whole debt back at
 *     once -- 255 frames into the supervisor's 256-frame proposal ring,
 *     186 of them DROPPED;
 *   * "drop the credit on ANY lateness" removed the burst (2 frames) but
 *     COST THE RATE: the guest's own sleep overshoots by more than a
 *     period under TCG, so the guest is ~1.02 periods late by
 *     construction, every late frame cost a full period, and the measured
 *     rate fell to 610/s.  The workload then was not the one the plan
 *     describes.
 *
 * The decision is `latch_soak_next_deadline()`, which keeps the grid
 * inside the allowance (ordinary jitter), drops the missed deadlines
 * outside it (a host stall), and advances the grid by exactly one period
 * when it is on schedule.
 */
static void soak_pace(uint64_t *deadline, uint64_t period_ns) {
    const uint64_t now = guest_now_ns();
    const uint64_t next = latch_soak_next_deadline(*deadline, now, period_ns);
    if (next > now) {
        const uint64_t remain_us = latch_soak_sleep_us(next, now);
        sys_sleep_us((long)remain_us);
    }
    *deadline = next;
}

static void run_governor_latency_soak(int hvc_fd) {
    lath_frame_t frame;
    uint32_t seq = 1u;
    uint32_t coherence = 0u;

    /* ---- THE PLAN, PRINTED BEFORE THE SESSION OPENS -------------------
     *
     * Two lines, and then the console goes quiet for the whole soak.  The
     * drain wait below is what makes "quiet" mean quiet: a /dev/kmsg write
     * returns as soon as the record is in the kernel's ring buffer, and the
     * host is still pushing it out through the PL011 afterwards.
     */
    phase_marker("[LATENCY] soak: " LATCH_STR(LATCH_GOVERNOR_SOAK_TARGET_HZ)
                 " Hz in-envelope CMD_V2 stream for "
                 LATCH_STR(LATCH_GOVERNOR_SOAK_DURATION_MS) " ms\n");
    phase_marker("[LATENCY] the plant is walked to 100 mrad on a 5 mrad staircase, "
                 "then holds\n");
    phase_marker("[LATENCY] the console stays quiet until the soak ends\n");

    /* The pacer needs the guest's monotonic clock.  If the clock cannot be
     * read, the soak cannot be paced -- and a soak that cannot be paced is
     * not a measurement, it is a random-length run.  Say so and stop BEFORE
     * the session opens, so the abort is visible on the console and costs
     * the dead-man nothing. */
    if (guest_now_ns() == 0u) {
        phase_marker("[LATENCY] ABORT: the guest monotonic clock is unavailable, "
                     "so the soak cannot be paced\n");
        for (;;) sys_sleep_ms(60000);
    }

    sys_sleep_ms(LATCH_GOVERNOR_CONSOLE_DRAIN_MS);

    /* The contract's warm-up heartbeats: the supervisor refuses commands
     * until it has seen `warmup_heartbeats` coherent heartbeats. */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_WARMUP_HEARTBEATS; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq,
                            &coherence, 0, 0u, 0u);
    }
    flush_frames(hvc_fd);

    const uint64_t period_ns = 1000000000ULL / (uint64_t)LATCH_GOVERNOR_SOAK_TARGET_HZ;
    uint64_t deadline = guest_now_ns();

    /* ---- THE SETTLING STAIRCASE ----------------------------------------
     *
     * The plant walks to the measurement position one small step at a time,
     * at the SAME rate as the measured window and with no gap between the
     * steps.  See the note above: this is what keeps the supervisor's jerk
     * model inside the signed envelope, and therefore what keeps the
     * workload from tripping the safety logic it is being used to measure.
     *
     * The targets are ABSOLUTE, so a step that the supervisor has not
     * consumed yet does not make the next one larger: the plant is always
     * at most one step behind the target.
     */
    const uint32_t settle_steps =
        (uint32_t)LATCH_GOVERNOR_SOAK_SETTLE_TARGET_MRAD /
        (uint32_t)LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD;
    for (uint32_t i = 1u; i <= settle_steps; ++i) {
        const int32_t target = (int32_t)(i * (uint32_t)LATCH_GOVERNOR_SOAK_SETTLE_STEP_MRAD);
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, target, 255u, 1u);
        flush_frames(hvc_fd);
        soak_pace(&deadline, period_ns);
    }

    /* ---- THE PLANT COMES TO REST ---------------------------------------
     *
     * The staircase leaves the plant moving at one step per tick.  These
     * HOLD commands stop it: the first one applies a zero step (the
     * velocity goes to zero), the second one zeroes the acceleration, and
     * after that the plant is at rest and the measured window measures the
     * steady state it is supposed to measure.
     */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_SOAK_SETTLE_FRAMES; ++i) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, (int32_t)LATCH_GOVERNOR_SOAK_SETTLE_TARGET_MRAD,
                            255u, 1u);
        soak_pace(&deadline, period_ns);
    }

    /* ---- THE SOAK ----------------------------------------------------
     *
     * An in-envelope motion command: 100 mrad, full confidence (255),
     * canonical unit 1.  These are the same values the scripted profile
     * uses for its NOMINAL commands, which the on-target verifier confirms
     * are ACCEPTED with no faults, so the supervisor stays in HP and the
     * sample is the HP workload.
     *
     * The plant is ALREADY at 100 mrad, so the command asks it to HOLD:
     * the step is zero, the plant's velocity stays zero, and an empty
     * proposal queue is harmless.  The decision path is the same either
     * way -- the frame is validated, the governor gate runs, the kinematic
     * envelope runs, the ladder is evaluated and the actuation is
     * published -- and that is what the measurement is about.
     */
    const uint64_t t_start   = guest_now_ns();
    const uint64_t t_end     = t_start +
                               ((uint64_t)LATCH_GOVERNOR_SOAK_DURATION_MS * 1000000ULL);
    deadline = t_start;

    while (guest_now_ns() < t_end) {
        send_governor_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq,
                            &coherence, (int32_t)LATCH_GOVERNOR_SOAK_SETTLE_TARGET_MRAD,
                            255u, 1u);
        soak_pace(&deadline, period_ns);
    }

    flush_frames(hvc_fd);
    sys_close(hvc_fd);
    for (;;) sys_sleep_ms(60000);
}
#endif /* LATCH_GOVERNOR_LATENCY_SOAK */

#ifdef LATCH_GOVERNOR_FEEDBACK
/* =========================================================================
 * THE HOST->GUEST FEEDBACK-TRANSPORT PROBE  (W4)
 *
 * WHAT THIS IS
 * ------------
 * The LATCH feedback channel (LFBK) carries the trusted supervisor's
 * VERDICT on a guest proposal back into the guest, so the guest's planner
 * can observe what the supervisor actually did instead of guessing.  It is
 * ADVISORY: the guest is untrusted, the safety envelope lives only in the
 * signed manifest, and the supervisor is the only thing that can actuate.
 * A lost or stale verdict can therefore never make the plant unsafe -- it
 * can only make the guest stop proposing, which the supervisor's dead-man
 * lease turns into a fail-closed LATCH.  LOSS IS SAFE; SILENCE IS FATAL.
 *
 * THIS FUNCTION IS THE DECISIVE TRANSPORT EXPERIMENT
 * --------------------------------------------------
 * It answers one question with a measurement: can the guest READ a byte
 * that the trusted host wrote, on this platform, without disturbing the
 * black channel?
 *
 * THE TRANSPORT IS A POLLED BLOCK DEVICE, AND EVERYTHING ELSE WAS REJECTED
 * BY MEASUREMENT ON THIS PLATFORM (QEMU AArch64 target, 2026-11-26):
 *
 *   1. A QNX `devc-pty` pair.  Its open ORDER decides whether the pair can
 *      be used at all (the reader must open the controller first, and a
 *      hostdev that cannot be opened is FATAL to the VM start), and it lets
 *      ANY process write into the channel.
 *
 *   2. The PL011 vdev's host->guest injection.  The bytes reach the
 *      hypervisor's own buffer -- the mailbox's readcond() is served, the
 *      vdev reads 1024/912/800-byte chunks -- and then STOP: the vdev only
 *      raises the guest's interrupt when a guest-visible register state
 *      says the receiver is enabled, and the state it waits for is not one
 *      the Linux `amba-pl011` driver produces.
 *
 *   3. The virtio-console vdev's host->guest input direction.  Its
 *      `receive_host_data` is reachable only through a flag that an
 *      UNREACHABLE error-recovery path sets, so the host's bytes are never
 *      handed to the guest.
 *
 *   4. `vdev virtio-blk`.  THIS ONE WORKS: the vdev opens a HOST FILE and
 *      serves it to the guest as a block device, READ-ONLY (`hostdev <`).
 *      The verdict frame lives in the file's first sector and the guest
 *      polls it.  The guest reads it with `pread64`, so a poll never
 *      disturbs the file's offset and the host's writer is never blocked.
 *
 * WHY THE PROBE RUNS BEFORE THE SESSION OPENS
 * -------------------------------------------
 * Two reasons, and both are hard rules on this platform:
 *
 *   1. The supervisor's dead-man starts counting at the FIRST FRAME, so a
 *      probe that runs inside the supervised window would look like guest
 *      silence to the supervisor.
 *   2. A console line costs ~1.3-1.8 ms PER CHARACTER on this PL011, and
 *      the signed lease is 100 ticks (~100 ms).  The probe's report is
 *      therefore emitted BEFORE the scenario's plan, so the single
 *      console-drain wait that already guards the plan also drains the
 *      probe's report (the console is FIFO).  `tools/consistency_check.py`
 *      adds the probe's characters to the plan's measured cost, so the
 *      drain wait grows with the report if the report grows.
 *
 * The probe's failure is NOT a safety event: the guest still proposes, the
 * supervisor still decides.  It is reported as a transport verdict.
 * ========================================================================= */

#define LATCH_FB_PROBE_MAGIC       0x4B42464Cu /* "LFBK" little-endian */
#define LATCH_FB_PROBE_VERSION     2u
#define LATCH_FB_PROBE_SIZE        28u
#define LATCH_FB_PROBE_TIMEOUT_MS  12000u
#define LATCH_FB_PROBE_WANT_FRAMES 4u
/*
 * The PRODUCTION LFBK frame (qnx/latch_feedback.h), reproduced here
 * because the guest policy is freestanding and must not pull a header out
 * of the QNX tree.  The layout, the magic, the version and the CRC rule
 * are the production ones -- there is exactly ONE feedback frame format in
 * the tree -- and tools/consistency_check.py checks that the two copies
 * agree.
 */
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
} latch_fb_probe_frame_t;

_Static_assert(sizeof(latch_fb_probe_frame_t) == LATCH_FB_PROBE_SIZE,
               "the probe frame must be a fixed 28-byte frame");
_Static_assert(offsetof(latch_fb_probe_frame_t, crc32) == 24u,
               "the probe CRC must cover the first 24 bytes");

/* A bounded formatter: the guest has no printf. */
static void fb_copy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (size_t i = 0u; i < n; ++i) {
        d[i] = s[i];
    }
}


#if defined(LATCH_GOVERNOR_FEEDBACK) || defined(LATCH_GOVERNOR_FEEDBACK_VERDICT)
/* =========================================================================
 * THE POLLED VERDICT SECTOR -- THE SHARED HOST->GUEST TRANSPORT
 *
 * The candidate block devices, the descriptor telemetry, the open sequence
 * and the FRESHNESS mechanism live in guest/latch_fb_transport.h, because
 * BOTH guest profiles use them and the freshness rule is LOAD-BEARING: a
 * guest that reads the sector through its page cache sees the SAME bytes
 * forever, and a channel that cannot show a change is not a channel.  Two
 * copies of that rule would drift, and the drift would be invisible until
 * a guest on a target silently stopped seeing its supervisor.
 * ========================================================================= */
#include "latch_fb_transport.h"
#endif

/* The probe's OWN constants.  Everything about the TRANSPORT itself --
 * which device, how fresh, how many bytes -- is in
 * guest/latch_fb_transport.h, shared with the W5 verdict watcher. */
#define LATCH_FB_PROBE_POLL_MS      20u
#define LATCH_FB_PROBE_BUDGET_MS    12000u
#define LATCH_FB_PROBE_WANT_CHANGES 2u

/*
 * Validate one sector as an LFBK frame.
 *
 * The frame is re-synchronised on the MAGIC and the CRC is validated, so a
 * sector that was read while the host was rewriting it cannot produce a
 * false "it worked": a frame is counted only if its magic, version, size
 * and CRC all agree.
 */
static int fb_frame_ok(const uint8_t *b, latch_fb_probe_frame_t *out) {
    uint32_t magic = 0u;
    latch_fb_probe_frame_t f;

    fb_copy(&magic, b, sizeof(magic));
    if (magic != LATCH_FB_PROBE_MAGIC) {
        return 0;
    }
    fb_copy(&f, b, sizeof(f));
    if (f.version != LATCH_FB_PROBE_VERSION || f.size != LATCH_FB_PROBE_SIZE) {
        return 0;
    }
    if (f.crc32 != ieee_crc32(b, 24u)) {
        return 0;
    }
    *out = f;
    return 1;
}

static void run_feedback_probe(void) {
    char report[288];
    size_t at = 0;
    static uint8_t sector[LATCH_FB_READ_BYTES]
        __attribute__((aligned(LATCH_FB_BUFFER_ALIGN)));
    static fb_blk_t blocks[LATCH_FB_BLOCK_MAX];
    uint32_t waited_ms = 0u;
    int best = -1;
    int opens = 0;

    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        blocks[i].fd = -1;
        blocks[i].open_errno = 0;
        blocks[i].direct = 0;
        blocks[i].direct_errno = 0;
        blocks[i].advise_errno = 0;
        blocks[i].read_errno = 0;
    }

    /* Open EVERY candidate.  A probe that guessed the wrong node would
     * report a false negative, so the census has to cover every candidate
     * it could have used. */
    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        blocks[i].fd = fb_open_block(fb_block_candidates[i],
                                     &blocks[i].open_errno,
                                     &blocks[i].direct,
                                     &blocks[i].direct_errno);
        if (blocks[i].fd >= 0) {
            opens++;
        }
    }

    /* Poll the verdict sector.
     *
     * The loop stops as soon as ONE candidate has shown TWO DIFFERENT
     * sequence numbers: that is the proof that the host's writes are
     * visible to the guest, which is the property the transport has to
     * have.  A channel that delivers a fixed image is not a channel. */
    while (waited_ms < LATCH_FB_PROBE_BUDGET_MS) {
        int live = 0;
        for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
            fb_blk_t *b = &blocks[i];
            latch_fb_probe_frame_t f;
            long n;

            if (b->fd < 0) {
                continue;
            }
            /* DROP THE CACHED PAGES BEFORE EVERY BUFFERED READ.
             *
             * Without this the guest's page cache answers the poll from
             * the FIRST read, and the probe measures its own cache
             * instead of the transport.  A DIRECT descriptor does not
             * need the advice -- it never caches. */
            LATCH_FB_DROP_CACHE(b);
            n = sys_pread64(b->fd, sector, sizeof(sector), 0);
            if (n < 0) {
                b->read_errno = (int)(-n);
                if (b->direct != 0 &&
                    (int)(-n) == LATCH_FB_EINVAL) {
                    /* The device refused a DIRECT read.  Fall back to the
                     * buffered view and SAY SO: a buffered probe can
                     * still find the device, but it cannot promise
                     * freshness. */
                    sys_close(b->fd);
                    b->fd = (int)sys_open(fb_block_candidates[i], O_RDONLY);
                    b->direct = 0;
                    if (b->fd >= 0) {
                        n = sys_pread64(b->fd, sector, sizeof(sector), 0);
                        if (n < 0) {
                            b->read_errno = (int)(-n);
                        }
                    }
                }
            }
            b->reads++;
            if (n != (long)sizeof(sector)) {
                b->bad++;
                continue;
            }
            if (!fb_frame_ok(sector, &f)) {
                b->bad++;
                continue;
            }
            if (b->valid == 0u) {
                b->first_seq = f.seq;
                b->last_seq = f.seq;
                b->epoch = f.epoch;
                b->verdict = f.verdict;
                b->rung = f.rung;
                b->faults = f.fault_bits;
            } else if (f.seq != b->last_seq) {
                b->changes++;
                b->last_seq = f.seq;
            }
            b->valid++;
        }
        for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
            if (blocks[i].changes >= LATCH_FB_PROBE_WANT_CHANGES) {
                live = 1;
            }
        }
        if (live) {
            break;
        }
        sys_sleep_ms(LATCH_FB_PROBE_POLL_MS);
        waited_ms += LATCH_FB_PROBE_POLL_MS;
    }

    /* The candidate that carried the channel is the one with the most
     * valid frames; a tie is broken by the number of observed changes. */
    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        if (blocks[i].valid == 0u) {
            continue;
        }
        if (best < 0 ||
            blocks[i].valid > blocks[best].valid ||
            (blocks[i].valid == blocks[best].valid &&
             blocks[i].changes > blocks[best].changes)) {
            best = i;
        }
    }

    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        if (blocks[i].fd >= 0) {
            sys_close(blocks[i].fd);
            blocks[i].fd = -1;
        }
    }

    at = fb_append_str(report, sizeof(report), at, "[FBPROBE] port=");
    at = fb_append_str(report, sizeof(report), at,
                       (best >= 0) ? fb_block_candidates[best] : "none");
    at = fb_append_str(report, sizeof(report), at, " bytes=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].reads * (uint32_t)LATCH_FB_READ_BYTES : 0u);
    at = fb_append_str(report, sizeof(report), at, " frames=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].valid : 0u);
    at = fb_append_str(report, sizeof(report), at, " seq=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].first_seq : 0u);
    at = fb_append_str(report, sizeof(report), at, "->");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].last_seq : 0u);
    at = fb_append_str(report, sizeof(report), at, " epoch=0x");
    at = fb_append_hex8(report, sizeof(report), at,
                        (best >= 0) ? blocks[best].epoch : 0u);
    at = fb_append_str(report, sizeof(report), at, " verdict=0x");
    at = fb_append_hex8(report, sizeof(report), at,
                        (best >= 0) ? blocks[best].verdict : 0u);
    at = fb_append_str(report, sizeof(report), at, " rung=0x");
    at = fb_append_hex8(report, sizeof(report), at,
                        (best >= 0) ? blocks[best].rung : 0u);
    at = fb_append_str(report, sizeof(report), at, " faults=0x");
    at = fb_append_hex8(report, sizeof(report), at,
                        (best >= 0) ? blocks[best].faults : 0u);
    /* The number of times the sequence number CHANGED under the guest.
     * It is the difference between "the guest read a sector" and "the
     * host's writes reach the guest". */
    at = fb_append_str(report, sizeof(report), at, " changes=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].changes : 0u);
    at = fb_append_str(report, sizeof(report), at, " opens=");
    at = fb_append_u32(report, sizeof(report), at, (uint32_t)opens);
    /* WHETHER THE WINNING DEVICE WAS READ WITHOUT THE PAGE CACHE.
     *
     * `dir=1` means every poll went straight at the device, so a sequence
     * number that CHANGED is the host's own write seen by the guest.
     * `dir=0` means the guest read through its page cache, and the report
     * can then claim the device but not its freshness. */
    at = fb_append_str(report, sizeof(report), at, " dir=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? (uint32_t)blocks[best].direct : 0u);
    /* WHY the direct view was not used, if it was not.  A report that says
     * "not direct" without saying why cannot be acted on. */
    at = fb_append_str(report, sizeof(report), at, " derr=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? (uint32_t)blocks[best].direct_errno : 0u);
    at = fb_append_str(report, sizeof(report), at, " ferr=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? (uint32_t)blocks[best].advise_errno : 0u);
    at = fb_append_str(report, sizeof(report), at, " rerr=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? (uint32_t)blocks[best].read_errno : 0u);
    at = fb_append_str(report, sizeof(report), at, " bad=");
    at = fb_append_u32(report, sizeof(report), at,
                       (best >= 0) ? blocks[best].bad : 0u);
    /* The per-candidate census: how many frames and how many changes each
     * candidate delivered.  It is what makes the verdict self-describing
     * -- a reader can see WHICH device carried the channel and which did
     * not. */
    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        at = fb_append_str(report, sizeof(report), at, " p");
        at = fb_append_u32(report, sizeof(report), at, (uint32_t)i);
        at = fb_append_str(report, sizeof(report), at, "=");
        at = fb_append_u32(report, sizeof(report), at, blocks[i].valid);
        at = fb_append_str(report, sizeof(report), at, "/");
        at = fb_append_u32(report, sizeof(report), at, blocks[i].changes);
    }
    /* Why each candidate that could not be opened could not be opened.
     * Without this the report cannot distinguish "the node does not exist"
     * from "the node exists and the open was refused", and those are
     * different faults with different fixes. */
    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        at = fb_append_str(report, sizeof(report), at, " e");
        at = fb_append_u32(report, sizeof(report), at, (uint32_t)i);
        at = fb_append_str(report, sizeof(report), at, "=");
        at = fb_append_u32(report, sizeof(report), at,
                           (uint32_t)(blocks[i].fd >= 0 ? 0 : blocks[i].open_errno));
    }
    at = fb_append_str(report, sizeof(report), at, "\n");
    report[at] = '\0';

    phase_marker(report);
}
#endif /* LATCH_GOVERNOR_FEEDBACK */


#ifdef LATCH_GOVERNOR_FEEDBACK_VERDICT
/* =========================================================================
 * THE HOST->GUEST VERDICT WATCHER  (W5)
 *
 * WHAT THIS IS
 * ------------
 * The W4 profile MEASURED that a host-side verdict reaches a freestanding
 * guest policy.  This profile is the next step, and it is the one that
 * turns the channel from TELEMETRY into CONTROL: the guest DECODES the
 * verdict, CORRELATES it with the proposal it answers, and STOPS
 * PROPOSING when the supervisor says no.
 *
 * THE FAIL-CLOSED DIRECTION
 * --------------------------
 * There are exactly three ways this can end, and all three stop the guest:
 *
 *   1. the supervisor says REJECT -- it refused the proposal;
 *   2. no verdict arrives -- the channel is silent, and a guest that
 *      cannot hear its supervisor must not keep asking;
 *   3. the verdict is not one the guest understands -- "I did not
 *      understand" is NEVER read as "yes".
 *
 * There is no fourth way.  In particular, a verdict the guest cannot
 * CORRELATE (a foreign session epoch, a sequence number it never sent) is
 * counted and ignored -- but it does not stop the guest, because it is not
 * about this guest's proposals.  The counter says so, so "the channel
 * carried somebody else's frames" is distinguishable from "the channel was
 * silent".
 *
 * ONE WRITER
 * ----------
 * The correlation state has exactly ONE writer: the watcher thread.  The
 * main thread never touches it; it publishes what it sent through two
 * volatile words, and the watcher folds them in.  That is not a style
 * choice: a state two threads mutate needs a lock, and a freestanding
 * policy has no lock.
 *
 * "IS A PROPOSAL STILL UNANSWERED?" is DERIVED, not stored
 * -------------------------------------------------------
 *      outstanding  <=>  last_cmd_seq != 0 && last_cmd_seq > last_seq_verdict
 *
 * A derived predicate cannot go stale, and it cannot disagree with
 * itself: there is no "awaiting" flag that a lost update could leave
 * behind saying "waiting" when nobody is.
 *
 * THE WATCHER IS A SEPARATE THREAD, AND THAT IS THE POINT
 * -------------------------------------------------------
 * The proposal cadence must not depend on the feedback channel.  If the
 * main thread polled the verdict sector itself, every poll would be a hole
 * in the frame stream and the supervisor's dead-man would see it.  So the
 * polling happens on its own thread, and the main thread's only
 * interaction with it is a bounded WAIT for the answer to the proposal it
 * just sent.
 *
 * THE ORDER OF THE FOLD AND THE READ IS LOAD-BEARING
 * --------------------------------------------------
 * The watcher READS the verdict sector and only THEN folds in the
 * sequence numbers the main thread published, and it correlates the frame
 * it read AFTER the fold.  The other order loses verdicts:
 *
 *   * if the watcher folded BEFORE the read, a verdict could arrive for a
 *     sequence number the watcher had not folded in yet, and its
 *     staleness test (`verdict.seq > last_seq_sent`) would throw that
 *     verdict away -- and the guest would then wait for an answer it had
 *     already discarded;
 *   * so the main thread publishes the sequence number BEFORE the frame
 *     goes on the wire, and the watcher folds AFTER the read.  A verdict
 *     that exists at read time was necessarily published before it, so
 *     the fold that follows the read always covers it.
 *
 * And the fold reads the COMMAND sequence number BEFORE the general one:
 * the main thread publishes `seq_sent` first and `cmd_seq` second, so a
 * fold that saw `cmd_seq = N` is guaranteed to see `seq_sent >= N` when
 * it reads it next.  The other order could see `cmd_seq = N` with
 * `seq_sent = N-1`, which is exactly the stale-verdict case above.
 *
 * THAT GUARANTEE IS A HARDWARE ONE, AND IT NEEDS A HARDWARE BARRIER.
 * AArch64 is weakly ordered, so the two stores may become visible to the
 * other core in either order and the two loads may be reordered with
 * respect to each other -- and a compiler barrier changes neither.  The
 * release fence between the two stores and the acquire fence between the
 * two loads are what make the guarantee real; see
 * `guest/latch_fb_publish.h`.
 * ========================================================================= */

#include "latch_fb_decode.h"
/* The cross-core publication protocol.  The watcher runs on its own core,
 * so every word it shares with the main thread crosses a core boundary --
 * and a core boundary needs a MEMORY barrier, not a compiler barrier. */
#include "latch_fb_publish.h"
/* The shared transport.  It is included HERE, in the W5 region, and in the
 * W4 region above -- one per profile -- because the W4 translation unit's
 * function ORDER is part of its byte-identity witness: moving the include
 * out of the W4 region would reorder the compiled functions and change the
 * measured binary.  The header's own include guard makes a double include
 * harmless, but there is never one. */
#include "latch_fb_transport.h"

/* --------------------------------------------------------------------------
 * THE BUDGETS
 * ------------------------------------------------------------------------ */

/* The watcher's poll period.  It is the WATCHER's latency, not the
 * proposal cadence's: the main thread never waits on it in order to
 * send. */
#define LATCH_FB_POLL_MS               1u

/* How many polls without a correlated verdict are fatal.
 *
 * The guest policy has no clock, so the timeout is counted in POLLS: a
 * poll is a fixed-cost action, and "N polls without an answer" is a
 * duration that does not depend on a clock the guest does not have. */
#define LATCH_FB_TIMEOUT_POLLS         1000u

/* The main thread's own bound on ONE wait.  It is longer than the
 * watcher's timeout, so the WATCHER is the one that decides the guest has
 * stopped; this is a backstop against a lost handshake. */
#define LATCH_FB_WAIT_MAX_POLLS        1500u

/* How often the main thread sends a heartbeat while it waits for an
 * answer.
 *
 * The dead-man measures a producer's LIVENESS, not its productivity: a
 * guest that is waiting for the supervisor's answer is alive, and it must
 * not be demoted for waiting.  Without this the lease would expire while
 * the guest waited, and the supervisor would demote itself for a guest
 * that was behaving perfectly. */
#define LATCH_FB_WAIT_KEEPALIVE_POLLS  25u

/* The clean proposals the guest makes before the one the supervisor
 * refuses. */
#define LATCH_FB_CLEAN_COMMANDS        8u

/* The silence after the guest stops.
 *
 * It has to cover FOUR lease expiries: the refusal already demoted the
 * ladder one rung (HP -> ADVISE, because LATCH_FAULT_UNIT is inside the
 * manifest's advisory fault mask), and LATCH is four rungs below ADVISE.
 * Each expiry is one signed lease (100 ticks = 100 ms). */
#define LATCH_FB_FINAL_SILENCE_MS      900u

/* The unit the supervisor refuses.  It is neither the manifest's canonical
 * unit nor one of its alternates, so the gate raises LATCH_FAULT_UNIT --
 * an ADVISORY fault, so the ladder demotes ONE rung and keeps running. */
#define LATCH_FB_UNKNOWN_UNIT          999u

/* How long the main thread waits for the watcher to open the channel.
 * The watcher's open sequence can take a couple of seconds: the guest's
 * block layer may not have probed the device yet, and a candidate that
 * does not exist is retried eight times at 250 ms. */
#define LATCH_FB_READY_MAX_POLLS       2000u

/* The clone flags for the watcher thread.
 *
 * CLONE_THREAD requires CLONE_SIGHAND and CLONE_VM (kernel/fork.c:
 * "if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
 *  return ERR_PTR(-EINVAL)"), and CLONE_SIGHAND requires CLONE_VM. */
#define LATCH_FB_CLONE_VM              0x00000100u
#define LATCH_FB_CLONE_FS              0x00000200u
#define LATCH_FB_CLONE_FILES           0x00000400u
#define LATCH_FB_CLONE_SIGHAND         0x00000800u
#define LATCH_FB_CLONE_THREAD          0x00010000u
#define LATCH_FB_CLONE_SYSVSEM         0x00040000u

/* The watcher's stack.  It is STATIC: the guest policy has no malloc,
 * and 64 KiB is far more than the watcher needs. */
#define LATCH_FB_STACK_BYTES           65536u

/* THE STACK POINTER IS NOT AT THE TOP OF THE ARRAY, AND THAT IS
 * LOAD-BEARING.
 *
 * MEASURED (QEMU AArch64 + Linux 6.12, 2026-11-27): with the clone
 * child's stack pointer at the TOP of its array, the child died with
 * SIGSEGV before it executed a single line of the watcher, and because it
 * is a thread of PID 1 the whole init group went down with it
 * ("Kernel panic - not syncing: Attempted to kill init!
 *  exitcode=0x0000000b").
 *
 * WHY.  The kernel sets the child's stack pointer to `newsp` EXACTLY
 * (kernel/fork.c: "childregs->sp = stack_start"), and the compiler gives
 * that child entry point a FRAME it SHARES with the parent.  The shared
 * frame puts the callee-saved spill slots at POSITIVE offsets from the
 * stack pointer, not below it.  Measured in the built binary:
 *
 *     stp x19, x20, [sp, #16]      <- the child's FIRST store
 *     stp x21, x22, [sp, #32]
 *     ...                          <- up to [sp, #208], in a 400-byte frame
 *
 * So the memory ABOVE the stack pointer has to be mapped, not just the
 * memory below it.  The array's top happened to be the ELF's RW segment
 * end (__bss_end__ = 0x432000), so the child's first store -- 0x432010 --
 * was in the first unmapped page above the image, and the child faulted
 * on its first instruction that touched memory.
 *
 * The slack below reserves that margin INSIDE the mapped array.  The
 * child's usable stack is still 60 KiB -- a poll loop needs a few
 * hundred bytes -- and the margin is four times the measured frame. */
#define LATCH_FB_STACK_SLACK           4096u

/* --------------------------------------------------------------------------
 * THE HAND-BETWEEN THE TWO THREADS
 * ------------------------------------------------------------------------ */

/* THE VERDICT PUBLICATION IS ONE 64-BIT WORD, NOT SEVERAL.
 *
 * A naturally-aligned 64-bit store is single-copy atomic on AArch64, so
 * the main thread can never see a sequence number and a verdict that do
 * not belong together.  With several separate words it could: it would
 * read the NEW sequence number and the OLD verdict, and conclude that a
 * REJECTION was an ACCEPTANCE -- which is the one mistake this whole
 * profile exists to prevent.
 *
 *   bits  0..7  : the verdict (0 = none, 1 = accept, 2 = reject)
 *   bits  8..31 : the sequence number the verdict answers
 *   bits 32..39 : why the guest stopped (0 none, 1 rejected, 2 timeout)
 */
static volatile uint64_t g_fb_verdict_word = 0u;

#define LATCH_FB_WORD_VERDICT(w)  ((uint32_t)((w) & 0xFFu))
#define LATCH_FB_WORD_SEQ(w)     ((uint32_t)(((w) >> 8) & 0xFFFFFFu))
#define LATCH_FB_WORD_STOP(w)    ((uint32_t)(((w) >> 32) & 0xFFu))

/* The sequence numbers the main thread published.  The watcher reads
 * `g_fb_cmd_seq` FIRST and `g_fb_seq_sent` second -- see the header. */
static volatile uint32_t g_fb_seq_sent = 0u;
static volatile uint32_t g_fb_cmd_seq  = 0u;

/* The main thread's own tallies.  Only the main thread writes them. */
static volatile uint32_t g_fb_frames_sent = 0u;
static volatile uint32_t g_fb_cmds_sent = 0u;

/* THE WATCHER'S HANDSHAKE.
 *
 * `g_fb_watcher_state` is the ONE publication point for the startup
 * handshake: the watcher moves it out of LATCH_FB_WATCHER_STARTING
 * exactly once -- to READY when the channel opened, or to FAILED when
 * there is no channel at all -- and the main thread waits for that.  It
 * was two flags (`ready` and `failed`) before, and two flags meant two
 * publication points: the main thread had to know WHICH one it had seen
 * to know which release fence had ordered the watcher's work.
 */
#define LATCH_FB_WATCHER_STARTING 0u
#define LATCH_FB_WATCHER_READY    1u
#define LATCH_FB_WATCHER_FAILED   2u

static volatile uint32_t g_fb_watcher_state = LATCH_FB_WATCHER_STARTING;
static volatile uint32_t g_fb_watcher_stop_requested = 0u;
static volatile uint32_t g_fb_watcher_stopped = 0u;

/* WHAT THE WATCHER PUBLISHES BACK FOR THE REPORT.
 *
 * The correlation state belongs to the watcher.  When the watcher stops it
 * copies what the report needs into this struct and then raises
 * `g_fb_watcher_stopped`; the main thread waits for that flag and then
 * reads the struct.  The barrier between them is a RELEASE fence before
 * the flag and an ACQUIRE fence after it, because the struct is PLAIN
 * memory: the flag is volatile and the struct is not, and only a
 * hardware barrier stops the other core from seeing the flag before the
 * struct's stores.  See `guest/latch_fb_publish.h`. */
typedef struct {
    uint32_t accepts;
    uint32_t rejects;
    uint32_t foreign;
    uint32_t stale;
    uint32_t duplicates;
    uint32_t torn;        /* looked like a frame and failed the CRC      */
    uint32_t empty;       /* did not even carry the frame magic          */
    uint32_t timeouts;
    uint32_t polls;
    uint32_t max_round_trip_polls;
    uint32_t pinned_epoch;
    uint32_t stop_reason;
    uint32_t last_seq_verdict;
    uint32_t reads;
    uint32_t valid;
    uint32_t changes;     /* DISTINCT verdicts seen                      */
    int      best;        /* the candidate that carried the channel      */
    int      opens;
} fb_watch_summary_t;

static fb_watch_summary_t g_fb_summary;

/* --------------------------------------------------------------------------
 * THE WATCHER
 * ------------------------------------------------------------------------ */

/* Publish one decision.
 *
 * The verdict word crosses the core boundary: the watcher writes it and
 * the main thread reads it.  The release fence inside the call is what
 * makes the word's contents visible to a reader that consumes it -- a
 * plain store would let the CPU make the word visible before the
 * decision it carries was complete.
 */
static void fb_publish(const latch_fb_state_t *st, uint8_t verdict, uint32_t seq) {
    uint64_t w = (uint64_t)seq << 8;
    w |= (uint64_t)(verdict & 0xFFu);
    w |= (uint64_t)((st->stop_reason & 0xFFu)) << 32;
    latch_fb_publish_release_store64(&g_fb_verdict_word, w);
}

static void fb_watcher_thread(void) {
    static uint8_t sector[LATCH_FB_READ_BYTES]
        __attribute__((aligned(LATCH_FB_BUFFER_ALIGN)));
    static fb_blk_t blocks[LATCH_FB_BLOCK_MAX];
    static uint32_t torn[LATCH_FB_BLOCK_MAX];
    static uint32_t empty[LATCH_FB_BLOCK_MAX];
    latch_fb_state_t st;
    latch_fb_frame_t pending;
    int have_pending = 0;
    int opens = 0;

    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        blocks[i].fd = -1;
        blocks[i].open_errno = 0;
        blocks[i].direct = 0;
        blocks[i].direct_errno = 0;
        blocks[i].advise_errno = 0;
        blocks[i].read_errno = 0;
        torn[i] = 0u;
        empty[i] = 0u;
    }

    latch_fb_state_init(&st, LATCH_FB_TIMEOUT_POLLS);

    /* Open EVERY candidate.  A watcher that guessed the wrong node would
     * never see a verdict, and it would report a channel that does not
     * exist. */
    for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
        blocks[i].fd = fb_open_block(fb_block_candidates[i],
                                     &blocks[i].open_errno,
                                     &blocks[i].direct,
                                     &blocks[i].direct_errno);
        if (blocks[i].fd >= 0) {
            opens++;
        }
    }

    if (opens == 0) {
        /* NO DEVICE AT ALL.  The guest cannot see its supervisor, so it
         * does not propose: fail closed, and say so. */
        st.stopped = 1;
        st.stop_reason = LATCH_FB_STOP_TIMEOUT;
        st.timeouts = 1u;
        fb_publish(&st, 0u, 0u);
        /* THE PUBLICATION POINT.  The release fence inside the call makes
         * the verdict word and the state visible before the state itself
         * becomes visible, so a main thread that sees FAILED also sees
         * WHY. */
        latch_fb_publish_release_store32(&g_fb_watcher_state,
                                         LATCH_FB_WATCHER_FAILED);
        latch_fb_publish_release_store32(&g_fb_watcher_stopped, 1u);
        return;
    }

    latch_fb_publish_release_store32(&g_fb_watcher_state,
                                     LATCH_FB_WATCHER_READY);

    for (;;) {
        if (latch_fb_publish_acquire_load32(&g_fb_watcher_stop_requested)) {
            break;
        }

        have_pending = 0;

        /* ---- THE READ ------------------------------------------------- */
        for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
            fb_blk_t *b = &blocks[i];
            latch_fb_frame_t f;
            uint32_t prev_seq;
            uint32_t prev_valid;
            long n;

            if (b->fd < 0) {
                continue;
            }

            /* ONE FRESH READ: the shared macro drops the cached pages
             * before every buffered read, so the watcher measures the
             * TRANSPORT and not its own page cache.  See
             * guest/latch_fb_transport.h. */
            LATCH_FB_DROP_CACHE(b);
            n = sys_pread64(b->fd, sector, sizeof(sector), 0);
            if (n < 0) {
                b->read_errno = (int)(-n);
                if (b->direct != 0 && (int)(-n) == LATCH_FB_EINVAL) {
                    /* The device refused a DIRECT read.  Fall back to the
                     * buffered view and SAY SO: a buffered watcher can
                     * still find the device, but it cannot promise
                     * freshness. */
                    sys_close(b->fd);
                    b->fd = (int)sys_open(fb_block_candidates[i], O_RDONLY);
                    b->direct = 0;
                    if (b->fd >= 0) {
                        n = sys_pread64(b->fd, sector, sizeof(sector), 0);
                        if (n < 0) {
                            b->read_errno = (int)(-n);
                        }
                    }
                }
            }
            b->reads++;
            if (n != (long)sizeof(sector)) {
                empty[i]++;
                continue;
            }

            {
                int rc = latch_fb_decode(sector, LATCH_FB_SIZE, &f);
                if (rc != LATCH_FB_OK) {
                    if (rc == LATCH_FB_EFRAME) {
                        /* Was it a frame at all?  A sector that does not
                         * even carry the magic is simply not the channel;
                         * a sector that carries the magic and fails the
                         * version/size/CRC checks is a TORN READ, which is
                         * a different fault with a different fix. */
                        uint32_t magic = (uint32_t)sector[0] |
                                         ((uint32_t)sector[1] << 8) |
                                         ((uint32_t)sector[2] << 16) |
                                         ((uint32_t)sector[3] << 24);
                        if (magic == LATCH_FB_MAGIC) {
                            torn[i]++;
                        } else {
                            empty[i]++;
                        }
                    } else {
                        torn[i]++;
                    }
                    continue;
                }
            }

            prev_seq = b->last_seq;
            prev_valid = b->valid;
            b->valid++;
            if (prev_valid == 0u) {
                b->first_seq = f.seq;
                b->epoch = f.epoch;
            }
            if (f.seq != prev_seq) {
                b->changes++;
            }
            b->last_seq = f.seq;
            b->verdict = f.verdict;
            b->rung = f.rung;
            b->faults = f.fault_bits;

            /* THE VERDICT FILE HOLDS THE LATEST VERDICT, so a repeated
             * read of the SAME sequence number is the SAME verdict and is
             * not correlated again.  Correlating every read would turn
             * the census into a count of polls, and a count of polls
             * cannot answer "how many times was I told no?". */
            if (prev_valid == 0u || f.seq != prev_seq) {
                if (!have_pending) {
                    pending = f;
                    have_pending = 1;
                }
            }
        }

        /* ---- THE FOLD ---------------------------------------------------
         * AFTER the read, and the command sequence number BEFORE the
         * general one.  See the header for why the order is this one --
         * and the acquire fence between the two loads is what MAKES the
         * order real: without it the CPU is free to deliver the two
         * values in either order, and the guarantee the header claims
         * would be a claim about the source rather than about the
         * hardware. */
        {
            uint32_t cseq = 0u;
            uint32_t sseq = 0u;
            latch_fb_publish_seq_get(&g_fb_cmd_seq, &g_fb_seq_sent,
                                     &cseq, &sseq);
            latch_fb_note_cmd(&st, cseq);
            latch_fb_note_sent(&st, sseq);
        }

        /* ---- THE CORRELATION -------------------------------------------- */
        if (have_pending) {
            int res = latch_fb_correlate(&st, &pending);
            if (res == LATCH_FB_RES_ACCEPT || res == LATCH_FB_RES_REJECT) {
                fb_publish(&st, pending.verdict, pending.seq);
            }
        }

        /* ---- THE TIMEOUT --------------------------------------------------
         * A proposal that is never answered is a supervisor that has
         * stopped listening, and the guest must fail closed on it. */
        if (latch_fb_note_poll(&st)) {
            fb_publish(&st, 0u, st.last_cmd_seq);
        }

        sys_sleep_ms(LATCH_FB_POLL_MS);
    }

    /* ---- THE SUMMARY FOR THE REPORT ---------------------------------- */
    {
        int best = -1;
        for (int i = 0; i < LATCH_FB_BLOCK_MAX; ++i) {
            if (blocks[i].valid == 0u) {
                continue;
            }
            if (best < 0 ||
                blocks[i].valid > blocks[best].valid ||
                (blocks[i].valid == blocks[best].valid &&
                 blocks[i].changes > blocks[best].changes)) {
                best = i;
            }
        }
        g_fb_summary.accepts = st.accepts;
        g_fb_summary.rejects = st.rejects;
        g_fb_summary.foreign = st.foreign;
        g_fb_summary.stale = st.stale;
        g_fb_summary.duplicates = st.duplicates;
        g_fb_summary.torn = torn[best >= 0 ? best : 0];
        g_fb_summary.empty = empty[best >= 0 ? best : 0];
        g_fb_summary.timeouts = st.timeouts;
        g_fb_summary.polls = st.polls;
        g_fb_summary.max_round_trip_polls = st.max_round_trip_polls;
        g_fb_summary.pinned_epoch = st.pinned_epoch;
        g_fb_summary.stop_reason = st.stop_reason;
        g_fb_summary.last_seq_verdict = st.last_seq_verdict;
        g_fb_summary.reads = (best >= 0) ? blocks[best].reads : 0u;
        g_fb_summary.valid = (best >= 0) ? blocks[best].valid : 0u;
        g_fb_summary.changes = (best >= 0) ? blocks[best].changes : 0u;
        g_fb_summary.best = best;
        g_fb_summary.opens = opens;
    }
    /* THE PUBLICATION POINT.  Every field of `g_fb_summary` is PLAIN
     * memory -- not volatile, not atomic -- so the CPU is free to make
     * the flag store visible before the summary's stores.  The release
     * fence inside the call is what orders them, and it has to come
     * AFTER every summary write and not one instruction earlier. */
    latch_fb_publish_release_store32(&g_fb_watcher_stopped, 1u);
}

/* Start the watcher thread.  Returns 0 when the thread was created. */
static int fb_start_watcher(void) {
    static uint8_t stack[LATCH_FB_STACK_BYTES] __attribute__((aligned(16)));
    /* The low bits of `flags` are the EXIT SIGNAL.  SIGCHLD (17) is what
     * a thread group expects; the kernel's CLONE_THREAD path ignores it
     * for the child's own exit, but it must not be an uncatchable
     * signal. */
    unsigned long flags = LATCH_FB_CLONE_VM | LATCH_FB_CLONE_FS |
                          LATCH_FB_CLONE_FILES | LATCH_FB_CLONE_SIGHAND |
                          LATCH_FB_CLONE_THREAD | LATCH_FB_CLONE_SYSVSEM |
                          17u /* SIGCHLD */;

    /* AArch64's clone(2) is syscall 220, and arm64 DOES select
     * CONFIG_CLONE_BACKWARDS (arch/arm64/Kconfig:126 "select
     * CLONE_BACKWARDS"), so the kernel's signature is
     *   clone(clone_flags, newsp, parent_tidptr, tls, child_tidptr)
     * (kernel/fork.c: SYSCALL_DEFINE5(clone, clone_flags, newsp,
     * parent_tidptr, tls, child_tidptr)).  The three trailing arguments
     * are all NULL here, so their order does not matter -- but the
     * MEASURED fact is recorded because the earlier note in this file
     * claimed the opposite ("arm64 sets none of CONFIG_CLONE_BACKWARDS*")
     * and that claim was FALSE. */
    long ret = sys6(SYS_clone, (long)flags,
                    (long)(stack + sizeof(stack) - LATCH_FB_STACK_SLACK),
                    0, 0, 0, 0);
    if (ret == 0) {
        /* THE CHILD.  It has its own stack and it NEVER returns: the
         * function that called clone() lives on the MAIN thread's stack,
         * and returning into it from here would unwind a frame that
         * belongs to another thread. */
        fb_watcher_thread();
        for (;;) {
            sys_sleep_ms(60000);
        }
    }
    if (ret < 0) {
        return -1;
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * THE MAIN THREAD'S SIDE
 * ------------------------------------------------------------------------ */

/* Send one frame and PUBLISH its sequence number.
 *
 * The publication happens BEFORE the frame goes on the wire, and the
 * reason is in the header: the watcher's staleness test is
 * `verdict.seq > last_seq_sent`, so a sequence number published after the
 * frame was on the wire could be seen by the watcher as a verdict for a
 * proposal it has not recorded -- and that verdict would be thrown away.
 *
 * The ORDER of the two stores, and the fence between them, live inside
 * `latch_fb_publish_seq_set()`: the general sequence number first, the
 * command sequence number second, with a release fence between them.
 * That is what makes the guest's own guarantee real -- IF THE WATCHER
 * SEES `cmd_seq = N`, IT ALSO SEES `seq_sent >= N` -- on hardware that
 * is weakly ordered, and it is impossible to spell the pair the wrong
 * way round at a call site.
 */
static void fb_send_frame(int hvc_fd, lath_frame_t *frame, uint8_t kind,
                          uint32_t *seq, uint32_t *coherence, int32_t value,
                          uint8_t confidence_q8, uint32_t unit_id, int is_cmd) {
    uint32_t this_seq = *seq;

    latch_fb_publish_seq_set(&g_fb_seq_sent, &g_fb_cmd_seq, this_seq, is_cmd);
    g_fb_frames_sent++;
    if (is_cmd) {
        g_fb_cmds_sent++;
    }

    send_governor_frame(hvc_fd, frame, kind, seq, coherence, value,
                        confidence_q8, unit_id);
}

/*
 * Wait for the verdict on ONE proposal.
 *
 * Returns 0 when the supervisor ACCEPTED the proposal, and -1 when it
 * refused it, when the channel went silent, or when the wait expired.
 * Every one of those is a reason to stop, so the caller does not have to
 * distinguish them -- but the REPORT does, and the watcher records which.
 */
static int fb_wait_for_verdict(int hvc_fd, lath_frame_t *frame, uint32_t cmd_seq,
                               uint32_t *seq, uint32_t *coherence) {
    for (uint32_t i = 0u; i < LATCH_FB_WAIT_MAX_POLLS; ++i) {
        /* The verdict word crosses the core boundary, so it is read
         * through the acquire accessor: the load is relaxed and the
         * fence that follows it is what makes the verdict's bits visible
         * to this core. */
        uint64_t w = latch_fb_publish_acquire_load64(&g_fb_verdict_word);
        uint32_t wseq = LATCH_FB_WORD_SEQ(w);
        uint32_t wstop = LATCH_FB_WORD_STOP(w);

        if (wseq >= cmd_seq) {
            if (wstop != LATCH_FB_STOP_NONE) {
                return -1;      /* the supervisor said no */
            }
            return 0;          /* the supervisor accepted */
        }
        if (wstop != LATCH_FB_STOP_NONE) {
            return -1;          /* the watcher gave up: fail closed */
        }

        /* Keep the lease alive while we wait: the dead-man measures a
         * producer's LIVENESS, not its productivity. */
        if (((i + 1u) % LATCH_FB_WAIT_KEEPALIVE_POLLS) == 0u) {
            fb_send_frame(hvc_fd, frame, GOV_WIRE_HEARTBEAT, seq, coherence,
                          0, 0u, 0u, 0);
            flush_frames(hvc_fd);
        }
        sys_sleep_ms(LATCH_FB_POLL_MS);
    }
    return -1;                  /* the wait expired: fail closed */
}

/* THE REPORT.
 *
 * It ends with `end=1`, which is the completeness sentinel: a report that
 * was cut short by the console does not end with it, and the harness
 * requires it.  The marker is written AFTER the session is over, so the
 * console cost of the report cannot eat the lease.
 *
 * THE ACQUIRE IS HERE, INSIDE THE FUNCTION THAT READS THE SUMMARY, so
 * that the ordering cannot be forgotten at a call site.  `g_fb_summary`
 * is PLAIN memory written by the watcher thread, and the stopped flag is
 * its publication point: the watcher's release fence orders the summary's
 * stores before the flag, and the acquire fence here orders the flag's
 * load before the summary's loads.  The two together are what make the
 * report a coherent snapshot rather than a torn one.
 */
static void fb_build_report(char *dst, size_t cap) {
    size_t at = 0;
    const fb_watch_summary_t *s;
    uint64_t w;

    (void)latch_fb_publish_acquire_load32(&g_fb_watcher_stopped);
    s = &g_fb_summary;
    w = latch_fb_publish_acquire_load64(&g_fb_verdict_word);

    at = fb_append_str(dst, cap, at, "[FBVERDICT] port=");
    at = fb_append_str(dst, cap, at,
                       (s->best >= 0) ? fb_block_candidates[s->best] : "none");
    at = fb_append_str(dst, cap, at, " opens=");
    at = fb_append_u32(dst, cap, at, (uint32_t)s->opens);
    at = fb_append_str(dst, cap, at, " reads=");
    at = fb_append_u32(dst, cap, at, s->reads);
    at = fb_append_str(dst, cap, at, " frames=");
    at = fb_append_u32(dst, cap, at, s->valid);
    at = fb_append_str(dst, cap, at, " changes=");
    at = fb_append_u32(dst, cap, at, s->changes);
    at = fb_append_str(dst, cap, at, " sent=");
    at = fb_append_u32(dst, cap, at, g_fb_frames_sent);
    at = fb_append_str(dst, cap, at, " cmds=");
    at = fb_append_u32(dst, cap, at, g_fb_cmds_sent);
    at = fb_append_str(dst, cap, at, " acc=");
    at = fb_append_u32(dst, cap, at, s->accepts);
    at = fb_append_str(dst, cap, at, " rej=");
    at = fb_append_u32(dst, cap, at, s->rejects);
    at = fb_append_str(dst, cap, at, " foreign=");
    at = fb_append_u32(dst, cap, at, s->foreign);
    at = fb_append_str(dst, cap, at, " stale=");
    at = fb_append_u32(dst, cap, at, s->stale);
    at = fb_append_str(dst, cap, at, " dup=");
    at = fb_append_u32(dst, cap, at, s->duplicates);
    at = fb_append_str(dst, cap, at, " torn=");
    at = fb_append_u32(dst, cap, at, s->torn);
    at = fb_append_str(dst, cap, at, " empty=");
    at = fb_append_u32(dst, cap, at, s->empty);
    at = fb_append_str(dst, cap, at, " to=");
    at = fb_append_u32(dst, cap, at, s->timeouts);
    at = fb_append_str(dst, cap, at, " polls=");
    at = fb_append_u32(dst, cap, at, s->polls);
    at = fb_append_str(dst, cap, at, " maxrt=");
    at = fb_append_u32(dst, cap, at, s->max_round_trip_polls);
    at = fb_append_str(dst, cap, at, " epoch=0x");
    at = fb_append_hex8(dst, cap, at, s->pinned_epoch);
    at = fb_append_str(dst, cap, at, " stop=");
    at = fb_append_str(dst, cap, at,
                       (s->stop_reason == LATCH_FB_STOP_REJECTED) ? "reject" :
                       (s->stop_reason == LATCH_FB_STOP_TIMEOUT)  ? "timeout" :
                                                                    "none");
    at = fb_append_str(dst, cap, at, " last=");
    at = fb_append_u32(dst, cap, at, LATCH_FB_WORD_SEQ(w));
    at = fb_append_str(dst, cap, at, " end=1");
    if (at < cap) {
        dst[at] = '\0';
    }
}

/* --------------------------------------------------------------------------
 * THE SCENARIO
 * ------------------------------------------------------------------------ */
static void run_governor_verdict_demo(int hvc_fd) {
    lath_frame_t frame;
    uint32_t seq = 1u;
    uint32_t coherence = 0u;
    uint32_t clean_ok = 1u;
    uint32_t watcher_state = LATCH_FB_WATCHER_STARTING;
    char report[250];

    /* ---- THE WATCHER ----------------------------------------------------
     * The watcher is started FIRST, before any console output: its open
     * sequence can take a couple of seconds (the guest's block layer may
     * not have probed the device yet), and that time is free while the
     * dead-man is not running. */
    if (fb_start_watcher() != 0) {
        phase_marker("[FBVERDICT] FATAL: cannot start the verdict watcher\n");
        for (;;) {
            sys_sleep_ms(60000);
        }
    }
    /* THE HANDSHAKE.  ONE state word, published ONCE by the watcher, and
     * read here through the acquire accessor: the load is relaxed and the
     * fence that follows it is what makes the watcher's own work visible
     * to this core.  Two flags would have meant two publication points
     * and two chances to read the wrong one first. */
    for (uint32_t i = 0u; i < LATCH_FB_READY_MAX_POLLS; ++i) {
        watcher_state = latch_fb_publish_acquire_load32(&g_fb_watcher_state);
        if (watcher_state != LATCH_FB_WATCHER_STARTING) {
            break;
        }
        sys_sleep_ms(10);
    }

    /* ---- THE SCENARIO PLAN ----------------------------------------------
     *
     * EVERY annotation for the whole scenario is printed HERE, before the
     * session opens.  That is a measured requirement, not a style choice:
     * a console line costs ~70 ms of GUEST TIME on this platform and the
     * signed lease is 100 ticks (~100 ms), so a marker inside the
     * supervised window would EAT the lease.  The whole plan therefore
     * goes out BEFORE the session opens, and the console is then given
     * LATCH_GOVERNOR_CONSOLE_DRAIN_MS to drain while the dead-man is
     * still not running.
     *
     * From the warm-up flush onwards the guest writes NOTHING to the
     * console: the report comes out after the final silence, when the
     * session is already over and the lease no longer matters. */
    phase_marker("[FBVERDICT] verdict watcher: 4 warm-up heartbeats\n");
    phase_marker("[FBVERDICT] 8 clean proposals, each waited for its verdict\n");
    phase_marker("[FBVERDICT] one proposal in an unknown unit: refused\n");
    phase_marker("[FBVERDICT] the guest stops; the lease expires; the ladder reaches LATCH\n");
    sys_sleep_ms(LATCH_GOVERNOR_CONSOLE_DRAIN_MS);

    /* If the channel could not be opened at all, the guest does not
     * propose: a guest that cannot see its supervisor must not keep
     * asking.  The report says why.  The state was read through the
     * acquire accessor when the handshake completed, so the value here is
     * the one the watcher published. */
    if (watcher_state == LATCH_FB_WATCHER_FAILED) {
        fb_build_report(report, sizeof(report));
        phase_marker(report);
        for (;;) {
            sys_sleep_ms(60000);
        }
    }

    /* ---- THE WARM-UP ----------------------------------------------------
     * The signed contract wants four coherent heartbeats before the first
     * motion proposal; the supervisor counts them and refuses a command
     * that arrives before the warm-up is complete. */
    for (uint32_t i = 0u; i < LATCH_GOVERNOR_WARMUP_HEARTBEATS; ++i) {
        fb_send_frame(hvc_fd, &frame, GOV_WIRE_HEARTBEAT, &seq, &coherence,
                      0, 0u, 0u, 0);
    }
    flush_frames(hvc_fd);

    /* ---- THE CLEAN PROPOSALS --------------------------------------------
     * One at a time, each waited for: the verdict file holds the LATEST
     * verdict, so a guest that fired them all at once would only ever see
     * the last answer.  The verdict file is the transport, and the
     * transport's shape is part of the protocol. */
    for (uint32_t i = 0u; i < LATCH_FB_CLEAN_COMMANDS; ++i) {
        uint32_t cmd_seq = seq;
        fb_send_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq, &coherence,
                      100, 255u, 1u, 1);
        flush_frames(hvc_fd);
        if (fb_wait_for_verdict(hvc_fd, &frame, cmd_seq, &seq, &coherence) != 0) {
            clean_ok = 0u;
            break;
        }
    }

    /* ---- THE PROPOSAL THE SUPERVISOR REFUSES ----------------------------
     * The unit is not in the manifest, so the gate raises LATCH_FAULT_UNIT
     * and the supervisor answers "no".  The guest reads that answer and
     * stops asking. */
    if (clean_ok) {
        uint32_t cmd_seq = seq;
        fb_send_frame(hvc_fd, &frame, GOV_WIRE_CMD_V2, &seq, &coherence,
                      120, 255u, LATCH_FB_UNKNOWN_UNIT, 1);
        flush_frames(hvc_fd);
        (void)fb_wait_for_verdict(hvc_fd, &frame, cmd_seq, &seq, &coherence);
    }

    /* ---- THE GUEST STOPS -------------------------------------------------
     * Nothing else goes on the wire.  The trusted host owns lease time: the
     * silence is what expires the lease, and the ladder ratchets to LATCH.
     * The guest's job is to stop asking; the host's job is to fail closed
     * when the guest stops.
     *
     * Both flags cross the core boundary, so both go through the
     * protocol: the request is published with a release fence (so the
     * watcher sees it), and the acknowledgement is consumed with an
     * acquire fence (so the summary the watcher wrote is visible to the
     * report). */
    latch_fb_publish_release_store32(&g_fb_watcher_stop_requested, 1u);
    for (uint32_t i = 0u; i < 1000u; ++i) {
        if (latch_fb_publish_acquire_load32(&g_fb_watcher_stopped)) {
            break;
        }
        sys_sleep_ms(1);
    }

    sys_sleep_ms(LATCH_FB_FINAL_SILENCE_MS);

    /* ---- THE REPORT ------------------------------------------------------
     * The session is over, so the console is free and the report costs
     * nothing that matters. */
    fb_build_report(report, sizeof(report));
    phase_marker(report);

    sys_close(hvc_fd);
    for (;;) {
        sys_sleep_ms(60000);
    }
}
#endif /* LATCH_GOVERNOR_FEEDBACK_VERDICT */


#endif /* !LATCH_GOVERNOR_INFER */
#endif /* LATCH_GOVERNOR_V2 */

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
    /* Lift the /dev/kmsg userspace rate limit before the first marker, so
     * that no phase marker is silently dropped.  See phase_marker(). */
    enable_devkmsg_log();

    /* Never open a second marker port in the GOVERNOR profile. The only
     * virtio-console is the safety-relevant black channel; all markers stay
     * on the non-blocking kernel log path. */
#ifdef LATCH_GOVERNOR_V2
    g_marker_fd = -1;
#else
    g_marker_fd = (int)sys_open("/dev/hvc1", O_WRONLY | O_NOCTTY);
#endif

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

#ifdef LATCH_GOVERNOR_V2
    phase_marker("[guest] /dev/hvc0 opened! Configuring raw mode for GOVERNOR wire v2...\n");
#else
    phase_marker("[guest] /dev/hvc0 opened! Configuring raw mode & streaming the 84-frame LATH suite...\n");
#endif
    set_tty_raw(hvc_fd);

#if defined(LATCH_GOVERNOR_INFER)
    run_infer_profile(hvc_fd);
#elif defined(LATCH_GOVERNOR_FEEDBACK)
    /* The feedback-TRANSPORT PROBE runs BEFORE the session opens: the
     * supervisor's dead-man starts counting at the first frame, and the
     * probe's report must be on the console while the dead-man is not yet
     * running.  It is a transport measurement, not a safety event. */
    run_feedback_probe();
    run_governor_demo(hvc_fd);
#elif defined(LATCH_GOVERNOR_FEEDBACK_VERDICT)
    /* The verdict WATCHER runs its own scenario.  It starts the watcher
     * thread BEFORE the session opens (so the channel is open before the
     * first proposal), and it reports ONCE, after the final silence, when
     * the session is over and the console costs nothing that matters. */
    run_governor_verdict_demo(hvc_fd);
#elif defined(LATCH_GOVERNOR_LATENCY_SOAK)
    /* The U-4 LATENCY SOAK streams in-envelope commands at a fixed rate for
     * 25 minutes so the supervisor can aggregate its own decision-latency
     * distribution over a million-plus ticks.  The console is quiet for the
     * whole soak: the plan was printed before the session opened. */
    run_governor_latency_soak(hvc_fd);
#elif defined(LATCH_GOVERNOR_V2)
    run_governor_demo(hvc_fd);
#else
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
     * sent LATCH_WIRE_FLAG_SILENCE frames here; the host honors that flag as
     * an idle tick (latchd.c:831-833), so those were counted as replays and
     * the watchdog never fired. This revision STOPS WRITING for a REAL gap. */
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
#endif
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
