/*
 * guest/lath_guest_init.c
 *
 * Freestanding static AArch64 Linux /init for QNX Hypervisor 8.0 (qvm) guest.
 * Zero libc dependencies: uses direct AArch64 Linux syscalls (`svc #0`).
 * Mounts proc/sysfs/devtmpfs, creates /dev/hvc0 (229:0) & /dev/console (5:1),
 * prints status to /dev/console, and streams the 200-tick LATH wire-frame
 * fault suite at 1 ms pacing to /dev/hvc0.
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

#define LATCH_WIRE_MAGIC        0x4C415448u
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

static inline uint64_t mkdev(uint32_t maj, uint32_t min) {
    return (((uint64_t)(maj & 0xfffu)) << 8) | ((uint64_t)(min & 0xffu));
}

static void kputs(int fd, const char *s) {
    size_t len = 0;
    while (s[len] != '\0') ++len;
    sys_write(fd, s, len);
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

static uint8_t tx_buf[1024];
static size_t  tx_len = 0;

static void flush_frames(int hvc_fd) {
    const uint8_t *p = tx_buf;
    size_t rem = tx_len;
    while (rem > 0) {
        long n = sys_write(hvc_fd, p, rem);
        if (n < 0) {
            if (n == -4 || n == -11) { /* -EINTR / -EAGAIN */
                sys_sleep_ms(1);
                continue;
            }
            break;
        }
        p += (size_t)n;
        rem -= (size_t)n;
    }
    tx_len = 0;
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

    int cfd = (int)sys_open("/dev/console", O_RDWR);
    if (cfd >= 0) {
        sys_dup2(cfd, 0);
        sys_dup2(cfd, 1);
        sys_dup2(cfd, 2);
        if (cfd > 2) sys_close(cfd);
    }

    kputs(1, "\n=== LATCH Linux 6.12 Guest Userspace (/init) Alive ===\n");

    int hvc_fd = -1;
    for (int attempt = 0; attempt < 20; ++attempt) {
        hvc_fd = (int)sys_open("/dev/hvc0", O_WRONLY | O_NOCTTY);
        if (hvc_fd >= 0) break;
        kputs(1, "[guest] waiting for /dev/hvc0...\n");
        sys_sleep_ms(100);
    }

    if (hvc_fd < 0) {
        kputs(1, "[guest] FATAL: cannot open /dev/hvc0\n");
        for (;;) sys_sleep_ms(10000);
    }

    kputs(1, "[guest] /dev/hvc0 opened! Configuring raw mode & streaming 200-tick LATH suite...\n");
    set_tty_raw(hvc_fd);

    uint32_t seq = 1u;
    int32_t theta = 0;
    lath_frame_t f;

    for (int t = 1; t <= 25; ++t) {
        if (theta > -150) theta -= 10;
        pack_frame(&f, seq++, theta, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    for (int t = 26; t <= 32; ++t) {
        pack_frame(&f, seq++, 450, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);
    sys_sleep_ms(10);
    for (int t = 33; t <= 57; ++t) {
        pack_frame(&f, seq++, -150, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    for (int t = 58; t <= 62; ++t) {
        if (theta > -180) theta -= 10;
        pack_frame(&f, seq++, theta, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);
    sys_sleep_ms(10);
    for (int t = 63; t <= 66; ++t) {
        pack_frame(&f, seq++, -180, LATCH_WIRE_FLAG_NONE, 1);
        send_frame(hvc_fd, &f);
    }
    for (int t = 67; t <= 70; ++t) {
        pack_frame(&f, seq++, LATCH_NAN_MRAD, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    uint32_t last_good_seq = seq;
    for (int t = 71; t <= 80; ++t) {
        last_good_seq = seq;
        pack_frame(&f, seq++, -180, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    for (int t = 81; t <= 84; ++t) {
        pack_frame(&f, last_good_seq, -180, LATCH_WIRE_FLAG_NONE, 0);
        send_frame(hvc_fd, &f);
    }
    for (int t = 85; t <= 200; ++t) {
        pack_frame(&f, last_good_seq, 0, LATCH_WIRE_FLAG_SILENCE, 0);
        send_frame(hvc_fd, &f);
    }
    flush_frames(hvc_fd);

    kputs(1, "[guest] 200-tick LATH suite complete! Entering idle sleep.\n");
    sys_close(hvc_fd);

    for (;;) {
        sys_sleep_ms(60000);
    }
    sys6(SYS_exit, 0, 0, 0, 0, 0, 0);
}
