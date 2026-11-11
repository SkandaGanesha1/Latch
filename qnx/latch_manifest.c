/*
 * qnx/latch_manifest.c
 *
 * LATCH — Last Authority for Trusted Control Handoff (QNX SDP 8.0)
 *
 * Fail-Closed Zero-Dependency Manifest Parser & SHA-256 Verifier.
 * Complies with -Wall -Wextra -Werror -Wpedantic -std=c11 on both
 * QNX SDP 8.0 (qcc) and Linux host simulation (gcc).
 */

#include "latch_manifest.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ==========================================================================
 * 1. Self-Contained FIPS 180-2 SHA-256 Implementation (Zero Dependencies)
 * ========================================================================== */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} latch_sha256_ctx_t;

#define ROR32(val, bits) (((val) >> (bits)) | ((val) << (32 - (bits))))
#define CH(x, y, z)      (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)     (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)           (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x)           (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x)          (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)          (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void latch_sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    uint32_t w[64];

    for (size_t i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (size_t i = 16; i < 64; ++i) {
        w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
    }

    for (size_t i = 0; i < 64; ++i) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K256[i] + w[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

static void latch_sha256_init(latch_sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->count = 0;
}

static void latch_sha256_update(latch_sha256_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buffer_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    size_t part_len = 64 - buffer_idx;
    size_t i = 0;

    if (len >= part_len) {
        memcpy(&ctx->buffer[buffer_idx], p, part_len);
        latch_sha256_transform(ctx->state, ctx->buffer);
        for (i = part_len; i + 63 < len; i += 64) {
            latch_sha256_transform(ctx->state, &p[i]);
        }
        buffer_idx = 0;
    }
    if (i < len) {
        memcpy(&ctx->buffer[buffer_idx], &p[i], len - i);
    }
}

static void latch_sha256_final(latch_sha256_ctx_t *ctx, uint8_t hash[32]) {
    uint8_t final_count[8];
    uint64_t bits = ctx->count << 3;
    for (int i = 0; i < 8; ++i) {
        final_count[i] = (uint8_t)((bits >> ((7 - i) * 8)) & 0xFFu);
    }

    size_t buffer_idx = (size_t)(ctx->count & 0x3F);
    size_t pad_len = (buffer_idx < 56) ? (56 - buffer_idx) : (120 - buffer_idx);
    static const uint8_t padding[64] = { 0x80u };
    latch_sha256_update(ctx, padding, pad_len);
    latch_sha256_update(ctx, final_count, 8);

    for (int i = 0; i < 8; ++i) {
        hash[i * 4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFFu);
        hash[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFFu);
        hash[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8)  & 0xFFu);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]         & 0xFFu);
    }
}

int latch_manifest_compute_sha256(const char *path, uint8_t hash_out[32], char hex_out[65]) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -errno;
    }

    latch_sha256_ctx_t ctx;
    latch_sha256_init(&ctx);

    uint8_t buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        latch_sha256_update(&ctx, buf, n);
    }
    fclose(f);

    latch_sha256_final(&ctx, hash_out);
    for (int i = 0; i < 32; ++i) {
        snprintf(&hex_out[i * 2], 3, "%02x", hash_out[i]);
    }
    hex_out[64] = '\0';
    return 0;
}

static void latch_sha256_buffer(const void *data, size_t len, uint8_t hash_out[32], char hex_out[65]) {
    latch_sha256_ctx_t ctx;
    latch_sha256_init(&ctx);
    if (data != NULL && len > 0) {
        latch_sha256_update(&ctx, (const uint8_t *)data, len);
    }
    latch_sha256_final(&ctx, hash_out);
    if (hex_out != NULL) {
        for (int i = 0; i < 32; ++i) {
            snprintf(&hex_out[i * 2], 3, "%02x", hash_out[i]);
        }
        hex_out[64] = '\0';
    }
}

int latch_manifest_selftest_sha256(void) {
    uint8_t hash[32];
    char hex[65];

    /* Test Vector 1: Empty string -> e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 */
    latch_sha256_buffer("", 0, hash, hex);
    if (strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") != 0) {
        return -1;
    }

    /* Test Vector 2: "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    latch_sha256_buffer("abc", 3, hash, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) {
        return -2;
    }

    return 0;
}

/* ==========================================================================
 * 2. Conservative Defaults Initialization
 * ========================================================================== */

void latch_manifest_init_defaults(latch_manifest_t *m) {
    if (m == NULL) return;
    memset(m, 0, sizeof(*m));

    m->schema_version = LATCH_MANIFEST_SCHEMA_VERSION;
    strncpy(m->plant_name, "servo-horn-1d", sizeof(m->plant_name) - 1);
    m->num_axes = 1;
    m->axes[0].id = 0;
    strncpy(m->axes[0].kind, "angular", sizeof(m->axes[0].kind) - 1);
    strncpy(m->axes[0].unit, "mrad", sizeof(m->axes[0].unit) - 1);
    m->axes[0].min = -1000;
    m->axes[0].max = 1000;

    m->envelope.theta_min_mrad = -1000;
    m->envelope.theta_max_mrad = 1000;
    m->envelope.num_keepouts = 1;
    m->envelope.keepout[0].lo_mrad = 250;
    m->envelope.keepout[0].hi_mrad = 650;
    strncpy(m->envelope.keepout[0].label, "PERSON", sizeof(m->envelope.keepout[0].label) - 1);

    m->envelope.v_max = 25;
    m->envelope.a_max = 10;
    m->envelope.j_max = 20;
    m->envelope.v_home = 10;
    m->envelope.lookahead_ticks = 10;

    m->timing.period_us = 1000;
    m->timing.watchdog_ticks = 2;
    m->timing.wcet_budget_us = 100;

    m->recovery.hysteresis_clean_frames = 25;
    m->recovery.hold_to_home_ticks = 50;

    m->decision.cpu = 0;
    m->decision.priority = 63;
    m->decision.pulse_priority = 63;

    m->ingest.cpu = 1;
    strncpy(m->ingest.delivery, "queued", sizeof(m->ingest.delivery) - 1);
    m->ingest.queue_depth = 16;

    strncpy(m->paths.proposal, "/dev/latch/proposal", sizeof(m->paths.proposal) - 1);
    strncpy(m->paths.actuator, "/dev/latch/actuator", sizeof(m->paths.actuator) - 1);
    strncpy(m->paths.ability, "latch/actuator", sizeof(m->paths.ability) - 1);
    strncpy(m->paths.i2c_bus, "/dev/i2c1", sizeof(m->paths.i2c_bus) - 1);

    strncpy(m->actuator.type, "pca9685", sizeof(m->actuator.type) - 1);
    m->actuator.addr = 0x40;
    m->actuator.freq_hz = 50;
    m->actuator.prescale = 121;
    m->actuator.pwm_center = 307;
    m->actuator.pwm_min = 205;
    m->actuator.pwm_max = 410;
    m->actuator.retries = 1;
    m->actuator.init_delay_us = 600;

    m->tape.capacity = 4096;

    strncpy(m->protocol.magic, "LATH", sizeof(m->protocol.magic) - 1);
    m->protocol.version = 1;
    strncpy(m->protocol.crc, "ieee32", sizeof(m->protocol.crc) - 1);
    m->protocol.coverage = 16;
}

/* ==========================================================================
 * 3. Keep-Out Region Geometry Helpers
 * ========================================================================== */

bool latch_manifest_in_keepout(const latch_manifest_t *m, int32_t theta_mrad) {
    if (m == NULL) return false;
    for (uint32_t i = 0; i < m->envelope.num_keepouts; ++i) {
        if (theta_mrad >= m->envelope.keepout[i].lo_mrad &&
            theta_mrad <= m->envelope.keepout[i].hi_mrad) {
            return true;
        }
    }
    return false;
}

bool latch_manifest_crossed_keepout(const latch_manifest_t *m, int32_t theta_a, int32_t theta_b) {
    if (m == NULL) return false;
    for (uint32_t i = 0; i < m->envelope.num_keepouts; ++i) {
        int32_t lo = m->envelope.keepout[i].lo_mrad;
        int32_t hi = m->envelope.keepout[i].hi_mrad;

        if ((theta_a >= lo && theta_a <= hi) || (theta_b >= lo && theta_b <= hi)) {
            return true;
        }
        if (theta_a < lo && theta_b > hi) {
            return true;
        }
        if (theta_a > hi && theta_b < lo) {
            return true;
        }
    }
    return false;
}

/* ==========================================================================
 * 4. Lightweight Fail-Closed JSON Parser
 * ========================================================================== */

static const char *skip_ws(const char *p) {
    while (*p && (isspace((unsigned char)*p) || *p == ',' || *p == ':')) {
        p++;
    }
    return p;
}

static bool json_match_str(const char **src, char *out_str, size_t max_len) {
    const char *p = skip_ws(*src);
    if (*p != '\"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '\"' && i + 1 < max_len) {
        if (*p == '\\' && *(p + 1)) p++;
        out_str[i++] = *p++;
    }
    if (*p != '\"') return false;
    out_str[i] = '\0';
    *src = p + 1;
    return true;
}

static bool json_match_int32(const char **src, int32_t *out_val) {
    const char *p = skip_ws(*src);
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return false;
    *out_val = (int32_t)v;
    *src = end;
    return true;
}

static bool json_match_uint32(const char **src, uint32_t *out_val) {
    const char *p = skip_ws(*src);
    char *end = NULL;
    unsigned long v = strtoul(p, &end, 10);
    if (end == p) return false;
    *out_val = (uint32_t)v;
    *src = end;
    return true;
}

static const char *json_find_key(const char *json, const char *key) {
    char target[128];
    snprintf(target, sizeof(target), "\"%s\"", key);
    const char *p = strstr(json, target);
    if (!p) return NULL;
    p += strlen(target);
    return skip_ws(p);
}

int latch_manifest_load(const char *path, latch_manifest_t *out_m, char *err_buf, size_t err_len) {
    if (out_m == NULL || path == NULL) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid arguments to latch_manifest_load");
        return -EINVAL;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err_buf) snprintf(err_buf, err_len, "Cannot open manifest '%s': %s", path, strerror(errno));
        return -errno;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 65536) {
        fclose(f);
        if (err_buf) snprintf(err_buf, err_len, "Manifest size invalid: %ld bytes (max 64KB)", sz);
        return -EFBIG;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        if (err_buf) snprintf(err_buf, err_len, "Out of memory reading manifest");
        return -ENOMEM;
    }

    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[read_bytes] = '\0';

    /* Initialize to defaults first */
    latch_manifest_init_defaults(out_m);

    /* Compute SHA-256 */
    latch_sha256_ctx_t sctx;
    latch_sha256_init(&sctx);
    latch_sha256_update(&sctx, buf, read_bytes);
    latch_sha256_final(&sctx, out_m->sha256);
    for (int i = 0; i < 32; ++i) {
        snprintf(&out_m->sha256_hex[i * 2], 3, "%02x", out_m->sha256[i]);
    }

    const char *p;

    /* Parse schema_version */
    if ((p = json_find_key(buf, "schema_version")) != NULL) {
        if (!json_match_uint32(&p, &out_m->schema_version) || out_m->schema_version != LATCH_MANIFEST_SCHEMA_VERSION) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len, "Unsupported manifest schema_version (%u != %u)",
                                  out_m->schema_version, LATCH_MANIFEST_SCHEMA_VERSION);
            return -EINVAL;
        }
    }

    /* Parse plant name */
    if ((p = json_find_key(buf, "name")) != NULL) {
        json_match_str(&p, out_m->plant_name, sizeof(out_m->plant_name));
    }

    /* Parse envelope constants */
    if ((p = json_find_key(buf, "theta_min_mrad")) != NULL) json_match_int32(&p, &out_m->envelope.theta_min_mrad);
    if ((p = json_find_key(buf, "theta_max_mrad")) != NULL) json_match_int32(&p, &out_m->envelope.theta_max_mrad);
    if ((p = json_find_key(buf, "v_max")) != NULL)          json_match_int32(&p, &out_m->envelope.v_max);
    if ((p = json_find_key(buf, "a_max")) != NULL)          json_match_int32(&p, &out_m->envelope.a_max);
    if ((p = json_find_key(buf, "j_max")) != NULL)          json_match_int32(&p, &out_m->envelope.j_max);
    if ((p = json_find_key(buf, "v_home")) != NULL)         json_match_int32(&p, &out_m->envelope.v_home);
    if ((p = json_find_key(buf, "lookahead_ticks")) != NULL) json_match_uint32(&p, &out_m->envelope.lookahead_ticks);

    /* Parse keepout array */
    if ((p = json_find_key(buf, "keepout")) != NULL) {
        p = strchr(p, '[');
        if (p) {
            p++;
            out_m->envelope.num_keepouts = 0;
            while (*p && *p != ']' && out_m->envelope.num_keepouts < LATCH_MAX_KEEPOUTS) {
                const char *obj = strchr(p, '{');
                if (!obj) break;
                const char *lo_ptr = json_find_key(obj, "lo_mrad");
                const char *hi_ptr = json_find_key(obj, "hi_mrad");
                const char *lb_ptr = json_find_key(obj, "label");

                if (lo_ptr && hi_ptr) {
                    uint32_t idx = out_m->envelope.num_keepouts;
                    json_match_int32(&lo_ptr, &out_m->envelope.keepout[idx].lo_mrad);
                    json_match_int32(&hi_ptr, &out_m->envelope.keepout[idx].hi_mrad);
                    if (lb_ptr) {
                        json_match_str(&lb_ptr, out_m->envelope.keepout[idx].label,
                                       sizeof(out_m->envelope.keepout[idx].label));
                    }
                    out_m->envelope.num_keepouts++;
                }
                p = strchr(obj, '}');
                if (!p) break;
                p++;
            }
        }
    }

    /* Parse timing */
    if ((p = json_find_key(buf, "period_us")) != NULL)      json_match_uint32(&p, &out_m->timing.period_us);
    if ((p = json_find_key(buf, "watchdog_ticks")) != NULL) json_match_uint32(&p, &out_m->timing.watchdog_ticks);
    if ((p = json_find_key(buf, "wcet_budget_us")) != NULL) json_match_uint32(&p, &out_m->timing.wcet_budget_us);

    /* Parse recovery */
    if ((p = json_find_key(buf, "hysteresis_clean_frames")) != NULL) json_match_uint32(&p, &out_m->recovery.hysteresis_clean_frames);
    if ((p = json_find_key(buf, "hold_to_home_ticks")) != NULL)      json_match_uint32(&p, &out_m->recovery.hold_to_home_ticks);

    /* Parse decision / ingest cpu */
    if ((p = json_find_key(buf, "decision")) != NULL) {
        const char *cpu_ptr = json_find_key(p, "cpu");
        if (cpu_ptr) json_match_uint32(&cpu_ptr, &out_m->decision.cpu);
        const char *pri_ptr = json_find_key(p, "priority");
        if (pri_ptr) json_match_uint32(&pri_ptr, &out_m->decision.priority);
    }
    if ((p = json_find_key(buf, "ingest")) != NULL) {
        const char *cpu_ptr = json_find_key(p, "cpu");
        if (cpu_ptr) json_match_uint32(&cpu_ptr, &out_m->ingest.cpu);
        const char *deliv_ptr = json_find_key(p, "delivery");
        if (deliv_ptr) json_match_str(&deliv_ptr, out_m->ingest.delivery, sizeof(out_m->ingest.delivery));
        const char *qd_ptr = json_find_key(p, "queue_depth");
        if (qd_ptr) json_match_uint32(&qd_ptr, &out_m->ingest.queue_depth);
    }

    /* Parse paths */
    if ((p = json_find_key(buf, "proposal")) != NULL) json_match_str(&p, out_m->paths.proposal, sizeof(out_m->paths.proposal));
    if ((p = json_find_key(buf, "actuator")) != NULL) json_match_str(&p, out_m->paths.actuator, sizeof(out_m->paths.actuator));
    if ((p = json_find_key(buf, "ability")) != NULL)  json_match_str(&p, out_m->paths.ability, sizeof(out_m->paths.ability));
    if ((p = json_find_key(buf, "i2c_bus")) != NULL)  json_match_str(&p, out_m->paths.i2c_bus, sizeof(out_m->paths.i2c_bus));

    /* Parse actuator PCA9685 calibration */
    if ((p = json_find_key(buf, "pwm_center")) != NULL) json_match_int32(&p, &out_m->actuator.pwm_center);
    if ((p = json_find_key(buf, "pwm_min")) != NULL)    json_match_int32(&p, &out_m->actuator.pwm_min);
    if ((p = json_find_key(buf, "pwm_max")) != NULL)    json_match_int32(&p, &out_m->actuator.pwm_max);

    free(buf);

    /* Fail-closed semantic safety validation */
    if (out_m->envelope.theta_min_mrad >= out_m->envelope.theta_max_mrad) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid envelope stops: min %d >= max %d",
                              out_m->envelope.theta_min_mrad, out_m->envelope.theta_max_mrad);
        return -EINVAL;
    }
    if (out_m->envelope.v_max <= 0 || out_m->envelope.a_max <= 0 ||
        out_m->envelope.j_max <= 0 || out_m->envelope.v_home <= 0) {
        if (err_buf) snprintf(err_buf, err_len, "Kinematic bounds must be positive (v_max=%d, a_max=%d, j_max=%d, v_home=%d)",
                              out_m->envelope.v_max, out_m->envelope.a_max, out_m->envelope.j_max, out_m->envelope.v_home);
        return -EINVAL;
    }
    if (strcmp(out_m->ingest.delivery, "queued") != 0 &&
        strcmp(out_m->ingest.delivery, "latest") != 0) {
        if (err_buf) snprintf(err_buf, err_len, "Unknown ingest delivery mode '%s' (must be 'queued' or 'latest')",
                              out_m->ingest.delivery);
        return -EINVAL;
    }
    if (out_m->ingest.queue_depth < 1 || out_m->ingest.queue_depth > 64) {
        if (err_buf) snprintf(err_buf, err_len, "Queue depth %u outside [1, 64]", out_m->ingest.queue_depth);
        return -EINVAL;
    }
    if (latch_manifest_in_keepout(out_m, 0)) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: Home position (0 mrad) sits inside keep-out interval!");
        return -EINVAL;
    }
    if (out_m->timing.period_us < 250 || out_m->timing.period_us > 100000) {
        if (err_buf) snprintf(err_buf, err_len, "Period %u us outside [250, 100000]", out_m->timing.period_us);
        return -EINVAL;
    }
    if (out_m->timing.watchdog_ticks < 1) {
        if (err_buf) snprintf(err_buf, err_len, "Watchdog ticks must be >= 1");
        return -EINVAL;
    }
    if (out_m->actuator.pwm_min >= out_m->actuator.pwm_center ||
        out_m->actuator.pwm_center >= out_m->actuator.pwm_max) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid PWM calibration: min %d, center %d, max %d",
                              out_m->actuator.pwm_min, out_m->actuator.pwm_center, out_m->actuator.pwm_max);
        return -EINVAL;
    }

    return 0;
}

