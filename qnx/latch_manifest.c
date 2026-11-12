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
    m->axes[0].fullscale_counts_span = 2000;

    m->envelope.theta_min_mrad = -1000;
    m->envelope.theta_max_mrad = 1000;
    m->envelope.home_mrad = 0;
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
    m->timing.max_backlog_ticks = 4;

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
    m->actuator.required = false;

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

static const char *json_find_key_bounded(const char *start, const char *end, const char *key) {
    if (!start || !end || start >= end || !key) return NULL;
    char target[128];
    snprintf(target, sizeof(target), "\"%s\"", key);
    size_t tlen = strlen(target);
    size_t span = (size_t)(end - start);
    if (tlen > span) return NULL;

    for (const char *p = start; p <= end - tlen; ++p) {
        if (strncmp(p, target, tlen) == 0) {
            const char *val = skip_ws(p + tlen);
            if (val < end) return val;
            return NULL;
        }
    }
    return NULL;
}

static const char *json_find_section(const char *json, const char *sec_name, const char **out_sec_end) {
    if (!json || !sec_name) return NULL;
    const char *p = json_find_key(json, sec_name);
    if (!p) return NULL;
    const char *brace = strchr(p, '{');
    if (!brace) return NULL;
    int depth = 1;
    const char *c = brace + 1;
    while (*c && depth > 0) {
        if (*c == '{') depth++;
        else if (*c == '}') depth--;
        c++;
    }
    if (depth == 0) {
        if (out_sec_end) *out_sec_end = c - 1;
        return brace;
    }
    return NULL;
}

int latch_manifest_verify_sidecar(const char *manifest_path, const char *computed_hex, char *err_buf, size_t err_len) {
    if (manifest_path == NULL || computed_hex == NULL) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid arguments to sidecar verification");
        return -EINVAL;
    }
    char sidecar_path[512];
    snprintf(sidecar_path, sizeof(sidecar_path), "%s.sha256", manifest_path);

    FILE *sf = fopen(sidecar_path, "r");
    if (!sf) {
        /* Sidecar is optional, absence is not an error */
        return 0;
    }

    char expected_hex[128];
    if (fscanf(sf, "%127s", expected_hex) != 1) {
        fclose(sf);
        if (err_buf) snprintf(err_buf, err_len, "Malformed sidecar file '%s'", sidecar_path);
        return -EINVAL;
    }
    fclose(sf);

    /* Strip potential trailing newline or whitespace */
    char *end = expected_hex;
    while (*end && isxdigit((unsigned char)*end)) {
        end++;
    }
    *end = '\0';

    if (strlen(expected_hex) != 64) {
        if (err_buf) snprintf(err_buf, err_len, "Sidecar digest length invalid (%zu != 64)", strlen(expected_hex));
        return -EINVAL;
    }

    for (size_t i = 0; i < 64; ++i) {
        if (tolower((unsigned char)expected_hex[i]) != tolower((unsigned char)computed_hex[i])) {
            if (err_buf) {
                snprintf(err_buf, err_len,
                         "Sidecar SHA-256 mismatch: computed %.16s... != expected %.16s... (Fail-Closed)",
                         computed_hex, expected_hex);
            }
            return -1;
        }
    }
    return 0;
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
        return -EINVAL;
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

    /* Anti-Silent-Defaults: zero out target struct (no fallback pre-population) */
    memset(out_m, 0, sizeof(*out_m));

    /* Compute SHA-256 */
    latch_sha256_ctx_t sctx;
    latch_sha256_init(&sctx);
    latch_sha256_update(&sctx, buf, read_bytes);
    latch_sha256_final(&sctx, out_m->sha256);
    for (int i = 0; i < 32; ++i) {
        snprintf(&out_m->sha256_hex[i * 2], 3, "%02x", out_m->sha256[i]);
    }

    /* Verify sidecar SHA-256 file if present (<path>.sha256) */
    if (latch_manifest_verify_sidecar(path, out_m->sha256_hex, err_buf, err_len) != 0) {
        free(buf);
        return -1;
    }

    /* Validate mandatory sections */
    const char *env_end = NULL, *tim_end = NULL, *rec_end = NULL;
    const char *dec_end = NULL, *ing_end = NULL, *paths_end = NULL;
    const char *act_end = NULL, *proto_end = NULL, *tape_end = NULL;
    const char *plant_end = NULL;

    const char *env_sec   = json_find_section(buf, "envelope", &env_end);
    const char *tim_sec   = json_find_section(buf, "timing", &tim_end);
    const char *rec_sec   = json_find_section(buf, "recovery", &rec_end);
    const char *dec_sec   = json_find_section(buf, "decision", &dec_end);
    const char *ing_sec   = json_find_section(buf, "ingest", &ing_end);
    const char *paths_sec = json_find_section(buf, "paths", &paths_end);
    const char *act_sec   = json_find_section(buf, "actuator", &act_end);
    const char *proto_sec = json_find_section(buf, "protocol", &proto_end);
    const char *tape_sec  = json_find_section(buf, "tape", &tape_end);
    const char *plant_sec = json_find_section(buf, "plant", &plant_end);

    if (!env_sec || !tim_sec || !rec_sec || !act_sec || !proto_sec) {
        free(buf);
        if (err_buf) snprintf(err_buf, err_len, "Manifest missing mandatory sections (envelope, timing, recovery, actuator, protocol)");
        return -EINVAL;
    }

    bool has_schema = false;
    bool has_theta_min = false, has_theta_max = false, has_home = false;
    bool has_v_max = false, has_a_max = false, has_j_max = false, has_v_home = false;
    bool has_period = false, has_watchdog = false, has_wcet = false;
    bool has_clean_frames = false, has_hold_to_home = false;
    bool has_proto_magic = false, has_proto_version = false;
    bool has_actuator_type = false;

    const char *p;

    /* 1. Parse schema_version */
    if ((p = json_find_key(buf, "schema_version")) != NULL) {
        if (json_match_uint32(&p, &out_m->schema_version) &&
            (out_m->schema_version == 1u || out_m->schema_version == LATCH_MANIFEST_SCHEMA_VERSION)) {
            has_schema = true;
        }
    }

    /* 2. Parse plant */
    if (plant_sec && plant_end) {
        const char *np = json_find_key_bounded(plant_sec, plant_end, "name");
        if (np) json_match_str(&np, out_m->plant_name, sizeof(out_m->plant_name));

        const char *axes_ptr = json_find_key_bounded(plant_sec, plant_end, "axes");
        if (axes_ptr) {
            axes_ptr = strchr(axes_ptr, '[');
            if (axes_ptr && axes_ptr < plant_end) {
                axes_ptr++;
                out_m->num_axes = 0;
                while (*axes_ptr && *axes_ptr != ']' && axes_ptr < plant_end && out_m->num_axes < LATCH_MAX_AXES) {
                    const char *obj = strchr(axes_ptr, '{');
                    if (!obj || obj >= plant_end) break;
                    const char *obj_end = strchr(obj, '}');
                    if (!obj_end || obj_end >= plant_end) break;
                    uint32_t idx = out_m->num_axes;
                    const char *id_ptr   = json_find_key_bounded(obj, obj_end, "id");
                    const char *kind_ptr = json_find_key_bounded(obj, obj_end, "kind");
                    const char *unit_ptr = json_find_key_bounded(obj, obj_end, "unit");
                    const char *min_ptr  = json_find_key_bounded(obj, obj_end, "min");
                    const char *max_ptr  = json_find_key_bounded(obj, obj_end, "max");
                    if (id_ptr)   json_match_uint32(&id_ptr, &out_m->axes[idx].id);
                    if (kind_ptr) json_match_str(&kind_ptr, out_m->axes[idx].kind, sizeof(out_m->axes[idx].kind));
                    if (unit_ptr) json_match_str(&unit_ptr, out_m->axes[idx].unit, sizeof(out_m->axes[idx].unit));
                    if (min_ptr)  json_match_int32(&min_ptr, &out_m->axes[idx].min);
                    if (max_ptr)  json_match_int32(&max_ptr, &out_m->axes[idx].max);
                    out_m->axes[idx].fullscale_counts_span = out_m->axes[idx].max - out_m->axes[idx].min;
                    out_m->num_axes++;
                    axes_ptr = obj_end + 1;
                }
            }
        }
    }

    /* 3. Parse envelope within envelope_sec */
    {
        const char *tmin_p = json_find_key_bounded(env_sec, env_end, "theta_min_mrad");
        if (tmin_p && json_match_int32(&tmin_p, &out_m->envelope.theta_min_mrad)) has_theta_min = true;

        const char *tmax_p = json_find_key_bounded(env_sec, env_end, "theta_max_mrad");
        if (tmax_p && json_match_int32(&tmax_p, &out_m->envelope.theta_max_mrad)) has_theta_max = true;

        const char *home_p = json_find_key_bounded(env_sec, env_end, "home_mrad");
        if (home_p && json_match_int32(&home_p, &out_m->envelope.home_mrad)) has_home = true;

        const char *vmax_p = json_find_key_bounded(env_sec, env_end, "v_max");
        if (vmax_p && json_match_int32(&vmax_p, &out_m->envelope.v_max)) has_v_max = true;

        const char *amax_p = json_find_key_bounded(env_sec, env_end, "a_max");
        if (amax_p && json_match_int32(&amax_p, &out_m->envelope.a_max)) has_a_max = true;

        const char *jmax_p = json_find_key_bounded(env_sec, env_end, "j_max");
        if (jmax_p && json_match_int32(&jmax_p, &out_m->envelope.j_max)) has_j_max = true;

        const char *vhome_p = json_find_key_bounded(env_sec, env_end, "v_home");
        if (vhome_p && json_match_int32(&vhome_p, &out_m->envelope.v_home)) has_v_home = true;

        const char *la_p = json_find_key_bounded(env_sec, env_end, "lookahead_ticks");
        if (la_p) json_match_uint32(&la_p, &out_m->envelope.lookahead_ticks);
        if (out_m->envelope.lookahead_ticks == 0u) out_m->envelope.lookahead_ticks = 10u;

        const char *ko_ptr = json_find_key_bounded(env_sec, env_end, "keepout");
        if (ko_ptr) {
            ko_ptr = strchr(ko_ptr, '[');
            if (ko_ptr && ko_ptr < env_end) {
                ko_ptr++;
                out_m->envelope.num_keepouts = 0;
                while (*ko_ptr && *ko_ptr != ']' && ko_ptr < env_end && out_m->envelope.num_keepouts < LATCH_MAX_KEEPOUTS) {
                    const char *obj = strchr(ko_ptr, '{');
                    if (!obj || obj >= env_end) break;
                    const char *obj_end = strchr(obj, '}');
                    if (!obj_end || obj_end >= env_end) break;
                    const char *lo_ptr = json_find_key_bounded(obj, obj_end, "lo_mrad");
                    const char *hi_ptr = json_find_key_bounded(obj, obj_end, "hi_mrad");
                    const char *lb_ptr = json_find_key_bounded(obj, obj_end, "label");

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
                    ko_ptr = obj_end + 1;
                }
            }
        }
    }

    /* 4. Parse timing within tim_sec */
    {
        const char *per_p = json_find_key_bounded(tim_sec, tim_end, "period_us");
        if (per_p && json_match_uint32(&per_p, &out_m->timing.period_us)) has_period = true;

        const char *wd_p = json_find_key_bounded(tim_sec, tim_end, "watchdog_ticks");
        if (wd_p && json_match_uint32(&wd_p, &out_m->timing.watchdog_ticks)) has_watchdog = true;

        const char *wcet_p = json_find_key_bounded(tim_sec, tim_end, "wcet_budget_us");
        if (wcet_p && json_match_uint32(&wcet_p, &out_m->timing.wcet_budget_us)) has_wcet = true;

        const char *mb_p = json_find_key_bounded(tim_sec, tim_end, "max_backlog_ticks");
        if (mb_p) json_match_uint32(&mb_p, &out_m->timing.max_backlog_ticks);
        if (out_m->timing.max_backlog_ticks == 0u) out_m->timing.max_backlog_ticks = 4u;
    }

    /* 5. Parse recovery within rec_sec */
    {
        const char *cf_p = json_find_key_bounded(rec_sec, rec_end, "hysteresis_clean_frames");
        if (cf_p && json_match_uint32(&cf_p, &out_m->recovery.hysteresis_clean_frames)) has_clean_frames = true;

        const char *hh_p = json_find_key_bounded(rec_sec, rec_end, "hold_to_home_ticks");
        if (hh_p && json_match_uint32(&hh_p, &out_m->recovery.hold_to_home_ticks)) has_hold_to_home = true;
    }

    /* 6. Parse decision */
    if (dec_sec && dec_end) {
        const char *cp_p = json_find_key_bounded(dec_sec, dec_end, "cpu");
        if (cp_p) json_match_uint32(&cp_p, &out_m->decision.cpu);

        const char *pr_p = json_find_key_bounded(dec_sec, dec_end, "priority");
        if (pr_p) json_match_uint32(&pr_p, &out_m->decision.priority);
        if (out_m->decision.priority == 0u) out_m->decision.priority = 63u;

        const char *pp_p = json_find_key_bounded(dec_sec, dec_end, "pulse_priority");
        if (pp_p) json_match_uint32(&pp_p, &out_m->decision.pulse_priority);
        if (out_m->decision.pulse_priority == 0u) out_m->decision.pulse_priority = 63u;
    } else {
        out_m->decision.priority = 63u;
        out_m->decision.pulse_priority = 63u;
    }

    /* 7. Parse ingest */
    if (ing_sec && ing_end) {
        const char *cp_p = json_find_key_bounded(ing_sec, ing_end, "cpu");
        if (cp_p) json_match_uint32(&cp_p, &out_m->ingest.cpu);

        const char *del_p = json_find_key_bounded(ing_sec, ing_end, "delivery");
        if (del_p) json_match_str(&del_p, out_m->ingest.delivery, sizeof(out_m->ingest.delivery));

        const char *qd_p = json_find_key_bounded(ing_sec, ing_end, "queue_depth");
        if (qd_p) json_match_uint32(&qd_p, &out_m->ingest.queue_depth);
    }
    if (out_m->ingest.delivery[0] == '\0') strncpy(out_m->ingest.delivery, "queued", sizeof(out_m->ingest.delivery) - 1);
    if (out_m->ingest.queue_depth == 0u) out_m->ingest.queue_depth = 64u;

    /* 8. Parse paths */
    if (paths_sec && paths_end) {
        const char *prop_p = json_find_key_bounded(paths_sec, paths_end, "proposal");
        if (prop_p) json_match_str(&prop_p, out_m->paths.proposal, sizeof(out_m->paths.proposal));

        const char *act_p  = json_find_key_bounded(paths_sec, paths_end, "actuator");
        if (act_p) json_match_str(&act_p, out_m->paths.actuator, sizeof(out_m->paths.actuator));

        const char *ab_p   = json_find_key_bounded(paths_sec, paths_end, "ability");
        if (ab_p) json_match_str(&ab_p, out_m->paths.ability, sizeof(out_m->paths.ability));

        const char *i2c_p  = json_find_key_bounded(paths_sec, paths_end, "i2c_bus");
        if (i2c_p) json_match_str(&i2c_p, out_m->paths.i2c_bus, sizeof(out_m->paths.i2c_bus));
    }
    if (out_m->paths.proposal[0] == '\0') strncpy(out_m->paths.proposal, "/dev/latch/proposal", sizeof(out_m->paths.proposal) - 1);
    if (out_m->paths.actuator[0] == '\0') strncpy(out_m->paths.actuator, "/dev/latch/actuator", sizeof(out_m->paths.actuator) - 1);
    if (out_m->paths.ability[0] == '\0')  strncpy(out_m->paths.ability, "latch/actuator", sizeof(out_m->paths.ability) - 1);
    if (out_m->paths.i2c_bus[0] == '\0')  strncpy(out_m->paths.i2c_bus, "/dev/i2c1", sizeof(out_m->paths.i2c_bus) - 1);

    /* 9. Parse actuator within act_sec */
    {
        const char *t_p = json_find_key_bounded(act_sec, act_end, "type");
        if (t_p && json_match_str(&t_p, out_m->actuator.type, sizeof(out_m->actuator.type))) has_actuator_type = true;

        const char *a_p = json_find_key_bounded(act_sec, act_end, "addr");
        if (a_p) json_match_uint32(&a_p, &out_m->actuator.addr);

        const char *f_p = json_find_key_bounded(act_sec, act_end, "freq_hz");
        if (f_p) json_match_uint32(&f_p, &out_m->actuator.freq_hz);

        const char *pr_p = json_find_key_bounded(act_sec, act_end, "prescale");
        if (pr_p) json_match_uint32(&pr_p, &out_m->actuator.prescale);

        const char *ret_p = json_find_key_bounded(act_sec, act_end, "retries");
        if (ret_p) json_match_uint32(&ret_p, &out_m->actuator.retries);

        const char *id_p = json_find_key_bounded(act_sec, act_end, "init_delay_us");
        if (id_p) json_match_uint32(&id_p, &out_m->actuator.init_delay_us);

        const char *req_p = json_find_key_bounded(act_sec, act_end, "required");
        if (req_p) {
            if (strncmp(req_p, "true", 4) == 0) out_m->actuator.required = true;
            else if (strncmp(req_p, "false", 5) == 0) out_m->actuator.required = false;
        }

        const char *pc_p = json_find_key_bounded(act_sec, act_end, "pwm_center");
        if (pc_p) json_match_int32(&pc_p, &out_m->actuator.pwm_center);

        const char *pmin_p = json_find_key_bounded(act_sec, act_end, "pwm_min");
        if (pmin_p) json_match_int32(&pmin_p, &out_m->actuator.pwm_min);

        const char *pmax_p = json_find_key_bounded(act_sec, act_end, "pwm_max");
        if (pmax_p) json_match_int32(&pmax_p, &out_m->actuator.pwm_max);
    }

    /* 10. Parse tape */
    if (tape_sec && tape_end) {
        const char *cap_p = json_find_key_bounded(tape_sec, tape_end, "capacity");
        if (cap_p) json_match_uint32(&cap_p, &out_m->tape.capacity);
    }
    if (out_m->tape.capacity == 0u) out_m->tape.capacity = 4096u;

    /* 11. Parse protocol within proto_sec */
    {
        const char *mag_p = json_find_key_bounded(proto_sec, proto_end, "magic");
        if (mag_p && json_match_str(&mag_p, out_m->protocol.magic, sizeof(out_m->protocol.magic))) has_proto_magic = true;

        const char *ver_p = json_find_key_bounded(proto_sec, proto_end, "version");
        if (ver_p && json_match_uint32(&ver_p, &out_m->protocol.version)) has_proto_version = true;

        const char *crc_p = json_find_key_bounded(proto_sec, proto_end, "crc");
        if (crc_p) json_match_str(&crc_p, out_m->protocol.crc, sizeof(out_m->protocol.crc));

        const char *cov_p = json_find_key_bounded(proto_sec, proto_end, "coverage");
        if (cov_p) json_match_uint32(&cov_p, &out_m->protocol.coverage);
    }

    free(buf);

    /* Enforce strict Anti-Silent-Defaults: all required safety keys must be present */
    if (!has_schema || !has_theta_min || !has_theta_max || !has_home ||
        !has_v_max || !has_a_max || !has_j_max || !has_v_home ||
        !has_period || !has_watchdog || !has_wcet ||
        !has_clean_frames || !has_hold_to_home ||
        !has_proto_magic || !has_proto_version || !has_actuator_type) {
        if (err_buf) snprintf(err_buf, err_len,
                              "Manifest missing required safety parameters (anti-silent-defaults: fail-closed)");
        return -EINVAL;
    }

    latch_admissibility_t admit = latch_manifest_validate(out_m, err_buf, err_len);
    if (admit != LATCH_ADMIT_SATISFIED) {
        return -EINVAL;
    }

    return 0;
}

latch_admissibility_t latch_manifest_validate(const latch_manifest_t *m, char *err_buf, size_t err_len) {
    if (m == NULL) {
        if (err_buf) snprintf(err_buf, err_len, "Manifest pointer is NULL");
        return LATCH_ADMIT_UNRESOLVED;
    }

    /* 1. Completeness of Prerequisites (Ak(m) in {0,1}) */
    if (m->schema_version != 1u && m->schema_version != LATCH_MANIFEST_SCHEMA_VERSION) {
        if (err_buf) snprintf(err_buf, err_len, "Unsupported manifest schema_version (%u)",
                              m->schema_version);
        return LATCH_ADMIT_UNRESOLVED;
    }
    if (m->timing.period_us == 0u || m->timing.watchdog_ticks == 0u) {
        if (err_buf) snprintf(err_buf, err_len, "Missing or zero timing parameters (period=%u, watchdog=%u)",
                              m->timing.period_us, m->timing.watchdog_ticks);
        return LATCH_ADMIT_UNRESOLVED;
    }
    if (m->timing.period_us < 250 || m->timing.period_us > 100000) {
        if (err_buf) snprintf(err_buf, err_len, "Period %u us outside [250, 100000]", m->timing.period_us);
        return LATCH_ADMIT_UNRESOLVED;
    }

    /* 2. Safety Invariant Satisfaction (phi_k(m) >= 0) */
    if (m->envelope.theta_min_mrad >= m->envelope.theta_max_mrad) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid envelope stops: min %d >= max %d",
                              m->envelope.theta_min_mrad, m->envelope.theta_max_mrad);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->envelope.v_max <= 0 || m->envelope.a_max <= 0 ||
        m->envelope.j_max <= 0 || m->envelope.v_home <= 0) {
        if (err_buf) snprintf(err_buf, err_len, "Kinematic bounds must be positive (v_max=%d, a_max=%d, j_max=%d, v_home=%d)",
                              m->envelope.v_max, m->envelope.a_max, m->envelope.j_max, m->envelope.v_home);
        return LATCH_ADMIT_VIOLATED;
    }
    if (strcmp(m->ingest.delivery, "queued") != 0 &&
        strcmp(m->ingest.delivery, "latest") != 0) {
        if (err_buf) snprintf(err_buf, err_len, "Unknown ingest delivery mode '%s' (must be 'queued' or 'latest')",
                              m->ingest.delivery);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->ingest.queue_depth < 1 || m->ingest.queue_depth > 256) {
        if (err_buf) snprintf(err_buf, err_len, "Queue depth %u outside [1, 256]", m->ingest.queue_depth);
        return LATCH_ADMIT_VIOLATED;
    }
    if (latch_manifest_in_keepout(m, m->envelope.home_mrad)) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: Home position (%d mrad) sits inside keep-out interval!",
                              m->envelope.home_mrad);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->envelope.lookahead_ticks < 1 || m->envelope.lookahead_ticks > 64) {
        if (err_buf) snprintf(err_buf, err_len, "Lookahead ticks %u outside [1, 64]", m->envelope.lookahead_ticks);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->decision.priority < 1 || m->decision.priority > 255 || m->decision.cpu >= 256) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid decision priority %u or CPU %u",
                              m->decision.priority, m->decision.cpu);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->protocol.magic[0] != '\0') {
        if (strcmp(m->protocol.magic, "LATH") != 0 ||
            m->protocol.version != 1u ||
            (strcmp(m->protocol.crc, "ieee32") != 0 && strcmp(m->protocol.crc, "crc32-ieee") != 0) ||
            m->protocol.coverage != 16u) {
            if (err_buf) snprintf(err_buf, err_len, "Protocol metadata mismatch (magic='%s', ver=%u, crc='%s', cov=%u)",
                                  m->protocol.magic, m->protocol.version, m->protocol.crc, m->protocol.coverage);
            return LATCH_ADMIT_VIOLATED;
        }
    }
    for (uint32_t i = 0; i < m->envelope.num_keepouts; ++i) {
        if (m->envelope.keepout[i].lo_mrad >= m->envelope.keepout[i].hi_mrad ||
            m->envelope.keepout[i].lo_mrad < m->envelope.theta_min_mrad ||
            m->envelope.keepout[i].hi_mrad > m->envelope.theta_max_mrad) {
            if (err_buf) snprintf(err_buf, err_len, "Keep-out interval [%d, %d] invalid or exceeds stops [%d, %d]",
                                  m->envelope.keepout[i].lo_mrad, m->envelope.keepout[i].hi_mrad,
                                  m->envelope.theta_min_mrad, m->envelope.theta_max_mrad);
            return LATCH_ADMIT_VIOLATED;
        }
    }
    if (m->envelope.v_home > m->envelope.v_max) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: v_home (%d) exceeds v_max (%d)",
                              m->envelope.v_home, m->envelope.v_max);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->envelope.home_mrad < m->envelope.theta_min_mrad ||
        m->envelope.home_mrad > m->envelope.theta_max_mrad) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: Home position (%d) sits outside envelope [%d, %d]",
                              m->envelope.home_mrad, m->envelope.theta_min_mrad, m->envelope.theta_max_mrad);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->decision.pulse_priority < 1 || m->decision.pulse_priority > 255) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: Pulse priority %u outside [1, 255]",
                              m->decision.pulse_priority);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->tape.capacity < 1 || m->tape.capacity > LATCH_MANIFEST_MAX_TAPE_CAPACITY) {
        if (err_buf) snprintf(err_buf, err_len, "Fail closed: Tape capacity %u outside [1, %u]",
                              m->tape.capacity, (unsigned int)LATCH_MANIFEST_MAX_TAPE_CAPACITY);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->actuator.pwm_min >= m->actuator.pwm_center ||
        m->actuator.pwm_center >= m->actuator.pwm_max) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid PWM calibration: min %d, center %d, max %d",
                              m->actuator.pwm_min, m->actuator.pwm_center, m->actuator.pwm_max);
        return LATCH_ADMIT_VIOLATED;
    }

    return LATCH_ADMIT_SATISFIED;
}

