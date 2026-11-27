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
    /* DEPRECATED: this function is not called anywhere in the codebase.
     * All manifest loading goes through latch_manifest_load() which
     * performs strict schema-3 validation (json_object_has_only_keys
     * rejects duplicate/unknown keys). Schema-1/2 sections use
     * json_find_key_bounded() which is first-match-wins for duplicate
     * keys and silently ignores unknown keys — this is a known
     * limitation of the legacy schemas. The schema-3 governor/units/
     * medical/rate sections are the only ones with strict validation.
     * If a new default-initialization path is ever needed, re-add here
     * with a caller and a test. */
    (void)m;
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

static const char *skip_pure_ws(const char *p, const char *end) {
    while (p < end && *p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static const char *json_skip_string(const char *p, const char *end) {
    if (p >= end || *p != '\"') return p;
    p++;
    while (p < end && *p) {
        if (*p == '\\' && (p + 1) < end && *(p + 1)) {
            p += 2;
            continue;
        }
        if (*p == '\"') {
            return p + 1;
        }
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
    if (*p == '\0') return false;
    char *end = NULL;
    errno = 0;
    long v = strtol(p, &end, 10);
    if (end == p || errno == ERANGE || v < INT32_MIN || v > INT32_MAX) return false;
    *out_val = (int32_t)v;
    *src = end;
    return true;
}

static bool json_match_uint32(const char **src, uint32_t *out_val) {
    const char *p = skip_ws(*src);
    if (*p == '\0' || *p == '-') return false;
    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(p, &end, 10);
    if (end == p || errno == ERANGE || v > UINT32_MAX) return false;
    *out_val = (uint32_t)v;
    *src = end;
    return true;
}

/*
 * String-literal-aware & object-depth-aware JSON key finder.
 * Finds `"key": <val>` only at object brace depth `target_depth` within [start, end).
 */
static const char *json_find_key_depth(const char *start, const char *end,
                                       const char *key, int target_depth) {
    if (!start || !end || start >= end || !key) return NULL;
    size_t klen = strlen(key);
    int depth = 0;
    const char *p = start;

    while (p < end && *p) {
        char ch = *p;
        if (ch == '{' || ch == '[') {
            depth++;
            p++;
        } else if (ch == '}' || ch == ']') {
            if (depth > 0) depth--;
            p++;
        } else if (ch == '\"') {
            const char *str_end = json_skip_string(p, end);
            if (depth == target_depth && str_end > p + 1 && *(str_end - 1) == '\"') {
                size_t tok_len = (size_t)((str_end - 1) - (p + 1));
                if (tok_len == klen && strncmp(p + 1, key, klen) == 0) {
                    const char *after = skip_pure_ws(str_end, end);
                    if (after < end && *after == ':') {
                        const char *val = skip_pure_ws(after + 1, end);
                        if (val < end) return val;
                        return NULL;
                    }
                }
            }
            p = str_end;
        } else {
            p++;
        }
    }
    return NULL;
}

static const char *json_find_key_bounded(const char *start, const char *end, const char *key) {
    /* Caller passes section `{ ... }` (start == '{'), so keys directly inside it are at depth 1 */
    return json_find_key_depth(start, end, key, 1);
}

static const char *json_find_object_end(const char *brace, const char *limit);

static const char *json_find_child_section(const char *parent, const char *parent_end,
                                           const char *name, const char **child_end) {
    const char *child = json_find_key_bounded(parent, parent_end, name);
    if (child == NULL || *child != '{') return NULL;
    const char *end = json_find_object_end(child, parent_end + 1);
    if (end == NULL || end > parent_end) return NULL;
    if (child_end != NULL) *child_end = end;
    return child;
}

static const char *json_find_object_end(const char *brace, const char *limit) {
    if (!brace || brace >= limit || *brace != '{') return NULL;
    int depth = 1;
    const char *c = brace + 1;
    while (c < limit && *c && depth > 0) {
        if (*c == '\"') {
            c = json_skip_string(c, limit);
            continue;
        }
        if (*c == '{') depth++;
        else if (*c == '}') depth--;
        c++;
    }
    return (depth == 0) ? (c - 1) : NULL;
}

static const char *json_find_section(const char *json, const char *sec_name, const char **out_sec_end) {
    if (!json || !sec_name) return NULL;
    const char *limit = json + strlen(json);
    const char *val = json_find_key_depth(json, limit, sec_name, 1);
    if (!val || *val != '{') return NULL;
    const char *sec_end = json_find_object_end(val, limit);
    if (!sec_end) return NULL;
    if (out_sec_end) *out_sec_end = sec_end;
    return val;
}

static bool json_object_has_only_uint_keys(const char *obj, const char *obj_end,
                                           const char *const *allowed, size_t allowed_count) {
    if (obj == NULL || obj_end == NULL || obj >= obj_end || *obj != '{' ||
        allowed == NULL || allowed_count == 0u) {
        return false;
    }
    bool seen[16] = { false };
    if (allowed_count > sizeof(seen) / sizeof(seen[0])) return false;

    const char *p = skip_pure_ws(obj + 1, obj_end);
    if (p == obj_end || *p == '}') return false;

    for (;;) {
        if (p >= obj_end || *p != '"') return false;
        const char *key_end = json_skip_string(p, obj_end + 1);
        if (key_end <= p + 1 || key_end > obj_end + 1 || *(key_end - 1) != '"') return false;
        const char *key_start = p + 1;
        size_t key_len = (size_t)((key_end - 1) - key_start);
        size_t match = allowed_count;
        for (size_t i = 0; i < allowed_count; ++i) {
            if (strlen(allowed[i]) == key_len && strncmp(key_start, allowed[i], key_len) == 0) {
                match = i;
                break;
            }
        }
        if (match == allowed_count || seen[match]) return false;
        seen[match] = true;

        p = skip_pure_ws(key_end, obj_end + 1);
        if (p >= obj_end || *p != ':') return false;
        p = skip_pure_ws(p + 1, obj_end + 1);
        if (p >= obj_end || !isdigit((unsigned char)*p)) return false;
        while (p < obj_end && isdigit((unsigned char)*p)) p++;
        p = skip_pure_ws(p, obj_end + 1);
        if (p < obj_end && *p == ',') {
            p = skip_pure_ws(p + 1, obj_end + 1);
            continue;
        }
        if (p == obj_end && *p == '}') {
            for (size_t i = 0; i < allowed_count; ++i) {
                if (!seen[i]) return false;
            }
            return true;
        }
        return false;
    }
}

static bool json_object_has_only_keys_ex(const char *obj, const char *obj_end,
                                          const char *const *allowed, size_t allowed_count,
                                          size_t required_count);

static bool json_object_has_only_keys(const char *obj, const char *obj_end,
                                      const char *const *allowed, size_t allowed_count) {
    return json_object_has_only_keys_ex(obj, obj_end, allowed, allowed_count, allowed_count);
}

/*
 * Strict key-set validation with an OPTIONAL tail.
 *
 * The first `required_count` entries of `allowed` must all be present; the
 * remaining entries are OPTIONAL -- if present they must still be known and
 * unique, but their absence is not an error.  This is what lets the
 * schema-3 top level accept "medical" and "homeostat" as optional sections
 * while still rejecting a typo that would silently DISABLE a safety gate
 * (e.g. "medcial" would otherwise be ignored and the dose gate would be
 * off with no diagnostic).
 */
static bool json_object_has_only_keys_ex(const char *obj, const char *obj_end,
                                          const char *const *allowed, size_t allowed_count,
                                          size_t required_count) {
    if (obj == NULL || obj_end == NULL || obj >= obj_end || *obj != '{' ||
        allowed == NULL || allowed_count == 0u || allowed_count > 16u ||
        required_count > allowed_count) return false;
    bool seen[16] = { false };
    const char *p = skip_pure_ws(obj + 1, obj_end);
    if (p == obj_end || *p == '}') return false;

    for (;;) {
        if (p >= obj_end || *p != '"') return false;
        const char *key_end = json_skip_string(p, obj_end + 1);
        if (key_end <= p + 1 || key_end > obj_end + 1 || *(key_end - 1) != '"') return false;
        const char *key_start = p + 1;
        size_t key_len = (size_t)((key_end - 1) - key_start);
        size_t match = allowed_count;
        for (size_t i = 0; i < allowed_count; ++i) {
            if (strlen(allowed[i]) == key_len && strncmp(key_start, allowed[i], key_len) == 0) {
                match = i;
                break;
            }
        }
        if (match == allowed_count || seen[match]) return false;
        seen[match] = true;
        p = skip_pure_ws(key_end, obj_end + 1);
        if (p >= obj_end || *p++ != ':') return false;
        p = skip_pure_ws(p, obj_end + 1);
        if (p >= obj_end) return false;

        if (*p == '{' || *p == '[') {
            char open = *p;
            char close = open == '{' ? '}' : ']';
            unsigned int depth = 0u;
            do {
                if (*p == '"') {
                    p = json_skip_string(p, obj_end + 1);
                    if (p > obj_end + 1) return false;
                    continue;
                }
                if (*p == open) depth++;
                else if (*p == close) {
                    if (depth == 0u) return false;
                    depth--;
                }
                p++;
            } while (p <= obj_end && depth != 0u);
            if (depth != 0u) return false;
        } else if (*p == '"') {
            p = json_skip_string(p, obj_end + 1);
            if (p > obj_end + 1) return false;
        } else {
            while (p < obj_end && *p != ',' && *p != '}') p++;
        }

        p = skip_pure_ws(p, obj_end + 1);
        if (p < obj_end && *p == ',') {
            p = skip_pure_ws(p + 1, obj_end + 1);
            continue;
        }
        if (p == obj_end && *p == '}') {
            for (size_t i = 0; i < required_count; ++i) {
                if (!seen[i]) return false;
            }
            return true;
        }
        return false;
    }
}

static bool json_match_uint_array(const char **src, const char *limit,
                                  uint32_t *values, size_t capacity,
                                  uint32_t *count_out) {
    if (src == NULL || *src == NULL || values == NULL || count_out == NULL) return false;
    const char *p = skip_pure_ws(*src, limit);
    if (p >= limit || *p++ != '[') return false;
    p = skip_pure_ws(p, limit);
    uint32_t count = 0u;
    if (p < limit && *p == ']') {
        *src = p + 1;
        *count_out = 0u;
        return true;
    }
    for (;;) {
        uint32_t value;
        const char *num = p;
        if (count >= capacity || !json_match_uint32(&num, &value) || num > limit) return false;
        values[count++] = value;
        p = skip_pure_ws(num, limit);
        if (p >= limit) return false;
        if (*p == ']') {
            *src = p + 1;
            *count_out = count;
            return true;
        }
        if (*p++ != ',') return false;
        p = skip_pure_ws(p, limit);
    }
}

static bool json_get_uint(const char *obj, const char *obj_end,
                          const char *key, uint32_t *out) {
    const char *value = json_find_key_bounded(obj, obj_end, key);
    return value != NULL && json_match_uint32(&value, out);
}

static bool json_get_uint_array(const char *obj, const char *obj_end,
                                const char *key, uint32_t *values,
                                size_t capacity, uint32_t *count) {
    const char *value = json_find_key_bounded(obj, obj_end, key);
    return value != NULL && json_match_uint_array(&value, obj_end + 1,
                                                 values, capacity, count);
}

int latch_manifest_verify_sidecar(const char *manifest_path, const char *computed_hex,
                                  bool require_sidecar, char *err_buf, size_t err_len) {
    if (manifest_path == NULL || computed_hex == NULL) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid arguments to sidecar verification");
        return -EINVAL;
    }
    char sidecar_path[512];
    snprintf(sidecar_path, sizeof(sidecar_path), "%s.sha256", manifest_path);

    FILE *sf = fopen(sidecar_path, "r");
    if (!sf) {
        if (require_sidecar) {
            if (err_buf) snprintf(err_buf, err_len,
                                  "Missing mandatory SHA-256 sidecar '%s' (Fail-Closed)", sidecar_path);
            return -ENOENT;
        }
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
    return latch_manifest_load_opts(path, out_m, true, err_buf, err_len);
}

int latch_manifest_load_opts(const char *path, latch_manifest_t *out_m, bool require_sidecar,
                             char *err_buf, size_t err_len) {
    if (out_m == NULL || path == NULL) {
        if (err_buf) snprintf(err_buf, err_len, "Invalid arguments to latch_manifest_load_opts");
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

    /* Verify sidecar SHA-256 file (<path>.sha256) */
    if (latch_manifest_verify_sidecar(path, out_m->sha256_hex, require_sidecar, err_buf, err_len) != 0) {
        free(buf);
        return -1;
    }

    /* Validate mandatory sections */
    const char *env_end = NULL, *tim_end = NULL, *rec_end = NULL;
    const char *dec_end = NULL, *ing_end = NULL, *paths_end = NULL;
    const char *act_end = NULL, *proto_end = NULL, *tape_end = NULL;
    const char *plant_end = NULL;
    const char *gov_end = NULL;

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
    const char *gov_sec   = json_find_section(buf, "governor", &gov_end);
    const char *med_end   = NULL;
    const char *med_sec   = json_find_section(buf, "medical", &med_end);
    const char *home_end  = NULL;
    const char *home_sec  = json_find_section(buf, "homeostat", &home_end);

    if (!plant_sec || !env_sec || !tim_sec || !rec_sec || !dec_sec ||
        !ing_sec || !paths_sec || !act_sec || !tape_sec || !proto_sec) {
        free(buf);
        if (err_buf) snprintf(err_buf, err_len,
                              "Manifest missing mandatory sections (plant, envelope, timing, recovery, decision, ingest, paths, actuator, tape, protocol)");
        return -EINVAL;
    }

    bool has_schema = false;
    bool has_plant_name = false, has_axes = false;
    bool has_theta_min = false, has_theta_max = false, has_home = false;
    bool has_v_max = false, has_a_max = false, has_j_max = false, has_v_home = false;
    bool has_lookahead = false;
    bool has_period = false, has_watchdog = false, has_wcet = false, has_max_backlog = false;
    bool has_clean_frames = false, has_hold_to_home = false;
    bool has_dec_cpu = false, has_dec_prio = false, has_dec_pulse_prio = false;
    bool has_ing_cpu = false, has_ing_delivery = false, has_ing_qdepth = false;
    bool has_path_prop = false, has_path_act = false, has_path_abil = false, has_path_i2c = false;
    bool has_actuator_type = false, has_act_addr = false, has_act_freq = false, has_act_prescale = false;
    bool has_act_retries = false, has_act_init_delay = false, has_act_required = false;
    bool has_pwm_center = false, has_pwm_min = false, has_pwm_max = false;
    bool has_tape_cap = false, has_tape_log_path = false;
    bool has_proto_magic = false, has_proto_version = false, has_proto_crc = false, has_proto_cov = false;

    const char *buf_end = buf + read_bytes;
    const char *p;

    /* 1. Parse schema_version */
    if ((p = json_find_key_depth(buf, buf_end, "schema_version", 1)) != NULL) {
        if (json_match_uint32(&p, &out_m->schema_version) &&
            (out_m->schema_version == 1u ||
             out_m->schema_version == LATCH_MANIFEST_SCHEMA_VERSION ||
             out_m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION)) {
            has_schema = true;
        }
    }

    /*
     * 1b. STRICT KEY-SET VALIDATION FOR EVERY SECTION (L-4).
     *
     * The sidecar digest defends the manifest against TAMPERING; it does not
     * defend it against AUTHORSHIP ERROR.  A signed manifest with a typo
     * ("v_max" written twice, "hysteresis_clean_frames" misspelled) used to
     * load the first value and silently ignore the rest -- the loader was
     * first-match-wins for duplicate keys and ignored unknown keys outside
     * the governor/units/medical/rate/homeostat sections.
     *
     * Every section is therefore checked here: the key set must be exactly
     * the known set, with no unknown keys and no duplicates.  A typo is now
     * a LOAD FAILURE, not a silently different safety envelope.
     *
     * The TOP level is checked too, and that is the sharpest edge of it: a
     * misspelled "medical" or "homeostat" section used to be ignored, which
     * silently turned the dose gate or the contraction loop OFF while the
     * manifest still verified against its sidecar.
     */
    {
        static const char *const top_keys_v12[] = {
            "schema_version", "plant", "envelope", "timing", "recovery",
            "decision", "ingest", "paths", "actuator", "tape", "protocol"
        };
        static const char *const top_keys_v3[] = {
            "schema_version", "plant", "envelope", "timing", "recovery",
            "decision", "ingest", "paths", "actuator", "tape", "protocol",
            "governor", "medical", "homeostat"
        };
        static const char *const plant_keys[] = { "name", "axes" };
        static const char *const axis_keys[] = { "id", "kind", "unit", "min", "max" };
        static const char *const envelope_keys[] = {
            "theta_min_mrad", "theta_max_mrad", "home_mrad", "keepout",
            "v_max", "a_max", "j_max", "v_home", "lookahead_ticks"
        };
        static const char *const keepout_keys[] = { "lo_mrad", "hi_mrad", "label" };
        static const char *const timing_keys[] = {
            "period_us", "watchdog_ticks", "wcet_budget_us", "max_backlog_ticks"
        };
        static const char *const recovery_keys[] = {
            "hysteresis_clean_frames", "hold_to_home_ticks"
        };
        static const char *const decision_keys[] = { "cpu", "priority", "pulse_priority" };
        static const char *const ingest_keys[] = { "cpu", "delivery", "queue_depth" };
        static const char *const paths_keys[] = {
            "proposal", "actuator", "ability", "i2c_bus"
        };
        static const char *const actuator_keys[] = {
            "type", "addr", "freq_hz", "prescale", "pwm_center", "pwm_min",
            "pwm_max", "retries", "init_delay_us", "required"
        };
        static const char *const tape_keys[] = { "capacity", "log_path" };
        static const char *const protocol_keys[] = { "magic", "version", "crc", "coverage" };

        const char *top_end = json_find_object_end(buf, buf_end);
        bool top_ok = false;
        if (top_end != NULL && buf_end >= top_end) {
            if (out_m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
                top_ok = json_object_has_only_keys_ex(buf, top_end, top_keys_v3,
                                                      sizeof(top_keys_v3) / sizeof(top_keys_v3[0]),
                                                      11u);
            } else {
                top_ok = json_object_has_only_keys_ex(buf, top_end, top_keys_v12,
                                                      sizeof(top_keys_v12) / sizeof(top_keys_v12[0]),
                                                      11u);
            }
        }
        if (!top_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Manifest top level contains unknown or duplicate keys "
                                  "(a typo must fail closed, not silently change the safety envelope)");
            return -EINVAL;
        }

        bool sections_ok =
            json_object_has_only_keys(plant_sec, plant_end, plant_keys,
                                      sizeof(plant_keys) / sizeof(plant_keys[0])) &&
            json_object_has_only_keys(env_sec, env_end, envelope_keys,
                                      sizeof(envelope_keys) / sizeof(envelope_keys[0])) &&
            json_object_has_only_keys(tim_sec, tim_end, timing_keys,
                                      sizeof(timing_keys) / sizeof(timing_keys[0])) &&
            json_object_has_only_keys(rec_sec, rec_end, recovery_keys,
                                      sizeof(recovery_keys) / sizeof(recovery_keys[0])) &&
            json_object_has_only_keys(dec_sec, dec_end, decision_keys,
                                      sizeof(decision_keys) / sizeof(decision_keys[0])) &&
            json_object_has_only_keys(ing_sec, ing_end, ingest_keys,
                                      sizeof(ingest_keys) / sizeof(ingest_keys[0])) &&
            json_object_has_only_keys(paths_sec, paths_end, paths_keys,
                                      sizeof(paths_keys) / sizeof(paths_keys[0])) &&
            json_object_has_only_keys(act_sec, act_end, actuator_keys,
                                      sizeof(actuator_keys) / sizeof(actuator_keys[0])) &&
            json_object_has_only_keys(tape_sec, tape_end, tape_keys,
                                      sizeof(tape_keys) / sizeof(tape_keys[0])) &&
            json_object_has_only_keys(proto_sec, proto_end, protocol_keys,
                                      sizeof(protocol_keys) / sizeof(protocol_keys[0]));
        if (!sections_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Manifest section contains unknown or duplicate keys "
                                  "(a typo must fail closed, not silently change the safety envelope)");
            return -EINVAL;
        }

        /* Every axis entry and every keep-out entry is a safety parameter
         * too, so each object in those arrays is checked individually. */
        bool entries_ok = true;
        {
            const char *axes_ptr = json_find_key_bounded(plant_sec, plant_end, "axes");
            if (axes_ptr != NULL) {
                axes_ptr = skip_pure_ws(axes_ptr, plant_end);
                if (axes_ptr < plant_end && *axes_ptr == '[') {
                    axes_ptr++;
                    while (axes_ptr < plant_end) {
                        axes_ptr = skip_pure_ws(axes_ptr, plant_end);
                        while (axes_ptr < plant_end && *axes_ptr == ',') {
                            axes_ptr = skip_pure_ws(axes_ptr + 1, plant_end);
                        }
                        if (axes_ptr >= plant_end || *axes_ptr == ']') break;
                        if (*axes_ptr != '{') { entries_ok = false; break; }
                        const char *obj = axes_ptr;
                        const char *obj_end = json_find_object_end(obj, plant_end);
                        if (!obj_end || obj_end >= plant_end) { entries_ok = false; break; }
                        if (!json_object_has_only_keys(obj, obj_end, axis_keys,
                                                        sizeof(axis_keys) / sizeof(axis_keys[0]))) {
                            entries_ok = false;
                            break;
                        }
                        axes_ptr = obj_end + 1;
                    }
                }
            }
            const char *ko_ptr = json_find_key_bounded(env_sec, env_end, "keepout");
            if (ko_ptr != NULL) {
                ko_ptr = skip_pure_ws(ko_ptr, env_end);
                if (ko_ptr < env_end && *ko_ptr == '[') {
                    ko_ptr++;
                    while (ko_ptr < env_end) {
                        ko_ptr = skip_pure_ws(ko_ptr, env_end);
                        while (ko_ptr < env_end && *ko_ptr == ',') {
                            ko_ptr = skip_pure_ws(ko_ptr + 1, env_end);
                        }
                        if (ko_ptr >= env_end || *ko_ptr == ']') break;
                        if (*ko_ptr != '{') { entries_ok = false; break; }
                        const char *obj = ko_ptr;
                        const char *obj_end = json_find_object_end(obj, env_end);
                        if (!obj_end || obj_end >= env_end) { entries_ok = false; break; }
                        if (!json_object_has_only_keys(obj, obj_end, keepout_keys,
                                                        sizeof(keepout_keys) / sizeof(keepout_keys[0]))) {
                            entries_ok = false;
                            break;
                        }
                        ko_ptr = obj_end + 1;
                    }
                }
            }
        }
        if (!entries_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Manifest axis or keep-out entry contains unknown or duplicate keys");
            return -EINVAL;
        }
    }

    /* 2. Parse plant */
    {
        const char *np = json_find_key_bounded(plant_sec, plant_end, "name");
        if (np && json_match_str(&np, out_m->plant_name, sizeof(out_m->plant_name)) &&
            out_m->plant_name[0] != '\0') {
            has_plant_name = true;
        }

        const char *axes_ptr = json_find_key_bounded(plant_sec, plant_end, "axes");
        if (axes_ptr) {
            axes_ptr = skip_pure_ws(axes_ptr, plant_end);
            if (axes_ptr < plant_end && *axes_ptr == '[') {
                axes_ptr++;
                out_m->num_axes = 0;
                while (axes_ptr < plant_end && out_m->num_axes < LATCH_MAX_AXES) {
                    axes_ptr = skip_pure_ws(axes_ptr, plant_end);
                    while (axes_ptr < plant_end && *axes_ptr == ',') {
                        axes_ptr++;
                        axes_ptr = skip_pure_ws(axes_ptr, plant_end);
                    }
                    if (axes_ptr >= plant_end || *axes_ptr == ']') break;
                    if (*axes_ptr != '{') break;
                    const char *obj = axes_ptr;
                    const char *obj_end = json_find_object_end(obj, plant_end);
                    if (!obj_end || obj_end >= plant_end) break;
                    uint32_t idx = out_m->num_axes;
                    const char *id_ptr   = json_find_key_bounded(obj, obj_end + 1, "id");
                    const char *kind_ptr = json_find_key_bounded(obj, obj_end + 1, "kind");
                    const char *unit_ptr = json_find_key_bounded(obj, obj_end + 1, "unit");
                    const char *min_ptr  = json_find_key_bounded(obj, obj_end + 1, "min");
                    const char *max_ptr  = json_find_key_bounded(obj, obj_end + 1, "max");
                    bool ok_axis = (id_ptr   && json_match_uint32(&id_ptr, &out_m->axes[idx].id)) &&
                                   (kind_ptr && json_match_str(&kind_ptr, out_m->axes[idx].kind, sizeof(out_m->axes[idx].kind))) &&
                                   (unit_ptr && json_match_str(&unit_ptr, out_m->axes[idx].unit, sizeof(out_m->axes[idx].unit))) &&
                                   (min_ptr  && json_match_int32(&min_ptr, &out_m->axes[idx].min)) &&
                                   (max_ptr  && json_match_int32(&max_ptr, &out_m->axes[idx].max));
                    if (!ok_axis) break;
                    out_m->axes[idx].fullscale_counts_span = out_m->axes[idx].max - out_m->axes[idx].min;
                    out_m->num_axes++;
                    axes_ptr = obj_end + 1;
                }
                if (out_m->num_axes >= 1u) has_axes = true;
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
        if (la_p && json_match_uint32(&la_p, &out_m->envelope.lookahead_ticks)) has_lookahead = true;

        const char *ko_ptr = json_find_key_bounded(env_sec, env_end, "keepout");
        if (ko_ptr) {
            ko_ptr = skip_pure_ws(ko_ptr, env_end);
            if (ko_ptr < env_end && *ko_ptr == '[') {
                ko_ptr++;
                out_m->envelope.num_keepouts = 0;
                while (ko_ptr < env_end && out_m->envelope.num_keepouts < LATCH_MAX_KEEPOUTS) {
                    ko_ptr = skip_pure_ws(ko_ptr, env_end);
                    while (ko_ptr < env_end && *ko_ptr == ',') {
                        ko_ptr++;
                        ko_ptr = skip_pure_ws(ko_ptr, env_end);
                    }
                    if (ko_ptr >= env_end || *ko_ptr == ']') break;
                    if (*ko_ptr != '{') break;
                    const char *obj = ko_ptr;
                    const char *obj_end = json_find_object_end(obj, env_end);
                    if (!obj_end || obj_end >= env_end) break;
                    const char *lo_ptr = json_find_key_bounded(obj, obj_end + 1, "lo_mrad");
                    const char *hi_ptr = json_find_key_bounded(obj, obj_end + 1, "hi_mrad");
                    const char *lb_ptr = json_find_key_bounded(obj, obj_end + 1, "label");

                    if (lo_ptr && hi_ptr) {
                        uint32_t idx = out_m->envelope.num_keepouts;
                        if (json_match_int32(&lo_ptr, &out_m->envelope.keepout[idx].lo_mrad) &&
                            json_match_int32(&hi_ptr, &out_m->envelope.keepout[idx].hi_mrad)) {
                            if (lb_ptr) {
                                json_match_str(&lb_ptr, out_m->envelope.keepout[idx].label,
                                               sizeof(out_m->envelope.keepout[idx].label));
                            }
                            out_m->envelope.num_keepouts++;
                        }
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
        if (mb_p && json_match_uint32(&mb_p, &out_m->timing.max_backlog_ticks)) has_max_backlog = true;
    }

    /* 5. Parse recovery within rec_sec */
    {
        const char *cf_p = json_find_key_bounded(rec_sec, rec_end, "hysteresis_clean_frames");
        if (cf_p && json_match_uint32(&cf_p, &out_m->recovery.hysteresis_clean_frames)) has_clean_frames = true;

        const char *hh_p = json_find_key_bounded(rec_sec, rec_end, "hold_to_home_ticks");
        if (hh_p && json_match_uint32(&hh_p, &out_m->recovery.hold_to_home_ticks)) has_hold_to_home = true;
    }

    /* 6. Parse decision */
    {
        const char *cp_p = json_find_key_bounded(dec_sec, dec_end, "cpu");
        if (cp_p && json_match_uint32(&cp_p, &out_m->decision.cpu)) has_dec_cpu = true;

        const char *pr_p = json_find_key_bounded(dec_sec, dec_end, "priority");
        if (pr_p && json_match_uint32(&pr_p, &out_m->decision.priority)) has_dec_prio = true;

        const char *pp_p = json_find_key_bounded(dec_sec, dec_end, "pulse_priority");
        if (pp_p && json_match_uint32(&pp_p, &out_m->decision.pulse_priority)) has_dec_pulse_prio = true;
    }

    /* 7. Parse ingest */
    {
        const char *cp_p = json_find_key_bounded(ing_sec, ing_end, "cpu");
        if (cp_p && json_match_uint32(&cp_p, &out_m->ingest.cpu)) has_ing_cpu = true;

        const char *del_p = json_find_key_bounded(ing_sec, ing_end, "delivery");
        if (del_p && json_match_str(&del_p, out_m->ingest.delivery, sizeof(out_m->ingest.delivery))) has_ing_delivery = true;

        const char *qd_p = json_find_key_bounded(ing_sec, ing_end, "queue_depth");
        if (qd_p && json_match_uint32(&qd_p, &out_m->ingest.queue_depth)) has_ing_qdepth = true;
    }

    /* 8. Parse paths */
    {
        const char *prop_p = json_find_key_bounded(paths_sec, paths_end, "proposal");
        if (prop_p && json_match_str(&prop_p, out_m->paths.proposal, sizeof(out_m->paths.proposal)) &&
            out_m->paths.proposal[0] != '\0') has_path_prop = true;

        const char *act_p = json_find_key_bounded(paths_sec, paths_end, "actuator");
        if (act_p && json_match_str(&act_p, out_m->paths.actuator, sizeof(out_m->paths.actuator)) &&
            out_m->paths.actuator[0] != '\0') has_path_act = true;

        const char *ab_p = json_find_key_bounded(paths_sec, paths_end, "ability");
        if (ab_p && json_match_str(&ab_p, out_m->paths.ability, sizeof(out_m->paths.ability)) &&
            out_m->paths.ability[0] != '\0') has_path_abil = true;

        const char *i2c_p = json_find_key_bounded(paths_sec, paths_end, "i2c_bus");
        if (i2c_p && json_match_str(&i2c_p, out_m->paths.i2c_bus, sizeof(out_m->paths.i2c_bus)) &&
            out_m->paths.i2c_bus[0] != '\0') has_path_i2c = true;
    }

    /* 9. Parse actuator within act_sec */
    {
        const char *t_p = json_find_key_bounded(act_sec, act_end, "type");
        if (t_p && json_match_str(&t_p, out_m->actuator.type, sizeof(out_m->actuator.type)) &&
            out_m->actuator.type[0] != '\0') has_actuator_type = true;

        const char *a_p = json_find_key_bounded(act_sec, act_end, "addr");
        if (a_p && json_match_uint32(&a_p, &out_m->actuator.addr)) has_act_addr = true;

        const char *f_p = json_find_key_bounded(act_sec, act_end, "freq_hz");
        if (f_p && json_match_uint32(&f_p, &out_m->actuator.freq_hz)) has_act_freq = true;

        const char *pr_p = json_find_key_bounded(act_sec, act_end, "prescale");
        if (pr_p && json_match_uint32(&pr_p, &out_m->actuator.prescale)) has_act_prescale = true;

        const char *ret_p = json_find_key_bounded(act_sec, act_end, "retries");
        if (ret_p && json_match_uint32(&ret_p, &out_m->actuator.retries)) has_act_retries = true;

        const char *id_p = json_find_key_bounded(act_sec, act_end, "init_delay_us");
        if (id_p && json_match_uint32(&id_p, &out_m->actuator.init_delay_us)) has_act_init_delay = true;

        const char *req_p = json_find_key_bounded(act_sec, act_end, "required");
        if (req_p) {
            if ((req_p + 4 <= act_end) && strncmp(req_p, "true", 4) == 0 &&
                (req_p + 4 == act_end || isspace((unsigned char)req_p[4]) ||
                 req_p[4] == ',' || req_p[4] == '}')) {
                out_m->actuator.required = true;
                has_act_required = true;
            } else if ((req_p + 5 <= act_end) && strncmp(req_p, "false", 5) == 0 &&
                       (req_p + 5 == act_end || isspace((unsigned char)req_p[5]) ||
                        req_p[5] == ',' || req_p[5] == '}')) {
                out_m->actuator.required = false;
                has_act_required = true;
            }
        }

        const char *pc_p = json_find_key_bounded(act_sec, act_end, "pwm_center");
        if (pc_p && json_match_int32(&pc_p, &out_m->actuator.pwm_center)) has_pwm_center = true;

        const char *pmin_p = json_find_key_bounded(act_sec, act_end, "pwm_min");
        if (pmin_p && json_match_int32(&pmin_p, &out_m->actuator.pwm_min)) has_pwm_min = true;

        const char *pmax_p = json_find_key_bounded(act_sec, act_end, "pwm_max");
        if (pmax_p && json_match_int32(&pmax_p, &out_m->actuator.pwm_max)) has_pwm_max = true;
    }

    /* 10. Parse tape */
    {
        const char *cap_p = json_find_key_bounded(tape_sec, tape_end, "capacity");
        if (cap_p && json_match_uint32(&cap_p, &out_m->tape.capacity)) has_tape_cap = true;

        const char *lp_p = json_find_key_bounded(tape_sec, tape_end, "log_path");
        if (lp_p && json_match_str(&lp_p, out_m->tape.log_path, sizeof(out_m->tape.log_path)) &&
            out_m->tape.log_path[0] != '\0') {
            has_tape_log_path = true;
        }
    }

    /* 11. Parse protocol within proto_sec */
    {
        const char *mag_p = json_find_key_bounded(proto_sec, proto_end, "magic");
        if (mag_p && json_match_str(&mag_p, out_m->protocol.magic, sizeof(out_m->protocol.magic))) has_proto_magic = true;

        const char *ver_p = json_find_key_bounded(proto_sec, proto_end, "version");
        if (ver_p && json_match_uint32(&ver_p, &out_m->protocol.version)) has_proto_version = true;

        const char *crc_p = json_find_key_bounded(proto_sec, proto_end, "crc");
        if (crc_p && json_match_str(&crc_p, out_m->protocol.crc, sizeof(out_m->protocol.crc))) has_proto_crc = true;

        const char *cov_p = json_find_key_bounded(proto_sec, proto_end, "coverage");
        if (cov_p && json_match_uint32(&cov_p, &out_m->protocol.coverage)) has_proto_cov = true;
    }

    bool has_gov_enabled = false;
    bool has_gov_ladder = false, has_gov_deadman = false;
    bool has_gov_units = false, has_gov_rate = false;
    if (out_m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
        static const char *const governor_keys[] = { "enabled", "ladder", "deadman", "units", "rate" };
        static const char *const ladder_keys[] = {
            "advise_fault_mask", "clamp_max_step", "slow_scale_pct", "safe_stop_decel",
            "demote_faults_per_rung", "promote_clean_frames", "min_confidence_q8"
        };
        static const char *const deadman_keys[] = {
            "lease_ticks", "coherence_max_gap", "warmup_heartbeats"
        };
        static const char *const unit_keys[] = {
            "enabled", "canonical_unit_id", "alternate_unit_ids",
            "conversion_numerators", "conversion_denominators"
        };
        static const char *const rate_keys[] = {
            "enabled", "burst_tokens", "refill_per_tick", "sustain_per_tick"
        };
        const char *ladder_end = NULL, *deadman_end = NULL;
        const char *units_end = NULL, *rate_end = NULL;
        const char *ladder_sec = json_find_child_section(gov_sec, gov_end, "ladder", &ladder_end);
        const char *deadman_sec = json_find_child_section(gov_sec, gov_end, "deadman", &deadman_end);
        const char *units_sec = json_find_child_section(gov_sec, gov_end, "units", &units_end);
        const char *rate_sec = json_find_child_section(gov_sec, gov_end, "rate", &rate_end);
        if (gov_sec == NULL ||
            !json_object_has_only_keys(gov_sec, gov_end, governor_keys,
                                       sizeof(governor_keys) / sizeof(governor_keys[0])) ||
            ladder_sec == NULL || deadman_sec == NULL || units_sec == NULL || rate_sec == NULL ||
            !json_object_has_only_uint_keys(ladder_sec, ladder_end, ladder_keys,
                                            sizeof(ladder_keys) / sizeof(ladder_keys[0])) ||
            !json_object_has_only_uint_keys(deadman_sec, deadman_end, deadman_keys,
                                            sizeof(deadman_keys) / sizeof(deadman_keys[0])) ||
            !json_object_has_only_keys(units_sec, units_end, unit_keys,
                                       sizeof(unit_keys) / sizeof(unit_keys[0])) ||
            !json_object_has_only_uint_keys(rate_sec, rate_end, rate_keys,
                                            sizeof(rate_keys) / sizeof(rate_keys[0]))) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 requires known, unique GOVERNOR sections with valid field types");
            return -EINVAL;
        }

        uint32_t numerator_count = 0u, denominator_count = 0u;
        has_gov_enabled = json_get_uint(gov_sec, gov_end, "enabled", &out_m->governor.enabled);
        bool gov_values_ok =
            json_get_uint(ladder_sec, ladder_end, "advise_fault_mask", &out_m->governor.advise_fault_mask) &&
            json_get_uint(ladder_sec, ladder_end, "clamp_max_step", &out_m->governor.clamp_max_step) &&
            json_get_uint(ladder_sec, ladder_end, "slow_scale_pct", &out_m->governor.slow_scale_pct) &&
            json_get_uint(ladder_sec, ladder_end, "safe_stop_decel", &out_m->governor.safe_stop_decel) &&
            json_get_uint(ladder_sec, ladder_end, "demote_faults_per_rung", &out_m->governor.demote_faults_per_rung) &&
            json_get_uint(ladder_sec, ladder_end, "promote_clean_frames", &out_m->governor.promote_clean_frames) &&
            json_get_uint(ladder_sec, ladder_end, "min_confidence_q8", &out_m->governor.min_confidence_q8) &&
            json_get_uint(deadman_sec, deadman_end, "lease_ticks", &out_m->governor.lease_ticks) &&
            json_get_uint(deadman_sec, deadman_end, "coherence_max_gap", &out_m->governor.coherence_max_gap) &&
            json_get_uint(deadman_sec, deadman_end, "warmup_heartbeats", &out_m->governor.warmup_heartbeats) &&
            json_get_uint(units_sec, units_end, "enabled", &out_m->governor.units_enabled) &&
            json_get_uint(units_sec, units_end, "canonical_unit_id", &out_m->governor.canonical_unit_id) &&
            json_get_uint_array(units_sec, units_end, "alternate_unit_ids",
                                out_m->governor.alternate_unit_ids,
                                sizeof(out_m->governor.alternate_unit_ids) /
                                    sizeof(out_m->governor.alternate_unit_ids[0]),
                                &out_m->governor.unit_scale_count) &&
            json_get_uint_array(units_sec, units_end, "conversion_numerators",
                                out_m->governor.conversion_numerators,
                                sizeof(out_m->governor.conversion_numerators) /
                                    sizeof(out_m->governor.conversion_numerators[0]),
                                &numerator_count) &&
            json_get_uint_array(units_sec, units_end, "conversion_denominators",
                                out_m->governor.conversion_denominators,
                                sizeof(out_m->governor.conversion_denominators) /
                                    sizeof(out_m->governor.conversion_denominators[0]),
                                &denominator_count) &&
            out_m->governor.unit_scale_count == numerator_count &&
            numerator_count == denominator_count && numerator_count > 0u &&
            json_get_uint(rate_sec, rate_end, "enabled", &out_m->governor.rate_enabled) &&
            json_get_uint(rate_sec, rate_end, "burst_tokens", &out_m->governor.rate_burst_tokens) &&
            json_get_uint(rate_sec, rate_end, "refill_per_tick", &out_m->governor.rate_refill_per_tick) &&
            json_get_uint(rate_sec, rate_end, "sustain_per_tick", &out_m->governor.rate_sustain_per_tick);
        if (!has_gov_enabled || !gov_values_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 GOVERNOR settings are missing or are not unsigned integers");
            return -EINVAL;
        }
        has_gov_ladder = true;
        has_gov_deadman = true;
        has_gov_units = true;
        has_gov_rate = true;
        out_m->governor_present = true;
    }

    if (med_sec != NULL) {
        if (out_m->schema_version != LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len, "Medical section is only supported in schema 3");
            return -EINVAL;
        }
        static const char *const medical_keys[] = {
            "drug_name", "drug_id", "concentration_uL_per_unit",
            "max_bolus_uL", "min_bolus_interval_ticks",
            "cumulative_dose_window_ticks", "max_cumulative_dose_uL"
        };
        if (!json_object_has_only_keys(med_sec, med_end, medical_keys,
                                       sizeof(medical_keys) / sizeof(medical_keys[0]))) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 medical section contains unknown or duplicate keys");
            return -EINVAL;
        }
        const char *np = json_find_key_bounded(med_sec, med_end, "drug_name");
        if (!np || !json_match_str(&np, out_m->medical.drug_name, sizeof(out_m->medical.drug_name)) ||
            out_m->medical.drug_name[0] == '\0') {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len, "Schema 3 medical section missing valid drug_name string");
            return -EINVAL;
        }
        bool med_ok =
            json_get_uint(med_sec, med_end, "drug_id", &out_m->medical.drug_id) &&
            json_get_uint(med_sec, med_end, "concentration_uL_per_unit", &out_m->medical.concentration_uL_per_unit) &&
            json_get_uint(med_sec, med_end, "max_bolus_uL", &out_m->medical.max_bolus_uL) &&
            json_get_uint(med_sec, med_end, "min_bolus_interval_ticks", &out_m->medical.min_bolus_interval_ticks) &&
            json_get_uint(med_sec, med_end, "cumulative_dose_window_ticks", &out_m->medical.cumulative_dose_window_ticks) &&
            json_get_uint(med_sec, med_end, "max_cumulative_dose_uL", &out_m->medical.max_cumulative_dose_uL);
        if (!med_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len, "Schema 3 medical numeric values are missing or invalid");
            return -EINVAL;
        }
        out_m->medical_present = true;
    }

    /*
     * HOMEOSTAT: OPTIONAL, schema-3, DEFAULT-OFF.
     *
     * An absent section leaves `homeostat_present == false` and the
     * supervisor behaves bit-identically to a build without the module.
     * A PRESENT section is parsed STRICTLY (unknown keys, duplicate keys
     * and non-integer values are all rejected) and its numeric ranges are
     * validated HERE, at load time, so an out-of-range safety parameter can
     * never reach the runtime loop as a silently clamped default.
     */
    if (home_sec != NULL) {
        if (out_m->schema_version != LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "HOMEOSTAT section is only supported in schema 3");
            return -EINVAL;
        }
        static const char *const homeostat_keys[] = {
            "enabled", "epoch_ticks", "reject_threshold_q8",
            "latency_spread_threshold_ns", "clamp_threshold_q8",
            "coherence_anomaly_threshold", "contraction_q8", "recovery_q8",
            "floor_q8"
        };
        if (!json_object_has_only_uint_keys(home_sec, home_end, homeostat_keys,
                                            sizeof(homeostat_keys) /
                                                sizeof(homeostat_keys[0]))) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 homeostat section contains unknown, duplicate or non-integer keys");
            return -EINVAL;
        }
        latch_manifest_homeostat_t *hs = &out_m->homeostat;
        bool home_ok =
            json_get_uint(home_sec, home_end, "enabled", &hs->enabled) &&
            json_get_uint(home_sec, home_end, "epoch_ticks", &hs->epoch_ticks) &&
            json_get_uint(home_sec, home_end, "reject_threshold_q8", &hs->reject_threshold_q8) &&
            json_get_uint(home_sec, home_end, "latency_spread_threshold_ns", &hs->latency_spread_threshold_ns) &&
            json_get_uint(home_sec, home_end, "clamp_threshold_q8", &hs->clamp_threshold_q8) &&
            json_get_uint(home_sec, home_end, "coherence_anomaly_threshold", &hs->coherence_anomaly_threshold) &&
            json_get_uint(home_sec, home_end, "contraction_q8", &hs->contraction_q8) &&
            json_get_uint(home_sec, home_end, "recovery_q8", &hs->recovery_q8) &&
            json_get_uint(home_sec, home_end, "floor_q8", &hs->floor_q8);
        if (!home_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 homeostat numeric values are missing or invalid");
            return -EINVAL;
        }
        /* Fail-closed range validation. Every one of these is a SAFETY
         * parameter, so an out-of-range value is a manifest rejection, not a
         * runtime clamp:
         *   enabled             0 or 1 only
         *   epoch_ticks         >= 1 (a zero-length epoch never closes)
         *   floor_q8            1..256 (Q8; 0 would collapse the envelope to
         *                      zero velocity, 256 is unity)
         *   contraction_q8      >= 1 (a zero step would never contract)
         *   recovery_q8         >= 1 (a zero step would never recover)
         *   *_threshold_q8      0..256 (0 disables that trigger)
         */
        bool home_range_ok =
            hs->enabled <= 1u &&
            hs->epoch_ticks >= 1u &&
            hs->floor_q8 >= 1u && hs->floor_q8 <= 256u &&
            hs->contraction_q8 >= 1u &&
            hs->recovery_q8 >= 1u &&
            hs->reject_threshold_q8 <= 256u &&
            hs->clamp_threshold_q8 <= 256u;
        if (!home_range_ok) {
            free(buf);
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 homeostat values out of range "
                                  "(enabled<=1, epoch_ticks>=1, 1<=floor_q8<=256, "
                                  "contraction_q8>=1, recovery_q8>=1, thresholds<=256)");
            return -EINVAL;
        }
        out_m->homeostat_present = true;
    }

    free(buf);

    /* Enforce strict Anti-Silent-Defaults: all required safety & binding keys must be present */
    if (!has_schema || !has_plant_name || !has_axes ||
        !has_theta_min || !has_theta_max || !has_home ||
        !has_v_max || !has_a_max || !has_j_max || !has_v_home || !has_lookahead ||
        !has_period || !has_watchdog || !has_wcet || !has_max_backlog ||
        !has_clean_frames || !has_hold_to_home ||
        !has_dec_cpu || !has_dec_prio || !has_dec_pulse_prio ||
        !has_ing_cpu || !has_ing_delivery || !has_ing_qdepth ||
        !has_path_prop || !has_path_act || !has_path_abil || !has_path_i2c ||
        !has_actuator_type || !has_act_addr || !has_act_freq || !has_act_prescale ||
        !has_act_retries || !has_act_init_delay || !has_act_required ||
        !has_pwm_center || !has_pwm_min || !has_pwm_max ||
        !has_tape_cap || !has_tape_log_path ||
        !has_proto_magic || !has_proto_version || !has_proto_crc || !has_proto_cov) {
        if (err_buf) snprintf(err_buf, err_len,
                              "Manifest missing required safety parameters (anti-silent-defaults: fail-closed)");
        return -EINVAL;
    }

    if (out_m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION &&
        (!has_gov_enabled || !has_gov_ladder || !has_gov_deadman || !has_gov_units || !has_gov_rate)) {
        if (err_buf) snprintf(err_buf, err_len,
                              "Schema 3 governor object is missing one or more required settings");
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
    if (m->schema_version != 1u && m->schema_version != LATCH_MANIFEST_SCHEMA_VERSION &&
        m->schema_version != LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
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
    if (m->envelope.v_max <= 0 || m->envelope.v_max > 1000000000 ||
        m->envelope.a_max <= 0 || m->envelope.j_max <= 0 || m->envelope.v_home <= 0) {
        if (err_buf) snprintf(err_buf, err_len, "Kinematic bounds must be positive and bounded <= 1e9 (v_max=%d, a_max=%d, j_max=%d, v_home=%d)",
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
        bool protocol_v1_ok = m->protocol.version == 1u &&
            (strcmp(m->protocol.crc, "ieee32") == 0 || strcmp(m->protocol.crc, "crc32-ieee") == 0) &&
            m->protocol.coverage == 16u;
        bool protocol_v2_ok = m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION &&
            m->protocol.version == 2u && strcmp(m->protocol.crc, "ieee32-v2") == 0 &&
            m->protocol.coverage == 28u;
        if (strcmp(m->protocol.magic, "LATH") != 0 || (!protocol_v1_ok && !protocol_v2_ok)) {
            if (err_buf) snprintf(err_buf, err_len, "Protocol metadata mismatch (magic='%s', ver=%u, crc='%s', cov=%u)",
                                  m->protocol.magic, m->protocol.version, m->protocol.crc, m->protocol.coverage);
            return LATCH_ADMIT_VIOLATED;
        }
    }
    if (m->schema_version == LATCH_MANIFEST_GOVERNOR_SCHEMA_VERSION) {
        const uint32_t advisory_allowed = (1u << 7) | (1u << 12) | (1u << 15);
        if (!m->governor_present || m->governor.enabled > 1u ||
            m->governor.clamp_max_step == 0u ||
            m->governor.clamp_max_step > (uint32_t)m->envelope.v_max ||
            m->governor.slow_scale_pct == 0u || m->governor.slow_scale_pct > 100u ||
            m->governor.safe_stop_decel == 0u ||
            m->governor.safe_stop_decel > (uint32_t)m->envelope.a_max ||
            m->governor.demote_faults_per_rung == 0u ||
            m->governor.demote_faults_per_rung > 1000000u ||
            m->governor.promote_clean_frames == 0u ||
            m->governor.promote_clean_frames > 1000000u ||
            m->governor.min_confidence_q8 == 0u ||
            m->governor.min_confidence_q8 > 255u ||
            m->governor.lease_ticks < 2u || m->governor.lease_ticks > 100u ||
            m->governor.coherence_max_gap == 0u || m->governor.coherence_max_gap > 0x7FFFFFu ||
            m->governor.warmup_heartbeats == 0u ||
            (m->governor.advise_fault_mask & ~advisory_allowed) != 0u ||
            m->governor.units_enabled > 1u || m->governor.rate_enabled > 1u ||
            (m->governor.units_enabled != 0u &&
             (m->governor.canonical_unit_id == 0u || m->governor.unit_scale_count == 0u)) ||
            m->governor.unit_scale_count > 4u ||
            (m->governor.rate_enabled != 0u &&
             (m->governor.rate_burst_tokens == 0u || m->governor.rate_refill_per_tick == 0u ||
              m->governor.rate_refill_per_tick > m->governor.rate_burst_tokens ||
              m->governor.rate_sustain_per_tick == 0u ||
              m->governor.rate_sustain_per_tick > (uint32_t)m->envelope.v_max))) {
            if (err_buf) snprintf(err_buf, err_len,
                                  "Schema 3 governor values are invalid or outside the supported range");
            return LATCH_ADMIT_VIOLATED;
        }
        for (uint32_t i = 0u; i < m->governor.unit_scale_count; ++i) {
            if (m->governor.alternate_unit_ids[i] == 0u ||
                m->governor.conversion_numerators[i] == 0u ||
                m->governor.conversion_denominators[i] == 0u) {
                if (err_buf) snprintf(err_buf, err_len,
                                      "GOVERNOR unit IDs and rational conversion terms must be non-zero");
                return LATCH_ADMIT_VIOLATED;
            }
            if (m->governor.alternate_unit_ids[i] == m->governor.canonical_unit_id) {
                if (err_buf) snprintf(err_buf, err_len,
                                      "GOVERNOR alternate unit IDs cannot equal the canonical unit ID");
                return LATCH_ADMIT_VIOLATED;
            }
            for (uint32_t j = 0u; j < i; ++j) {
                if (m->governor.alternate_unit_ids[i] == m->governor.alternate_unit_ids[j]) {
                    if (err_buf) snprintf(err_buf, err_len, "GOVERNOR alternate unit IDs must be unique");
                    return LATCH_ADMIT_VIOLATED;
                }
            }
        }
        if ((m->governor.enabled == 0u && m->protocol.version != 1u) ||
            (m->governor.enabled != 0u && m->protocol.version != 2u)) {
            if (err_buf) snprintf(err_buf, err_len,
                                  "GOVERNOR enabled state and protocol version must agree");
            return LATCH_ADMIT_VIOLATED;
        }
        if (m->medical_present) {
            if (m->medical.drug_name[0] == '\0' ||
                m->medical.drug_id == 0u ||
                m->medical.concentration_uL_per_unit == 0u ||
                m->medical.max_bolus_uL == 0u ||
                m->medical.min_bolus_interval_ticks == 0u ||
                m->medical.cumulative_dose_window_ticks == 0u ||
                m->medical.max_cumulative_dose_uL == 0u ||
                m->medical.max_cumulative_dose_uL < m->medical.max_bolus_uL ||
                (m->governor.advise_fault_mask & (1u << 15)) != 0u) {
                if (err_buf) snprintf(err_buf, err_len,
                                      "Schema 3 medical parameters are invalid, outside supported safety bounds, or allow advisory DOSE");
                return LATCH_ADMIT_VIOLATED;
            }
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
        for (uint32_t j = i + 1; j < m->envelope.num_keepouts; ++j) {
            int32_t lo_i = m->envelope.keepout[i].lo_mrad;
            int32_t hi_i = m->envelope.keepout[i].hi_mrad;
            int32_t lo_j = m->envelope.keepout[j].lo_mrad;
            int32_t hi_j = m->envelope.keepout[j].hi_mrad;
            if (lo_i <= hi_j && lo_j <= hi_i) {
                if (err_buf) snprintf(err_buf, err_len,
                                      "Keep-out intervals overlap: [%d, %d] and [%d, %d]",
                                      lo_i, hi_i, lo_j, hi_j);
                return LATCH_ADMIT_VIOLATED;
            }
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
    if (m->tape.log_path[0] != '/') {
        if (err_buf) snprintf(err_buf, err_len,
                              "Fail closed: tape.log_path '%s' must be an absolute path",
                              m->tape.log_path);
        return LATCH_ADMIT_VIOLATED;
    }
    if (m->actuator.init_delay_us > 1000000u) {
        if (err_buf) snprintf(err_buf, err_len,
                              "Fail closed: actuator.init_delay_us %u exceeds 1000000 us",
                              m->actuator.init_delay_us);
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

