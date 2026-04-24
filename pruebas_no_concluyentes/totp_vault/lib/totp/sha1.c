#include "sha1.h"
#include <string.h>

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[80];

    for(int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4    ] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] <<  8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for(int i = 16; i < 80; i++) {
        w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3]; e = state[4];

    for(int i = 0; i < 80; i++) {
        if(i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        } else if(i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if(i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = ROL32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROL32(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_init(Sha1Ctx* ctx) {
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void sha1_update(Sha1Ctx* ctx, const uint8_t* data, size_t len) {
    uint32_t j = (ctx->count[0] >> 3) & 63u;

    uint32_t bits_lo = (uint32_t)(len << 3);
    if((ctx->count[0] += bits_lo) < bits_lo) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);

    if(j + len < 64) {
        memcpy(&ctx->buf[j], data, len);
        return;
    }
    size_t i = 64 - j;
    memcpy(&ctx->buf[j], data, i);
    sha1_transform(ctx->state, ctx->buf);

    for(; i + 63 < len; i += 64) {
        sha1_transform(ctx->state, data + i);
    }
    memcpy(ctx->buf, data + i, len - i);
}

void sha1_final(Sha1Ctx* ctx, uint8_t digest[20]) {
    uint8_t finalcount[8];
    for(int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)(ctx->count[(i < 4) ? 1 : 0] >> ((3 - (i & 3)) * 8));
    }

    uint8_t c = 0x80;
    sha1_update(ctx, &c, 1);
    c = 0x00;
    while((ctx->count[0] & 504u) != 448u) {
        sha1_update(ctx, &c, 1);
    }
    sha1_update(ctx, finalcount, 8);

    for(int i = 0; i < 20; i++) {
        digest[i] = (uint8_t)(ctx->state[i >> 2] >> ((3 - (i & 3)) * 8));
    }
}

void hmac_sha1(
    const uint8_t* key,
    size_t         key_len,
    const uint8_t* msg,
    size_t         msg_len,
    uint8_t        mac[20]) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));

    if(key_len > 64) {
        Sha1Ctx ctx;
        sha1_init(&ctx);
        sha1_update(&ctx, key, key_len);
        sha1_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64], opad[64];
    for(int i = 0; i < 64; i++) {
        ipad[i] = k[i] ^ 0x36u;
        opad[i] = k[i] ^ 0x5Cu;
    }

    uint8_t inner[20];
    Sha1Ctx ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, 64);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, opad, 64);
    sha1_update(&ctx, inner, 20);
    sha1_final(&ctx, mac);
}
