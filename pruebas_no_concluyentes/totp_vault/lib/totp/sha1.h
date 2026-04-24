#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t  buf[64];
} Sha1Ctx;

void sha1_init(Sha1Ctx* ctx);
void sha1_update(Sha1Ctx* ctx, const uint8_t* data, size_t len);
void sha1_final(Sha1Ctx* ctx, uint8_t digest[20]);

// HMAC-SHA1 — used by HOTP/TOTP (RFC 2104)
void hmac_sha1(
    const uint8_t* key,
    size_t         key_len,
    const uint8_t* msg,
    size_t         msg_len,
    uint8_t        mac[20]);
