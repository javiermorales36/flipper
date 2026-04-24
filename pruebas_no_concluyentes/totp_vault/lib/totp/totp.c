#include "totp.h"
#include "sha1.h"

#include <string.h>
#include <stdio.h>

// HOTP (RFC 4226)
static uint32_t hotp(const uint8_t* key, size_t key_len, uint64_t counter) {
    // Encode counter as big-endian 8 bytes
    uint8_t msg[8];
    for(int i = 7; i >= 0; i--) {
        msg[i] = counter & 0xFFu;
        counter >>= 8;
    }

    uint8_t mac[20];
    hmac_sha1(key, key_len, msg, 8, mac);

    // Dynamic truncation (RFC 4226 §5.4)
    int offset  = mac[19] & 0x0Fu;
    uint32_t code =
        ((uint32_t)(mac[offset    ] & 0x7Fu) << 24) |
        ((uint32_t)(mac[offset + 1] & 0xFFu) << 16) |
        ((uint32_t)(mac[offset + 2] & 0xFFu) <<  8) |
        ((uint32_t)(mac[offset + 3] & 0xFFu));

    return code % 1000000u;
}

uint32_t totp_generate(
    const uint8_t* key,
    size_t         key_len,
    uint32_t       unix_time,
    uint8_t        period) {
    uint64_t counter = unix_time / (uint64_t)(period ? period : 30u);
    return hotp(key, key_len, counter);
}

void totp_format(uint32_t code, char out[7]) {
    snprintf(out, 7, "%06u", (unsigned)code);
}

// Base32 alphabet: A-Z = 0-25, 2-7 = 26-31
bool base32_decode(
    const char* encoded,
    uint8_t*    decoded,
    size_t      max_len,
    size_t*     out_len) {
    // Lookup table (256 entries): -1 = invalid, >= 0 = value
    static const int8_t TABLE[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, //  0-15
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 16-31
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 32-47 (space,'!'...)
        -1,-1,26,27,28,29,30,31,-1,-1,-1,-1,-1,-1,-1,-1, // 48-63 ('0'-'7')
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 64-79 ('@','A'-'O')
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 80-95 ('P'-'Z')
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 96-111 ('`','a'-'o')
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 112-127 ('p'-'z')
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 128-143
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 144-159
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 160-175
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 176-191
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 192-207
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 208-223
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 224-239
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 240-255
    };

    uint32_t buffer = 0;
    int      bits   = 0;
    size_t   pos    = 0;

    for(size_t i = 0; encoded[i] != '\0'; i++) {
        uint8_t ch = (uint8_t)encoded[i];
        if(ch == '=' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
        int8_t val = TABLE[ch];
        if(val < 0) return false;

        buffer = (buffer << 5) | (uint8_t)val;
        bits  += 5;

        if(bits >= 8) {
            bits -= 8;
            if(pos >= max_len) return false;
            decoded[pos++] = (uint8_t)((buffer >> bits) & 0xFFu);
        }
    }

    *out_len = pos;
    return true;
}
