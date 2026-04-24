#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Generate a 6-digit TOTP code (RFC 6238 with SHA-1)
uint32_t totp_generate(
    const uint8_t* key,
    size_t         key_len,
    uint32_t       unix_time,
    uint8_t        period); // typically 30

// Format as zero-padded 6-digit string into out[7] (includes NUL)
void totp_format(uint32_t code, char out[7]);

// Base32 decode (RFC 4648, case-insensitive, '=' and spaces ignored)
// Returns true on success. *out_len set to number of decoded bytes.
bool base32_decode(
    const char* encoded,
    uint8_t*    decoded,
    size_t      max_len,
    size_t*     out_len);
