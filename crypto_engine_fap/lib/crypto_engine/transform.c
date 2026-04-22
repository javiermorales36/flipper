#include "crypto_engine.h"
#include <string.h>

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int8_t crypto_engine_base64_decode_value(char value) {
    if(value >= 'A' && value <= 'Z') return (int8_t)(value - 'A');
    if(value >= 'a' && value <= 'z') return (int8_t)(value - 'a' + 26);
    if(value >= '0' && value <= '9') return (int8_t)(value - '0' + 52);
    if(value == '+') return 62;
    if(value == '/') return 63;
    return -1;
}

size_t crypto_engine_hex_encode(
    const uint8_t* src,
    size_t src_len,
    char* dst,
    size_t dst_len) {
    const char hex_table[] = "0123456789abcdef";
    if (!src || !dst) {
        return 0;
    }
    if (dst_len < (src_len * 2 + 1)) {
        return 0;
    }
    for (size_t i = 0; i < src_len; i++) {
        dst[2 * i] = hex_table[(src[i] >> 4) & 0xF];
        dst[2 * i + 1] = hex_table[src[i] & 0xF];
    }
    dst[2 * src_len] = '\0';
    return 2 * src_len;
}

int crypto_engine_hex_decode(
    const char* src,
    uint8_t* dst,
    size_t* dst_len) {
    if (!src || !dst || !dst_len) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }
    size_t src_len = strlen(src);
    if ((src_len & 1) != 0) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }
    size_t out_size = src_len / 2;
    if (*dst_len < out_size) {
        return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    }
    for (size_t i = 0; i < out_size; i++) {
        char high = src[2 * i];
        char low = src[2 * i + 1];
        uint8_t hi = (high >= '0' && high <= '9') ? high - '0'
                    : (high >= 'a' && high <= 'f') ? 10 + high - 'a'
                    : (high >= 'A' && high <= 'F') ? 10 + high - 'A'
                    : 255;
        uint8_t lo = (low >= '0' && low <= '9') ? low - '0'
                    : (low >= 'a' && low <= 'f') ? 10 + low - 'a'
                    : (low >= 'A' && low <= 'F') ? 10 + low - 'A'
                    : 255;
        if (hi == 255 || lo == 255) {
            return CRYPTO_ENGINE_ERROR_BAD_INPUT;
        }
        dst[i] = (hi << 4) | lo;
    }
    *dst_len = out_size;
    return CRYPTO_ENGINE_SUCCESS;
}

size_t crypto_engine_base64_encode(
    const uint8_t* src,
    size_t src_len,
    char* dst,
    size_t dst_len) {
    if (!src || !dst) {
        return 0;
    }

    size_t needed = ((src_len + 2) / 3) * 4 + 1;
    if (dst_len < needed) {
        return 0;
    }

    size_t out_pos = 0;
    for (size_t i = 0; i + 2 < src_len; i += 3) {
        uint32_t value = ((uint32_t)src[i] << 16) | ((uint32_t)src[i + 1] << 8) | src[i + 2];
        dst[out_pos++] = base64_chars[(value >> 18) & 0x3F];
        dst[out_pos++] = base64_chars[(value >> 12) & 0x3F];
        dst[out_pos++] = base64_chars[(value >> 6) & 0x3F];
        dst[out_pos++] = base64_chars[value & 0x3F];
    }

    size_t remainder = src_len % 3;
    if (remainder != 0) {
        uint32_t value = 0;
        size_t offset = 0;
        for (size_t i = src_len - remainder; i < src_len; i++) {
            value = (value << 8) | src[i];
            offset++;
        }
        value <<= (3 - remainder) * 8;

        dst[out_pos++] = base64_chars[(value >> 18) & 0x3F];
        dst[out_pos++] = base64_chars[(value >> 12) & 0x3F];
        dst[out_pos++] = remainder == 1 ? '=' : base64_chars[(value >> 6) & 0x3F];
        dst[out_pos++] = '=';
    }

    dst[out_pos] = '\0';
    return out_pos;
}

int crypto_engine_base64_decode(
    const char* src,
    uint8_t* dst,
    size_t* dst_len) {
    if (!src || !dst || !dst_len) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    size_t src_len = strlen(src);
    if (src_len % 4 != 0) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    size_t expected = (src_len / 4) * 3;
    if (src_len >= 2 && src[src_len - 1] == '=') {
        expected--;
        if (src[src_len - 2] == '=') {
            expected--;
        }
    }
    if (*dst_len < expected) {
        return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    }

    size_t out_pos = 0;
    for (size_t i = 0; i < src_len; i += 4) {
        int8_t v0 = crypto_engine_base64_decode_value(src[i]);
        int8_t v1 = crypto_engine_base64_decode_value(src[i + 1]);
        int8_t v2 = src[i + 2] == '=' ? 0 : crypto_engine_base64_decode_value(src[i + 2]);
        int8_t v3 = src[i + 3] == '=' ? 0 : crypto_engine_base64_decode_value(src[i + 3]);

        if (v0 < 0 || v1 < 0 || (src[i + 2] != '=' && v2 < 0) || (src[i + 3] != '=' && v3 < 0)) {
            return CRYPTO_ENGINE_ERROR_BAD_INPUT;
        }

        uint32_t value = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) | ((uint32_t)v2 << 6) | (uint32_t)v3;
        if (src[i + 2] != '=') {
            dst[out_pos++] = (uint8_t)(value >> 16);
        }
        if (src[i + 3] != '=') {
            dst[out_pos++] = (uint8_t)((value >> 8) & 0xFF);
            dst[out_pos++] = (uint8_t)(value & 0xFF);
        } else if (src[i + 2] != '=') {
            dst[out_pos++] = (uint8_t)((value >> 8) & 0xFF);
        }
    }

    *dst_len = out_pos;
    return CRYPTO_ENGINE_SUCCESS;
}

size_t crypto_engine_to_uppercase(char* data, size_t len) {
    if (!data) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 'a' && data[i] <= 'z') {
            data[i] -= 'a' - 'A';
        }
    }
    return len;
}

size_t crypto_engine_to_lowercase(char* data, size_t len) {
    if (!data) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (data[i] >= 'A' && data[i] <= 'Z') {
            data[i] += 'a' - 'A';
        }
    }
    return len;
}
