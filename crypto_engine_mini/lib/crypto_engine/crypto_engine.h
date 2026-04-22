#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CRYPTO_ENGINE_SUCCESS 0
#define CRYPTO_ENGINE_ERROR -1
#define CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER -2
#define CRYPTO_ENGINE_ERROR_BAD_INPUT -3

// ChaCha20 streaming encryption / decryption
int crypto_engine_chacha20_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output);

int crypto_engine_chacha20_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output);

// PBKDF2-HMAC-SHA256
int crypto_engine_pbkdf2_hmac_sha256(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* output,
    size_t output_len);

// LZ4 block helpers
size_t crypto_engine_lz4_max_compressed_size(size_t input_size);
int crypto_engine_lz4_compress(
    const uint8_t* src,
    size_t src_len,
    uint8_t* dst,
    size_t* dst_len);
int crypto_engine_lz4_decompress(
    const uint8_t* src,
    size_t src_len,
    uint8_t* dst,
    size_t* dst_len);

// Text / binary transformations
size_t crypto_engine_hex_encode(
    const uint8_t* src,
    size_t src_len,
    char* dst,
    size_t dst_len);
int crypto_engine_hex_decode(
    const char* src,
    uint8_t* dst,
    size_t* dst_len);

size_t crypto_engine_base64_encode(
    const uint8_t* src,
    size_t src_len,
    char* dst,
    size_t dst_len);
int crypto_engine_base64_decode(
    const char* src,
    uint8_t* dst,
    size_t* dst_len);

size_t crypto_engine_to_uppercase(char* data, size_t len);
size_t crypto_engine_to_lowercase(char* data, size_t len);

#ifdef __cplusplus
}
#endif
