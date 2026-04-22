#include <crypto_engine.h>
#include "../bcon/sha256.h"

#include <string.h>

#define PBKDF2_SHA256_BLOCK_SIZE 64u

static void pbkdf2_sha256_digest(const uint8_t* input, size_t input_len, uint8_t output[32]) {
    SHA256_CTX context;
    sha256_init(&context);
    sha256_update(&context, input, input_len);
    sha256_final(&context, output);
}

static void pbkdf2_hmac_sha256(
    const uint8_t* key,
    size_t key_len,
    const uint8_t* message,
    size_t message_len,
    uint8_t output[32]) {
    uint8_t key_block[PBKDF2_SHA256_BLOCK_SIZE] = {0};
    uint8_t inner_hash[32];
    uint8_t pad[PBKDF2_SHA256_BLOCK_SIZE];
    SHA256_CTX context;

    if(key_len > PBKDF2_SHA256_BLOCK_SIZE) {
        pbkdf2_sha256_digest(key, key_len, key_block);
    } else {
        memcpy(key_block, key, key_len);
    }

    for(size_t index = 0; index < PBKDF2_SHA256_BLOCK_SIZE; index++) {
        pad[index] = key_block[index] ^ 0x36u;
    }

    sha256_init(&context);
    sha256_update(&context, pad, sizeof(pad));
    sha256_update(&context, message, message_len);
    sha256_final(&context, inner_hash);

    for(size_t index = 0; index < PBKDF2_SHA256_BLOCK_SIZE; index++) {
        pad[index] = key_block[index] ^ 0x5cu;
    }

    sha256_init(&context);
    sha256_update(&context, pad, sizeof(pad));
    sha256_update(&context, inner_hash, sizeof(inner_hash));
    sha256_final(&context, output);
}

int crypto_engine_pbkdf2_hmac_sha256(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t iterations,
    uint8_t* output,
    size_t output_len) {
    if(!password || !salt || !output || output_len == 0 || iterations == 0) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    uint8_t counter_block[256];
    uint8_t u[32];
    uint8_t t[32];
    uint32_t block_index = 1;
    size_t produced = 0;

    if(salt_len > (sizeof(counter_block) - 4u)) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    while(produced < output_len) {
        memcpy(counter_block, salt, salt_len);
        counter_block[salt_len + 0u] = (uint8_t)((block_index >> 24) & 0xFFu);
        counter_block[salt_len + 1u] = (uint8_t)((block_index >> 16) & 0xFFu);
        counter_block[salt_len + 2u] = (uint8_t)((block_index >> 8) & 0xFFu);
        counter_block[salt_len + 3u] = (uint8_t)(block_index & 0xFFu);

        pbkdf2_hmac_sha256(password, password_len, counter_block, salt_len + 4u, u);
        memcpy(t, u, sizeof(t));

        for(uint32_t iteration = 1; iteration < iterations; iteration++) {
            pbkdf2_hmac_sha256(password, password_len, u, sizeof(u), u);
            for(size_t index = 0; index < sizeof(t); index++) {
                t[index] ^= u[index];
            }
        }

        size_t chunk_size = output_len - produced;
        if(chunk_size > sizeof(t)) {
            chunk_size = sizeof(t);
        }

        memcpy(output + produced, t, chunk_size);
        produced += chunk_size;
        block_index++;
    }

    memset(counter_block, 0, sizeof(counter_block));
    memset(u, 0, sizeof(u));
    memset(t, 0, sizeof(t));
    return CRYPTO_ENGINE_SUCCESS;
}