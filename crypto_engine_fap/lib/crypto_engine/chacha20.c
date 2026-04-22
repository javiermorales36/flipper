#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

int crypto_engine_chacha20_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output) {
    if(!key || !nonce || !input || !output) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    crypto_chacha20_ietf(output, input, input_len, key, nonce, 0);
    return CRYPTO_ENGINE_SUCCESS;
}

int crypto_engine_chacha20_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* input,
    size_t input_len,
    uint8_t* output) {
    return crypto_engine_chacha20_encrypt(key, nonce, input, input_len, output);
}