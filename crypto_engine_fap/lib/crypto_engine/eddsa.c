#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

void crypto_engine_eddsa_keygen(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32]) {
    // seed[32] → sk[64] (clave privada expandida con nonce interno) + pk[32]
    crypto_eddsa_key_pair(sk, pk, seed);
}

void crypto_engine_eddsa_sign(
    uint8_t sig[64],
    const uint8_t sk[64],
    const uint8_t* msg,
    size_t msg_len) {
    crypto_eddsa_sign(sig, sk, msg, msg_len);
}

int crypto_engine_eddsa_verify(
    const uint8_t sig[64],
    const uint8_t pk[32],
    const uint8_t* msg,
    size_t msg_len) {
    // crypto_eddsa_check devuelve 0 = válido, -1 = inválido (tiempo constante)
    if(crypto_eddsa_check(sig, pk, msg, msg_len) != 0) {
        return CRYPTO_ENGINE_ERROR;
    }
    return CRYPTO_ENGINE_SUCCESS;
}
