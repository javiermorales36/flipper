#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

void crypto_engine_aead_encrypt(
    uint8_t* cipher,
    uint8_t mac[16],
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t* ad,
    size_t ad_len,
    const uint8_t* plain,
    size_t plain_len) {
    // XChaCha20-Poly1305: autenticación + cifrado en una pasada
    crypto_aead_lock(cipher, mac, key, nonce, ad, ad_len, plain, plain_len);
}

int crypto_engine_aead_decrypt(
    uint8_t* plain,
    const uint8_t mac[16],
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t* ad,
    size_t ad_len,
    const uint8_t* cipher,
    size_t cipher_len) {
    // Verifica MAC antes de descifrar (tiempo constante) — 0=OK, -1=fallo de autenticación
    if(crypto_aead_unlock(plain, mac, key, nonce, ad, ad_len, cipher, cipher_len) != 0) {
        return CRYPTO_ENGINE_ERROR;
    }
    return CRYPTO_ENGINE_SUCCESS;
}
