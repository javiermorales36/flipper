#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

#include <string.h>

void crypto_engine_x25519_keygen(uint8_t pk[32], const uint8_t sk[32]) {
    crypto_x25519_public_key(pk, sk);
}

int crypto_engine_x25519_dh(
    const uint8_t sk[32],
    const uint8_t peer_pk[32],
    uint8_t shared_secret[32]) {
    if(!sk || !peer_pk || !shared_secret) return CRYPTO_ENGINE_ERROR_BAD_INPUT;

    // Derivar raw shared secret
    uint8_t raw[32];
    crypto_x25519(raw, sk, peer_pk);

    // Hashear con BLAKE2b: convierte el punto de curva en material de clave uniforme
    crypto_blake2b(shared_secret, 32, raw, 32);

    // Limpiar datos sensibles
    crypto_wipe(raw, sizeof(raw));
    return CRYPTO_ENGINE_SUCCESS;
}
