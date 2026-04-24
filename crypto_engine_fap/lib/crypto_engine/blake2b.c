#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

void crypto_engine_blake2b(
    uint8_t* hash,
    size_t hash_len,
    const uint8_t* msg,
    size_t msg_len) {
    // hash_len de 1 a 64 bytes; 32 es el más común (256 bits)
    crypto_blake2b(hash, hash_len, msg, msg_len);
}
