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

// ─── Fase 1: primitivos modernos vía monocypher ───────────────────────────

// X25519 — clave pública desde clave privada (32 bytes cada una)
void crypto_engine_x25519_keygen(uint8_t pk[32], const uint8_t sk[32]);

// X25519 ECDH — shared secret hasheado con BLAKE2b (listo para usar como KEK)
int crypto_engine_x25519_dh(
    const uint8_t sk[32],
    const uint8_t peer_pk[32],
    uint8_t shared_secret[32]);

// EdDSA (Curve25519 + BLAKE2b) — generación de par de claves desde semilla
// seed[32] → sk[64] (clave privada expandida) + pk[32] (clave pública)
void crypto_engine_eddsa_keygen(uint8_t sk[64], uint8_t pk[32], uint8_t seed[32]);

// EdDSA — firma (sig[64]) y verificación (0=OK, negativo=fallo)
void crypto_engine_eddsa_sign(
    uint8_t sig[64],
    const uint8_t sk[64],
    const uint8_t* msg,
    size_t msg_len);
int crypto_engine_eddsa_verify(
    const uint8_t sig[64],
    const uint8_t pk[32],
    const uint8_t* msg,
    size_t msg_len);

// AEAD — XChaCha20-Poly1305 (nonce 24B, MAC 16B, cifrado autenticado real)
// Cifrado y MAC son separados; el caller une [mac|cipher] o [cipher|mac] según protocolo.
void crypto_engine_aead_encrypt(
    uint8_t* cipher,
    uint8_t mac[16],
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t* ad,
    size_t ad_len,
    const uint8_t* plain,
    size_t plain_len);
// Retorna CRYPTO_ENGINE_SUCCESS o CRYPTO_ENGINE_ERROR si MAC no coincide (tiempo constante)
int crypto_engine_aead_decrypt(
    uint8_t* plain,
    const uint8_t mac[16],
    const uint8_t key[32],
    const uint8_t nonce[24],
    const uint8_t* ad,
    size_t ad_len,
    const uint8_t* cipher,
    size_t cipher_len);

// Argon2i — KDF resistente a GPU y fuerza bruta
// nb_blocks >= 8 (recomendado 64 en Flipper, 8 para tests rápidos)
// nb_passes >= 1 (recomendado 3 para Argon2i)
// Aloja work_area = nb_blocks * 1024 bytes en heap internamente
int crypto_engine_argon2i(
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t nb_blocks,
    uint32_t nb_passes,
    uint8_t* key,
    size_t key_len);

// BLAKE2b — hash de propósito general (hash_len de 1 a 64 bytes)
void crypto_engine_blake2b(
    uint8_t* hash,
    size_t hash_len,
    const uint8_t* msg,
    size_t msg_len);

#ifdef __cplusplus
}
#endif
