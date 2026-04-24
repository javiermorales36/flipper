#include <furi.h>
#include <dialogs/dialogs.h>

#include <crypto_engine.h>

#include <stdio.h>
#include <string.h>

// ─── Tests primitivos clásicos ────────────────────────────────────────────
static bool test_classic(void) {
    static const uint8_t password[] = "flipper";
    static const uint8_t salt[]     = "crypto-engine";
    static const uint8_t key[32] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    static const uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    };
    static const uint8_t sample[] = "crypto-engine-fap";

    uint8_t pbkdf2_out[32] = {0};
    uint8_t chacha_out[sizeof(sample)] = {0};
    uint8_t lz4_buf[128]   = {0};
    uint8_t lz4_plain[sizeof(sample)] = {0};
    char    b64_buf[64]    = {0};
    size_t  lz4_sz  = sizeof(lz4_buf);
    size_t  plain_sz = sizeof(lz4_plain);

    return
        crypto_engine_pbkdf2_hmac_sha256(
            password, sizeof(password) - 1,
            salt,     sizeof(salt) - 1,
            1024, pbkdf2_out, sizeof(pbkdf2_out)) == CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_chacha20_encrypt(
            key, nonce, sample, sizeof(sample) - 1, chacha_out) == CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_lz4_compress(sample, sizeof(sample) - 1, lz4_buf, &lz4_sz)
            == CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_lz4_decompress(lz4_buf, lz4_sz, lz4_plain, &plain_sz)
            == CRYPTO_ENGINE_SUCCESS &&
        plain_sz == (sizeof(sample) - 1) &&
        memcmp(lz4_plain, sample, plain_sz) == 0 &&
        crypto_engine_base64_encode(sample, sizeof(sample) - 1, b64_buf, sizeof(b64_buf)) > 0;
}

// ─── Tests X25519 ECDH ────────────────────────────────────────────────────
static bool test_x25519(void) {
    // Claves estáticas de test (RFC 7748 §6.1)
    static const uint8_t alice_sk[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x1f, 0xb2, 0xc4, 0x71, 0x56, 0x97, 0x8a,
        0xe7, 0x7f, 0xf5, 0x0f, 0x38, 0x3d, 0x22, 0xe8,
    };
    static const uint8_t bob_sk[32] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    };

    uint8_t alice_pk[32], bob_pk[32];
    uint8_t ss_alice[32], ss_bob[32];

    crypto_engine_x25519_keygen(alice_pk, alice_sk);
    crypto_engine_x25519_keygen(bob_pk,   bob_sk);

    if(crypto_engine_x25519_dh(alice_sk, bob_pk,   ss_alice) != CRYPTO_ENGINE_SUCCESS) return false;
    if(crypto_engine_x25519_dh(bob_sk,   alice_pk, ss_bob)   != CRYPTO_ENGINE_SUCCESS) return false;

    // Ambos lados deben llegar al mismo shared secret
    return memcmp(ss_alice, ss_bob, 32) == 0;
}

// ─── Tests EdDSA ─────────────────────────────────────────────────────────
static bool test_eddsa(void) {
    static const uint8_t seed[32] = {
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4d, 0x0b, 0x59, 0x47,
    };
    static const uint8_t msg[] = "Javier Morales - Flipper Zero 2026";

    uint8_t sk[64], pk[32], sig[64];
    uint8_t seed_copy[32];
    memcpy(seed_copy, seed, 32); // crypto_eddsa_key_pair consume/limpia la semilla

    crypto_engine_eddsa_keygen(sk, pk, seed_copy);
    crypto_engine_eddsa_sign(sig, sk, msg, sizeof(msg) - 1);

    // Verificación válida
    if(crypto_engine_eddsa_verify(sig, pk, msg, sizeof(msg) - 1) != CRYPTO_ENGINE_SUCCESS)
        return false;

    // Verificación con mensaje alterado debe fallar
    uint8_t bad_msg[] = "Javier Morales - Flipper Zero 2027";
    if(crypto_engine_eddsa_verify(sig, pk, bad_msg, sizeof(bad_msg) - 1) == CRYPTO_ENGINE_SUCCESS)
        return false;

    return true;
}

// ─── Tests AEAD (XChaCha20-Poly1305) ─────────────────────────────────────
static bool test_aead(void) {
    static const uint8_t key[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    };
    static const uint8_t nonce[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    static const uint8_t plain[]  = "Flipper cripto portatil de pro";
    static const uint8_t ad[]     = "crypto_engine_fap_v2";

    uint8_t cipher[sizeof(plain)];
    uint8_t decrypted[sizeof(plain)];
    uint8_t mac[16];

    crypto_engine_aead_encrypt(
        cipher, mac, key, nonce, ad, sizeof(ad) - 1, plain, sizeof(plain) - 1);

    // Descifrado correcto
    if(crypto_engine_aead_decrypt(
           decrypted, mac, key, nonce,
           ad, sizeof(ad) - 1, cipher, sizeof(plain) - 1) != CRYPTO_ENGINE_SUCCESS)
        return false;

    if(memcmp(decrypted, plain, sizeof(plain) - 1) != 0) return false;

    // MAC adulterado debe rechazarse
    uint8_t bad_mac[16];
    memcpy(bad_mac, mac, 16);
    bad_mac[0] ^= 0xFF;
    if(crypto_engine_aead_decrypt(
           decrypted, bad_mac, key, nonce,
           ad, sizeof(ad) - 1, cipher, sizeof(plain) - 1) == CRYPTO_ENGINE_SUCCESS)
        return false;

    return true;
}

// ─── Tests Argon2i ───────────────────────────────────────────────────────
static bool test_argon2i(void) {
    static const uint8_t pass[] = "mi_pin_secreto";
    static const uint8_t salt[] = "flipper-salt-16b";
    uint8_t key[32] = {0};

    // nb_blocks=8 (mínimo, 8KB heap) para no tardar en el self-test
    return crypto_engine_argon2i(
               pass, sizeof(pass) - 1,
               salt, sizeof(salt) - 1,
               8, 1, key, sizeof(key)) == CRYPTO_ENGINE_SUCCESS &&
           key[0] != 0; // Verificar que la salida no es cero
}

// ─── Tests BLAKE2b ───────────────────────────────────────────────────────
static bool test_blake2b(void) {
    static const uint8_t msg[] = "flipper";
    uint8_t h1[32] = {0};
    uint8_t h2[32] = {0};

    crypto_engine_blake2b(h1, 32, msg, sizeof(msg) - 1);
    crypto_engine_blake2b(h2, 32, msg, sizeof(msg) - 1);

    // Determinismo: mismo mensaje → mismo hash
    return memcmp(h1, h2, 32) == 0 && h1[0] != 0;
}

// ─── Entry point ─────────────────────────────────────────────────────────
int32_t crypto_engine_fap_app(void* p) {
    UNUSED(p);

    bool classic  = test_classic();
    bool x25519   = test_x25519();
    bool eddsa    = test_eddsa();
    bool aead     = test_aead();
    bool argon2i  = test_argon2i();
    bool blake2b  = test_blake2b();

    char body[512];
    snprintf(
        body, sizeof(body),
        "=== Crypto Engine v2 ===\n"
        "ChaCha20/PBKDF2/LZ4: %s\n"
        "X25519 ECDH:         %s\n"
        "EdDSA sign/verify:   %s\n"
        "AEAD XChaCha20:      %s\n"
        "Argon2i KDF:         %s\n"
        "BLAKE2b hash:        %s\n"
        "\n%s",
        classic ? "OK" : "FAIL",
        x25519  ? "OK" : "FAIL",
        eddsa   ? "OK" : "FAIL",
        aead    ? "OK" : "FAIL",
        argon2i ? "OK" : "FAIL",
        blake2b ? "OK" : "FAIL",
        (classic && x25519 && eddsa && aead && argon2i && blake2b)
            ? "Todo OK. Flipper listo." : "ALGUN TEST HA FALLADO");

    DialogsApp*    dialogs = furi_record_open(RECORD_DIALOGS);
    DialogMessage* dlg     = dialog_message_alloc();

    dialog_message_set_header(dlg, "Crypto Engine v2", 64, 4, AlignCenter, AlignTop);
    dialog_message_set_text(dlg, body, 4, 16, AlignLeft, AlignTop);
    dialog_message_set_buttons(dlg, NULL, NULL, "Exit");
    dialog_message_show(dialogs, dlg);

    dialog_message_free(dlg);
    furi_record_close(RECORD_DIALOGS);

    return 0;
}
