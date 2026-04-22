#include <furi.h>
#include <dialogs/dialogs.h>

#include <crypto_engine.h>

#include <stdio.h>
#include <string.h>

static bool crypto_engine_run_self_test(char* body, size_t body_size) {
    static const uint8_t password[] = "flipper";
    static const uint8_t salt[] = "crypto-engine";
    static const uint8_t key[32] = {
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
        0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };
    static const uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
    };
    static const uint8_t sample[] = "crypto-engine-fap";

    uint8_t pbkdf2_out[32] = {0};
    uint8_t chacha_out[sizeof(sample)] = {0};
    uint8_t lz4_buf[128] = {0};
    uint8_t lz4_plain[sizeof(sample)] = {0};
    char base64_buf[64] = {0};
    char hex_buf[65] = {0};
    size_t lz4_size = sizeof(lz4_buf);
    size_t plain_size = sizeof(lz4_plain);

    bool ok =
        crypto_engine_pbkdf2_hmac_sha256(
            password,
            sizeof(password) - 1,
            salt,
            sizeof(salt) - 1,
            1024,
            pbkdf2_out,
            sizeof(pbkdf2_out)) == CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_chacha20_encrypt(key, nonce, sample, sizeof(sample) - 1, chacha_out) ==
            CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_lz4_compress(sample, sizeof(sample) - 1, lz4_buf, &lz4_size) ==
            CRYPTO_ENGINE_SUCCESS &&
        crypto_engine_lz4_decompress(lz4_buf, lz4_size, lz4_plain, &plain_size) ==
            CRYPTO_ENGINE_SUCCESS &&
        plain_size == (sizeof(sample) - 1) && memcmp(lz4_plain, sample, sizeof(sample) - 1) == 0 &&
        crypto_engine_base64_encode(sample, sizeof(sample) - 1, base64_buf, sizeof(base64_buf)) > 0 &&
        crypto_engine_hex_encode(pbkdf2_out, 8, hex_buf, sizeof(hex_buf)) > 0;

    snprintf(
        body,
        body_size,
        "FAP autocontenido en SD\nChaCha20: %s\nPBKDF2: %s\nLZ4: %s\nBase64: %s\nPBKDF2[0:8]: %s",
        ok ? "OK" : "FAIL",
        ok ? "OK" : "FAIL",
        ok ? "OK" : "FAIL",
        ok ? base64_buf : "-",
        ok ? hex_buf : "-");

    return ok;
}

int32_t crypto_engine_fap_app(void* p) {
    UNUSED(p);

    char body[256];
    crypto_engine_run_self_test(body, sizeof(body));

    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogMessage* message_dialog = dialog_message_alloc();

    dialog_message_set_header(message_dialog, "Crypto Engine", 64, 4, AlignCenter, AlignTop);
    dialog_message_set_text(message_dialog, body, 4, 16, AlignLeft, AlignTop);
    dialog_message_set_buttons(message_dialog, NULL, NULL, "Exit");
    dialog_message_show(dialogs, message_dialog);

    dialog_message_free(message_dialog);
    furi_record_close(RECORD_DIALOGS);

    return 0;
}