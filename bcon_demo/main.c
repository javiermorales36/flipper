#include <furi.h>
#include <dialogs/dialogs.h>

#include <sha256.h>

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void bytes_to_hex(const uint8_t* input, size_t input_size, char* output, size_t output_size) {
    static const char alphabet[] = "0123456789abcdef";
    const size_t required = (input_size * 2) + 1;

    if(output_size < required) return;

    for(size_t index = 0; index < input_size; index++) {
        output[index * 2] = alphabet[input[index] >> 4];
        output[(index * 2) + 1] = alphabet[input[index] & 0x0F];
    }

    output[input_size * 2] = '\0';
}

int32_t bcon_demo_app(void* p) {
    UNUSED(p);

    static const uint8_t message[] = "B-Con SHA256 demo on Flipper";

    SHA256_CTX chunked_ctx;
    SHA256_CTX single_ctx;
    uint8_t chunked_digest[SHA256_BLOCK_SIZE];
    uint8_t single_digest[SHA256_BLOCK_SIZE];
    char digest_hex[(16 * 2) + 1];
    char body[256];

    sha256_init(&chunked_ctx);
    sha256_update(&chunked_ctx, message, 10);
    sha256_update(&chunked_ctx, message + 10, (sizeof(message) - 1) - 10);
    sha256_final(&chunked_ctx, chunked_digest);

    sha256_init(&single_ctx);
    sha256_update(&single_ctx, message, sizeof(message) - 1);
    sha256_final(&single_ctx, single_digest);

    const bool match = memcmp(chunked_digest, single_digest, sizeof(chunked_digest)) == 0;
    bytes_to_hex(chunked_digest, 16, digest_hex, sizeof(digest_hex));

    snprintf(
        body,
        sizeof(body),
        "Algo: SHA-256\nChunked update: OK\nSingle vs chunked: %s\nDigest[0:16]: %s",
        match ? "MATCH" : "FAIL",
        digest_hex);

    DialogsApp* dialogs = furi_record_open(RECORD_DIALOGS);
    DialogMessage* message_dialog = dialog_message_alloc();

    dialog_message_set_header(message_dialog, "B-Con", 64, 4, AlignCenter, AlignTop);
    dialog_message_set_text(message_dialog, body, 4, 14, AlignLeft, AlignTop);
    dialog_message_set_buttons(message_dialog, NULL, NULL, "Exit");
    dialog_message_show(dialogs, message_dialog);

    dialog_message_free(message_dialog);
    furi_record_close(RECORD_DIALOGS);

    memset(chunked_digest, 0, sizeof(chunked_digest));
    memset(single_digest, 0, sizeof(single_digest));
    return 0;
}