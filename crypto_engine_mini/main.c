#include <furi.h>
#include <furi_hal_random.h>
#include <storage/storage.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/modules/file_browser.h>

#include <crypto_engine.h>
#include "lib/bcon/sha256.h"

#include <stdio.h>
#include <string.h>

#define CRYPTO_MINI_PASSWORD_SIZE 64u
#define CRYPTO_MINI_TEXT_SIZE 768u
#define CRYPTO_MINI_OUTPUT_SIZE 4096u
#define CRYPTO_MINI_FILE_TEXT_SIZE 1536u
#define CRYPTO_MINI_BINARY_BUFFER_SIZE (CRYPTO_MINI_FILE_TEXT_SIZE + 16u)
#define CRYPTO_MINI_SALT_SIZE 16u
#define CRYPTO_MINI_NONCE_SIZE 12u
#define CRYPTO_MINI_KEY_SIZE 32u
#define CRYPTO_MINI_MAC_SIZE SHA256_BLOCK_SIZE
#define CRYPTO_MINI_DERIVED_KEY_SIZE (CRYPTO_MINI_KEY_SIZE * 2u)
#define CRYPTO_MINI_PBKDF2_ITERATIONS 2048u
#define CRYPTO_MINI_MAGIC "CEM1:"
#define CRYPTO_MINI_FORMAT_PREFIX_AUTH "CE2"
#define CRYPTO_MINI_FORMAT_PREFIX_LEGACY "CE1"
#define CRYPTO_MINI_TEXT_RESULT_SUFFIX_SIZE 16u

typedef enum {
    CryptoMiniViewMenu,
    CryptoMiniViewTextInput,
    CryptoMiniViewTextBox,
    CryptoMiniViewBrowser,
} CryptoMiniView;

typedef enum {
    CryptoMiniMenuRoot,
    CryptoMiniMenuText,
    CryptoMiniMenuFile,
} CryptoMiniMenuMode;

typedef enum {
    CryptoMiniActionEncryptText,
    CryptoMiniActionDecryptText,
    CryptoMiniActionEncryptFile,
    CryptoMiniActionDecryptFile,
    CryptoMiniActionSaveLastText,
    CryptoMiniActionAbout,
} CryptoMiniAction;

typedef enum {
    CryptoMiniMenuItemOpenText = 100u,
    CryptoMiniMenuItemOpenFile,
    CryptoMiniMenuItemBack,
} CryptoMiniMenuItem;

typedef enum {
    CryptoMiniInputPassword,
    CryptoMiniInputPayload,
} CryptoMiniInputStage;

typedef struct {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextInput* text_input;
    TextBox* text_box;
    FileBrowser* file_browser;
    FuriString* browser_result;
    FuriString* browser_start_path;
    CryptoMiniView current_view;
    CryptoMiniMenuMode menu_mode;
    CryptoMiniAction pending_action;
    CryptoMiniInputStage input_stage;
    char password[CRYPTO_MINI_PASSWORD_SIZE + 1u];
    char payload[CRYPTO_MINI_TEXT_SIZE + 1u];
    char output[CRYPTO_MINI_OUTPUT_SIZE];
    char file_path[256];
    char menu_header[96];
    bool last_result_available;
    char last_result[CRYPTO_MINI_OUTPUT_SIZE];
    char last_result_suffix[CRYPTO_MINI_TEXT_RESULT_SUFFIX_SIZE];
    uint8_t buffer_a[CRYPTO_MINI_BINARY_BUFFER_SIZE];
    uint8_t buffer_b[CRYPTO_MINI_BINARY_BUFFER_SIZE];
} CryptoMiniApp;

static void crypto_mini_menu_callback(void* context, uint32_t index);
static void crypto_mini_text_input_callback(void* context);
static void crypto_mini_file_browser_callback(void* context);
static bool crypto_mini_navigation_callback(void* context);

static void crypto_mini_zeroize(void* buffer, size_t size) {
    volatile uint8_t* bytes = buffer;
    while(size--) {
        *bytes++ = 0;
    }
}

static bool crypto_mini_constant_time_equal(const uint8_t* left, const uint8_t* right, size_t length) {
    uint8_t diff = 0;

    for(size_t index = 0; index < length; index++) {
        diff |= left[index] ^ right[index];
    }

    return diff == 0;
}

static void crypto_mini_clear_last_result(CryptoMiniApp* app) {
    app->last_result_available = false;
    app->last_result[0] = '\0';
    app->last_result_suffix[0] = '\0';
}

static void crypto_mini_store_last_result(CryptoMiniApp* app, const char* text, const char* suffix) {
    snprintf(app->last_result, sizeof(app->last_result), "%s", text);
    snprintf(app->last_result_suffix, sizeof(app->last_result_suffix), "%s", suffix);
    app->last_result_available = true;
}

static bool crypto_mini_is_file_action(CryptoMiniAction action) {
    return action == CryptoMiniActionEncryptFile || action == CryptoMiniActionDecryptFile;
}

static void crypto_mini_show_text(CryptoMiniApp* app, const char* text) {
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    app->current_view = CryptoMiniViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewTextBox);
}

static void crypto_mini_trim_newlines(char* text) {
    if(!text) return;
    size_t length = strlen(text);
    while(length > 0u && (text[length - 1u] == '\n' || text[length - 1u] == '\r')) {
        text[length - 1u] = '\0';
        length--;
    }
}

static bool crypto_mini_write_text_file(const char* path, const char* text) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    const size_t text_length = strlen(text);
    bool ok = false;

    if(storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = storage_file_write(file, text, text_length) == text_length;
        if(ok) {
            ok = storage_file_sync(file);
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool crypto_mini_read_text_file(char* output, size_t output_size, const char* path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool ok = false;

    if(storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        const uint64_t file_size = storage_file_size(file);
        if(file_size > 0u && file_size < output_size) {
            const size_t read_size = storage_file_read(file, output, output_size - 1u);
            output[read_size] = '\0';
            ok = read_size > 0u;
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool crypto_mini_build_output_path(
    const char* input_path,
    const char* suffix,
    char* output,
    size_t output_size) {
    const char* slash = strrchr(input_path, '/');
    const char* dot = strrchr(input_path, '.');
    size_t prefix_length = strlen(input_path);

    if(dot && (!slash || dot > slash) && strcmp(dot, ".txt") == 0) {
        prefix_length = (size_t)(dot - input_path);
    }

    const int length = snprintf(output, output_size, "%.*s%s", (int)prefix_length, input_path, suffix);
    return length > 0 && (size_t)length < output_size;
}

static bool crypto_mini_build_saved_text_path(
    const CryptoMiniApp* app,
    char* output,
    size_t output_size) {
    const unsigned long random_id = (unsigned long)furi_hal_random_get();
    const int length = snprintf(
        output,
        output_size,
        "/ext/crypto_mini_%08lx%s",
        random_id,
        app->last_result_suffix[0] ? app->last_result_suffix : ".txt");
    return length > 0 && (size_t)length < output_size;
}

static bool crypto_mini_derive_keys(
    const char* password,
    const uint8_t salt[CRYPTO_MINI_SALT_SIZE],
    uint8_t encryption_key[CRYPTO_MINI_KEY_SIZE],
    uint8_t mac_key[CRYPTO_MINI_KEY_SIZE]) {
    uint8_t derived_keys[CRYPTO_MINI_DERIVED_KEY_SIZE];
    bool ok = crypto_engine_pbkdf2_hmac_sha256(
               (const uint8_t*)password,
               strlen(password),
               salt,
               CRYPTO_MINI_SALT_SIZE,
               CRYPTO_MINI_PBKDF2_ITERATIONS,
               derived_keys,
               sizeof(derived_keys)) == CRYPTO_ENGINE_SUCCESS;

    if(ok) {
        memcpy(encryption_key, derived_keys, CRYPTO_MINI_KEY_SIZE);
        memcpy(mac_key, derived_keys + CRYPTO_MINI_KEY_SIZE, CRYPTO_MINI_KEY_SIZE);
    }

    crypto_mini_zeroize(derived_keys, sizeof(derived_keys));
    return ok;
}

static void crypto_mini_compute_auth_tag(
    const uint8_t mac_key[CRYPTO_MINI_KEY_SIZE],
    const uint8_t salt[CRYPTO_MINI_SALT_SIZE],
    const uint8_t nonce[CRYPTO_MINI_NONCE_SIZE],
    const uint8_t* ciphertext,
    size_t ciphertext_length,
    uint8_t tag[CRYPTO_MINI_MAC_SIZE]) {
    uint8_t key_block[64] = {0};
    uint8_t inner_pad[64];
    uint8_t outer_pad[64];
    uint8_t inner_hash[CRYPTO_MINI_MAC_SIZE];
    SHA256_CTX sha_ctx;

    memcpy(key_block, mac_key, CRYPTO_MINI_KEY_SIZE);
    for(size_t index = 0; index < sizeof(key_block); index++) {
        inner_pad[index] = key_block[index] ^ 0x36u;
        outer_pad[index] = key_block[index] ^ 0x5cu;
    }

    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, inner_pad, sizeof(inner_pad));
    sha256_update(
        &sha_ctx, (const BYTE*)CRYPTO_MINI_FORMAT_PREFIX_AUTH, sizeof(CRYPTO_MINI_FORMAT_PREFIX_AUTH) - 1u);
    sha256_update(&sha_ctx, salt, CRYPTO_MINI_SALT_SIZE);
    sha256_update(&sha_ctx, nonce, CRYPTO_MINI_NONCE_SIZE);
    sha256_update(&sha_ctx, ciphertext, ciphertext_length);
    sha256_final(&sha_ctx, inner_hash);

    sha256_init(&sha_ctx);
    sha256_update(&sha_ctx, outer_pad, sizeof(outer_pad));
    sha256_update(&sha_ctx, inner_hash, sizeof(inner_hash));
    sha256_final(&sha_ctx, tag);

    crypto_mini_zeroize(&sha_ctx, sizeof(sha_ctx));
    crypto_mini_zeroize(key_block, sizeof(key_block));
    crypto_mini_zeroize(inner_pad, sizeof(inner_pad));
    crypto_mini_zeroize(outer_pad, sizeof(outer_pad));
    crypto_mini_zeroize(inner_hash, sizeof(inner_hash));
}

static bool crypto_mini_encrypt_payload(
    CryptoMiniApp* app,
    const uint8_t* input,
    size_t input_length,
    char* output,
    size_t output_size) {
    uint8_t salt[CRYPTO_MINI_SALT_SIZE];
    uint8_t nonce[CRYPTO_MINI_NONCE_SIZE];
    uint8_t encryption_key[CRYPTO_MINI_KEY_SIZE];
    uint8_t mac_key[CRYPTO_MINI_KEY_SIZE];
    uint8_t tag[CRYPTO_MINI_MAC_SIZE];
    char salt_hex[(CRYPTO_MINI_SALT_SIZE * 2u) + 1u];
    char nonce_hex[(CRYPTO_MINI_NONCE_SIZE * 2u) + 1u];
    char tag_hex[(CRYPTO_MINI_MAC_SIZE * 2u) + 1u];
    const size_t magic_length = sizeof(CRYPTO_MINI_MAGIC) - 1u;
    const size_t total_length = magic_length + input_length;
    bool ok = false;

    if(total_length > sizeof(app->buffer_a)) {
        goto cleanup;
    }

    memcpy(app->buffer_a, CRYPTO_MINI_MAGIC, magic_length);
    memcpy(app->buffer_a + magic_length, input, input_length);

    furi_hal_random_fill_buf(salt, CRYPTO_MINI_SALT_SIZE);
    furi_hal_random_fill_buf(nonce, CRYPTO_MINI_NONCE_SIZE);

    if(!crypto_mini_derive_keys(app->password, salt, encryption_key, mac_key)) {
        goto cleanup;
    }

    if(crypto_engine_chacha20_encrypt(
           encryption_key, nonce, app->buffer_a, total_length, app->buffer_b) !=
       CRYPTO_ENGINE_SUCCESS) {
        goto cleanup;
    }

    crypto_mini_compute_auth_tag(mac_key, salt, nonce, app->buffer_b, total_length, tag);

    if(crypto_engine_hex_encode(salt, sizeof(salt), salt_hex, sizeof(salt_hex)) == 0 ||
       crypto_engine_hex_encode(nonce, sizeof(nonce), nonce_hex, sizeof(nonce_hex)) == 0 ||
       crypto_engine_hex_encode(tag, sizeof(tag), tag_hex, sizeof(tag_hex)) == 0) {
        goto cleanup;
    }

    const int prefix_length = snprintf(
        output,
        output_size,
        "%s:%s:%s:%s:",
        CRYPTO_MINI_FORMAT_PREFIX_AUTH,
        salt_hex,
        nonce_hex,
        tag_hex);
    if(prefix_length <= 0 || (size_t)prefix_length >= output_size) {
        goto cleanup;
    }

    const size_t written = crypto_engine_hex_encode(
        app->buffer_b,
        total_length,
        output + prefix_length,
        output_size - (size_t)prefix_length);
    if(written == 0) {
        goto cleanup;
    }

    ok = true;

cleanup:
    crypto_mini_zeroize(encryption_key, sizeof(encryption_key));
    crypto_mini_zeroize(mac_key, sizeof(mac_key));
    crypto_mini_zeroize(tag, sizeof(tag));
    crypto_mini_zeroize(salt, sizeof(salt));
    crypto_mini_zeroize(nonce, sizeof(nonce));
    return ok;
}

static bool crypto_mini_decrypt_payload(
    CryptoMiniApp* app,
    const char* encoded,
    char* output,
    size_t output_size,
    const char** error_text) {
    uint8_t salt[CRYPTO_MINI_SALT_SIZE];
    uint8_t nonce[CRYPTO_MINI_NONCE_SIZE];
    uint8_t encryption_key[CRYPTO_MINI_KEY_SIZE];
    uint8_t mac_key[CRYPTO_MINI_KEY_SIZE];
    uint8_t expected_tag[CRYPTO_MINI_MAC_SIZE];
    uint8_t provided_tag[CRYPTO_MINI_MAC_SIZE];
    char salt_hex[(CRYPTO_MINI_SALT_SIZE * 2u) + 1u];
    char nonce_hex[(CRYPTO_MINI_NONCE_SIZE * 2u) + 1u];
    char tag_hex[(CRYPTO_MINI_MAC_SIZE * 2u) + 1u];
    size_t cipher_length = sizeof(app->buffer_a);
    const size_t magic_length = sizeof(CRYPTO_MINI_MAGIC) - 1u;
    const char* salt_start;
    const char* nonce_start;
    const char* tag_start;
    const char* cipher_start;
    const char* nonce_separator;
    const char* cipher_separator;
    const char* tag_separator = NULL;
    const bool is_authenticated = strncmp(encoded, CRYPTO_MINI_FORMAT_PREFIX_AUTH ":", 4u) == 0;
    bool ok = false;

    if(error_text) {
        *error_text = "Formato no valido.";
    }

    if(!is_authenticated && strncmp(encoded, CRYPTO_MINI_FORMAT_PREFIX_LEGACY ":", 4u) != 0) {
        goto cleanup;
    }

    salt_start = encoded + 4u;
    nonce_separator = strchr(salt_start, ':');
    if(!nonce_separator || (size_t)(nonce_separator - salt_start) != (CRYPTO_MINI_SALT_SIZE * 2u)) {
        goto cleanup;
    }

    nonce_start = nonce_separator + 1;
    cipher_separator = strchr(nonce_start, ':');
    if(!cipher_separator || (size_t)(cipher_separator - nonce_start) != (CRYPTO_MINI_NONCE_SIZE * 2u)) {
        goto cleanup;
    }

    memcpy(salt_hex, salt_start, CRYPTO_MINI_SALT_SIZE * 2u);
    salt_hex[CRYPTO_MINI_SALT_SIZE * 2u] = '\0';
    memcpy(nonce_hex, nonce_start, CRYPTO_MINI_NONCE_SIZE * 2u);
    nonce_hex[CRYPTO_MINI_NONCE_SIZE * 2u] = '\0';

    if(is_authenticated) {
        tag_start = cipher_separator + 1;
        tag_separator = strchr(tag_start, ':');
        if(!tag_separator || (size_t)(tag_separator - tag_start) != (CRYPTO_MINI_MAC_SIZE * 2u)) {
            goto cleanup;
        }

        memcpy(tag_hex, tag_start, CRYPTO_MINI_MAC_SIZE * 2u);
        tag_hex[CRYPTO_MINI_MAC_SIZE * 2u] = '\0';
        cipher_start = tag_separator + 1;
    } else {
        cipher_start = cipher_separator + 1;
    }

    {
        size_t salt_length = sizeof(salt);
        size_t nonce_length = sizeof(nonce);
        if(crypto_engine_hex_decode(salt_hex, salt, &salt_length) != CRYPTO_ENGINE_SUCCESS ||
           salt_length != sizeof(salt) ||
           crypto_engine_hex_decode(nonce_hex, nonce, &nonce_length) != CRYPTO_ENGINE_SUCCESS ||
           nonce_length != sizeof(nonce)) {
            goto cleanup;
        }

        if(is_authenticated) {
            size_t tag_length = sizeof(provided_tag);
            if(crypto_engine_hex_decode(tag_hex, provided_tag, &tag_length) != CRYPTO_ENGINE_SUCCESS ||
               tag_length != sizeof(provided_tag)) {
                goto cleanup;
            }
        }
    }

    if(crypto_engine_hex_decode(cipher_start, app->buffer_a, &cipher_length) != CRYPTO_ENGINE_SUCCESS) {
        goto cleanup;
    }

    if(!crypto_mini_derive_keys(app->password, salt, encryption_key, mac_key)) {
        if(error_text) {
            *error_text = "No se pudo derivar la clave.";
        }
        goto cleanup;
    }

    if(is_authenticated) {
        crypto_mini_compute_auth_tag(mac_key, salt, nonce, app->buffer_a, cipher_length, expected_tag);
        if(!crypto_mini_constant_time_equal(provided_tag, expected_tag, sizeof(expected_tag))) {
            if(error_text) {
                *error_text = "MAC no valida. Clave incorrecta o datos manipulados.";
            }
            goto cleanup;
        }
    }

    if(crypto_engine_chacha20_decrypt(
           encryption_key, nonce, app->buffer_a, cipher_length, app->buffer_b) !=
       CRYPTO_ENGINE_SUCCESS) {
        if(error_text) {
            *error_text = "Fallo al descifrar.";
        }
        goto cleanup;
    }

    if(cipher_length < magic_length || memcmp(app->buffer_b, CRYPTO_MINI_MAGIC, magic_length) != 0) {
        if(error_text) {
            *error_text = is_authenticated ? "Clave incorrecta o formato no valido." :
                                             "Clave incorrecta o formato legacy no valido.";
        }
        goto cleanup;
    }

    cipher_length -= magic_length;
    if(cipher_length + 1u > output_size) {
        if(error_text) {
            *error_text = "Salida demasiado grande.";
        }
        goto cleanup;
    }

    memcpy(output, app->buffer_b + magic_length, cipher_length);
    output[cipher_length] = '\0';
    ok = true;

cleanup:
    crypto_mini_zeroize(encryption_key, sizeof(encryption_key));
    crypto_mini_zeroize(mac_key, sizeof(mac_key));
    crypto_mini_zeroize(expected_tag, sizeof(expected_tag));
    crypto_mini_zeroize(provided_tag, sizeof(provided_tag));
    crypto_mini_zeroize(salt, sizeof(salt));
    crypto_mini_zeroize(nonce, sizeof(nonce));
    return ok;
}

static bool crypto_mini_process_text_action(CryptoMiniApp* app) {
    const char* error_text = NULL;

    crypto_mini_clear_last_result(app);

    if(app->pending_action == CryptoMiniActionEncryptText) {
        if(!crypto_mini_encrypt_payload(
               app,
               (const uint8_t*)app->payload,
               strlen(app->payload),
               app->output,
               sizeof(app->output))) {
            snprintf(app->output, sizeof(app->output), "No se pudo cifrar el texto.");
            return false;
        }
        crypto_mini_store_last_result(app, app->output, ".enc.txt");
        return true;
    }

    if(!crypto_mini_decrypt_payload(app, app->payload, app->output, sizeof(app->output), &error_text)) {
        snprintf(app->output, sizeof(app->output), "%s", error_text ? error_text : "No se pudo descifrar el texto.");
        return false;
    }

    crypto_mini_store_last_result(app, app->output, ".dec.txt");
    return true;
}

static bool crypto_mini_save_last_text_result(CryptoMiniApp* app) {
    char output_path[256];

    if(!app->last_result_available) {
        snprintf(app->output, sizeof(app->output), "No hay un resultado de texto para guardar todavia.");
        return false;
    }

    if(!crypto_mini_build_saved_text_path(app, output_path, sizeof(output_path))) {
        snprintf(app->output, sizeof(app->output), "No se pudo construir la ruta para guardar el resultado.");
        return false;
    }

    if(!crypto_mini_write_text_file(output_path, app->last_result)) {
        snprintf(app->output, sizeof(app->output), "No se pudo guardar el resultado.\n%s", output_path);
        return false;
    }

    snprintf(app->output, sizeof(app->output), "Resultado guardado\n%s", output_path);
    return true;
}

static bool crypto_mini_process_file_action(CryptoMiniApp* app) {
    char file_contents[CRYPTO_MINI_FILE_TEXT_SIZE + 1u];
    char output_path[256];
    const char* error_text = NULL;

    if(!crypto_mini_read_text_file(file_contents, sizeof(file_contents), app->file_path)) {
        snprintf(app->output, sizeof(app->output), "No se pudo leer el archivo.\n%s", app->file_path);
        return false;
    }

    if(app->pending_action == CryptoMiniActionDecryptFile) {
        crypto_mini_trim_newlines(file_contents);
    }

    if(app->pending_action == CryptoMiniActionEncryptFile) {
        if(!crypto_mini_encrypt_payload(
               app,
               (const uint8_t*)file_contents,
               strlen(file_contents),
               app->output,
               sizeof(app->output))) {
            snprintf(app->output, sizeof(app->output), "No se pudo cifrar el archivo.");
            return false;
        }
        if(!crypto_mini_build_output_path(app->file_path, ".enc.txt", output_path, sizeof(output_path))) {
            snprintf(app->output, sizeof(app->output), "No se pudo construir la ruta de salida.");
            return false;
        }
    } else {
        if(!crypto_mini_decrypt_payload(app, file_contents, app->output, sizeof(app->output), &error_text)) {
            snprintf(app->output, sizeof(app->output), "%s", error_text ? error_text : "No se pudo descifrar el archivo.");
            return false;
        }
        if(!crypto_mini_build_output_path(app->file_path, ".dec.txt", output_path, sizeof(output_path))) {
            snprintf(app->output, sizeof(app->output), "No se pudo construir la ruta de salida.");
            return false;
        }
    }

    if(!crypto_mini_write_text_file(output_path, app->output)) {
        snprintf(app->output, sizeof(app->output), "No se pudo escribir la salida.\n%s", output_path);
        return false;
    }

    snprintf(
        app->output,
        sizeof(app->output),
        "%s\nEntrada: %s\nSalida: %s",
        app->pending_action == CryptoMiniActionEncryptFile ? "Archivo cifrado OK" : "Archivo descifrado OK",
        app->file_path,
        output_path);
    return true;
}

static void crypto_mini_start_payload_input(CryptoMiniApp* app) {
    app->input_stage = CryptoMiniInputPayload;
    text_input_reset(app->text_input);
    app->payload[0] = '\0';

    if(app->pending_action == CryptoMiniActionEncryptText) {
        text_input_set_header_text(app->text_input, "Texto a cifrar");
    } else {
        text_input_set_header_text(app->text_input, "Texto cifrado");
    }

    text_input_set_result_callback(
        app->text_input,
        crypto_mini_text_input_callback,
        app,
        app->payload,
        sizeof(app->payload),
        true);

    app->current_view = CryptoMiniViewTextInput;
    view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewTextInput);
}

static void crypto_mini_start_password_input(CryptoMiniApp* app, CryptoMiniAction action) {
    app->pending_action = action;
    app->input_stage = CryptoMiniInputPassword;
    text_input_reset(app->text_input);
    app->password[0] = '\0';

    text_input_set_header_text(app->text_input, "Clave / password");
    text_input_set_result_callback(
        app->text_input,
        crypto_mini_text_input_callback,
        app,
        app->password,
        sizeof(app->password),
        true);

    app->current_view = CryptoMiniViewTextInput;
    view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewTextInput);
}

static void crypto_mini_refresh_menu(CryptoMiniApp* app) {
    submenu_reset(app->submenu);

    if(app->menu_mode == CryptoMiniMenuText) {
        snprintf(app->menu_header, sizeof(app->menu_header), "Texto");
        submenu_set_header(app->submenu, app->menu_header);
        submenu_add_item(app->submenu, "Cifrar", CryptoMiniActionEncryptText, crypto_mini_menu_callback, app);
        submenu_add_item(app->submenu, "Descifrar", CryptoMiniActionDecryptText, crypto_mini_menu_callback, app);
        if(app->last_result_available) {
            submenu_add_item(app->submenu, "Guardar ultimo", CryptoMiniActionSaveLastText, crypto_mini_menu_callback, app);
        }
        submenu_add_item(app->submenu, "Atras", CryptoMiniMenuItemBack, crypto_mini_menu_callback, app);
        return;
    }

    if(app->menu_mode == CryptoMiniMenuFile) {
        snprintf(app->menu_header, sizeof(app->menu_header), "Archivos TXT");
        submenu_set_header(app->submenu, app->menu_header);
        submenu_add_item(app->submenu, "Cifrar TXT", CryptoMiniActionEncryptFile, crypto_mini_menu_callback, app);
        submenu_add_item(app->submenu, "Descifrar TXT", CryptoMiniActionDecryptFile, crypto_mini_menu_callback, app);
        submenu_add_item(app->submenu, "Atras", CryptoMiniMenuItemBack, crypto_mini_menu_callback, app);
        return;
    }

    snprintf(app->menu_header, sizeof(app->menu_header), "Crypto Mini");
    submenu_set_header(app->submenu, app->menu_header);
    submenu_add_item(app->submenu, "Texto", CryptoMiniMenuItemOpenText, crypto_mini_menu_callback, app);
    submenu_add_item(app->submenu, "Archivos TXT", CryptoMiniMenuItemOpenFile, crypto_mini_menu_callback, app);
    if(app->last_result_available) {
        submenu_add_item(app->submenu, "Guardar ultimo", CryptoMiniActionSaveLastText, crypto_mini_menu_callback, app);
    }
    submenu_add_item(app->submenu, "Acerca de", CryptoMiniActionAbout, crypto_mini_menu_callback, app);
}

static void crypto_mini_menu_callback(void* context, uint32_t index) {
    CryptoMiniApp* app = context;

    if(index == CryptoMiniMenuItemOpenText) {
        app->menu_mode = CryptoMiniMenuText;
        crypto_mini_refresh_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
        return;
    }

    if(index == CryptoMiniMenuItemOpenFile) {
        app->menu_mode = CryptoMiniMenuFile;
        crypto_mini_refresh_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
        return;
    }

    if(index == CryptoMiniMenuItemBack) {
        app->menu_mode = CryptoMiniMenuRoot;
        crypto_mini_refresh_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
        return;
    }

    if(index == CryptoMiniActionSaveLastText) {
        crypto_mini_save_last_text_result(app);
        crypto_mini_show_text(app, app->output);
        return;
    }

    if(index == CryptoMiniActionAbout) {
        snprintf(
            app->output,
            sizeof(app->output),
            "Crypto Mini\n\nCifra y descifra texto o archivos .txt con ChaCha20.\n\nClave: PBKDF2-HMAC-SHA256\nFormato nuevo: CE2:salt:nonce:mac:cipherhex\nCompatibilidad: tambien lee CE1 antiguo.\n\nEl MAC detecta clave incorrecta y manipulacion real de datos.");
        crypto_mini_show_text(app, app->output);
        return;
    }

    crypto_mini_start_password_input(app, (CryptoMiniAction)index);
}

static void crypto_mini_text_input_callback(void* context) {
    CryptoMiniApp* app = context;

    if(app->input_stage == CryptoMiniInputPassword) {
        if(crypto_mini_is_file_action(app->pending_action)) {
            file_browser_start(app->file_browser, app->browser_start_path);
            app->current_view = CryptoMiniViewBrowser;
            view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewBrowser);
        } else {
            crypto_mini_start_payload_input(app);
        }
        return;
    }

    crypto_mini_process_text_action(app);
    crypto_mini_show_text(app, app->output);
}

static void crypto_mini_file_browser_callback(void* context) {
    CryptoMiniApp* app = context;
    strncpy(app->file_path, furi_string_get_cstr(app->browser_result), sizeof(app->file_path) - 1u);
    app->file_path[sizeof(app->file_path) - 1u] = '\0';
    file_browser_stop(app->file_browser);
    crypto_mini_process_file_action(app);
    crypto_mini_show_text(app, app->output);
}

static bool crypto_mini_navigation_callback(void* context) {
    CryptoMiniApp* app = context;

    if(app->current_view == CryptoMiniViewBrowser) {
        file_browser_stop(app->file_browser);
    }

    if(app->current_view == CryptoMiniViewMenu && app->menu_mode != CryptoMiniMenuRoot) {
        app->menu_mode = CryptoMiniMenuRoot;
        crypto_mini_refresh_menu(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
        return true;
    }

    if(app->current_view != CryptoMiniViewMenu) {
        crypto_mini_refresh_menu(app);
        app->current_view = CryptoMiniViewMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
        return true;
    }

    return false;
}

static CryptoMiniApp* crypto_mini_app_alloc(void) {
    CryptoMiniApp* app = malloc(sizeof(CryptoMiniApp));
    furi_assert(app);

    memset(app, 0, sizeof(CryptoMiniApp));
    crypto_mini_clear_last_result(app);
    app->menu_mode = CryptoMiniMenuRoot;
    app->view_dispatcher = view_dispatcher_alloc();
    app->submenu = submenu_alloc();
    app->text_input = text_input_alloc();
    app->text_box = text_box_alloc();
    app->browser_result = furi_string_alloc();
    app->browser_start_path = furi_string_alloc();
    furi_string_set(app->browser_start_path, "/ext");
    app->file_browser = file_browser_alloc(app->browser_result);
    file_browser_configure(app->file_browser, ".txt", "/ext", false, true, NULL, false);
    file_browser_set_callback(app->file_browser, crypto_mini_file_browser_callback, app);

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, crypto_mini_navigation_callback);

    view_dispatcher_add_view(app->view_dispatcher, CryptoMiniViewMenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(app->view_dispatcher, CryptoMiniViewTextInput, text_input_get_view(app->text_input));
    view_dispatcher_add_view(app->view_dispatcher, CryptoMiniViewTextBox, text_box_get_view(app->text_box));
    view_dispatcher_add_view(app->view_dispatcher, CryptoMiniViewBrowser, file_browser_get_view(app->file_browser));

    crypto_mini_refresh_menu(app);
    return app;
}

static void crypto_mini_app_free(CryptoMiniApp* app) {
    furi_assert(app);

    view_dispatcher_remove_view(app->view_dispatcher, CryptoMiniViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, CryptoMiniViewTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, CryptoMiniViewTextBox);
    view_dispatcher_remove_view(app->view_dispatcher, CryptoMiniViewBrowser);

    text_box_free(app->text_box);
    text_input_free(app->text_input);
    submenu_free(app->submenu);
    file_browser_free(app->file_browser);
    view_dispatcher_free(app->view_dispatcher);

    furi_string_free(app->browser_result);
    furi_string_free(app->browser_start_path);
    free(app);
}

int32_t crypto_engine_mini_app(void* p) {
    UNUSED(p);

    CryptoMiniApp* app = crypto_mini_app_alloc();
    Gui* gui = furi_record_open(RECORD_GUI);

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    app->current_view = CryptoMiniViewMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, CryptoMiniViewMenu);
    view_dispatcher_run(app->view_dispatcher);

    crypto_mini_app_free(app);
    furi_record_close(RECORD_GUI);
    return 0;
}