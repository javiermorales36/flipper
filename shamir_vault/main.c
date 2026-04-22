#include <furi.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/modules/text_input.h>
#include <gui/view_dispatcher.h>
#include <storage/storage.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHAMIR_FIELD_PRIME 257u
#define SHAMIR_THRESHOLD 3u
#define SHAMIR_SHARE_TOTAL 5u
#define SHAMIR_MAX_SECRET_LEN 32u
#define SHAMIR_SHARE_PATH_1 APP_DATA_PATH("share_1.txt")
#define SHAMIR_SHARE_PATH_2 APP_DATA_PATH("share_2.txt")
#define SHAMIR_SHARE_PATH_3 APP_DATA_PATH("share_3.txt")
#define SHAMIR_SHARE_PATH_4 APP_DATA_PATH("share_4.txt")
#define SHAMIR_SHARE_PATH_5 APP_DATA_PATH("share_5.txt")

typedef enum {
    ShamirViewMenu,
    ShamirViewTextInput,
    ShamirViewTextBox,
} ShamirView;

typedef enum {
    ShamirInputSecret,
} ShamirInputMode;

typedef enum {
    ShamirActionEditSecret,
    ShamirActionSplit,
    ShamirActionReconstruct,
    ShamirActionAbout,
} ShamirAction;

typedef struct {
    bool valid;
    uint8_t index;
    uint8_t threshold;
    uint8_t total;
    uint8_t length;
    uint16_t values[SHAMIR_MAX_SECRET_LEN];
} ShamirShare;

typedef struct {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextInput* text_input;
    TextBox* text_box;
    ShamirView current_view;
    ShamirInputMode input_mode;
    char secret[SHAMIR_MAX_SECRET_LEN + 1];
    char menu_header[96];
    char status[1024];
} ShamirApp;

static const char* shamir_share_paths[SHAMIR_SHARE_TOTAL] = {
    SHAMIR_SHARE_PATH_1,
    SHAMIR_SHARE_PATH_2,
    SHAMIR_SHARE_PATH_3,
    SHAMIR_SHARE_PATH_4,
    SHAMIR_SHARE_PATH_5,
};

static void shamir_app_refresh_menu(ShamirApp* app);
static void shamir_app_show_text(ShamirApp* app, const char* text);
static void shamir_start_text_input(ShamirApp* app, ShamirInputMode mode);
static void shamir_menu_callback(void* context, uint32_t index);
static bool shamir_navigation_callback(void* context);

static void shamir_zeroize(void* buffer, size_t size) {
    volatile uint8_t* bytes = buffer;
    while(size--) {
        *bytes++ = 0;
    }
}

static void shamir_copy_string(char* target, size_t target_size, const char* source) {
    if(target_size == 0) {
        return;
    }

    snprintf(target, target_size, "%s", source ? source : "");
}

static uint16_t shamir_mod_add(uint16_t left, uint16_t right) {
    uint16_t result = left + right;
    if(result >= SHAMIR_FIELD_PRIME) {
        result -= SHAMIR_FIELD_PRIME;
    }
    return result;
}

static uint16_t shamir_mod_sub(uint16_t left, uint16_t right) {
    return (left >= right) ? (left - right) : (uint16_t)(SHAMIR_FIELD_PRIME + left - right);
}

static uint16_t shamir_mod_mul(uint16_t left, uint16_t right) {
    return (uint16_t)(((uint32_t)left * (uint32_t)right) % SHAMIR_FIELD_PRIME);
}

static uint16_t shamir_mod_inv(uint16_t value) {
    int32_t t = 0;
    int32_t new_t = 1;
    int32_t r = SHAMIR_FIELD_PRIME;
    int32_t new_r = value;

    while(new_r != 0) {
        int32_t quotient = r / new_r;
        int32_t temp_t = t - (quotient * new_t);
        int32_t temp_r = r - (quotient * new_r);
        t = new_t;
        new_t = temp_t;
        r = new_r;
        new_r = temp_r;
    }

    if(r > 1) {
        return 0;
    }

    if(t < 0) {
        t += SHAMIR_FIELD_PRIME;
    }

    return (uint16_t)t;
}

static uint16_t shamir_random_field(void) {
    uint8_t random_bytes[2];
    uint16_t candidate = 0;

    do {
        furi_hal_random_fill_buf(random_bytes, sizeof(random_bytes));
        candidate = (uint16_t)(((uint16_t)random_bytes[0] << 8) | random_bytes[1]);
    } while(candidate >= 65535u);

    return (uint16_t)(candidate % SHAMIR_FIELD_PRIME);
}

static char shamir_hex_digit(uint8_t nibble) {
    return (nibble < 10u) ? (char)('0' + nibble) : (char)('A' + (nibble - 10u));
}

static bool shamir_hex_encode_values(
    const uint16_t* values,
    size_t value_count,
    char* output,
    size_t output_size) {
    const size_t expected_size = (value_count * 4u) + 1u;
    if(output_size < expected_size) {
        return false;
    }

    for(size_t index = 0; index < value_count; index++) {
        uint16_t value = values[index];
        output[index * 4u] = shamir_hex_digit((uint8_t)((value >> 12) & 0x0Fu));
        output[(index * 4u) + 1u] = shamir_hex_digit((uint8_t)((value >> 8) & 0x0Fu));
        output[(index * 4u) + 2u] = shamir_hex_digit((uint8_t)((value >> 4) & 0x0Fu));
        output[(index * 4u) + 3u] = shamir_hex_digit((uint8_t)(value & 0x0Fu));
    }

    output[value_count * 4u] = '\0';
    return true;
}

static bool shamir_hex_decode_nibble(char character, uint8_t* nibble) {
    if(character >= '0' && character <= '9') {
        *nibble = (uint8_t)(character - '0');
        return true;
    }

    if(character >= 'a' && character <= 'f') {
        *nibble = (uint8_t)(character - 'a' + 10);
        return true;
    }

    if(character >= 'A' && character <= 'F') {
        *nibble = (uint8_t)(character - 'A' + 10);
        return true;
    }

    return false;
}

static bool shamir_hex_decode_values(
    const char* encoded,
    uint16_t* values,
    size_t expected_values) {
    if(strlen(encoded) != (expected_values * 4u)) {
        return false;
    }

    for(size_t index = 0; index < expected_values; index++) {
        uint8_t nibbles[4];
        const size_t offset = index * 4u;
        for(size_t nibble_index = 0; nibble_index < 4u; nibble_index++) {
            if(!shamir_hex_decode_nibble(encoded[offset + nibble_index], &nibbles[nibble_index])) {
                return false;
            }
        }

        values[index] = (uint16_t)((nibbles[0] << 12) | (nibbles[1] << 8) | (nibbles[2] << 4) |
                                   nibbles[3]);
        if(values[index] >= SHAMIR_FIELD_PRIME) {
            return false;
        }
    }

    return true;
}

static bool shamir_write_text_file(const char* path, const char* text) {
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

static bool shamir_read_text_file(char* output, size_t output_size, const char* path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool ok = false;

    if(storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        const uint64_t file_size = storage_file_size(file);
        if(file_size > 0 && file_size < output_size) {
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

static void shamir_trim_line(char* line) {
    while(*line == '\r' || *line == '\n') {
        memmove(line, line + 1, strlen(line));
    }

    size_t length = strlen(line);
    while(length > 0 && (line[length - 1u] == '\r' || line[length - 1u] == '\n')) {
        line[length - 1u] = '\0';
        length--;
    }
}

static bool shamir_load_share_file(const char* path, ShamirShare* share) {
    char file_buffer[512];
    char data_hex[(SHAMIR_MAX_SECRET_LEN * 4u) + 1u];
    bool has_scheme = false;
    bool has_index = false;
    bool has_length = false;
    bool has_threshold = false;
    bool has_total = false;
    bool has_data = false;

    memset(share, 0, sizeof(ShamirShare));
    memset(data_hex, 0, sizeof(data_hex));

    if(!shamir_read_text_file(file_buffer, sizeof(file_buffer), path)) {
        return false;
    }

    char* cursor = file_buffer;
    while(*cursor != '\0') {
        char* line = cursor;
        char* next_line = strchr(cursor, '\n');
        if(next_line != NULL) {
            *next_line = '\0';
            cursor = next_line + 1;
        } else {
            cursor += strlen(cursor);
        }

        shamir_trim_line(line);
        if(line[0] == '\0') {
            continue;
        }

        char* separator = strchr(line, '=');
        if(separator == NULL) {
            continue;
        }

        *separator = '\0';
        const char* key = line;
        const char* value = separator + 1;

        if(strcmp(key, "scheme") == 0) {
            has_scheme = strcmp(value, "shamir257") == 0;
        } else if(strcmp(key, "threshold") == 0) {
            share->threshold = (uint8_t)strtoul(value, NULL, 10);
            has_threshold = true;
        } else if(strcmp(key, "total") == 0) {
            share->total = (uint8_t)strtoul(value, NULL, 10);
            has_total = true;
        } else if(strcmp(key, "length") == 0) {
            share->length = (uint8_t)strtoul(value, NULL, 10);
            has_length = true;
        } else if(strcmp(key, "index") == 0) {
            share->index = (uint8_t)strtoul(value, NULL, 10);
            has_index = true;
        } else if(strcmp(key, "data") == 0) {
            shamir_copy_string(data_hex, sizeof(data_hex), value);
            has_data = true;
        }
    }

    if(!has_scheme || !has_index || !has_length || !has_threshold || !has_total || !has_data) {
        return false;
    }

    if(share->threshold != SHAMIR_THRESHOLD || share->total != SHAMIR_SHARE_TOTAL ||
       share->index == 0u || share->index > SHAMIR_SHARE_TOTAL || share->length == 0u ||
       share->length > SHAMIR_MAX_SECRET_LEN) {
        return false;
    }

    if(!shamir_hex_decode_values(data_hex, share->values, share->length)) {
        return false;
    }

    share->valid = true;
    return true;
}

static bool shamir_generate_shares(const char* secret, char* status, size_t status_size) {
    uint16_t shares[SHAMIR_SHARE_TOTAL][SHAMIR_MAX_SECRET_LEN];
    uint16_t coefficients[SHAMIR_THRESHOLD];
    char encoded[(SHAMIR_MAX_SECRET_LEN * 4u) + 1u];
    const size_t secret_length = strlen(secret);

    if(secret_length == 0u || secret_length > SHAMIR_MAX_SECRET_LEN) {
        snprintf(status, status_size, "Introduce un secreto primero.\n\nLimite: %u caracteres.", SHAMIR_MAX_SECRET_LEN);
        return false;
    }

    memset(shares, 0, sizeof(shares));
    memset(coefficients, 0, sizeof(coefficients));
    memset(encoded, 0, sizeof(encoded));

    for(size_t char_index = 0; char_index < secret_length; char_index++) {
        coefficients[0] = (uint8_t)secret[char_index];
        coefficients[1] = shamir_random_field();
        coefficients[2] = shamir_random_field();

        for(uint8_t share_index = 0; share_index < SHAMIR_SHARE_TOTAL; share_index++) {
            const uint16_t x = (uint16_t)(share_index + 1u);
            uint16_t value = coefficients[SHAMIR_THRESHOLD - 1u];

            for(int coefficient_index = (int)SHAMIR_THRESHOLD - 2; coefficient_index >= 0;
                coefficient_index--) {
                value = shamir_mod_add(
                    shamir_mod_mul(value, x), coefficients[(size_t)coefficient_index]);
            }

            shares[share_index][char_index] = value;
        }
    }

    for(uint8_t share_index = 0; share_index < SHAMIR_SHARE_TOTAL; share_index++) {
        char file_buffer[320];

        if(!shamir_hex_encode_values(shares[share_index], secret_length, encoded, sizeof(encoded))) {
            snprintf(status, status_size, "Error al codificar la parte %u.", (unsigned)(share_index + 1u));
            shamir_zeroize(shares, sizeof(shares));
            shamir_zeroize(coefficients, sizeof(coefficients));
            return false;
        }

        const int file_length = snprintf(
            file_buffer,
            sizeof(file_buffer),
            "scheme=shamir257\nthreshold=%u\ntotal=%u\nlength=%u\nindex=%u\ndata=%s\n",
            SHAMIR_THRESHOLD,
            SHAMIR_SHARE_TOTAL,
            (unsigned)secret_length,
            (unsigned)(share_index + 1u),
            encoded);

        if(file_length <= 0 || (size_t)file_length >= sizeof(file_buffer) ||
           !shamir_write_text_file(shamir_share_paths[share_index], file_buffer)) {
            snprintf(
                status,
                status_size,
                "Error al escribir la parte %u.\n\nRevisa la SD e intenta de nuevo.",
                (unsigned)(share_index + 1u));
            shamir_zeroize(shares, sizeof(shares));
            shamir_zeroize(coefficients, sizeof(coefficients));
            return false;
        }
    }

    snprintf(
        status,
        status_size,
        "Generadas 5 partes en apps_data.\nSe necesitan 3 para recuperar el secreto.\n\nArchivos:\n%s\n%s\n%s\n%s\n%s",
        shamir_share_paths[0],
        shamir_share_paths[1],
        shamir_share_paths[2],
        shamir_share_paths[3],
        shamir_share_paths[4]);

    shamir_zeroize(shares, sizeof(shares));
    shamir_zeroize(coefficients, sizeof(coefficients));
    return true;
}

static bool shamir_pick_shares(ShamirShare* all_shares, ShamirShare* selected_shares) {
    uint8_t selected_count = 0u;
    uint8_t expected_length = 0u;

    for(uint8_t share_index = 0; share_index < SHAMIR_SHARE_TOTAL && selected_count < SHAMIR_THRESHOLD;
        share_index++) {
        if(!all_shares[share_index].valid) {
            continue;
        }

        if(selected_count == 0u) {
            expected_length = all_shares[share_index].length;
        }

        if(all_shares[share_index].length != expected_length) {
            continue;
        }

        bool duplicate = false;
        for(uint8_t previous = 0u; previous < selected_count; previous++) {
            if(selected_shares[previous].index == all_shares[share_index].index) {
                duplicate = true;
                break;
            }
        }

        if(!duplicate) {
            selected_shares[selected_count++] = all_shares[share_index];
        }
    }

    return selected_count == SHAMIR_THRESHOLD;
}

static bool shamir_reconstruct_secret(char* output, size_t output_size, char* status, size_t status_size) {
    ShamirShare loaded_shares[SHAMIR_SHARE_TOTAL];
    ShamirShare selected_shares[SHAMIR_THRESHOLD];

    memset(loaded_shares, 0, sizeof(loaded_shares));
    memset(selected_shares, 0, sizeof(selected_shares));

    for(uint8_t share_index = 0; share_index < SHAMIR_SHARE_TOTAL; share_index++) {
        shamir_load_share_file(shamir_share_paths[share_index], &loaded_shares[share_index]);
    }

    if(!shamir_pick_shares(loaded_shares, selected_shares)) {
        snprintf(
            status,
            status_size,
            "Se necesitan al menos 3 partes validas.\n\nArchivos esperados:\n%s\n%s\n%s\n%s\n%s",
            shamir_share_paths[0],
            shamir_share_paths[1],
            shamir_share_paths[2],
            shamir_share_paths[3],
            shamir_share_paths[4]);
        return false;
    }

    const uint8_t secret_length = selected_shares[0].length;
    if(output_size <= secret_length) {
        snprintf(status, status_size, "Buffer interno demasiado pequeno.");
        return false;
    }

    for(uint8_t value_index = 0; value_index < secret_length; value_index++) {
        uint16_t secret_value = 0u;

        for(uint8_t share_position = 0; share_position < SHAMIR_THRESHOLD; share_position++) {
            const uint16_t x_i = selected_shares[share_position].index;
            uint16_t numerator = 1u;
            uint16_t denominator = 1u;

            for(uint8_t other_position = 0; other_position < SHAMIR_THRESHOLD; other_position++) {
                if(share_position == other_position) {
                    continue;
                }

                const uint16_t x_j = selected_shares[other_position].index;
                numerator = shamir_mod_mul(numerator, shamir_mod_sub(0u, x_j));
                denominator = shamir_mod_mul(denominator, shamir_mod_sub(x_i, x_j));
            }

            const uint16_t denominator_inverse = shamir_mod_inv(denominator);
            if(denominator_inverse == 0u) {
                snprintf(status, status_size, "Fallo la interpolacion.\n\nRevisa partes duplicadas o corruptas.");
                return false;
            }

            const uint16_t basis = shamir_mod_mul(numerator, denominator_inverse);
            const uint16_t term = shamir_mod_mul(selected_shares[share_position].values[value_index], basis);
            secret_value = shamir_mod_add(secret_value, term);
        }

        if(secret_value > 255u) {
            snprintf(status, status_size, "Valor recuperado %u fuera del rango de byte.\n\nUna o mas partes parecen corruptas.", secret_value);
            shamir_zeroize(output, output_size);
            return false;
        }

        output[value_index] = (char)secret_value;
    }

    output[secret_length] = '\0';
    snprintf(
        status,
        status_size,
        "Recuperado con las partes %u, %u y %u.\n\nSecreto:\n%s",
        (unsigned)selected_shares[0].index,
        (unsigned)selected_shares[1].index,
        (unsigned)selected_shares[2].index,
        output);
    return true;
}

static void shamir_text_input_callback(void* context) {
    ShamirApp* app = context;

    if(app->input_mode == ShamirInputSecret) {
        shamir_app_refresh_menu(app);
        app->current_view = ShamirViewMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, ShamirViewMenu);
    }
}

static void shamir_app_show_text(ShamirApp* app, const char* text) {
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    app->current_view = ShamirViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, ShamirViewTextBox);
}

static void shamir_start_text_input(ShamirApp* app, ShamirInputMode mode) {
    app->input_mode = mode;
    text_input_reset(app->text_input);

    if(mode == ShamirInputSecret) {
        text_input_set_header_text(app->text_input, "Secreto (max 32 caracteres)");
        text_input_set_result_callback(
            app->text_input,
            shamir_text_input_callback,
            app,
            app->secret,
            sizeof(app->secret),
            false);
    }

    app->current_view = ShamirViewTextInput;
    view_dispatcher_switch_to_view(app->view_dispatcher, ShamirViewTextInput);
}

static void shamir_app_refresh_menu(ShamirApp* app) {
    snprintf(
        app->menu_header,
        sizeof(app->menu_header),
        "Shamir Vault\nSecreto: %s",
        app->secret[0] ? "cargado" : "<vacio>");

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, app->menu_header);
    submenu_add_item(app->submenu, "Editar secreto", ShamirActionEditSecret, shamir_menu_callback, app);
    submenu_add_item(app->submenu, "Dividir 3-de-5", ShamirActionSplit, shamir_menu_callback, app);
    submenu_add_item(app->submenu, "Reconstruir", ShamirActionReconstruct, shamir_menu_callback, app);
    submenu_add_item(app->submenu, "Acerca de", ShamirActionAbout, shamir_menu_callback, app);
}

static void shamir_menu_callback(void* context, uint32_t index) {
    ShamirApp* app = context;

    switch(index) {
    case ShamirActionEditSecret:
        shamir_start_text_input(app, ShamirInputSecret);
        break;
    case ShamirActionSplit:
        if(shamir_generate_shares(app->secret, app->status, sizeof(app->status))) {
            shamir_app_show_text(app, app->status);
        } else {
            shamir_app_show_text(app, app->status);
        }
        break;
    case ShamirActionReconstruct: {
        char reconstructed[SHAMIR_MAX_SECRET_LEN + 1u];
        memset(reconstructed, 0, sizeof(reconstructed));
        shamir_reconstruct_secret(reconstructed, sizeof(reconstructed), app->status, sizeof(app->status));
        shamir_app_show_text(app, app->status);
        shamir_zeroize(reconstructed, sizeof(reconstructed));
        break;
    }
    case ShamirActionAbout:
        snprintf(
            app->status,
            sizeof(app->status),
            "Shamir Vault\n\nDivide un secreto ASCII en 5 partes y las guarda en apps_data. Cualquier combinacion de 3 partes reconstruye el secreto original.\n\nDetalle: usa el campo primo GF(257) para una comparticion compacta y auditable por bytes en el dispositivo.");
        shamir_app_show_text(app, app->status);
        break;
    }
}

static bool shamir_navigation_callback(void* context) {
    ShamirApp* app = context;

    if(app->current_view != ShamirViewMenu) {
        app->current_view = ShamirViewMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, ShamirViewMenu);
        return true;
    }

    return false;
}

static ShamirApp* shamir_app_alloc(void) {
    ShamirApp* app = malloc(sizeof(ShamirApp));
    furi_assert(app);

    memset(app, 0, sizeof(ShamirApp));
    app->view_dispatcher = view_dispatcher_alloc();
    app->submenu = submenu_alloc();
    app->text_input = text_input_alloc();
    app->text_box = text_box_alloc();

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, shamir_navigation_callback);

    view_dispatcher_add_view(app->view_dispatcher, ShamirViewMenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(
        app->view_dispatcher, ShamirViewTextInput, text_input_get_view(app->text_input));
    view_dispatcher_add_view(app->view_dispatcher, ShamirViewTextBox, text_box_get_view(app->text_box));

    shamir_copy_string(app->secret, sizeof(app->secret), "");
    shamir_app_refresh_menu(app);
    return app;
}

static void shamir_app_free(ShamirApp* app) {
    furi_assert(app);

    view_dispatcher_remove_view(app->view_dispatcher, ShamirViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, ShamirViewTextInput);
    view_dispatcher_remove_view(app->view_dispatcher, ShamirViewTextBox);

    text_box_free(app->text_box);
    text_input_free(app->text_input);
    submenu_free(app->submenu);
    view_dispatcher_free(app->view_dispatcher);
    shamir_zeroize(app->secret, sizeof(app->secret));
    shamir_zeroize(app->status, sizeof(app->status));
    free(app);
}

int32_t shamir_vault_app(void* p) {
    UNUSED(p);

    ShamirApp* app = shamir_app_alloc();
    Gui* gui = furi_record_open(RECORD_GUI);

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    app->current_view = ShamirViewMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, ShamirViewMenu);
    view_dispatcher_run(app->view_dispatcher);

    shamir_app_free(app);
    furi_record_close(RECORD_GUI);
    return 0;
}