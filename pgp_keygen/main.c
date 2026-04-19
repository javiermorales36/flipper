#include <furi.h>
#include <gui/canvas.h>
#include <gui/elements.h>
#include <gui/gui.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>
#include <furi_hal_random.h>
#include <furi_hal_rtc.h>
#include <storage/storage.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
    PgpKeygenMenuView,
    PgpKeygenKeyboardView,
    PgpKeygenTextBoxView,
} PgpKeygenView;

typedef enum {
    PgpKeygenFieldName,
    PgpKeygenFieldEmail,
    PgpKeygenFieldPassphrase,
} PgpKeygenField;

typedef enum {
    MenuActionEditName,
    MenuActionEditEmail,
    MenuActionEditPassphrase,
    MenuActionSaveProfile,
    MenuActionExport,
    MenuActionAbout,
} MenuAction;

typedef enum {
    PgpKeygenKeyboardActionChar,
    PgpKeygenKeyboardActionBackspace,
    PgpKeygenKeyboardActionSave,
} PgpKeygenKeyboardAction;

typedef struct {
    const char* label;
    PgpKeygenKeyboardAction action;
    char value;
} PgpKeygenKeyboardKey;

struct App;

typedef struct {
    struct App* app;
    uint8_t page;
    uint8_t row;
    uint8_t col;
    uint16_t revision;
} PgpKeygenKeyboardModel;

typedef struct App {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    View* keyboard_view;
    TextBox* text_box;
    PgpKeygenView current_view;
    char name[64];
    char email[96];
    char passphrase[64];
    char input_buffer[128];
    char menu_header[192];
    char status_buffer[512];
    PgpKeygenField active_field;
} App;

#define PGP_KEYGEN_NAME_SIZE 64
#define PGP_KEYGEN_EMAIL_SIZE 96
#define PGP_KEYGEN_PASSPHRASE_SIZE 64
#define PGP_KEYGEN_INPUT_BUFFER_SIZE 128
#define PGP_KEYGEN_KEYBOARD_COLUMNS 5
#define PGP_KEYGEN_KEYBOARD_ROWS 5
#define PGP_KEYGEN_KEYBOARD_PAGES 2
#define PGP_KEYGEN_KEY_WIDTH 24
#define PGP_KEYGEN_KEY_HEIGHT 8
#define PGP_KEYGEN_KEYBOARD_ORIGIN_X 1
#define PGP_KEYGEN_KEYBOARD_ORIGIN_Y 22
#define PGP_KEYGEN_PROFILE_PATH APP_DATA_PATH("pgp_keygen_profile.txt")
#define PGP_KEYGEN_EXPORT_PATH "/ext/pgp_keygen.asc"
#define PGP_KEYGEN_PUBLIC_EXPORT_PATH "/ext/pgp_keygen_public.asc"

static const PgpKeygenKeyboardKey pgp_keygen_keyboard_pages[PGP_KEYGEN_KEYBOARD_PAGES]
                                                        [PGP_KEYGEN_KEYBOARD_ROWS]
                                                        [PGP_KEYGEN_KEYBOARD_COLUMNS] = {
    {
        {
            {"a", PgpKeygenKeyboardActionChar, 'a'},
            {"b", PgpKeygenKeyboardActionChar, 'b'},
            {"c", PgpKeygenKeyboardActionChar, 'c'},
            {"d", PgpKeygenKeyboardActionChar, 'd'},
            {"e", PgpKeygenKeyboardActionChar, 'e'},
        },
        {
            {"f", PgpKeygenKeyboardActionChar, 'f'},
            {"g", PgpKeygenKeyboardActionChar, 'g'},
            {"h", PgpKeygenKeyboardActionChar, 'h'},
            {"i", PgpKeygenKeyboardActionChar, 'i'},
            {"j", PgpKeygenKeyboardActionChar, 'j'},
        },
        {
            {"k", PgpKeygenKeyboardActionChar, 'k'},
            {"l", PgpKeygenKeyboardActionChar, 'l'},
            {"m", PgpKeygenKeyboardActionChar, 'm'},
            {"n", PgpKeygenKeyboardActionChar, 'n'},
            {"o", PgpKeygenKeyboardActionChar, 'o'},
        },
        {
            {"p", PgpKeygenKeyboardActionChar, 'p'},
            {"q", PgpKeygenKeyboardActionChar, 'q'},
            {"r", PgpKeygenKeyboardActionChar, 'r'},
            {"s", PgpKeygenKeyboardActionChar, 's'},
            {"t", PgpKeygenKeyboardActionChar, 't'},
        },
        {
            {"u", PgpKeygenKeyboardActionChar, 'u'},
            {"v", PgpKeygenKeyboardActionChar, 'v'},
            {"w", PgpKeygenKeyboardActionChar, 'w'},
            {"x", PgpKeygenKeyboardActionChar, 'x'},
            {"y", PgpKeygenKeyboardActionChar, 'y'},
        },
    },
    {
        {
            {"z", PgpKeygenKeyboardActionChar, 'z'},
            {"sp", PgpKeygenKeyboardActionChar, ' '},
            {"_", PgpKeygenKeyboardActionChar, '_'},
            {"@", PgpKeygenKeyboardActionChar, '@'},
            {".", PgpKeygenKeyboardActionChar, '.'},
        },
        {
            {"del", PgpKeygenKeyboardActionBackspace, 0},
                {"save", PgpKeygenKeyboardActionSave, 0},
            {"0", PgpKeygenKeyboardActionChar, '0'},
            {"1", PgpKeygenKeyboardActionChar, '1'},
            {"2", PgpKeygenKeyboardActionChar, '2'},
        },
        {
            {"3", PgpKeygenKeyboardActionChar, '3'},
            {"4", PgpKeygenKeyboardActionChar, '4'},
            {"5", PgpKeygenKeyboardActionChar, '5'},
            {"6", PgpKeygenKeyboardActionChar, '6'},
            {"7", PgpKeygenKeyboardActionChar, '7'},
        },
        {
            {"8", PgpKeygenKeyboardActionChar, '8'},
            {"9", PgpKeygenKeyboardActionChar, '9'},
            {"-", PgpKeygenKeyboardActionChar, '-'},
            {"'", PgpKeygenKeyboardActionChar, '\''},
            {"/", PgpKeygenKeyboardActionChar, '/'},
        },
        {
            {"+", PgpKeygenKeyboardActionChar, '+'},
            {"?", PgpKeygenKeyboardActionChar, '?'},
            {"!", PgpKeygenKeyboardActionChar, '!'},
            {",", PgpKeygenKeyboardActionChar, ','},
            {":", PgpKeygenKeyboardActionChar, ':'},
        },
    },
};

static void pgp_keygen_menu_callback(void* context, uint32_t index);
static void pgp_keygen_start_keyboard_input(App* app, PgpKeygenField field);
static void pgp_keygen_keyboard_commit(App* app);
static void pgp_keygen_keyboard_cancel(App* app);
static void pgp_keygen_show_text(App* app, const char* text);

static const char* pgp_keygen_field_label(PgpKeygenField field) {
    switch(field) {
    case PgpKeygenFieldName:
        return "Name";
    case PgpKeygenFieldEmail:
        return "Email";
    case PgpKeygenFieldPassphrase:
        return "Passphrase";
    }

    return "Field";
}

static const char* pgp_keygen_keyboard_page_label(uint8_t page) {
    switch(page) {
    case 0:
        return "Letters";
    case 1:
        return "Symbols";
    default:
        return "Keyboard";
    }
}

static void pgp_keygen_copy_string(char* destination, size_t destination_size, const char* source) {
    if(destination_size == 0) {
        return;
    }

    size_t copy_size = strlen(source);
    if(copy_size >= destination_size) {
        copy_size = destination_size - 1;
    }

    memcpy(destination, source, copy_size);
    destination[copy_size] = '\0';
}

static void pgp_keygen_format_name(char* text) {
    bool capitalize_next = true;

    for(size_t index = 0; text[index] != '\0'; index++) {
        if(text[index] == '_') {
            text[index] = ' ';
            capitalize_next = true;
        } else if(text[index] == ' ') {
            capitalize_next = true;
        } else {
            if(capitalize_next && text[index] >= 'a' && text[index] <= 'z') {
                text[index] = (char)(text[index] - 'a' + 'A');
            }
            capitalize_next = false;
        }
    }
}

static void pgp_keygen_make_preview(char* target, size_t target_size, const char* source) {
    if(target_size == 0) {
        return;
    }

    size_t source_length = strlen(source);
    if(source_length < target_size) {
        snprintf(target, target_size, "%s", source);
        return;
    }

    if(target_size <= 4) {
        target[0] = '\0';
        return;
    }

    snprintf(target, target_size, "%.*s...", (int)(target_size - 4), source);
}

static size_t pgp_keygen_base64_encoded_size(size_t input_size) {
    return ((input_size + 2) / 3) * 4;
}

static bool pgp_keygen_base64_encode(
    const uint8_t* input,
    size_t input_size,
    char* output,
    size_t output_size,
    size_t* output_length) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t encoded_size = pgp_keygen_base64_encoded_size(input_size);

    if(output_size < (encoded_size + 1)) {
        return false;
    }

    size_t input_index = 0;
    size_t output_index = 0;
    while((input_index + 3) <= input_size) {
        uint32_t triple = ((uint32_t)input[input_index] << 16) |
                          ((uint32_t)input[input_index + 1] << 8) |
                          ((uint32_t)input[input_index + 2]);

        output[output_index++] = table[(triple >> 18) & 0x3F];
        output[output_index++] = table[(triple >> 12) & 0x3F];
        output[output_index++] = table[(triple >> 6) & 0x3F];
        output[output_index++] = table[triple & 0x3F];
        input_index += 3;
    }

    size_t remaining = input_size - input_index;
    if(remaining == 1) {
        uint32_t triple = ((uint32_t)input[input_index] << 16);
        output[output_index++] = table[(triple >> 18) & 0x3F];
        output[output_index++] = table[(triple >> 12) & 0x3F];
        output[output_index++] = '=';
        output[output_index++] = '=';
    } else if(remaining == 2) {
        uint32_t triple = ((uint32_t)input[input_index] << 16) |
                          ((uint32_t)input[input_index + 1] << 8);
        output[output_index++] = table[(triple >> 18) & 0x3F];
        output[output_index++] = table[(triple >> 12) & 0x3F];
        output[output_index++] = table[(triple >> 6) & 0x3F];
        output[output_index++] = '=';
    }

    output[encoded_size] = '\0';
    if(output_length != NULL) {
        *output_length = output_index;
    }
    return true;
}

static char* pgp_keygen_find_line_break(char* text) {
    for(char* cursor = text; *cursor != '\0'; cursor++) {
        if(*cursor == '\r' || *cursor == '\n') {
            return cursor;
        }
    }

    return NULL;
}

#define PGP_KEYGEN_EXPORT_BINARY_CAPACITY 2048
#define PGP_KEYGEN_EXPORT_ARMOR_CAPACITY 4096
#define PGP_KEYGEN_PROFILE_FILE_BUFFER_SIZE 512
#define PGP_KEYGEN_PGP_USER_ID_CAPACITY 192
#define PGP_KEYGEN_PGP_PACKET_CAPACITY 256
#define PGP_KEYGEN_CREATION_TIME_SAFETY_SECONDS (24u * 60u * 60u)

static uint8_t pgp_keygen_export_public_body[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_secret_body[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_userid_body[PGP_KEYGEN_PGP_USER_ID_CAPACITY];
static uint8_t pgp_keygen_export_hashed_subpackets[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_unhashed_subpackets[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_signature_body[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_fingerprint_input[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_mpi_buffer[PGP_KEYGEN_PGP_PACKET_CAPACITY];
static uint8_t pgp_keygen_export_point_buffer[1 + (2 * 32)];
static char pgp_keygen_export_user_id[PGP_KEYGEN_PGP_USER_ID_CAPACITY];
static uint8_t pgp_keygen_export_signature_prefix[6 + PGP_KEYGEN_PGP_PACKET_CAPACITY];

static const uint8_t pgp_keygen_curve_oid[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

typedef struct {
    uint8_t* data;
    size_t size;
    size_t capacity;
} PgpKeygenBuffer;

static void pgp_keygen_buffer_init(PgpKeygenBuffer* buffer, uint8_t* data, size_t capacity) {
    buffer->data = data;
    buffer->size = 0;
    buffer->capacity = capacity;
}

static bool pgp_keygen_buffer_append(PgpKeygenBuffer* buffer, const void* data, size_t size) {
    if(buffer->size + size > buffer->capacity) {
        return false;
    }

    memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
    return true;
}

static bool pgp_keygen_buffer_append_u8(PgpKeygenBuffer* buffer, uint8_t value) {
    return pgp_keygen_buffer_append(buffer, &value, sizeof(value));
}

static bool pgp_keygen_buffer_append_u16_be(PgpKeygenBuffer* buffer, uint16_t value) {
    uint8_t encoded[2] = {(uint8_t)(value >> 8), (uint8_t)(value & 0xFF)};
    return pgp_keygen_buffer_append(buffer, encoded, sizeof(encoded));
}

static bool pgp_keygen_buffer_append_u32_be(PgpKeygenBuffer* buffer, uint32_t value) {
    uint8_t encoded[4] = {
        (uint8_t)(value >> 24),
        (uint8_t)(value >> 16),
        (uint8_t)(value >> 8),
        (uint8_t)(value & 0xFF),
    };
    return pgp_keygen_buffer_append(buffer, encoded, sizeof(encoded));
}

static bool pgp_keygen_buffer_append_packet_header(
    PgpKeygenBuffer* buffer,
    uint8_t tag,
    size_t body_size) {
    if(!pgp_keygen_buffer_append_u8(buffer, (uint8_t)(0xC0 | (tag & 0x3F)))) {
        return false;
    }

    if(body_size < 192) {
        return pgp_keygen_buffer_append_u8(buffer, (uint8_t)body_size);
    }

    if(body_size <= 8383) {
        body_size -= 192;
        uint8_t first = (uint8_t)((body_size / 256) + 192);
        uint8_t second = (uint8_t)(body_size % 256);
        return pgp_keygen_buffer_append_u8(buffer, first) && pgp_keygen_buffer_append_u8(buffer, second);
    }

    return pgp_keygen_buffer_append_u8(buffer, 255) && pgp_keygen_buffer_append_u32_be(buffer, (uint32_t)body_size);
}

static bool pgp_keygen_encode_mpi(const mbedtls_mpi* value, uint8_t* buffer, size_t buffer_size, size_t* encoded_size) {
    size_t byte_size = mbedtls_mpi_size(value);
    size_t bit_size = mbedtls_mpi_bitlen(value);

    if((byte_size + 2) > buffer_size || bit_size > 0xFFFFu) {
        return false;
    }

    buffer[0] = (uint8_t)(bit_size >> 8);
    buffer[1] = (uint8_t)(bit_size & 0xFF);

    if(mbedtls_mpi_write_binary(value, buffer + 2, byte_size) != 0) {
        return false;
    }

    *encoded_size = byte_size + 2;
    return true;
}

static bool pgp_keygen_buffer_append_mpi(PgpKeygenBuffer* buffer, const mbedtls_mpi* value) {
    uint8_t encoded[PGP_KEYGEN_PGP_PACKET_CAPACITY];
    size_t encoded_size = 0;

    if(!pgp_keygen_encode_mpi(value, encoded, sizeof(encoded), &encoded_size)) {
        return false;
    }

    return pgp_keygen_buffer_append(buffer, encoded, encoded_size);
}

static uint32_t pgp_keygen_crc24(const uint8_t* data, size_t size) {
    uint32_t crc = 0xB704CE;

    for(size_t index = 0; index < size; index++) {
        crc ^= (uint32_t)data[index] << 16;
        for(uint8_t bit = 0; bit < 8; bit++) {
            crc <<= 1;
            if(crc & 0x1000000u) {
                crc ^= 0x1864CFBu;
            }
        }
    }

    return crc & 0xFFFFFFu;
}

static int pgp_keygen_rng(void* context, unsigned char* buffer, size_t size) {
    UNUSED(context);
    furi_hal_random_fill_buf(buffer, size);
    return 0;
}

static void pgp_keygen_profile_apply_line(App* app, const char* key, const char* value) {
    if(strcmp(key, "name") == 0) {
        pgp_keygen_copy_string(app->name, sizeof(app->name), value);
    } else if(strcmp(key, "email") == 0) {
        pgp_keygen_copy_string(app->email, sizeof(app->email), value);
    } else if(strcmp(key, "passphrase") == 0) {
        pgp_keygen_copy_string(app->passphrase, sizeof(app->passphrase), value);
    }
}

static bool pgp_keygen_profile_save(const App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool ok = false;

    if(storage_file_open(file, PGP_KEYGEN_PROFILE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        char buffer[384];
        int length = snprintf(
            buffer,
            sizeof(buffer),
            "name=%s\nemail=%s\npassphrase=%s\n",
            app->name,
            app->email,
            app->passphrase);

        if(length > 0 && (size_t)length < sizeof(buffer)) {
            size_t written = storage_file_write(file, buffer, (size_t)length);
            ok = written == (size_t)length;
            if(ok) {
                ok = storage_file_sync(file);
            }
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool pgp_keygen_profile_load(App* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool loaded = false;

    if(storage_file_open(file, PGP_KEYGEN_PROFILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint64_t file_size = storage_file_size(file);
        if(file_size > 0 && file_size < PGP_KEYGEN_PROFILE_FILE_BUFFER_SIZE) {
            char buffer[PGP_KEYGEN_PROFILE_FILE_BUFFER_SIZE];
            size_t read_size = storage_file_read(file, buffer, sizeof(buffer) - 1);
            buffer[read_size] = '\0';

            char* cursor = buffer;
            while(*cursor != '\0') {
                char* line = cursor;
                char* separator = pgp_keygen_find_line_break(cursor);
                if(separator != NULL) {
                    *separator = '\0';
                    cursor = separator + 1;
                    while(*cursor == '\r' || *cursor == '\n') {
                        cursor++;
                    }
                } else {
                    cursor += strlen(cursor);
                }

                char* equals = strchr(line, '=');
                if(equals != NULL) {
                    *equals = '\0';
                    pgp_keygen_profile_apply_line(app, line, equals + 1);
                    loaded = true;
                }
            }
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return loaded;
}

static bool pgp_keygen_make_user_id(const App* app, char* buffer, size_t buffer_size) {
    if(buffer_size == 0 || !app->name[0] || !app->email[0]) {
        return false;
    }

    int length = snprintf(buffer, buffer_size, "%s <%s>", app->name, app->email);
    return length > 0 && (size_t)length < buffer_size;
}

static bool pgp_keygen_build_export_binary(
    const App* app,
    uint8_t* private_buffer,
    size_t private_buffer_size,
    size_t* private_length,
    uint8_t* public_buffer,
    size_t public_buffer_size,
    size_t* public_length) {
    bool ok = false;
    uint8_t fingerprint[20];
    uint8_t key_id[8];
    size_t point_length = 0;
    size_t mpi_length = 0;
    mbedtls_ecp_group group;
    mbedtls_mpi private_key;
    mbedtls_ecp_point public_point;
    mbedtls_mpi public_point_mpi;

    if(!pgp_keygen_make_user_id(
           app, pgp_keygen_export_user_id, sizeof(pgp_keygen_export_user_id))) {
        return false;
    }

    mbedtls_ecp_group_init(&group);
    mbedtls_mpi_init(&private_key);
    mbedtls_ecp_point_init(&public_point);
    mbedtls_mpi_init(&public_point_mpi);

    do {
        PgpKeygenBuffer public_key_buffer;
        PgpKeygenBuffer secret_buffer;
        PgpKeygenBuffer user_buffer;
        PgpKeygenBuffer hashed_buffer;
        PgpKeygenBuffer unhashed_buffer;
        PgpKeygenBuffer sig_buffer;
        PgpKeygenBuffer fingerprint_buffer;
        mbedtls_sha256_context sha256;
        uint32_t creation_time = furi_hal_rtc_get_timestamp();
        if(creation_time > PGP_KEYGEN_CREATION_TIME_SAFETY_SECONDS) {
            creation_time -= PGP_KEYGEN_CREATION_TIME_SAFETY_SECONDS;
        }
        uint8_t digest[32];
        uint16_t digest_prefix = 0;
        mbedtls_mpi r;
        mbedtls_mpi s;

        mbedtls_mpi_init(&r);
        mbedtls_mpi_init(&s);

        if(mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        if(mbedtls_ecp_gen_keypair(&group, &private_key, &public_point, pgp_keygen_rng, NULL) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        if(mbedtls_ecp_point_write_binary(
               &group,
               &public_point,
               MBEDTLS_ECP_PF_UNCOMPRESSED,
               &point_length,
               pgp_keygen_export_point_buffer,
               sizeof(pgp_keygen_export_point_buffer)) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        if(mbedtls_mpi_read_binary(
               &public_point_mpi,
               pgp_keygen_export_point_buffer,
               point_length) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        pgp_keygen_buffer_init(
            &public_key_buffer,
            pgp_keygen_export_public_body,
            sizeof(pgp_keygen_export_public_body));
        if(!pgp_keygen_buffer_append_u8(&public_key_buffer, 4) ||
           !pgp_keygen_buffer_append_u32_be(&public_key_buffer, creation_time) ||
           !pgp_keygen_buffer_append_u8(&public_key_buffer, 19) ||
           !pgp_keygen_buffer_append_u8(&public_key_buffer, (uint8_t)sizeof(pgp_keygen_curve_oid)) ||
           !pgp_keygen_buffer_append(&public_key_buffer, pgp_keygen_curve_oid, sizeof(pgp_keygen_curve_oid)) ||
           !pgp_keygen_buffer_append_mpi(&public_key_buffer, &public_point_mpi)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        pgp_keygen_buffer_init(
            &fingerprint_buffer,
            pgp_keygen_export_fingerprint_input,
            sizeof(pgp_keygen_export_fingerprint_input));
        if(!pgp_keygen_buffer_append_u8(&fingerprint_buffer, 0x99) ||
           !pgp_keygen_buffer_append_u16_be(&fingerprint_buffer, (uint16_t)public_key_buffer.size) ||
           !pgp_keygen_buffer_append(
               &fingerprint_buffer,
               pgp_keygen_export_public_body,
               public_key_buffer.size) ||
           mbedtls_sha1(fingerprint_buffer.data, fingerprint_buffer.size, fingerprint) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        memcpy(key_id, fingerprint + sizeof(fingerprint) - sizeof(key_id), sizeof(key_id));

        pgp_keygen_buffer_init(
            &secret_buffer,
            pgp_keygen_export_secret_body,
            sizeof(pgp_keygen_export_secret_body));
        if(!pgp_keygen_buffer_append(
               &secret_buffer,
               pgp_keygen_export_public_body,
               public_key_buffer.size) ||
           !pgp_keygen_buffer_append_u8(&secret_buffer, 0) ||
           !pgp_keygen_encode_mpi(
               &private_key,
               pgp_keygen_export_mpi_buffer,
               sizeof(pgp_keygen_export_mpi_buffer),
               &mpi_length) ||
           !pgp_keygen_buffer_append(
               &secret_buffer,
               pgp_keygen_export_mpi_buffer,
               mpi_length)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        uint16_t checksum = 0;
        for(size_t index = 0; index < mpi_length; index++) {
            checksum = (uint16_t)((checksum + pgp_keygen_export_mpi_buffer[index]) & 0xFFFFu);
        }
        if(!pgp_keygen_buffer_append_u16_be(&secret_buffer, checksum)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        pgp_keygen_buffer_init(
            &user_buffer, pgp_keygen_export_userid_body, sizeof(pgp_keygen_export_userid_body));
        if(!pgp_keygen_buffer_append(
               &user_buffer,
               pgp_keygen_export_user_id,
               strlen(pgp_keygen_export_user_id))) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        pgp_keygen_buffer_init(
            &hashed_buffer,
            pgp_keygen_export_hashed_subpackets,
            sizeof(pgp_keygen_export_hashed_subpackets));
        {
            uint8_t creation_subpacket[5] = {
                0x02,
                (uint8_t)(creation_time >> 24),
                (uint8_t)(creation_time >> 16),
                (uint8_t)(creation_time >> 8),
                (uint8_t)(creation_time & 0xFF),
            };
            uint8_t key_flags_subpacket[1] = {0x03};

            if(!pgp_keygen_buffer_append_u8(&hashed_buffer, sizeof(creation_subpacket)) ||
               !pgp_keygen_buffer_append(&hashed_buffer, creation_subpacket, sizeof(creation_subpacket)) ||
               !pgp_keygen_buffer_append_u8(&hashed_buffer, 2) ||
               !pgp_keygen_buffer_append_u8(&hashed_buffer, 0x1B) ||
               !pgp_keygen_buffer_append(&hashed_buffer, key_flags_subpacket, sizeof(key_flags_subpacket))) {
                mbedtls_mpi_free(&r);
                mbedtls_mpi_free(&s);
                break;
            }
        }

        pgp_keygen_buffer_init(
            &unhashed_buffer,
            pgp_keygen_export_unhashed_subpackets,
            sizeof(pgp_keygen_export_unhashed_subpackets));
        {
            uint8_t issuer_subpacket[8] = {
                key_id[0], key_id[1], key_id[2], key_id[3], key_id[4], key_id[5], key_id[6], key_id[7],
            };

            if(!pgp_keygen_buffer_append_u8(&unhashed_buffer, 0x09) ||
               !pgp_keygen_buffer_append_u8(&unhashed_buffer, 0x10) ||
               !pgp_keygen_buffer_append(&unhashed_buffer, issuer_subpacket, sizeof(issuer_subpacket))) {
                mbedtls_mpi_free(&r);
                mbedtls_mpi_free(&s);
                break;
            }
        }

        mbedtls_sha256_init(&sha256);
        if(mbedtls_sha256_starts(&sha256, 0) != 0) {
            mbedtls_sha256_free(&sha256);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        uint8_t signed_public_key_prefix[3] = {
            0x99,
            (uint8_t)(public_key_buffer.size >> 8),
            (uint8_t)public_key_buffer.size,
        };
        uint8_t signed_user_id_prefix[5] = {0xB4, 0x00, 0x00, 0x00, 0x00};
        uint32_t user_id_size = (uint32_t)user_buffer.size;
        signed_user_id_prefix[1] = (uint8_t)(user_id_size >> 24);
        signed_user_id_prefix[2] = (uint8_t)(user_id_size >> 16);
        signed_user_id_prefix[3] = (uint8_t)(user_id_size >> 8);
        signed_user_id_prefix[4] = (uint8_t)user_id_size;

        if(mbedtls_sha256_update(&sha256, signed_public_key_prefix, sizeof(signed_public_key_prefix)) != 0 ||
           mbedtls_sha256_update(
               &sha256,
               pgp_keygen_export_public_body,
               public_key_buffer.size) != 0 ||
           mbedtls_sha256_update(&sha256, signed_user_id_prefix, sizeof(signed_user_id_prefix)) != 0 ||
           mbedtls_sha256_update(
               &sha256,
               pgp_keygen_export_userid_body,
               user_buffer.size) != 0) {
            mbedtls_sha256_free(&sha256);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        PgpKeygenBuffer signature_prefix_buffer;
        pgp_keygen_buffer_init(
            &signature_prefix_buffer,
            pgp_keygen_export_signature_prefix,
            sizeof(pgp_keygen_export_signature_prefix));
        if(!pgp_keygen_buffer_append_u8(&signature_prefix_buffer, 4) ||
           !pgp_keygen_buffer_append_u8(&signature_prefix_buffer, 0x13) ||
           !pgp_keygen_buffer_append_u8(&signature_prefix_buffer, 19) ||
           !pgp_keygen_buffer_append_u8(&signature_prefix_buffer, 8) ||
           !pgp_keygen_buffer_append_u16_be(&signature_prefix_buffer, (uint16_t)hashed_buffer.size) ||
           !pgp_keygen_buffer_append(
               &signature_prefix_buffer,
               pgp_keygen_export_hashed_subpackets,
               hashed_buffer.size)) {
            mbedtls_sha256_free(&sha256);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        if(mbedtls_sha256_update(
               &sha256,
               pgp_keygen_export_signature_prefix,
               signature_prefix_buffer.size) != 0) {
            mbedtls_sha256_free(&sha256);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        uint8_t trailer[6] = {
            0x04,
            0xFF,
            (uint8_t)(signature_prefix_buffer.size >> 24),
            (uint8_t)(signature_prefix_buffer.size >> 16),
            (uint8_t)(signature_prefix_buffer.size >> 8),
            (uint8_t)signature_prefix_buffer.size,
        };

        if(mbedtls_sha256_update(&sha256, trailer, sizeof(trailer)) != 0 ||
           mbedtls_sha256_finish(&sha256, digest) != 0) {
            mbedtls_sha256_free(&sha256);
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        mbedtls_sha256_free(&sha256);

        if(mbedtls_ecdsa_sign(&group, &r, &s, &private_key, digest, sizeof(digest), pgp_keygen_rng, NULL) != 0) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        pgp_keygen_buffer_init(
            &sig_buffer, pgp_keygen_export_signature_body, sizeof(pgp_keygen_export_signature_body));
        if(!pgp_keygen_buffer_append(
               &sig_buffer,
               pgp_keygen_export_signature_prefix,
               signature_prefix_buffer.size) ||
           !pgp_keygen_buffer_append_u16_be(&sig_buffer, (uint16_t)unhashed_buffer.size) ||
           !pgp_keygen_buffer_append(
               &sig_buffer,
               pgp_keygen_export_unhashed_subpackets,
               unhashed_buffer.size)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        digest_prefix = (uint16_t)(((uint16_t)digest[0] << 8) | digest[1]);
        if(!pgp_keygen_buffer_append_u16_be(&sig_buffer, digest_prefix) ||
           !pgp_keygen_buffer_append_mpi(&sig_buffer, &r) ||
           !pgp_keygen_buffer_append_mpi(&sig_buffer, &s)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        if(private_buffer_size < 1 || public_buffer_size < 1) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        PgpKeygenBuffer private_output_buffer;
        PgpKeygenBuffer public_output_buffer;
        pgp_keygen_buffer_init(&private_output_buffer, private_buffer, private_buffer_size);
        pgp_keygen_buffer_init(&public_output_buffer, public_buffer, public_buffer_size);
        if(!pgp_keygen_buffer_append_packet_header(&private_output_buffer, 5, secret_buffer.size) ||
           !pgp_keygen_buffer_append(
               &private_output_buffer, pgp_keygen_export_secret_body, secret_buffer.size) ||
           !pgp_keygen_buffer_append_packet_header(&private_output_buffer, 13, user_buffer.size) ||
           !pgp_keygen_buffer_append(
               &private_output_buffer, pgp_keygen_export_userid_body, user_buffer.size) ||
           !pgp_keygen_buffer_append_packet_header(&private_output_buffer, 2, sig_buffer.size) ||
           !pgp_keygen_buffer_append(
               &private_output_buffer, pgp_keygen_export_signature_body, sig_buffer.size) ||
           !pgp_keygen_buffer_append_packet_header(&public_output_buffer, 6, public_key_buffer.size) ||
           !pgp_keygen_buffer_append(
               &public_output_buffer, pgp_keygen_export_public_body, public_key_buffer.size) ||
           !pgp_keygen_buffer_append_packet_header(&public_output_buffer, 13, user_buffer.size) ||
           !pgp_keygen_buffer_append(
               &public_output_buffer, pgp_keygen_export_userid_body, user_buffer.size) ||
           !pgp_keygen_buffer_append_packet_header(&public_output_buffer, 2, sig_buffer.size) ||
           !pgp_keygen_buffer_append(
               &public_output_buffer, pgp_keygen_export_signature_body, sig_buffer.size)) {
            mbedtls_mpi_free(&r);
            mbedtls_mpi_free(&s);
            break;
        }

        *private_length = private_output_buffer.size;
        *public_length = public_output_buffer.size;
        ok = true;
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
    } while(false);

    mbedtls_ecp_point_free(&public_point);
    mbedtls_mpi_free(&public_point_mpi);
    mbedtls_mpi_free(&private_key);
    mbedtls_ecp_group_free(&group);
    return ok;
}

static bool pgp_keygen_write_armored_file(
    const char* path,
    const uint8_t* binary,
    size_t binary_length,
    bool public_key) {
    bool ok = false;
    char* armored = NULL;
    char* base64 = NULL;

    size_t base64_length = pgp_keygen_base64_encoded_size(binary_length);
    armored = malloc(base64_length + 256 + (base64_length / 64) + 1);
    if(armored == NULL) {
        return false;
    }

    PgpKeygenBuffer armor_buffer;
    pgp_keygen_buffer_init(&armor_buffer, (uint8_t*)armored, base64_length + 256 + (base64_length / 64) + 1);
    const char* begin_line = public_key ? "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" : "-----BEGIN PGP PRIVATE KEY BLOCK-----\n";
    const char* version_line = "Version: PGP Keygen Lab\n\n";
    const char* end_line = public_key ? "\n-----END PGP PUBLIC KEY BLOCK-----\n" : "\n-----END PGP PRIVATE KEY BLOCK-----\n";

    base64 = malloc(base64_length + 1);
    if(base64 == NULL) {
        free(armored);
        return false;
    }

    if(!pgp_keygen_buffer_append(&armor_buffer, begin_line, strlen(begin_line)) ||
       !pgp_keygen_buffer_append(&armor_buffer, version_line, strlen(version_line))) {
        free(base64);
        free(armored);
        return false;
    }

    if(!pgp_keygen_base64_encode(binary, binary_length, base64, base64_length + 1, &base64_length)) {
        free(base64);
        free(armored);
        return false;
    }

    for(size_t index = 0; index < base64_length; index++) {
        if((index > 0) && ((index % 64) == 0)) {
            if(!pgp_keygen_buffer_append_u8(&armor_buffer, '\n')) {
                free(base64);
                free(armored);
                return false;
            }
        }

        if(!pgp_keygen_buffer_append_u8(&armor_buffer, base64[index])) {
            free(base64);
            free(armored);
            return false;
        }
    }

    uint32_t crc24 = pgp_keygen_crc24(binary, binary_length);
    uint8_t crc_bytes[3] = {(uint8_t)(crc24 >> 16), (uint8_t)(crc24 >> 8), (uint8_t)crc24};
    char crc_encoded[8];
    size_t crc_encoded_length = 0;
    if(!pgp_keygen_buffer_append_u8(&armor_buffer, '\n') ||
       !pgp_keygen_buffer_append_u8(&armor_buffer, '=') ||
       !pgp_keygen_base64_encode(crc_bytes, sizeof(crc_bytes), crc_encoded, sizeof(crc_encoded), &crc_encoded_length) ||
       !pgp_keygen_buffer_append(&armor_buffer, crc_encoded, crc_encoded_length) ||
       !pgp_keygen_buffer_append(&armor_buffer, end_line, strlen(end_line))) {
        free(base64);
        free(armored);
        return false;
    }

    armored[armor_buffer.size] = '\0';
    size_t armored_length = armor_buffer.size;

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    if(storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = storage_file_write(file, armored, armored_length) == armored_length;
        if(ok) {
            ok = storage_file_sync(file);
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    free(base64);
    free(armored);
    return ok;
}

static bool pgp_keygen_write_export(App* app) {
    if(!app->name[0] || !app->email[0]) {
        return false;
    }

    bool ok = false;
    uint8_t* private_binary = malloc(PGP_KEYGEN_EXPORT_BINARY_CAPACITY);
    uint8_t* public_binary = malloc(PGP_KEYGEN_EXPORT_BINARY_CAPACITY);
    size_t private_length = 0;
    size_t public_length = 0;

    if(private_binary == NULL || public_binary == NULL) {
        free(private_binary);
        free(public_binary);
        return false;
    }

    if(!pgp_keygen_build_export_binary(
           app,
           private_binary,
           PGP_KEYGEN_EXPORT_BINARY_CAPACITY,
           &private_length,
           public_binary,
           PGP_KEYGEN_EXPORT_BINARY_CAPACITY,
           &public_length)) {
        free(private_binary);
        free(public_binary);
        return false;
    }

        ok = pgp_keygen_write_armored_file(PGP_KEYGEN_EXPORT_PATH, private_binary, private_length, false) &&
            pgp_keygen_write_armored_file(PGP_KEYGEN_PUBLIC_EXPORT_PATH, public_binary, public_length, true);

    free(private_binary);
    free(public_binary);
    return ok;
}

static void pgp_keygen_refresh_menu(App* app) {
    snprintf(
        app->menu_header,
        sizeof(app->menu_header),
        "PGP Keygen Lab\nName: %s\nEmail: %s",
        app->name[0] ? app->name : "<empty>",
        app->email[0] ? app->email : "<empty>");

    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, app->menu_header);
    submenu_add_item(app->submenu, "Edit name", MenuActionEditName, pgp_keygen_menu_callback, app);
    submenu_add_item(app->submenu, "Edit email", MenuActionEditEmail, pgp_keygen_menu_callback, app);
    submenu_add_item(app->submenu, "Edit passphrase", MenuActionEditPassphrase, pgp_keygen_menu_callback, app);
    submenu_add_item(app->submenu, "Save profile", MenuActionSaveProfile, pgp_keygen_menu_callback, app);
    submenu_add_item(app->submenu, "Export OpenPGP", MenuActionExport, pgp_keygen_menu_callback, app);
    submenu_add_item(app->submenu, "About", MenuActionAbout, pgp_keygen_menu_callback, app);
}

static void pgp_keygen_show_text(App* app, const char* text) {
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    app->current_view = PgpKeygenTextBoxView;
    view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenTextBoxView);
}

static const PgpKeygenKeyboardKey* pgp_keygen_keyboard_get_key(
    uint8_t page,
    uint8_t row,
    uint8_t col) {
    furi_assert(page < PGP_KEYGEN_KEYBOARD_PAGES);
    furi_assert(row < PGP_KEYGEN_KEYBOARD_ROWS);
    furi_assert(col < PGP_KEYGEN_KEYBOARD_COLUMNS);

    return &pgp_keygen_keyboard_pages[page][row][col];
}

static bool pgp_keygen_keyboard_append(App* app, char value) {
    size_t length = strlen(app->input_buffer);
    if(length + 1 >= sizeof(app->input_buffer)) {
        return false;
    }

    app->input_buffer[length] = value;
    app->input_buffer[length + 1] = '\0';
    return true;
}

static bool pgp_keygen_keyboard_backspace(App* app) {
    size_t length = strlen(app->input_buffer);
    if(length == 0) {
        return false;
    }

    app->input_buffer[length - 1] = '\0';
    return true;
}

static void pgp_keygen_keyboard_commit(App* app) {
    switch(app->active_field) {
    case PgpKeygenFieldName:
        pgp_keygen_copy_string(app->name, sizeof(app->name), app->input_buffer);
        pgp_keygen_format_name(app->name);
        break;
    case PgpKeygenFieldEmail:
        pgp_keygen_copy_string(app->email, sizeof(app->email), app->input_buffer);
        break;
    case PgpKeygenFieldPassphrase:
        pgp_keygen_copy_string(app->passphrase, sizeof(app->passphrase), app->input_buffer);
        break;
    }

    if(pgp_keygen_profile_save(app)) {
        pgp_keygen_refresh_menu(app);
        app->current_view = PgpKeygenMenuView;
        view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenMenuView);
    } else {
        snprintf(
            app->status_buffer,
            sizeof(app->status_buffer),
            "Validation failed.\n\nCould not save the profile to:\n%s",
            PGP_KEYGEN_PROFILE_PATH);
        pgp_keygen_show_text(app, app->status_buffer);
    }
}

static void pgp_keygen_keyboard_cancel(App* app) {
    app->current_view = PgpKeygenMenuView;
    view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenMenuView);
}

static void pgp_keygen_keyboard_draw_callback(Canvas* canvas, void* model_data) {
    PgpKeygenKeyboardModel* model = model_data;
    App* app = model->app;
    char preview[32];

    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 8, pgp_keygen_field_label(app->active_field));
    canvas_draw_str_aligned(canvas, 126, 8, AlignRight, AlignTop, pgp_keygen_keyboard_page_label(model->page));

    pgp_keygen_make_preview(preview, sizeof(preview), app->input_buffer);
    canvas_draw_str(canvas, 2, 18, preview);

    for(uint8_t row = 0; row < PGP_KEYGEN_KEYBOARD_ROWS; row++) {
        for(uint8_t col = 0; col < PGP_KEYGEN_KEYBOARD_COLUMNS; col++) {
            const PgpKeygenKeyboardKey* key = pgp_keygen_keyboard_get_key(model->page, row, col);
            uint8_t x = PGP_KEYGEN_KEYBOARD_ORIGIN_X + (col * (PGP_KEYGEN_KEY_WIDTH + 1));
            uint8_t y = PGP_KEYGEN_KEYBOARD_ORIGIN_Y + (row * PGP_KEYGEN_KEY_HEIGHT);
            bool selected = (model->row == row) && (model->col == col);

            canvas_set_color(canvas, ColorBlack);
            if(selected) {
                canvas_draw_box(canvas, x, y, PGP_KEYGEN_KEY_WIDTH, PGP_KEYGEN_KEY_HEIGHT);
                canvas_set_color(canvas, ColorWhite);
            } else {
                canvas_draw_frame(canvas, x, y, PGP_KEYGEN_KEY_WIDTH, PGP_KEYGEN_KEY_HEIGHT);
            }

            canvas_draw_str_aligned(
                canvas,
                x + (PGP_KEYGEN_KEY_WIDTH / 2),
                y + (PGP_KEYGEN_KEY_HEIGHT / 2),
                AlignCenter,
                AlignCenter,
                key->label);
        }
    }

    canvas_set_color(canvas, ColorBlack);
}

static void pgp_keygen_keyboard_reset(App* app) {
    with_view_model(
        app->keyboard_view,
        PgpKeygenKeyboardModel* model,
        {
            model->app = app;
            model->page = 0;
            model->row = 0;
            model->col = 0;
            model->revision++;
        },
        false);
}

static void pgp_keygen_start_keyboard_input(App* app, PgpKeygenField field) {
    const char* default_text = "";

    app->active_field = field;
    switch(field) {
    case PgpKeygenFieldName:
        default_text = app->name;
        break;
    case PgpKeygenFieldEmail:
        default_text = app->email;
        break;
    case PgpKeygenFieldPassphrase:
        default_text = app->passphrase;
        break;
    }

    pgp_keygen_copy_string(app->input_buffer, sizeof(app->input_buffer), default_text);
    pgp_keygen_keyboard_reset(app);
    app->current_view = PgpKeygenKeyboardView;
    view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenKeyboardView);
}

static bool pgp_keygen_keyboard_input_callback(InputEvent* event, void* context) {
    App* app = context;
    bool consumed = false;
    bool should_finish = false;

    if(event->type == InputTypeLong && event->key == InputKeyBack) {
        pgp_keygen_keyboard_cancel(app);
        return true;
    }

    if(event->type == InputTypeShort || event->type == InputTypeRepeat) {
        with_view_model(
            app->keyboard_view,
            PgpKeygenKeyboardModel* model,
            {
                bool dirty = false;

                if(event->key == InputKeyLeft) {
                    if(model->col == 0) {
                        model->col = PGP_KEYGEN_KEYBOARD_COLUMNS - 1;
                    } else {
                        model->col--;
                    }
                    dirty = true;
                    consumed = true;
                } else if(event->key == InputKeyRight) {
                    model->col = (model->col + 1) % PGP_KEYGEN_KEYBOARD_COLUMNS;
                    dirty = true;
                    consumed = true;
                } else if(event->key == InputKeyUp) {
                    if(model->row == 0) {
                        model->page = (model->page + PGP_KEYGEN_KEYBOARD_PAGES - 1) %
                                      PGP_KEYGEN_KEYBOARD_PAGES;
                    } else {
                        model->row--;
                    }
                    dirty = true;
                    consumed = true;
                } else if(event->key == InputKeyDown) {
                    if(model->row == (PGP_KEYGEN_KEYBOARD_ROWS - 1)) {
                        model->page = (model->page + 1) % PGP_KEYGEN_KEYBOARD_PAGES;
                    } else {
                        model->row++;
                    }
                    dirty = true;
                    consumed = true;
                } else if(event->key == InputKeyBack) {
                    if(pgp_keygen_keyboard_backspace(app)) {
                        dirty = true;
                    }
                    consumed = true;
                } else if(event->key == InputKeyOk && event->type == InputTypeShort) {
                    const PgpKeygenKeyboardKey* key =
                        pgp_keygen_keyboard_get_key(model->page, model->row, model->col);

                    switch(key->action) {
                    case PgpKeygenKeyboardActionChar:
                        if(pgp_keygen_keyboard_append(app, key->value)) {
                            dirty = true;
                        }
                        consumed = true;
                        break;
                    case PgpKeygenKeyboardActionBackspace:
                        if(pgp_keygen_keyboard_backspace(app)) {
                            dirty = true;
                        }
                        consumed = true;
                        break;
                    case PgpKeygenKeyboardActionSave:
                        should_finish = true;
                        consumed = true;
                        break;
                    }
                }

                if(dirty) {
                    model->revision++;
                }
            },
            consumed);
    }

    if(should_finish) {
        pgp_keygen_keyboard_commit(app);
    }

    return consumed || should_finish;
}

static void pgp_keygen_menu_callback(void* context, uint32_t index) {
    App* app = context;

    switch(index) {
    case MenuActionEditName:
        pgp_keygen_start_keyboard_input(app, PgpKeygenFieldName);
        break;
    case MenuActionEditEmail:
        pgp_keygen_start_keyboard_input(app, PgpKeygenFieldEmail);
        break;
    case MenuActionEditPassphrase:
        pgp_keygen_start_keyboard_input(app, PgpKeygenFieldPassphrase);
        break;
    case MenuActionSaveProfile: {
        if(pgp_keygen_profile_save(app)) {
            snprintf(
                app->status_buffer,
                sizeof(app->status_buffer),
                "Profile saved.\n\nName: %s\nEmail: %s\nPassphrase length: %u\n\nThese values will be loaded next time.",
                app->name[0] ? app->name : "<empty>",
                app->email[0] ? app->email : "<empty>",
                (unsigned)strlen(app->passphrase));
        } else {
            snprintf(
                app->status_buffer,
                sizeof(app->status_buffer),
                "Profile save failed.\n\nCheck that internal storage is available.");
        }
        pgp_keygen_show_text(app, app->status_buffer);
        break;
    }
    case MenuActionExport: {
        if(pgp_keygen_write_export(app)) {
            snprintf(
                app->status_buffer,
                sizeof(app->status_buffer),
                "Private key saved to:\n%s\nPublic key saved to:\n%s\n\nOpenPGP keypair generated for:\n%s <%s>",
                PGP_KEYGEN_EXPORT_PATH,
                PGP_KEYGEN_PUBLIC_EXPORT_PATH,
                app->name[0] ? app->name : "<empty>",
                app->email[0] ? app->email : "<empty>");
        } else {
            snprintf(
                app->status_buffer,
                sizeof(app->status_buffer),
                "Export failed.\n\nFill in name and email first, then try again.\nIf storage is unavailable, check the device memory or SD card.");
        }
        pgp_keygen_show_text(app, app->status_buffer);
        break;
    }
    case MenuActionAbout:
        snprintf(
            app->status_buffer,
            sizeof(app->status_buffer),
            "PGP Keygen Lab\n\nSave profile stores name and email locally. Export builds a real OpenPGP ECDSA P-256 private key block with a self-signature.\n\nLong Back exits the keyboard.");
        pgp_keygen_show_text(app, app->status_buffer);
        break;
    }
}

static bool pgp_keygen_navigation_callback(void* context) {
    App* app = context;
    if(app->current_view != PgpKeygenMenuView) {
        app->current_view = PgpKeygenMenuView;
        view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenMenuView);
        return true;
    }

    return false;
}

static App* pgp_keygen_app_alloc(void) {
    App* app = malloc(sizeof(App));
    furi_assert(app);

    memset(app, 0, sizeof(App));
    snprintf(app->name, sizeof(app->name), "%s", "Javier Morales");
    snprintf(app->email, sizeof(app->email), "%s", "javiermorales36@github.com");
    app->passphrase[0] = '\0';
    pgp_keygen_profile_load(app);
    app->current_view = PgpKeygenMenuView;

    app->view_dispatcher = view_dispatcher_alloc();
    app->submenu = submenu_alloc();
    app->keyboard_view = view_alloc();
    app->text_box = text_box_alloc();

    view_set_context(app->keyboard_view, app);
    view_allocate_model(
        app->keyboard_view, ViewModelTypeLocking, sizeof(PgpKeygenKeyboardModel));
    with_view_model(
        app->keyboard_view,
        PgpKeygenKeyboardModel* model,
        {
            model->app = app;
            model->page = 0;
            model->row = 0;
            model->col = 0;
            model->revision = 0;
        },
        false);
    view_set_draw_callback(app->keyboard_view, pgp_keygen_keyboard_draw_callback);
    view_set_input_callback(app->keyboard_view, pgp_keygen_keyboard_input_callback);

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(
        app->view_dispatcher,
        pgp_keygen_navigation_callback);

    view_dispatcher_add_view(
        app->view_dispatcher,
        PgpKeygenMenuView,
        submenu_get_view(app->submenu));
    view_dispatcher_add_view(
        app->view_dispatcher,
        PgpKeygenKeyboardView,
        app->keyboard_view);
    view_dispatcher_add_view(
        app->view_dispatcher,
        PgpKeygenTextBoxView,
        text_box_get_view(app->text_box));

    pgp_keygen_refresh_menu(app);
    return app;
}

static void pgp_keygen_app_free(App* app) {
    furi_assert(app);

    pgp_keygen_profile_save(app);
    view_dispatcher_remove_view(app->view_dispatcher, PgpKeygenMenuView);
    view_dispatcher_remove_view(app->view_dispatcher, PgpKeygenKeyboardView);
    view_dispatcher_remove_view(app->view_dispatcher, PgpKeygenTextBoxView);

    text_box_free(app->text_box);
    view_free(app->keyboard_view);
    submenu_free(app->submenu);
    view_dispatcher_free(app->view_dispatcher);
    free(app);
}

int32_t pgp_keygen_app(void* p) {
    UNUSED(p);

    App* app = pgp_keygen_app_alloc();
    Gui* gui = furi_record_open(RECORD_GUI);

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    app->current_view = PgpKeygenMenuView;
    view_dispatcher_switch_to_view(app->view_dispatcher, PgpKeygenMenuView);
    view_dispatcher_run(app->view_dispatcher);

    pgp_keygen_app_free(app);
    furi_record_close(RECORD_GUI);
    return 0;
}
