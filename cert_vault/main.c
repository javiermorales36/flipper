#include <furi.h>
#include <gui/gui.h>
#include <gui/modules/file_browser.h>
#include <gui/modules/submenu.h>
#include <gui/modules/text_box.h>
#include <gui/view_dispatcher.h>
#include <storage/storage.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CERT_VAULT_PATH_SIZE 256u
#define CERT_VAULT_NAME_SIZE 96u
#define CERT_VAULT_SUBJECT_SIZE 256u
#define CERT_VAULT_ISSUER_SIZE 256u
#define CERT_VAULT_SERIAL_SIZE 96u
#define CERT_VAULT_DATE_SIZE 40u
#define CERT_VAULT_KEY_TYPE_SIZE 32u
#define CERT_VAULT_BUNDLE_KIND_SIZE 32u
#define CERT_VAULT_STATUS_SIZE 8192u
#define CERT_VAULT_FILE_BUFFER_SIZE 512u
#define CERT_VAULT_HEADER_BUFFER_SIZE 4096u
#define CERT_VAULT_INSTALLED_DIR "/ext/apps_data/cert_vault/installed"
#define CERT_VAULT_IMPORT_EXTENSION ".fvp12"
#define CERT_VAULT_FORMAT "FVP12-1"

typedef enum {
    CertVaultViewMenu,
    CertVaultViewTextBox,
    CertVaultViewBrowser,
} CertVaultView;

typedef enum {
    CertVaultActionInstallBundle,
    CertVaultActionInventory,
    CertVaultActionAbout,
} CertVaultAction;

typedef struct {
    char alias[CERT_VAULT_NAME_SIZE];
    char subject[CERT_VAULT_SUBJECT_SIZE];
    char issuer[CERT_VAULT_ISSUER_SIZE];
    char serial[CERT_VAULT_SERIAL_SIZE];
    char not_before[CERT_VAULT_DATE_SIZE];
    char not_after[CERT_VAULT_DATE_SIZE];
    char key_type[CERT_VAULT_KEY_TYPE_SIZE];
    char bundle_kind[CERT_VAULT_BUNDLE_KIND_SIZE];
    char source_name[CERT_VAULT_NAME_SIZE];
} CertVaultBundleMetadata;

typedef struct {
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    TextBox* text_box;
    FileBrowser* file_browser;
    FuriString* browser_result;
    FuriString* browser_start_path;
    CertVaultView current_view;
    char selected_path[CERT_VAULT_PATH_SIZE];
    char status[CERT_VAULT_STATUS_SIZE];
} CertVaultApp;

static void cert_vault_refresh_menu(CertVaultApp* app);
static void cert_vault_show_text(CertVaultApp* app, const char* text);
static void cert_vault_menu_callback(void* context, uint32_t index);
static void cert_vault_file_browser_callback(void* context);
static bool cert_vault_navigation_callback(void* context);

static void cert_vault_copy_string(char* target, size_t target_size, const char* source) {
    if(target_size == 0u) {
        return;
    }

    snprintf(target, target_size, "%s", source ? source : "");
}

static bool cert_vault_string_ends_with(const char* text, const char* suffix) {
    const size_t text_length = strlen(text);
    const size_t suffix_length = strlen(suffix);

    if(suffix_length > text_length) {
        return false;
    }

    return strcmp(text + text_length - suffix_length, suffix) == 0;
}

static void cert_vault_reset_metadata(CertVaultBundleMetadata* metadata) {
    memset(metadata, 0, sizeof(CertVaultBundleMetadata));
}

static void cert_vault_status_reset(CertVaultApp* app) {
    app->status[0] = '\0';
}

static void cert_vault_status_append(CertVaultApp* app, const char* format, ...) {
    va_list args;
    const size_t used = strlen(app->status);

    if(used >= sizeof(app->status) - 1u) {
        return;
    }

    va_start(args, format);
    vsnprintf(app->status + used, sizeof(app->status) - used, format, args);
    va_end(args);
}

static void cert_vault_show_text(CertVaultApp* app, const char* text) {
    text_box_reset(app->text_box);
    text_box_set_text(app->text_box, text);
    app->current_view = CertVaultViewTextBox;
    view_dispatcher_switch_to_view(app->view_dispatcher, CertVaultViewTextBox);
}

static void cert_vault_sanitize_alias(const char* input, char* output, size_t output_size) {
    size_t write_index = 0u;

    if(output_size == 0u) {
        return;
    }

    for(size_t index = 0u; input[index] != '\0' && write_index + 1u < output_size; index++) {
        const char character = input[index];
        if((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '_' || character == '-' ||
           character == '.') {
            output[write_index++] = character;
        } else if(character == ' ' || character == '/' || character == '\\') {
            output[write_index++] = '_';
        }
    }

    if(write_index == 0u && output_size > 1u) {
        output[write_index++] = 'c';
        output[write_index++] = 'e';
        output[write_index++] = 'r';
        output[write_index++] = 't';
    }

    output[write_index] = '\0';
}

static void cert_vault_path_basename(const char* path, char* output, size_t output_size) {
    const char* slash = strrchr(path, '/');
    const char* base = slash ? (slash + 1) : path;
    cert_vault_copy_string(output, output_size, base);
}

static bool cert_vault_read_bundle_metadata(const char* path, CertVaultBundleMetadata* metadata) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    char header[CERT_VAULT_HEADER_BUFFER_SIZE];
    bool ok = false;
    bool format_ok = false;

    cert_vault_reset_metadata(metadata);

    if(storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        const size_t read_size = storage_file_read(file, header, sizeof(header) - 1u);
        header[read_size] = '\0';

        char* cursor = header;
        while(*cursor != '\0') {
            char* line = cursor;
            char* next_line = strchr(cursor, '\n');
            if(next_line != NULL) {
                *next_line = '\0';
                cursor = next_line + 1;
            } else {
                cursor += strlen(cursor);
            }

            if(line[0] == '\r') {
                line++;
            }

            const size_t line_length = strlen(line);
            if(line_length > 0u && line[line_length - 1u] == '\r') {
                line[line_length - 1u] = '\0';
            }

            char* separator = strchr(line, '=');
            if(separator == NULL) {
                continue;
            }

            *separator = '\0';
            const char* key = line;
            const char* value = separator + 1;

            if(strcmp(key, "wrapped_p12_b64") == 0 || strcmp(key, "wrapped_keyset_b64") == 0) {
                break;
            } else if(strcmp(key, "format") == 0) {
                format_ok = strcmp(value, CERT_VAULT_FORMAT) == 0;
            } else if(strcmp(key, "bundle_kind") == 0) {
                cert_vault_copy_string(metadata->bundle_kind, sizeof(metadata->bundle_kind), value);
            } else if(strcmp(key, "alias") == 0) {
                cert_vault_copy_string(metadata->alias, sizeof(metadata->alias), value);
            } else if(strcmp(key, "subject") == 0) {
                cert_vault_copy_string(metadata->subject, sizeof(metadata->subject), value);
            } else if(strcmp(key, "issuer") == 0) {
                cert_vault_copy_string(metadata->issuer, sizeof(metadata->issuer), value);
            } else if(strcmp(key, "serial") == 0) {
                cert_vault_copy_string(metadata->serial, sizeof(metadata->serial), value);
            } else if(strcmp(key, "not_before") == 0) {
                cert_vault_copy_string(metadata->not_before, sizeof(metadata->not_before), value);
            } else if(strcmp(key, "not_after") == 0) {
                cert_vault_copy_string(metadata->not_after, sizeof(metadata->not_after), value);
            } else if(strcmp(key, "key_type") == 0) {
                cert_vault_copy_string(metadata->key_type, sizeof(metadata->key_type), value);
            } else if(strcmp(key, "source_name") == 0) {
                cert_vault_copy_string(metadata->source_name, sizeof(metadata->source_name), value);
            }
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    if(metadata->alias[0] == '\0') {
        char base_name[CERT_VAULT_NAME_SIZE];
        cert_vault_path_basename(path, base_name, sizeof(base_name));
        if(cert_vault_string_ends_with(base_name, CERT_VAULT_IMPORT_EXTENSION)) {
            base_name[strlen(base_name) - strlen(CERT_VAULT_IMPORT_EXTENSION)] = '\0';
        }
        cert_vault_sanitize_alias(base_name, metadata->alias, sizeof(metadata->alias));
    }

    ok = format_ok && metadata->alias[0] != '\0';
    return ok;
}

static bool cert_vault_ensure_storage_dirs(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    bool ok = storage_simply_mkdir(storage, "/ext/apps_data") &&
              storage_simply_mkdir(storage, "/ext/apps_data/cert_vault") &&
              storage_simply_mkdir(storage, CERT_VAULT_INSTALLED_DIR);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool cert_vault_build_installed_path(
    const char* alias,
    char* output,
    size_t output_size) {
    char safe_alias[CERT_VAULT_NAME_SIZE];
    cert_vault_sanitize_alias(alias, safe_alias, sizeof(safe_alias));
    const int length = snprintf(
        output, output_size, "%s/%s%s", CERT_VAULT_INSTALLED_DIR, safe_alias, CERT_VAULT_IMPORT_EXTENSION);
    return length > 0 && (size_t)length < output_size;
}

static bool cert_vault_copy_file(const char* source_path, const char* destination_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* source = storage_file_alloc(storage);
    File* destination = storage_file_alloc(storage);
    uint8_t buffer[CERT_VAULT_FILE_BUFFER_SIZE];
    bool ok = false;

    if(storage_file_open(source, source_path, FSAM_READ, FSOM_OPEN_EXISTING) &&
       storage_file_open(destination, destination_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = true;
        while(!storage_file_eof(source)) {
            const size_t read_size = storage_file_read(source, buffer, sizeof(buffer));
            if(read_size == 0u) {
                break;
            }

            if(storage_file_write(destination, buffer, read_size) != read_size) {
                ok = false;
                break;
            }
        }

        if(ok) {
            ok = storage_file_sync(destination);
        }
    }

    storage_file_close(source);
    storage_file_close(destination);
    storage_file_free(source);
    storage_file_free(destination);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool cert_vault_install_bundle(CertVaultApp* app, const char* source_path) {
    CertVaultBundleMetadata metadata;
    char destination_path[CERT_VAULT_PATH_SIZE];

    cert_vault_status_reset(app);

    if(!cert_vault_read_bundle_metadata(source_path, &metadata)) {
        cert_vault_status_append(app, "Bundle no valido o formato no soportado.\n%s", source_path);
        return false;
    }

    if(!cert_vault_ensure_storage_dirs()) {
        cert_vault_status_append(app, "No se pudo preparar el vault en la SD.");
        return false;
    }

    if(!cert_vault_build_installed_path(metadata.alias, destination_path, sizeof(destination_path))) {
        cert_vault_status_append(app, "No se pudo construir la ruta de instalacion.");
        return false;
    }

    if(strcmp(source_path, destination_path) != 0 && !cert_vault_copy_file(source_path, destination_path)) {
        cert_vault_status_append(app, "No se pudo copiar el bundle al vault.\n%s", destination_path);
        return false;
    }

    cert_vault_status_append(app, "Bundle instalado OK\n\nAlias: %s", metadata.alias);
    if(metadata.subject[0] != '\0') {
        cert_vault_status_append(app, "\nSubject: %s", metadata.subject);
    }
    if(metadata.key_type[0] != '\0') {
        cert_vault_status_append(app, "\nKey: %s", metadata.key_type);
    }
    if(metadata.bundle_kind[0] != '\0') {
        cert_vault_status_append(app, "\nBundle: %s", metadata.bundle_kind);
    }
    if(metadata.not_after[0] != '\0') {
        cert_vault_status_append(app, "\nExpira: %s", metadata.not_after);
    }
    cert_vault_status_append(app, "\n\nDestino: %s", destination_path);
    return true;
}

static bool cert_vault_build_inventory(CertVaultApp* app) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* directory = storage_file_alloc(storage);
    char file_name[CERT_VAULT_NAME_SIZE];
    bool any_entries = false;

    cert_vault_status_reset(app);

    if(!cert_vault_ensure_storage_dirs()) {
        cert_vault_status_append(app, "No se pudo preparar el directorio del vault.");
        storage_file_free(directory);
        furi_record_close(RECORD_STORAGE);
        return false;
    }

    if(!storage_dir_open(directory, CERT_VAULT_INSTALLED_DIR)) {
        cert_vault_status_append(app, "No se pudo abrir el directorio del vault.");
        storage_dir_close(directory);
        storage_file_free(directory);
        furi_record_close(RECORD_STORAGE);
        return false;
    }

    cert_vault_status_append(app, "Instalados\n\n");

    while(storage_dir_read(directory, NULL, file_name, sizeof(file_name))) {
        char full_path[CERT_VAULT_PATH_SIZE];
        CertVaultBundleMetadata metadata;

        if(!cert_vault_string_ends_with(file_name, CERT_VAULT_IMPORT_EXTENSION)) {
            continue;
        }

        if(snprintf(full_path, sizeof(full_path), "%s/%s", CERT_VAULT_INSTALLED_DIR, file_name) <= 0) {
            continue;
        }

        if(!cert_vault_read_bundle_metadata(full_path, &metadata)) {
            cert_vault_status_append(app, "%s\n  bundle ilegible\n\n", file_name);
            any_entries = true;
            continue;
        }

        cert_vault_status_append(app, "%s\n", metadata.alias);
        if(metadata.subject[0] != '\0') {
            cert_vault_status_append(app, "  Subject: %s\n", metadata.subject);
        }
        if(metadata.key_type[0] != '\0') {
            cert_vault_status_append(app, "  Key: %s\n", metadata.key_type);
        }
        if(metadata.bundle_kind[0] != '\0') {
            cert_vault_status_append(app, "  Bundle: %s\n", metadata.bundle_kind);
        }
        if(metadata.not_after[0] != '\0') {
            cert_vault_status_append(app, "  Expira: %s\n", metadata.not_after);
        }
        cert_vault_status_append(app, "\n");
        any_entries = true;
    }

    if(!any_entries) {
        cert_vault_status_append(
            app,
            "Vault vacio.\n\nGenera un bundle .fvp12 en el PC y luego instalalo desde esta app.");
    }

    storage_dir_close(directory);
    storage_file_free(directory);
    furi_record_close(RECORD_STORAGE);
    return true;
}

static void cert_vault_refresh_menu(CertVaultApp* app) {
    UNUSED(app);
    submenu_reset(app->submenu);
    submenu_set_header(app->submenu, "Cert Vault");
    submenu_add_item(
        app->submenu, "Instalar .fvp12", CertVaultActionInstallBundle, cert_vault_menu_callback, app);
    submenu_add_item(app->submenu, "Inventario", CertVaultActionInventory, cert_vault_menu_callback, app);
    submenu_add_item(app->submenu, "Acerca de", CertVaultActionAbout, cert_vault_menu_callback, app);
}

static void cert_vault_menu_callback(void* context, uint32_t index) {
    CertVaultApp* app = context;

    if(index == CertVaultActionInstallBundle) {
        file_browser_start(app->file_browser, app->browser_start_path);
        app->current_view = CertVaultViewBrowser;
        view_dispatcher_switch_to_view(app->view_dispatcher, CertVaultViewBrowser);
        return;
    }

    if(index == CertVaultActionInventory) {
        cert_vault_build_inventory(app);
        cert_vault_show_text(app, app->status);
        return;
    }

    cert_vault_status_reset(app);
    cert_vault_status_append(
        app,
        "Cert Vault\n\n1. Convierte el .p12/.pfx en el PC con tools/p12_to_flipper_bundle.py\n2. Copia el .fvp12 a la SD\n3. Instala el bundle desde esta app\n\nRol actual del Flipper:\n- guardar e inventariar identidades\n- llevar el vault contigo\n- preparar el siguiente paso de aprobacion o modo token\n\nEl PDF firmado se genera en el PC. El modo token USB/CCID vendra despues.");
    cert_vault_show_text(app, app->status);
}

static void cert_vault_file_browser_callback(void* context) {
    CertVaultApp* app = context;
    cert_vault_copy_string(
        app->selected_path,
        sizeof(app->selected_path),
        furi_string_get_cstr(app->browser_result));
    file_browser_stop(app->file_browser);
    cert_vault_install_bundle(app, app->selected_path);
    cert_vault_show_text(app, app->status);
}

static bool cert_vault_navigation_callback(void* context) {
    CertVaultApp* app = context;

    if(app->current_view == CertVaultViewBrowser) {
        file_browser_stop(app->file_browser);
    }

    if(app->current_view != CertVaultViewMenu) {
        cert_vault_refresh_menu(app);
        app->current_view = CertVaultViewMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, CertVaultViewMenu);
        return true;
    }

    return false;
}

static CertVaultApp* cert_vault_app_alloc(void) {
    CertVaultApp* app = malloc(sizeof(CertVaultApp));
    furi_assert(app);

    memset(app, 0, sizeof(CertVaultApp));
    app->view_dispatcher = view_dispatcher_alloc();
    app->submenu = submenu_alloc();
    app->text_box = text_box_alloc();
    app->browser_result = furi_string_alloc();
    app->browser_start_path = furi_string_alloc();
    furi_string_set(app->browser_start_path, "/ext");
    app->file_browser = file_browser_alloc(app->browser_result);
    file_browser_configure(
        app->file_browser, CERT_VAULT_IMPORT_EXTENSION, "/ext", false, true, NULL, false);
    file_browser_set_callback(app->file_browser, cert_vault_file_browser_callback, app);

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, cert_vault_navigation_callback);

    view_dispatcher_add_view(app->view_dispatcher, CertVaultViewMenu, submenu_get_view(app->submenu));
    view_dispatcher_add_view(app->view_dispatcher, CertVaultViewTextBox, text_box_get_view(app->text_box));
    view_dispatcher_add_view(app->view_dispatcher, CertVaultViewBrowser, file_browser_get_view(app->file_browser));

    cert_vault_refresh_menu(app);
    return app;
}

static void cert_vault_app_free(CertVaultApp* app) {
    furi_assert(app);

    view_dispatcher_remove_view(app->view_dispatcher, CertVaultViewMenu);
    view_dispatcher_remove_view(app->view_dispatcher, CertVaultViewTextBox);
    view_dispatcher_remove_view(app->view_dispatcher, CertVaultViewBrowser);

    submenu_free(app->submenu);
    text_box_free(app->text_box);
    file_browser_free(app->file_browser);
    view_dispatcher_free(app->view_dispatcher);
    furi_string_free(app->browser_result);
    furi_string_free(app->browser_start_path);
    free(app);
}

int32_t cert_vault_app(void* p) {
    UNUSED(p);

    CertVaultApp* app = cert_vault_app_alloc();
    Gui* gui = furi_record_open(RECORD_GUI);

    view_dispatcher_attach_to_gui(app->view_dispatcher, gui, ViewDispatcherTypeFullscreen);
    app->current_view = CertVaultViewMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, CertVaultViewMenu);
    view_dispatcher_run(app->view_dispatcher);

    cert_vault_app_free(app);
    furi_record_close(RECORD_GUI);
    return 0;
}