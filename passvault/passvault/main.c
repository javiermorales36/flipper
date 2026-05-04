#include "main.h"

#include "views/pin_view.h"
#include "views/saved_passwords.h"
#include "views/delete_password.h"
#include "views/bookmarks.h"
#include "views/generate_password.h"
#include "views/import_result.h"
#include "views/credential_detail.h"
#include "textInput/textInput.h"
#include "passwordStorage/passwordStorage.h"

static void pv_show_result(AppContext* app, const char* text) {
    snprintf(app->result_text, sizeof(app->result_text), "%s", text);
    text_box_reset(app->result_text_box);
    text_box_set_text(app->result_text_box, app->result_text);
    app->current_view = ViewResultText;
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewResultText);
}

static const char* pv_shorten_path(const char* path, char* buf, size_t buf_size) {
    size_t len;

    if(!path || buf_size == 0) return "";
    len = strlen(path);
    if(len + 1 <= buf_size) return path;
    if(buf_size <= 4) {
        buf[0] = '\0';
        return buf;
    }

    snprintf(buf, buf_size, "...%s", path + len - (buf_size - 4));
    return buf;
}

static void pv_open_file_browser(AppContext* app, FileCryptoAction action) {
    app->pending_file_action = action;
    furi_string_set(app->browser_start_path, VAULT_DIR);

    if(action == FileCryptoActionDecryptFile) {
        file_browser_configure(
            app->file_browser, FILE_CRYPTO_EXTENSION, VAULT_DIR, false, true, NULL, false);
    } else {
        file_browser_configure(app->file_browser, "*", VAULT_DIR, false, true, NULL, false);
    }

    file_browser_start(app->file_browser, app->browser_start_path);
    app->current_view = ViewFileBrowser;
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewFileBrowser);
}

static void pv_run_folder_action(AppContext* app, bool encrypt) {
    VaultBatchResult result = encrypt ?
        pv_vault_encrypt_tree(VAULT_DIR, app->delete_source_files) :
        pv_vault_decrypt_tree(VAULT_DIR, app->delete_source_files);

    snprintf(
        app->result_text,
        sizeof(app->result_text),
        "%s carpeta\n\nRuta: %s\nProcesados: %u\nOmitidos: %u\n\nBorrar origen: %s\nNotas:\n- No toca vault.fhs ni import.csv\n- Los archivos cifrados usan %s\n- Los descifrados salen como .dec",
        encrypt ? "Cifrado completo" : "Descifrado completo",
        VAULT_DIR,
        (unsigned)result.processed,
        (unsigned)result.skipped,
        app->delete_source_files ? "SI" : "NO",
        FILE_CRYPTO_EXTENSION);
    pv_show_result(app, app->result_text);
}

static void pv_file_browser_cb(void* context) {
    AppContext* app = context;
    char output_path[PATH_SIZE];
    char input_display[96];
    char output_display[96];
    VaultResult rc = VaultIoError;

    strncpy(
        app->selected_file_path,
        furi_string_get_cstr(app->browser_result),
        sizeof(app->selected_file_path) - 1);
    app->selected_file_path[sizeof(app->selected_file_path) - 1] = '\0';

    file_browser_stop(app->file_browser);

    if(app->pending_file_action == FileCryptoActionEncryptFile) {
        if(!pv_vault_build_file_output_path(
               app->selected_file_path, true, output_path, sizeof(output_path))) {
            snprintf(app->result_text, sizeof(app->result_text), "Ruta de salida demasiado larga.");
            pv_show_result(app, app->result_text);
            return;
        }
        rc = pv_vault_encrypt_file(app->selected_file_path, output_path, app->delete_source_files);
        if(rc == VaultOk) {
            snprintf(
                app->result_text,
                sizeof(app->result_text),
            "Archivo cifrado OK\n\nEntrada:\n%s\n\nSalida:\n%s\n\nBorrar origen: %s",
                pv_shorten_path(app->selected_file_path, input_display, sizeof(input_display)),
            pv_shorten_path(output_path, output_display, sizeof(output_display)),
            app->delete_source_files ? "SI" : "NO");
        }
    } else if(app->pending_file_action == FileCryptoActionDecryptFile) {
        if(!pv_vault_build_file_output_path(
               app->selected_file_path, false, output_path, sizeof(output_path))) {
            snprintf(app->result_text, sizeof(app->result_text), "Ruta de salida demasiado larga.");
            pv_show_result(app, app->result_text);
            return;
        }
        rc = pv_vault_decrypt_file(app->selected_file_path, output_path, app->delete_source_files);
        if(rc == VaultOk) {
            snprintf(
                app->result_text,
                sizeof(app->result_text),
            "Archivo descifrado OK\n\nEntrada:\n%s\n\nSalida:\n%s\n\nBorrar origen: %s",
                pv_shorten_path(app->selected_file_path, input_display, sizeof(input_display)),
            pv_shorten_path(output_path, output_display, sizeof(output_display)),
            app->delete_source_files ? "SI" : "NO");
        }
    }

    if(rc != VaultOk) {
        snprintf(
            app->result_text,
            sizeof(app->result_text),
            "No se pudo %s el archivo.\n\nRuta:\n%s\n\nCod: %d",
            app->pending_file_action == FileCryptoActionEncryptFile ? "cifrar" : "descifrar",
                pv_shorten_path(app->selected_file_path, input_display, sizeof(input_display)),
            (int)rc);
    }

    app->pending_file_action = FileCryptoActionNone;
    pv_show_result(app, app->result_text);
}

/* ============================================================
 *  Main menu – draw
 * ============================================================ */

static void mm_draw(Canvas* canvas, void* model) {
    AppContext** m = model;
    AppContext* app = *m;
    if(!app) return;

    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_str_aligned(canvas, 64, 7, AlignCenter, AlignCenter,
                            "PassVault");
    canvas_draw_line(canvas, 0, 12, 128, 12);

#define MM_VISIBLE 5

    size_t mm_start = app->scroll_offset;
    size_t mm_end   = mm_start + MM_VISIBLE;
    if(mm_end > MENU_ITEMS) mm_end = MENU_ITEMS;

    for(size_t i = mm_start; i < mm_end; i++) {
        int y = 24 + (int)(i - mm_start) * 9;

        if(i == app->selected) {
            canvas_set_color(canvas, ColorBlack);
            canvas_draw_box(canvas, 0, y - 8, 128, 9);
            canvas_set_color(canvas, ColorWhite);
        } else {
            canvas_set_color(canvas, ColorBlack);
        }
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 4, y, app->items[i]);
    }

    /* scroll indicator bar on the right */
    if(MENU_ITEMS > MM_VISIBLE) {
        canvas_set_color(canvas, ColorBlack);
        {
            int bar_h = 44;
            int ind_h = bar_h * MM_VISIBLE / (int)MENU_ITEMS;
            int scroll_range = (int)MENU_ITEMS - MM_VISIBLE;
            int ind_y;

            if(ind_h < 6) ind_h = 6;
            ind_y = 16 + (bar_h - ind_h) * (int)mm_start / scroll_range;
            canvas_draw_frame(canvas, 124, 16, 3, bar_h);
            canvas_draw_box(canvas, 124, ind_y, 3, ind_h);
        }
    }
}

/* ============================================================
 *  Main menu – input
 * ============================================================ */

static bool mm_input(InputEvent* event, void* context) {
    AppContext* app = context;

    if(event->type == InputTypeShort) {
        switch(event->key) {
        case InputKeyUp:
            if(app->selected > 0) {
                app->selected--;
                if(app->selected < app->scroll_offset)
                    app->scroll_offset--;
            }
            return true;

        case InputKeyDown:
            if(app->selected + 1 < MENU_ITEMS) {
                app->selected++;
                if(app->selected >= app->scroll_offset + MM_VISIBLE)
                    app->scroll_offset++;
            }
            return true;

        case InputKeyBack:
            app->running = false;
            view_dispatcher_stop(app->view_dispatcher);
            return true;

        case InputKeyOk:
            switch(app->selected) {
            /* 0 – Saved Passwords */
            case 0:
                /* credentials already in memory after unlock */
                app->selected      = 0;
                app->scroll_offset = 0;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewSavedPasswords);
                break;

            /* 1 – Add Password */
            case 1:
                app->tmp_name[0]     = '\0';
                app->tmp_username[0] = '\0';
                app->tmp_password[0] = '\0';
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewTextInputCredentialName);
                break;

            /* 2 – Delete Password */
            case 2:
                /* credentials already in memory */
                app->selected       = 0;
                app->scroll_offset  = 0;
                app->confirm_delete = false;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewDeletePassword);
                break;

            /* 3 – Bookmarks */
            case 3:
                /* credentials already in memory */
                app->bkm_selected      = 0;
                app->bkm_scroll_offset = 0;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewBookmarks);
                break;

            /* 4 – Generate Password */
            case 4:
                pv_gen_generate(app);
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewGeneratePassword);
                break;

            /* 5 – Change PIN */
            case 5:
                app->setting_pin = true;
                memset(app->pin_input, '0', PIN_LENGTH);
                app->pin_input[PIN_LENGTH] = '\0';
                app->pin_cursor = 0;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewPinEntry);
                break;

            /* 6 – Import CSV */
            case 6: {
                size_t result = pv_import_csv(app, IMPORT_FILE);
                if(result == SIZE_MAX) {
                    app->import_error = true;
                    app->import_count = 0;
                } else {
                    app->import_error = false;
                    app->import_count = result;
                }
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewImportResult);
                break;
            }

            /* 7 – Encrypt File */
            case 7:
                pv_open_file_browser(app, FileCryptoActionEncryptFile);
                break;

            /* 8 – Decrypt File */
            case 8:
                pv_open_file_browser(app, FileCryptoActionDecryptFile);
                break;

            /* 9 – Encrypt Folder */
            case 9:
                pv_run_folder_action(app, true);
                break;

            /* 10 – Decrypt Folder */
            case 10:
                pv_run_folder_action(app, false);
                break;

            /* 11 – Toggle delete source */
            case 11:
                app->delete_source_files = !app->delete_source_files;
                app->items[11] = app->delete_source_files ? "Delete Source: ON" : "Delete Source: OFF";
                break;

            default:
                break;
            }

            /* reset main menu selection after entering a sub-view */
            if(app->selected != 0) {
                /* keep selection so user can see where they were */
            }
            return true;

        default:
            break;
        }
    }
    return false;
}

/* ============================================================
 *  Navigation event callback (Back from sub-views)
 * ============================================================ */

static bool nav_cb(void* context) {
    AppContext* app = context;

    if(app->current_view == ViewFileBrowser) {
        file_browser_stop(app->file_browser);
    }

    /* If we are returning from the detail view, go back to the originating
       list instead of the main menu. */
    if(app->detail_origin == ViewSavedPasswords) {
        app->detail_origin = ViewMainMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher,
                                       ViewSavedPasswords);
        return true;
    }
    if(app->detail_origin == ViewBookmarks) {
        app->detail_origin = ViewMainMenu;
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewBookmarks);
        return true;
    }

    app->selected      = 0;
    app->scroll_offset = 0;
    app->current_view  = ViewMainMenu;
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
    return true;
}

/* ============================================================
 *  App entry point
 * ============================================================ */

int32_t passvault_app(void* p) {
    UNUSED(p);

    /* ---- allocate context ---- */
    AppContext* app = malloc(sizeof(AppContext));
    if(!app) return -1;
    memset(app, 0, sizeof(AppContext));

    /* ---- ensure storage directory exists ---- */
    pv_ensure_vault_dir();

    /* ---- first-run detection ---- */
    memset(app->pin_input, '0', PIN_LENGTH);
    app->pin_input[PIN_LENGTH] = '\0';

    app->vault_first_run = !pv_vault_exists();
    if(app->vault_first_run) {
        /* first launch – user must create a PIN */
        app->setting_pin = true;
    } else {
        /* vault exists – ask for PIN to unlock */
        app->setting_pin = false;
    }
    /* credentials are loaded during vault unlock (not at startup) */
    app->credentials_number = 0;

    /* ---- menu labels ---- */
    app->items[0] = "Saved Passwords";
    app->items[1] = "Add Password";
    app->items[2] = "Delete Password";
    app->items[3] = "Bookmarks";
    app->items[4] = "Generate Password";
    app->items[5] = "Change PIN";
    app->items[6] = "Import CSV";
    app->items[7] = "Encrypt File";
    app->items[8] = "Decrypt File";
    app->items[9] = "Encrypt Folder";
    app->items[10] = "Decrypt Folder";
    app->delete_source_files = false;
    app->items[11] = "Delete Source: OFF";

    /* ---- generator defaults ---- */
    app->gen_length = 12;
    app->gen_level  = 3; /* Ab12 */
    pv_gen_build_alphabet(app);

    /* ---- notifications ---- */
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    /* ---- GUI ---- */
    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    app->result_text_box = text_box_alloc();
    app->browser_result = furi_string_alloc();
    app->browser_start_path = furi_string_alloc();
    furi_string_set(app->browser_start_path, VAULT_DIR);
    app->file_browser = file_browser_alloc(app->browser_result);
    file_browser_configure(app->file_browser, "*", VAULT_DIR, false, true, NULL, false);
    file_browser_set_callback(app->file_browser, pv_file_browser_cb, app);
    app->current_view = ViewPinEntry;

    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);
    view_dispatcher_set_navigation_event_callback(app->view_dispatcher, nav_cb);
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui,
                                  ViewDispatcherTypeFullscreen);

    /* ---- main menu view ---- */
    app->main_menu_view = view_alloc();
    view_set_context(app->main_menu_view, app);
    view_allocate_model(app->main_menu_view, ViewModelTypeLockFree,
                        sizeof(AppContext*));
    AppContext** mm_model = view_get_model(app->main_menu_view);
    *mm_model = app;
    view_set_draw_callback(app->main_menu_view, mm_draw);
    view_set_input_callback(app->main_menu_view, mm_input);
    view_dispatcher_add_view(app->view_dispatcher, ViewMainMenu,
                             app->main_menu_view);

    /* ---- PIN view ---- */
    app->pin_view = pv_pin_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewPinEntry,
                             app->pin_view);

    /* ---- saved passwords view ---- */
    app->saved_passwords_view = pv_saved_passwords_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewSavedPasswords,
                             app->saved_passwords_view);

    /* ---- delete password view ---- */
    app->delete_password_view = pv_delete_password_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewDeletePassword,
                             app->delete_password_view);

    /* ---- bookmarks view ---- */
    app->bookmarks_view = pv_bookmarks_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewBookmarks,
                             app->bookmarks_view);

    /* ---- generate password view ---- */
    app->generate_password_view = pv_generate_password_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewGeneratePassword,
                             app->generate_password_view);

    /* ---- import result view ---- */
    app->import_result_view = pv_import_result_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewImportResult,
                             app->import_result_view);

    /* ---- credential detail view ---- */
    app->credential_detail_view = pv_credential_detail_view_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewCredentialDetail,
                             app->credential_detail_view);

    /* ---- text input views ---- */
    app->ti_cred_name = pv_ti_cred_name_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewTextInputCredentialName,
                             text_input_get_view(app->ti_cred_name));

    app->ti_username = pv_ti_username_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewTextInputUsername,
                             text_input_get_view(app->ti_username));

    app->ti_password = pv_ti_password_alloc(app);
    view_dispatcher_add_view(app->view_dispatcher, ViewTextInputPassword,
                             text_input_get_view(app->ti_password));

    view_dispatcher_add_view(app->view_dispatcher, ViewResultText,
                             text_box_get_view(app->result_text_box));

    view_dispatcher_add_view(app->view_dispatcher, ViewFileBrowser,
                             file_browser_get_view(app->file_browser));

    /* ---- start on PIN screen ---- */
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewPinEntry);

    /* ---- run ---- */
    view_dispatcher_run(app->view_dispatcher);

    /* ================================================================
     *  Cleanup
     * ================================================================ */

    view_dispatcher_remove_view(app->view_dispatcher, ViewMainMenu);
    view_free(app->main_menu_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewPinEntry);
    view_free(app->pin_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewSavedPasswords);
    view_free(app->saved_passwords_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewDeletePassword);
    view_free(app->delete_password_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewBookmarks);
    view_free(app->bookmarks_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewGeneratePassword);
    view_free(app->generate_password_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewImportResult);
    view_free(app->import_result_view);

    view_dispatcher_remove_view(app->view_dispatcher, ViewCredentialDetail);
    view_free(app->credential_detail_view);

    view_dispatcher_remove_view(app->view_dispatcher,
                                ViewTextInputCredentialName);
    text_input_free(app->ti_cred_name);

    view_dispatcher_remove_view(app->view_dispatcher, ViewTextInputUsername);
    text_input_free(app->ti_username);

    view_dispatcher_remove_view(app->view_dispatcher, ViewTextInputPassword);
    text_input_free(app->ti_password);

    view_dispatcher_remove_view(app->view_dispatcher, ViewResultText);
    text_box_free(app->result_text_box);

    view_dispatcher_remove_view(app->view_dispatcher, ViewFileBrowser);
    file_browser_free(app->file_browser);
    furi_string_free(app->browser_result);
    furi_string_free(app->browser_start_path);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

    pv_vault_lock(); /* zero session key from RAM before freeing context */
    free(app);
    return 0;
}
