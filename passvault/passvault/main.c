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

    /* scroll indicator dots on the right */
    if(MENU_ITEMS > MM_VISIBLE) {
        canvas_set_color(canvas, ColorBlack);
        for(size_t i = 0; i < MENU_ITEMS; i++) {
            int dot_y = 16 + (int)i * 7;
            if(i == app->selected)
                canvas_draw_box(canvas, 124, dot_y, 3, 3);
            else
                canvas_draw_frame(canvas, 124, dot_y, 3, 3);
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
                app->credentials_number =
                    pv_read_credentials(app->credentials, MAX_CREDENTIALS);
                pv_load_bookmarks(app->credentials, app->credentials_number);
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
                app->credentials_number =
                    pv_read_credentials(app->credentials, MAX_CREDENTIALS);
                pv_load_bookmarks(app->credentials, app->credentials_number);
                app->selected       = 0;
                app->scroll_offset  = 0;
                app->confirm_delete = false;
                view_dispatcher_switch_to_view(app->view_dispatcher,
                                               ViewDeletePassword);
                break;

            /* 3 – Bookmarks */
            case 3:
                app->credentials_number =
                    pv_read_credentials(app->credentials, MAX_CREDENTIALS);
                pv_load_bookmarks(app->credentials, app->credentials_number);
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
                /* load current list first for duplicate checking */
                app->credentials_number =
                    pv_read_credentials(app->credentials, MAX_CREDENTIALS);
                size_t result = pv_import_csv(IMPORT_FILE,
                                              app->credentials,
                                              app->credentials_number);
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

    /* ---- load or initialise PIN ---- */
    memset(app->pin, '0', PIN_LENGTH);
    app->pin[PIN_LENGTH] = '\0';
    memset(app->pin_input, '0', PIN_LENGTH);
    app->pin_input[PIN_LENGTH] = '\0';

    app->pin_set = pv_load_pin(app->pin);
    if(!app->pin_set) {
        /* first launch – user must set a PIN */
        app->setting_pin = true;
    } else {
        app->setting_pin = false;
    }

    /* ---- load credentials ---- */
    app->credentials_number =
        pv_read_credentials(app->credentials, MAX_CREDENTIALS);
    pv_load_bookmarks(app->credentials, app->credentials_number);

    /* ---- menu labels ---- */
    app->items[0] = "Saved Passwords";
    app->items[1] = "Add Password";
    app->items[2] = "Delete Password";
    app->items[3] = "Bookmarks";
    app->items[4] = "Generate Password";
    app->items[5] = "Change PIN";
    app->items[6] = "Import CSV";

    /* ---- generator defaults ---- */
    app->gen_length = 12;
    app->gen_level  = 3; /* Ab12 */
    pv_gen_build_alphabet(app);

    /* ---- notifications ---- */
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    /* ---- GUI ---- */
    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();

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

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);

    free(app);
    return 0;
}
