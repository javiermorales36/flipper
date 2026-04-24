#include "textInput.h"
#include "../passwordStorage/passwordStorage.h"
#include <string.h>

/* ---- credential name submitted ---- */
static void cb_cred_name(void* ctx) {
    AppContext* app = ctx;
    view_dispatcher_switch_to_view(app->view_dispatcher,
                                   ViewTextInputUsername);
}

/* ---- username submitted ---- */
static void cb_username(void* ctx) {
    AppContext* app = ctx;
    view_dispatcher_switch_to_view(app->view_dispatcher,
                                   ViewTextInputPassword);
}

/* ---- password submitted: save to file and return home ---- */
static void cb_password(void* ctx) {
    AppContext* app = ctx;

    pv_write_credential(app->tmp_name, app->tmp_username, app->tmp_password);

    /* add to in-memory list so list is immediately up to date */
    if(app->credentials_number < MAX_CREDENTIALS) {
        size_t i = app->credentials_number;
        strncpy(app->credentials[i].name,     app->tmp_name,     FIELD_SIZE - 1);
        strncpy(app->credentials[i].username, app->tmp_username, FIELD_SIZE - 1);
        strncpy(app->credentials[i].password, app->tmp_password, FIELD_SIZE - 1);
        app->credentials[i].bookmarked = false;
        app->credentials_number++;
    }

    /* clear tmp buffers */
    app->tmp_name[0]     = '\0';
    app->tmp_username[0] = '\0';
    app->tmp_password[0] = '\0';

    app->selected      = 0;
    app->scroll_offset = 0;
    view_dispatcher_switch_to_view(app->view_dispatcher, ViewMainMenu);
}

/* ------------------------------------------------------------------ */

TextInput* pv_ti_cred_name_alloc(AppContext* app) {
    TextInput* ti = text_input_alloc();
    text_input_set_header_text(ti, "Website / Service:");
    text_input_set_result_callback(ti, cb_cred_name, app,
                                   app->tmp_name, FIELD_SIZE, true);
    return ti;
}

TextInput* pv_ti_username_alloc(AppContext* app) {
    TextInput* ti = text_input_alloc();
    text_input_set_minimum_length(ti, 0);
    text_input_set_header_text(ti, "Username (optional):");
    text_input_set_result_callback(ti, cb_username, app,
                                   app->tmp_username, FIELD_SIZE, true);
    return ti;
}

TextInput* pv_ti_password_alloc(AppContext* app) {
    TextInput* ti = text_input_alloc();
    text_input_set_header_text(ti, "Password:");
    /* clear_default_text = false so a pre-filled generated password shows */
    text_input_set_result_callback(ti, cb_password, app,
                                   app->tmp_password, FIELD_SIZE, false);
    return ti;
}
