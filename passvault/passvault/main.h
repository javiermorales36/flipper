#pragma once

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <gui/elements.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <input/input.h>
#include <storage/storage.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */

#define MAX_CREDENTIALS 100
#define PIN_LENGTH      4
#define FIELD_SIZE      64
#define GEN_MAX_LEN     16

#define VAULT_DIR     "/ext/passvault"
#define FILE_PATH     "/ext/passvault/passwords.csv"
#define PIN_FILE      "/ext/passvault/pin.txt"
#define BKM_FILE      "/ext/passvault/bookmarks.txt"
#define TMP_FILE      "/ext/passvault/passwords.tmp"
#define IMPORT_FILE   "/ext/passvault/import.csv"

#define MENU_ITEMS 7

/* ------------------------------------------------------------------ */
/*  View IDs                                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    ViewPinEntry = 0,
    ViewMainMenu,
    ViewSavedPasswords,
    ViewDeletePassword,
    ViewBookmarks,
    ViewGeneratePassword,
    ViewCredentialDetail,
    ViewImportResult,
    ViewTextInputCredentialName,
    ViewTextInputUsername,
    ViewTextInputPassword,
} ViewID;

/* ------------------------------------------------------------------ */
/*  Data types                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    char name[FIELD_SIZE];
    char username[FIELD_SIZE];
    char password[FIELD_SIZE];
    bool bookmarked;
} Credential;

typedef struct {
    /* ---- navigation ------------------------------------------------ */
    const char* items[MENU_ITEMS];
    size_t      selected;
    size_t      scroll_offset;
    bool        running;

    /* ---- GUI handles ----------------------------------------------- */
    Gui*            gui;
    ViewDispatcher* view_dispatcher;
    View*           main_menu_view;
    View*           saved_passwords_view;
    View*           delete_password_view;
    View*           bookmarks_view;
    View*           generate_password_view;
    View*           pin_view;
    View*           import_result_view;
    View*           credential_detail_view;

    /* ---- index of credential being shown in detail view ----------- */
    size_t          detail_index;
    int             detail_origin; /* ViewID of list that opened the detail */

    /* ---- text input widgets ---------------------------------------- */
    TextInput* ti_cred_name;
    TextInput* ti_username;
    TextInput* ti_password;

    /* ---- credentials ----------------------------------------------- */
    Credential credentials[MAX_CREDENTIALS];
    size_t     credentials_number;

    /* ---- temporary buffers for text input flow --------------------- */
    char tmp_name[FIELD_SIZE];
    char tmp_username[FIELD_SIZE];
    char tmp_password[FIELD_SIZE];

    /* ---- PIN ------------------------------------------------------- */
    char pin[PIN_LENGTH + 1];       /* stored/correct PIN (digits)     */
    char pin_input[PIN_LENGTH + 1]; /* PIN the user is currently typing */
    int  pin_cursor;                /* active digit index 0-3           */
    bool pin_set;                   /* has a PIN been configured?       */
    bool setting_pin;               /* true = set-PIN mode, false = unlock */

    /* ---- password generator --------------------------------------- */
    char        generated_password[GEN_MAX_LEN + 1];
    int         gen_length;
    int         gen_level;
    const char* gen_alphabet;

    /* ---- notifications -------------------------------------------- */
    NotificationApp* notifications;

    /* ---- delete confirmation --------------------------------------- */
    bool confirm_delete;

    /* ---- bookmark list navigation ---------------------------------- */
    size_t bkm_selected;
    size_t bkm_scroll_offset;

    /* ---- import --------------------------------------------------- */
    size_t import_count;   /* entries added in last import             */
    bool   import_error;   /* true if import.csv was not found         */
} AppContext;
