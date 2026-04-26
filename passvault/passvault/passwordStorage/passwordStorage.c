#include "passwordStorage.h"
#include <string.h>
#include <stdlib.h>

/* ============================================================
 *  Directory
 * ============================================================ */

void pv_ensure_vault_dir(void) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(st, VAULT_DIR);
    furi_record_close(RECORD_STORAGE);
}

/* ============================================================
 *  Credentials: add
 * ============================================================ */

bool pv_write_credential(AppContext*  app,
                          const char* name,
                          const char* username,
                          const char* password) {
    if(!app || app->credentials_number >= MAX_CREDENTIALS) return false;

    size_t i = app->credentials_number;
    strncpy(app->credentials[i].name,     name,     FIELD_SIZE - 1);
    strncpy(app->credentials[i].username, username, FIELD_SIZE - 1);
    strncpy(app->credentials[i].password, password, FIELD_SIZE - 1);
    app->credentials[i].name[FIELD_SIZE - 1]     = '\0';
    app->credentials[i].username[FIELD_SIZE - 1] = '\0';
    app->credentials[i].password[FIELD_SIZE - 1] = '\0';
    app->credentials[i].bookmarked = false;
    app->credentials_number++;

    return pv_vault_save_current(app->credentials, app->credentials_number)
           == VaultOk;
}

/* ============================================================
 *  Credentials: delete by index (0-based)
 * ============================================================ */

bool pv_delete_credential(AppContext* app, size_t index) {
    if(!app || index >= app->credentials_number) return false;

    /* Compact the array */
    for(size_t i = index; i + 1 < app->credentials_number; i++) {
        app->credentials[i] = app->credentials[i + 1];
    }
    /* Zero the vacated last slot */
    memset(&app->credentials[app->credentials_number - 1], 0,
           sizeof(Credential));
    app->credentials_number--;

    return pv_vault_save_current(app->credentials, app->credentials_number)
           == VaultOk;
}

/* ============================================================
 *  Bookmarks: persist (re-encrypt whole vault with updated flags)
 * ============================================================ */

void pv_save_bookmarks(AppContext* app) {
    if(!app) return;
    pv_vault_save_current(app->credentials, app->credentials_number);
}

/* ============================================================
 *  Import CSV (plain-text, 3-field: name,username,password)
 * ============================================================ */

/** Read one text line from f, stripping \r\n.  Returns chars read or 0. */
static size_t csv_read_line(File* f, char* buf, size_t max) {
    if(!f || !buf || max == 0) return 0;
    size_t  n  = 0;
    uint8_t ch = 0;
    while(n < max - 1) {
        if(storage_file_read(f, &ch, 1) != 1) break;
        if(ch == '\n') break;
        if(ch != '\r') buf[n++] = (char)ch;
    }
    buf[n] = '\0';
    return n;
}

/** Parse backslash-escaped CSV with exactly 3 fields. */
static bool csv_parse3(const char* line,
                        char* f1, char* f2, char* f3) {
    char* fp[3] = {f1, f2, f3};
    int   fi = 0, ci = 0;
    bool  esc = false;

    for(int i = 0; line[i]; i++) {
        char c = line[i];
        if(esc) {
            if(ci < FIELD_SIZE - 1) fp[fi][ci++] = c;
            esc = false;
        } else if(c == '\\') {
            esc = true;
        } else if(c == ',' && fi < 2) {
            fp[fi][ci] = '\0'; fi++; ci = 0;
        } else {
            if(ci < FIELD_SIZE - 1) fp[fi][ci++] = c;
        }
    }
    if(esc) return false;
    fp[fi][ci] = '\0';
    return fi == 2; /* exactly 3 fields */
}

size_t pv_import_csv(AppContext* app, const char* src_path) {
    if(!app) return SIZE_MAX;

    Storage* st = furi_record_open(RECORD_STORAGE);
    File*    f  = storage_file_alloc(st);

    if(!storage_file_open(f, src_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return SIZE_MAX; /* file not found */
    }

    size_t added = 0;
    char   line[300];
    char   name[FIELD_SIZE], user[FIELD_SIZE], pass[FIELD_SIZE];

    while(app->credentials_number < MAX_CREDENTIALS) {
        if(csv_read_line(f, line, sizeof(line)) == 0) break;
        if(!csv_parse3(line, name, user, pass)) continue;

        /* skip duplicates (by name) */
        bool dup = false;
        for(size_t i = 0; i < app->credentials_number; i++) {
            if(strncmp(app->credentials[i].name, name, FIELD_SIZE) == 0) {
                dup = true; break;
            }
        }
        if(dup) continue;

        size_t j = app->credentials_number;
        strncpy(app->credentials[j].name,     name, FIELD_SIZE - 1);
        strncpy(app->credentials[j].username, user, FIELD_SIZE - 1);
        strncpy(app->credentials[j].password, pass, FIELD_SIZE - 1);
        app->credentials[j].name[FIELD_SIZE - 1]     = '\0';
        app->credentials[j].username[FIELD_SIZE - 1] = '\0';
        app->credentials[j].password[FIELD_SIZE - 1] = '\0';
        app->credentials[j].bookmarked = false;
        app->credentials_number++;
        added++;
    }

    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    /* Single vault write for the whole import */
    if(added > 0)
        pv_vault_save_current(app->credentials, app->credentials_number);

    return added;
}
