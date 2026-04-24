#include "passwordStorage.h"
#include <string.h>
#include <stdlib.h>

/* ============================================================
 *  Internal helpers
 * ============================================================ */

/** Read one text line (strips \r\n).  Returns chars read or 0 on EOF. */
static ssize_t read_line(File* f, char* buf, size_t max) {
    if(!f || !buf || max == 0) return -1;
    size_t n = 0;
    uint8_t ch;
    while(n < max - 1) {
        if(storage_file_read(f, &ch, 1) != 1) break;
        if(ch == '\n') break;
        if(ch != '\r') buf[n++] = (char)ch;
    }
    buf[n] = '\0';
    return (ssize_t)n;
}

/**
 * Parse one CSV line with backslash-escaping.
 * Fields are separated by ',' (literal comma is escaped as \,).
 * Returns true if exactly 3 fields were found.
 */
static bool parse_csv3(const char* line,
                        char* f1, char* f2, char* f3) {
    char* fields[3] = {f1, f2, f3};
    int fi = 0, ci = 0;
    bool esc = false;

    for(int i = 0; line[i]; i++) {
        char c = line[i];
        if(esc) {
            if(ci < FIELD_SIZE - 1) fields[fi][ci++] = c;
            esc = false;
        } else if(c == '\\') {
            esc = true;
        } else if(c == ',' && fi < 2) {
            fields[fi][ci] = '\0';
            fi++;
            ci = 0;
        } else {
            if(ci < FIELD_SIZE - 1) fields[fi][ci++] = c;
        }
    }
    if(esc) return false;
    fields[fi][ci] = '\0';
    return fi == 2; /* exactly 3 fields */
}

/** Write a single field with backslash-escaping of ',' and '\'. */
static void write_escaped(File* f, const char* s) {
    for(size_t i = 0; s[i]; i++) {
        char c = s[i];
        if(c == '\\' || c == ',') {
            char esc = '\\';
            storage_file_write(f, &esc, 1);
        }
        storage_file_write(f, &c, 1);
    }
}

/* ============================================================
 *  Directory
 * ============================================================ */

void pv_ensure_vault_dir(void) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    storage_simply_mkdir(st, VAULT_DIR);
    furi_record_close(RECORD_STORAGE);
}

/* ============================================================
 *  Credentials: read
 * ============================================================ */

size_t pv_read_credentials(Credential* out, size_t max) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    size_t count = 0;

    if(storage_file_open(f, FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char line[300];
        while(count < max) {
            if(read_line(f, line, sizeof(line)) <= 0) break;
            char n[FIELD_SIZE], u[FIELD_SIZE], p[FIELD_SIZE];
            if(parse_csv3(line, n, u, p)) {
                strncpy(out[count].name,     n, FIELD_SIZE - 1);
                strncpy(out[count].username, u, FIELD_SIZE - 1);
                strncpy(out[count].password, p, FIELD_SIZE - 1);
                out[count].bookmarked = false;
                count++;
            }
        }
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return count;
}

/* ============================================================
 *  Credentials: write (append)
 * ============================================================ */

bool pv_write_credential(const char* name, const char* username,
                         const char* password) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    bool ok = false;

    /* try append; if file missing, create it */
    if(!storage_file_open(f, FILE_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        storage_file_close(f);
        if(!storage_file_open(f, FILE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
            storage_file_free(f);
            furi_record_close(RECORD_STORAGE);
            return false;
        }
    }

    write_escaped(f, name);
    storage_file_write(f, ",", 1);
    write_escaped(f, username);
    storage_file_write(f, ",", 1);
    write_escaped(f, password);
    storage_file_write(f, "\n", 1);
    ok = true;

    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

/* ============================================================
 *  Credentials: delete by line index (0-based)
 * ============================================================ */

bool pv_delete_credential(size_t line_index) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* src = storage_file_alloc(st);
    File* tmp = storage_file_alloc(st);
    bool ok = false;

    if(!storage_file_open(src, FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        goto cleanup;
    }
    if(!storage_file_open(tmp, TMP_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        storage_file_close(src);
        goto cleanup;
    }

    char line[300];
    size_t cur = 0;
    while(true) {
        ssize_t len = read_line(src, line, sizeof(line));
        if(len <= 0) break;
        if(cur != line_index) {
            storage_file_write(tmp, line, (uint16_t)strlen(line));
            storage_file_write(tmp, "\n", 1);
        }
        cur++;
    }

    storage_file_close(src);
    storage_file_close(tmp);

    storage_simply_remove(st, FILE_PATH);
    storage_common_rename(st, TMP_FILE, FILE_PATH);
    ok = true;

cleanup:
    storage_file_free(src);
    storage_file_free(tmp);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

/* ============================================================
 *  Bookmarks
 * ============================================================ */

void pv_load_bookmarks(Credential* creds, size_t count) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);

    if(storage_file_open(f, BKM_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char line[FIELD_SIZE];
        while(read_line(f, line, sizeof(line)) > 0) {
            for(size_t i = 0; i < count; i++) {
                if(strncmp(creds[i].name, line, FIELD_SIZE) == 0) {
                    creds[i].bookmarked = true;
                }
            }
        }
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

void pv_save_bookmarks(Credential* creds, size_t count) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);

    if(storage_file_open(f, BKM_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        for(size_t i = 0; i < count; i++) {
            if(creds[i].bookmarked) {
                storage_file_write(f, creds[i].name,
                                   (uint16_t)strlen(creds[i].name));
                storage_file_write(f, "\n", 1);
            }
        }
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
}

/* ============================================================
 *  PIN
 * ============================================================ */

bool pv_load_pin(char pin_out[PIN_LENGTH + 1]) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    bool ok = false;

    if(storage_file_open(f, PIN_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        char buf[PIN_LENGTH + 2];
        ssize_t n = read_line(f, buf, sizeof(buf));
        if(n == PIN_LENGTH) {
            /* validate: must be 4 ASCII digits */
            bool valid = true;
            for(int i = 0; i < PIN_LENGTH; i++) {
                if(buf[i] < '0' || buf[i] > '9') { valid = false; break; }
            }
            if(valid) {
                memcpy(pin_out, buf, PIN_LENGTH);
                pin_out[PIN_LENGTH] = '\0';
                ok = true;
            }
        }
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

bool pv_save_pin(const char pin[PIN_LENGTH + 1]) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);
    bool ok = false;

    if(storage_file_open(f, PIN_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        ok = (storage_file_write(f, pin, PIN_LENGTH) == PIN_LENGTH);
        storage_file_write(f, "\n", 1);
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

/* ============================================================
 *  Import CSV
 * ============================================================ */

size_t pv_import_csv(const char*       src_path,
                     const Credential* existing,
                     size_t            existing_count) {
    Storage* st = furi_record_open(RECORD_STORAGE);
    File* f = storage_file_alloc(st);

    if(!storage_file_open(f, src_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return SIZE_MAX; /* file not found */
    }

    size_t added = 0;
    char line[300];
    char n[FIELD_SIZE], u[FIELD_SIZE], p[FIELD_SIZE];

    while(true) {
        if(read_line(f, line, sizeof(line)) <= 0) break;
        if(!parse_csv3(line, n, u, p)) continue;

        /* skip if a credential with this name already exists */
        bool duplicate = false;
        for(size_t i = 0; i < existing_count; i++) {
            if(strncmp(existing[i].name, n, FIELD_SIZE) == 0) {
                duplicate = true;
                break;
            }
        }
        if(duplicate) continue;

        if(pv_write_credential(n, u, p)) added++;
    }

    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return added;
}
