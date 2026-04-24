#pragma once
#include "../main.h"

/* ---- directory ---- */
void pv_ensure_vault_dir(void);

/* ---- credentials ---- */
size_t pv_read_credentials(Credential* out, size_t max);
bool   pv_write_credential(const char* name, const char* username, const char* password);
bool   pv_delete_credential(size_t line_index);

/* ---- bookmarks ---- */
void pv_load_bookmarks(Credential* creds, size_t count);
void pv_save_bookmarks(Credential* creds, size_t count);

/* ---- PIN ---- */
bool pv_load_pin(char pin_out[PIN_LENGTH + 1]);
bool pv_save_pin(const char pin[PIN_LENGTH + 1]);

/* ---- import ---- */
/* Read src_path (CSV), skip entries whose name already exists in
   existing[], append the rest to FILE_PATH.
   Returns the count of newly added entries, or SIZE_MAX on file-not-found. */
size_t pv_import_csv(const char*      src_path,
                     const Credential* existing,
                     size_t            existing_count);
