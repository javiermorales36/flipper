#pragma once
#include "../main.h"
#include <vault_crypto.h>

/* ---- directory ---- */
void pv_ensure_vault_dir(void);

/* ---- credentials (in-memory + vault re-encrypt) ---- */
/**
 * Append a new credential to app->credentials[] and re-encrypt the vault.
 * Returns false if the array is full or the vault save fails.
 */
bool pv_write_credential(AppContext*  app,
                          const char* name,
                          const char* username,
                          const char* password);

/**
 * Remove the credential at @p index from app->credentials[] and
 * re-encrypt the vault.  The array is compacted in place.
 */
bool pv_delete_credential(AppContext* app, size_t index);

/* ---- bookmarks ---- */
/** Persist the bookmark state of all credentials by re-encrypting the vault. */
void pv_save_bookmarks(AppContext* app);

/* ---- import ---- */
/**
 * Read a plain CSV from @p src_path (name,username,password per line,
 * backslash-escaped), skip duplicates already in app->credentials[],
 * add the rest and re-encrypt the vault once.
 * Returns the count of newly added entries, or SIZE_MAX on file-not-found.
 */
size_t pv_import_csv(AppContext* app, const char* src_path);
