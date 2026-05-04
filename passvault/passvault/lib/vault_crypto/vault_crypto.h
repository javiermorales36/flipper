/**
 * vault_crypto.h  –  PassVault encrypted storage layer
 *
 * Encrypted vault file format (.fhs):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *       0     4   Magic: "PVLT"
 *       4     1   Version: 0x01
 *       5    16   Salt  (random, used for PBKDF2 key derivation)
 *      21    12   Nonce (random, used for ChaCha20-IETF)
 *      33    32   HMAC-SHA-256(session_key, ciphertext)
 *      65     4   Payload length in bytes (little-endian uint32)
 *      69     N   ChaCha20-IETF ciphertext
 *
 * Key derivation: session_key = PBKDF2-HMAC-SHA256(PIN, salt, 2048, 32)
 *
 * The HMAC doubles as PIN verification: a wrong PIN produces the wrong key
 * which makes the HMAC check fail —> VaultWrongPin.
 *
 * Plaintext payload: UTF-8 CSV, one credential per line:
 *   name,username,password,bookmark_flag\n
 * Fields are backslash-escaped (literal comma → \, and backslash → \\).
 * bookmark_flag is '1' if bookmarked, '0' otherwise.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Include app types (Credential, AppContext, FIELD_SIZE, MAX_CREDENTIALS…) */
#include "../../main.h"

/* ── Constants ─────────────────────────────────────────────────────────── */

#define VAULT_MAGIC        "PVLT"
#define VAULT_VERSION      0x01u
#define VAULT_SALT_LEN     16u
#define VAULT_NONCE_LEN    12u
#define VAULT_MAC_LEN      32u
/** Total header size = 4 + 1 + 16 + 12 + 32 + 4 = 69 bytes */
#define VAULT_HDR_LEN      69u
/** PBKDF2 iterations – trade-off: security vs. unlock latency on Flipper */
#define VAULT_KDF_ITER     2048u

#define VAULT_FILE_MAGIC   "PVE1"
#define VAULT_FILE_VERSION 0x01u
#define VAULT_FILE_HDR_LEN 53u
#define VAULT_FILE_MAGIC_V2 "PVE2"
#define VAULT_FILE_VERSION_V2 0x02u
#define VAULT_FILE_V2_HDR_LEN 29u
#define VAULT_FILE_CHUNK_SIZE 4096u

/* ── Result codes ───────────────────────────────────────────────────────── */

typedef enum {
    VaultOk = 0,     /**< Success                                        */
    VaultWrongPin,   /**< HMAC mismatch: wrong PIN or data corrupted     */
    VaultCorrupted,  /**< Bad magic or unsupported version               */
    VaultIoError,    /**< Storage read / write failure                   */
    VaultNoMemory,   /**< malloc() returned NULL                         */
} VaultResult;

typedef struct {
    size_t processed;
    size_t skipped;
    VaultResult last_error;
} VaultBatchResult;

/* ── Public API ─────────────────────────────────────────────────────────── */

/**
 * Returns true if the vault file already exists on the SD card.
 * Used at startup to distinguish first run from subsequent unlocks.
 */
bool pv_vault_exists(void);

/**
 * Create a new vault file protected by @p pin.
 *
 * Generates a fresh random salt, derives the session key via PBKDF2,
 * serialises an *empty* credential list, encrypts it and writes the vault.
 * Also stores the session key internally so subsequent saves work without
 * re-entering the PIN.
 *
 * Call on first launch or after a PIN change has been initiated.
 */
VaultResult pv_vault_create(const char* pin);

/**
 * Unlock an existing vault.
 *
 * Reads the vault header, derives the session key from @p pin + stored salt,
 * verifies the HMAC, decrypts the payload and parses up to @p max credentials
 * into @p out.  On success @p *count is set and the session key is stored
 * internally.
 *
 * Returns VaultWrongPin if the HMAC does not match (wrong pin or corruption).
 */
VaultResult pv_vault_unlock(const char*  pin,
                             Credential*  out,
                             size_t       max,
                             size_t*      count);

/**
 * Re-encrypt and save @p count credentials using the session key that was
 * established by a previous pv_vault_unlock() or pv_vault_create() call.
 *
 * A fresh random nonce is generated for every save so the ciphertext is
 * never identical across writes even when the plaintext has not changed.
 *
 * Must NOT be called before the vault is unlocked/created.
 */
VaultResult pv_vault_save_current(const Credential* creds, size_t count);

/**
 * Change the vault password.
 *
 * Generates a new random salt, derives a new session key from @p new_pin,
 * re-encrypts @p creds and overwrites the vault file.  Updates the internal
 * session key so further saves continue to work.
 */
VaultResult pv_vault_change_pin(const char*       new_pin,
                                 const Credential* creds,
                                 size_t            count);

/**
 * Returns true when the vault session key is currently available in RAM.
 */
bool pv_vault_is_unlocked(void);

/**
 * Build the output path for a .pve encrypted file or a decrypted .dec file.
 */
bool pv_vault_build_file_output_path(
    const char* input_path,
    bool encrypt,
    char* output_path,
    size_t output_size);

/**
 * Encrypt or decrypt a single file using the current unlocked vault key.
 */
VaultResult pv_vault_encrypt_file(const char* input_path, const char* output_path, bool delete_source);
VaultResult pv_vault_decrypt_file(const char* input_path, const char* output_path, bool delete_source);

/**
 * Recursively encrypt/decrypt files under a directory. Encryption skips the
 * vault metadata files and files already ending in .pve.
 */
VaultBatchResult pv_vault_encrypt_tree(const char* root_path, bool delete_source);
VaultBatchResult pv_vault_decrypt_tree(const char* root_path, bool delete_source);

/**
 * Zeroize the session key from RAM.  Call this when the app exits so the
 * key does not linger in memory.
 */
void pv_vault_lock(void);
