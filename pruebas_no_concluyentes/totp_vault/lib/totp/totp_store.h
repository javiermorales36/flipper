#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define TOTP_MAX_ACCOUNTS 16
#define TOTP_NAME_MAX     32
#define TOTP_ISSUER_MAX   32
#define TOTP_SECRET_MAX   32 // raw bytes (20 para SHA-1, hasta 32 para SHA-256)

#define TOTP_VAULT_DIR   "/ext/totp_vault"
#define TOTP_VAULT_FILE  "/ext/totp_vault/vault.bin"
#define TOTP_IMPORT_FILE "/ext/totp_vault/import.txt"

typedef struct {
    char    name[TOTP_NAME_MAX + 1];
    char    issuer[TOTP_ISSUER_MAX + 1];
    uint8_t secret[TOTP_SECRET_MAX];
    uint8_t secret_len;
    uint8_t digits; // 6
    uint8_t period; // 30
} TotpAccount;

typedef enum {
    TotpStoreOk = 0,
    TotpStoreErrIo,
    TotpStoreErrBadPin,  // MAC verification failed
    TotpStoreErrNoFile,  // vault.bin no existe todavía
    TotpStoreErrNoImport, // import.txt no existe
    TotpStoreErrCorrupt,
} TotpStoreResult;

// Descifra y carga el vault desde la SD. pin = 4 dígitos ASCII (ej. "1234").
TotpStoreResult totp_store_load(
    const char*  pin,
    TotpAccount* accounts,
    uint8_t*     count);

// Cifra y guarda el vault en la SD. Crea /ext/totp_vault/ si no existe.
TotpStoreResult totp_store_save(
    const char*        pin,
    const TotpAccount* accounts,
    uint8_t            count);

// Lee /ext/totp_vault/import.txt (formato: name|base32secret o name|issuer|base32secret por línea).
TotpStoreResult totp_store_import(TotpAccount* accounts, uint8_t* count);
