#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ─── Tipos de entrada ────────────────────────────────────────────────────────
#define KL_NAME_MAX     32   // 32 chars + NUL
#define KL_MAX_ENTRIES  16

typedef enum {
    KlTypePassword = 0,   // password arbitrario (UTF-8, hasta 127 bytes)
    KlTypeEd25519  = 1,   // par de claves Ed25519 (sk 64B, pk 32B)
    KlTypeX25519   = 2,   // par de claves X25519  (sk 32B, pk 32B)
} KlEntryType;

// Entrada de password
typedef struct {
    char    name[KL_NAME_MAX + 1];
    char    password[128];       // UTF-8, NULL-terminated
} KlPassword;

// Entrada de clave asimétrica
typedef struct {
    char    name[KL_NAME_MAX + 1];
    KlEntryType type;            // Ed25519 o X25519
    uint8_t sk[64];              // 64B para Ed25519, 32B para X25519
    uint8_t pk[32];
    uint8_t sk_len;              // 64 o 32
} KlKeyPair;

// Entrada genérica del vault
typedef struct {
    KlEntryType type;
    union {
        KlPassword  pwd;
        KlKeyPair   key;
    };
} KlEntry;

// ─── Resultados ──────────────────────────────────────────────────────────────
typedef enum {
    KlOk = 0,
    KlErrIo,
    KlErrBadPin,
    KlErrNoFile,
    KlErrFull,
    KlErrCorrupt,
} KlResult;

// ─── Rutas ───────────────────────────────────────────────────────────────────
#define KL_DIR   "/ext/key_locker"
#define KL_FILE  "/ext/key_locker/vault.klv"

// ─── API ─────────────────────────────────────────────────────────────────────

// Carga el vault desde la SD. Llena entries[0..count-1].
// Retorna KlErrNoFile si vault.klv no existe.
// Retorna KlErrBadPin si el MAC falla (PIN incorrecto).
KlResult kl_store_load(const char* pin, KlEntry* entries, uint8_t* count);

// Cifra y guarda el vault en la SD.
KlResult kl_store_save(const char* pin, const KlEntry* entries, uint8_t count);

// Genera y añade un par de claves Ed25519 (seed aleatorio del TRNG).
// seed_out[32] es el seed exportado para backup (ya cifrado en vault al salvar).
KlResult kl_keygen_ed25519(KlEntry* entries, uint8_t* count, const char* name, uint8_t seed_out[32]);

// Genera y añade un par de claves X25519.
KlResult kl_keygen_x25519(KlEntry* entries, uint8_t* count, const char* name, uint8_t sk_out[32]);
