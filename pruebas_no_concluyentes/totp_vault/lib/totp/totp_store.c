#include "totp_store.h"
#include "totp.h"
#include "../monocypher/monocypher.h"

#include <storage/storage.h>
#include <furi_hal.h>

#include <stdlib.h>
#include <string.h>

// ─── Formato del vault v2 ────────────────────────────────────────────────────
// magic[4] | version[1] | salt[16] | nonce[24] | body_len[4] | ciphertext[body_len] | mac[16]
//
// KDF  : Argon2i(pin, salt, nb_blocks=32, nb_passes=2) → key[32]
// AEAD : XChaCha20-Poly1305 (crypto_aead_lock/unlock de monocypher)
//        MAC autentica el plaintext, no hace falta HMAC separado.

#define VAULT_MAGIC   "TVL2"
#define VAULT_VERSION ((uint8_t)2)

// 101 bytes por entrada (mismo layout que antes, sin cambios)
#define ENTRY_SIZE 101u

typedef struct __attribute__((packed)) {
    char    name[TOTP_NAME_MAX + 1];    // 33
    char    issuer[TOTP_ISSUER_MAX + 1]; // 33
    uint8_t secret[TOTP_SECRET_MAX];    // 32
    uint8_t secret_len;                 // 1
    uint8_t digits;                     // 1
    uint8_t period;                     // 1
} PlainEntry;                           // = 101 bytes

// ─── KDF: Argon2i(pin[4], salt[16]) → key[32] ────────────────────────────────
// nb_blocks=32 → 32 KB de work area en heap; nb_passes=2
static int derive_key(
    const char*   pin,
    const uint8_t salt[16],
    uint8_t       key[32]) {
    // 32 KB de work area (32 bloques × 1024 bytes)
    void* work = malloc(32u * 1024u);
    if(!work) return -1;

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = 32,
        .nb_passes = 2,
        .nb_lanes  = 1,
    };
    crypto_argon2_inputs inp = {
        .pass      = (const uint8_t*)pin,
        .salt      = salt,
        .pass_size = 4,
        .salt_size = 16,
    };

    crypto_argon2(key, 32, work, cfg, inp, crypto_argon2_no_extras);

    crypto_wipe(work, 32u * 1024u);
    free(work);
    return 0;
}

// ─── API pública ─────────────────────────────────────────────────────────────

TotpStoreResult totp_store_save(
    const char*        pin,
    const TotpAccount* accounts,
    uint8_t            count) {
    if(count > TOTP_MAX_ACCOUNTS) return TotpStoreErrIo;

    // Construir plaintext: [count(1)] + [entries]
    size_t body_len = 1u + (size_t)count * ENTRY_SIZE;
    uint8_t* body = malloc(body_len);
    if(!body) return TotpStoreErrIo;

    body[0] = count;
    for(uint8_t i = 0; i < count; i++) {
        PlainEntry* e = (PlainEntry*)(body + 1u + (size_t)i * ENTRY_SIZE);
        memset(e, 0, ENTRY_SIZE);
        strncpy(e->name,   accounts[i].name,   TOTP_NAME_MAX);
        strncpy(e->issuer, accounts[i].issuer,  TOTP_ISSUER_MAX);
        uint8_t sl = accounts[i].secret_len;
        if(sl > TOTP_SECRET_MAX) sl = TOTP_SECRET_MAX;
        memcpy(e->secret,  accounts[i].secret, sl);
        e->secret_len = sl;
        e->digits     = accounts[i].digits ? accounts[i].digits : 6u;
        e->period     = accounts[i].period ? accounts[i].period : 30u;
    }

    // Salt y nonce del TRNG del STM32WB55
    uint8_t salt[16], nonce[24];
    furi_hal_random_fill_buf(salt,  sizeof(salt));
    furi_hal_random_fill_buf(nonce, sizeof(nonce));

    // Derivar clave
    uint8_t key[32];
    if(derive_key(pin, salt, key) != 0) {
        memset(body, 0, body_len);
        free(body);
        return TotpStoreErrIo;
    }

    // Cifrar con XChaCha20-Poly1305: ciphertext mismo tamaño que plaintext
    uint8_t* cipher = malloc(body_len);
    uint8_t  mac[16];
    if(!cipher) {
        crypto_wipe(key, sizeof(key));
        memset(body, 0, body_len);
        free(body);
        return TotpStoreErrIo;
    }

    crypto_aead_lock(cipher, mac, key, nonce, NULL, 0, body, body_len);
    crypto_wipe(key,  sizeof(key));
    memset(body, 0, body_len);
    free(body);

    // Escribir archivo
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, TOTP_VAULT_DIR);
    File* f = storage_file_alloc(storage);

    bool ok = storage_file_open(f, TOTP_VAULT_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    if(ok) {
        uint8_t  ver = VAULT_VERSION;
        uint32_t bl  = (uint32_t)body_len;
        ok = ok && storage_file_write(f, VAULT_MAGIC, 4)      == 4;
        ok = ok && storage_file_write(f, &ver,         1)     == 1;
        ok = ok && storage_file_write(f, salt,        16)     == 16;
        ok = ok && storage_file_write(f, nonce,       24)     == 24;
        ok = ok && storage_file_write(f, &bl,          4)     == 4;
        ok = ok && (uint32_t)storage_file_write(f, cipher, body_len) == bl;
        ok = ok && storage_file_write(f, mac,         16)     == 16;
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    free(cipher);

    return ok ? TotpStoreOk : TotpStoreErrIo;
}

TotpStoreResult totp_store_load(
    const char*  pin,
    TotpAccount* accounts,
    uint8_t*     count) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File*    f       = storage_file_alloc(storage);

    if(!storage_file_open(f, TOTP_VAULT_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return TotpStoreErrNoFile;
    }

    char     magic[4];
    uint8_t  ver, salt[16], nonce[24];
    uint32_t body_len = 0;
    bool     ok       = true;

    ok = ok && storage_file_read(f, magic,     4)  == 4;
    ok = ok && (memcmp(magic, VAULT_MAGIC, 4) == 0);
    ok = ok && storage_file_read(f, &ver,      1)  == 1;
    ok = ok && (ver == VAULT_VERSION);
    ok = ok && storage_file_read(f, salt,     16)  == 16;
    ok = ok && storage_file_read(f, nonce,    24)  == 24;
    ok = ok && storage_file_read(f, &body_len, 4)  == 4;

    size_t max_body = 1u + TOTP_MAX_ACCOUNTS * ENTRY_SIZE;
    if(!ok || body_len == 0 || body_len > max_body) {
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return TotpStoreErrCorrupt;
    }

    uint8_t* cipher = malloc(body_len);
    uint8_t  mac[16];
    if(!cipher) {
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return TotpStoreErrIo;
    }

    ok = ok && (uint32_t)storage_file_read(f, cipher, body_len) == body_len;
    ok = ok && storage_file_read(f, mac, 16) == 16;
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    if(!ok) { free(cipher); return TotpStoreErrCorrupt; }

    // Derivar clave con el mismo PIN + salt
    uint8_t key[32];
    if(derive_key(pin, salt, key) != 0) {
        free(cipher);
        return TotpStoreErrIo;
    }

    // Descifrar — crypto_aead_unlock verifica MAC en tiempo constante
    uint8_t* body = malloc(body_len);
    if(!body) {
        crypto_wipe(key, sizeof(key));
        free(cipher);
        return TotpStoreErrIo;
    }

    int auth = crypto_aead_unlock(body, mac, key, nonce, NULL, 0, cipher, body_len);
    crypto_wipe(key, sizeof(key));
    free(cipher);

    if(auth != 0) {
        // MAC no coincide → PIN incorrecto o datos corruptos
        memset(body, 0, body_len);
        free(body);
        return TotpStoreErrBadPin;
    }

    // Parsear plaintext
    uint8_t n = body[0];
    if(n > TOTP_MAX_ACCOUNTS || (size_t)(1u + n * ENTRY_SIZE) > body_len) {
        memset(body, 0, body_len);
        free(body);
        return TotpStoreErrCorrupt;
    }

    for(uint8_t i = 0; i < n; i++) {
        PlainEntry* e = (PlainEntry*)(body + 1u + (size_t)i * ENTRY_SIZE);
        memset(&accounts[i], 0, sizeof(TotpAccount));
        strncpy(accounts[i].name,   e->name,   TOTP_NAME_MAX);
        strncpy(accounts[i].issuer, e->issuer,  TOTP_ISSUER_MAX);
        uint8_t sl = e->secret_len;
        if(sl > TOTP_SECRET_MAX) sl = TOTP_SECRET_MAX;
        memcpy(accounts[i].secret,  e->secret, sl);
        accounts[i].secret_len = sl;
        accounts[i].digits     = e->digits ? e->digits : 6u;
        accounts[i].period     = e->period ? e->period : 30u;
    }
    *count = n;

    memset(body, 0, body_len);
    free(body);
    return TotpStoreOk;
}

TotpStoreResult totp_store_import(TotpAccount* accounts, uint8_t* count) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File*    f       = storage_file_alloc(storage);

    if(!storage_file_open(f, TOTP_IMPORT_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return TotpStoreErrNoImport;
    }

    uint8_t* buf = malloc(4096);
    if(!buf) {
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return TotpStoreErrIo;
    }
    uint16_t nread = storage_file_read(f, buf, 4095);
    buf[nread]     = '\0';
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    uint8_t n    = 0;
    char*   line = (char*)buf;

    while(*line && n < TOTP_MAX_ACCOUNTS) {
        char* eol = line;
        while(*eol && *eol != '\n' && *eol != '\r') eol++;
        char saved = *eol;
        *eol = '\0';

        if(line[0] != '#' && line[0] != '\0') {
            // Formato: name|base32secret  ó  name|issuer|base32secret
            char* p1 = strchr(line, '|');
            if(p1) {
                *p1 = '\0';
                char* p2 = strchr(p1 + 1, '|');
                char* issuer_str;
                char* secret_str;

                if(p2) {
                    *p2        = '\0';
                    issuer_str = p1 + 1;
                    secret_str = p2 + 1;
                } else {
                    issuer_str = "";
                    secret_str = p1 + 1;
                }

                while(*secret_str == ' ') secret_str++;
                char* end = secret_str + strlen(secret_str);
                while(end > secret_str &&
                      (*(end - 1) == ' ' || *(end - 1) == '\r' || *(end - 1) == '\n'))
                    *--end = '\0';

                uint8_t decoded[TOTP_SECRET_MAX];
                size_t  decoded_len = 0;
                if(base32_decode(secret_str, decoded, sizeof(decoded), &decoded_len) &&
                   decoded_len > 0) {
                    memset(&accounts[n], 0, sizeof(TotpAccount));
                    strncpy(accounts[n].name,   line,        TOTP_NAME_MAX);
                    strncpy(accounts[n].issuer,  issuer_str,  TOTP_ISSUER_MAX);
                    memcpy(accounts[n].secret,  decoded,     decoded_len);
                    accounts[n].secret_len = (uint8_t)decoded_len;
                    accounts[n].digits     = 6u;
                    accounts[n].period     = 30u;
                    n++;
                }
            }
        }

        *eol = saved;
        line = eol;
        while(*line == '\n' || *line == '\r') line++;
    }

    free(buf);
    *count = n;
    return (n > 0) ? TotpStoreOk : TotpStoreErrNoImport;
}

