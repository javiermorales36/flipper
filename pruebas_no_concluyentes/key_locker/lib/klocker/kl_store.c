#include "kl_store.h"
#include "../monocypher/monocypher.h"

#include <storage/storage.h>
#include <furi_hal.h>
#include <stdlib.h>
#include <string.h>

// ─── Formato vault v1 ────────────────────────────────────────────────────────
// "KLV1"[4] | salt[16] | nonce[24] | body_len[4] | ciphertext[body_len] | mac[16]
// KDF: Argon2i(pin, salt, nb_blocks=32, nb_passes=2) → key[32]
// AEAD: XChaCha20-Poly1305
//
// Body (plaintext):
//   count[1] | entries[N × ENTRY_SIZE]
//
// ENTRY_SIZE = 1(type) + 33(name) + 128+1(union data, see below)
// Para KlTypePassword: type[1] + name[33] + password[128]     = 162 bytes
// Para KlTypeEd25519:  type[1] + name[33] + sk[64] + pk[32] + sk_len[1] = 131 bytes
// Para KlTypeX25519:   type[1] + name[33] + sk[32] + pk[32] + sk_len[1] = 99 bytes
// → Usamos tamaño fijo 165 bytes por entrada (máximo posible, bien alineado)

#define VAULT_MAGIC   "KLV1"
#define ENTRY_SIZE    166u

// Layout del entry serializado (packed, siempre 165 bytes)
typedef struct __attribute__((packed)) {
    uint8_t type;                   // KlEntryType (1B)
    char    name[KL_NAME_MAX + 1];  // 33B
    union {
        struct {
            char password[128];     // Para KlTypePassword
            uint8_t _pad[3];        // padding hasta 131B
        } pwd;
        struct {
            uint8_t sk[64];         // Para Ed25519/X25519 (máx 64B)
            uint8_t pk[32];
            uint8_t sk_len;
        } key;
    };
    uint8_t _align[1];              // total = 1+33+128+3+1 = 166B
} SerEntry;

// ─── KDF ─────────────────────────────────────────────────────────────────────
static int derive_key(const char* pin, const uint8_t salt[16], uint8_t key[32]) {
    void* work = malloc(32u * 1024u);
    if(!work) return -1;
    crypto_argon2_config cfg = { CRYPTO_ARGON2_I, 32, 2, 1 };
    crypto_argon2_inputs inp = {
        .pass      = (const uint8_t*)pin,
        .salt      = salt,
        .pass_size = (uint32_t)strlen(pin),
        .salt_size = 16,
    };
    crypto_argon2(key, 32, work, cfg, inp, crypto_argon2_no_extras);
    crypto_wipe(work, 32u * 1024u);
    free(work);
    return 0;
}

// ─── Serializar / deserializar ───────────────────────────────────────────────
static void entry_to_ser(const KlEntry* e, SerEntry* s) {
    memset(s, 0, ENTRY_SIZE);
    s->type = (uint8_t)e->type;
    strncpy(s->name, (e->type == KlTypePassword) ? e->pwd.name : e->key.name, KL_NAME_MAX);
    if(e->type == KlTypePassword) {
        strncpy(s->pwd.password, e->pwd.password, 127);
    } else {
        memcpy(s->key.sk, e->key.sk, e->key.sk_len);
        memcpy(s->key.pk, e->key.pk, 32);
        s->key.sk_len = e->key.sk_len;
    }
}

static void ser_to_entry(const SerEntry* s, KlEntry* e) {
    memset(e, 0, sizeof(KlEntry));
    e->type = (KlEntryType)s->type;
    if(e->type == KlTypePassword) {
        strncpy(e->pwd.name,     s->name,         KL_NAME_MAX);
        strncpy(e->pwd.password, s->pwd.password, 127);
    } else {
        e->key.type   = e->type;
        strncpy(e->key.name, s->name, KL_NAME_MAX);
        uint8_t sl = s->key.sk_len;
        if(sl > 64) sl = 64;
        memcpy(e->key.sk, s->key.sk, sl);
        memcpy(e->key.pk, s->key.pk, 32);
        e->key.sk_len = sl;
    }
}

// ─── API pública ─────────────────────────────────────────────────────────────

KlResult kl_store_save(const char* pin, const KlEntry* entries, uint8_t count) {
    if(count > KL_MAX_ENTRIES) return KlErrFull;

    size_t   body_len = 1u + (size_t)count * ENTRY_SIZE;
    uint8_t* body     = malloc(body_len);
    if(!body) return KlErrIo;

    body[0] = count;
    for(uint8_t i = 0; i < count; i++) {
        entry_to_ser(&entries[i], (SerEntry*)(body + 1u + (size_t)i * ENTRY_SIZE));
    }

    uint8_t salt[16], nonce[24], key[32];
    furi_hal_random_fill_buf(salt,  sizeof(salt));
    furi_hal_random_fill_buf(nonce, sizeof(nonce));

    if(derive_key(pin, salt, key) != 0) {
        memset(body, 0, body_len);
        free(body);
        return KlErrIo;
    }

    uint8_t* cipher = malloc(body_len);
    uint8_t  mac[16];
    if(!cipher) {
        crypto_wipe(key, 32);
        memset(body, 0, body_len);
        free(body);
        return KlErrIo;
    }

    crypto_aead_lock(cipher, mac, key, nonce, NULL, 0, body, body_len);
    crypto_wipe(key, 32);
    memset(body, 0, body_len);
    free(body);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, KL_DIR);
    File* f = storage_file_alloc(storage);
    bool  ok = storage_file_open(f, KL_FILE, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    if(ok) {
        uint32_t bl = (uint32_t)body_len;
        ok = ok && storage_file_write(f, VAULT_MAGIC, 4)  == 4;
        ok = ok && storage_file_write(f, salt,       16)  == 16;
        ok = ok && storage_file_write(f, nonce,      24)  == 24;
        ok = ok && storage_file_write(f, &bl,         4)  == 4;
        ok = ok && (uint32_t)storage_file_write(f, cipher, body_len) == bl;
        ok = ok && storage_file_write(f, mac,        16)  == 16;
    }
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    free(cipher);
    return ok ? KlOk : KlErrIo;
}

KlResult kl_store_load(const char* pin, KlEntry* entries, uint8_t* count) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File*    f       = storage_file_alloc(storage);

    if(!storage_file_open(f, KL_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return KlErrNoFile;
    }

    char     magic[4];
    uint8_t  salt[16], nonce[24];
    uint32_t body_len = 0;
    bool     ok       = true;

    ok = ok && storage_file_read(f, magic,     4)  == 4;
    ok = ok && (memcmp(magic, VAULT_MAGIC, 4) == 0);
    ok = ok && storage_file_read(f, salt,     16)  == 16;
    ok = ok && storage_file_read(f, nonce,    24)  == 24;
    ok = ok && storage_file_read(f, &body_len, 4)  == 4;

    size_t max_body = 1u + KL_MAX_ENTRIES * ENTRY_SIZE;
    if(!ok || body_len == 0 || body_len > max_body) {
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return KlErrCorrupt;
    }

    uint8_t* cipher = malloc(body_len);
    uint8_t  mac[16];
    if(!cipher) {
        storage_file_close(f);
        storage_file_free(f);
        furi_record_close(RECORD_STORAGE);
        return KlErrIo;
    }

    ok = ok && (uint32_t)storage_file_read(f, cipher, body_len) == body_len;
    ok = ok && storage_file_read(f, mac, 16) == 16;
    storage_file_close(f);
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    if(!ok) { free(cipher); return KlErrCorrupt; }

    uint8_t key[32];
    if(derive_key(pin, salt, key) != 0) { free(cipher); return KlErrIo; }

    uint8_t* body = malloc(body_len);
    if(!body) { crypto_wipe(key, 32); free(cipher); return KlErrIo; }

    int auth = crypto_aead_unlock(body, mac, key, nonce, NULL, 0, cipher, body_len);
    crypto_wipe(key, 32);
    free(cipher);

    if(auth != 0) {
        memset(body, 0, body_len);
        free(body);
        return KlErrBadPin;
    }

    uint8_t n = body[0];
    if(n > KL_MAX_ENTRIES || (size_t)(1u + n * ENTRY_SIZE) > body_len) {
        memset(body, 0, body_len);
        free(body);
        return KlErrCorrupt;
    }

    for(uint8_t i = 0; i < n; i++) {
        ser_to_entry((SerEntry*)(body + 1u + (size_t)i * ENTRY_SIZE), &entries[i]);
    }
    *count = n;
    memset(body, 0, body_len);
    free(body);
    return KlOk;
}

KlResult kl_keygen_ed25519(KlEntry* entries, uint8_t* count, const char* name, uint8_t seed_out[32]) {
    if(*count >= KL_MAX_ENTRIES) return KlErrFull;

    uint8_t seed[32];
    furi_hal_random_fill_buf(seed, 32);
    if(seed_out) memcpy(seed_out, seed, 32);

    KlEntry* e = &entries[*count];
    memset(e, 0, sizeof(KlEntry));
    e->type      = KlTypeEd25519;
    e->key.type  = KlTypeEd25519;
    e->key.sk_len = 64;
    strncpy(e->key.name, name, KL_NAME_MAX);
    // sk = seed || pk (formato monocypher: sk es 64B = seed[32] + pk[32])
    crypto_eddsa_key_pair(e->key.sk, e->key.pk, seed);
    crypto_wipe(seed, 32);
    (*count)++;
    return KlOk;
}

KlResult kl_keygen_x25519(KlEntry* entries, uint8_t* count, const char* name, uint8_t sk_out[32]) {
    if(*count >= KL_MAX_ENTRIES) return KlErrFull;

    KlEntry* e = &entries[*count];
    memset(e, 0, sizeof(KlEntry));
    e->type      = KlTypeX25519;
    e->key.type  = KlTypeX25519;
    e->key.sk_len = 32;
    strncpy(e->key.name, name, KL_NAME_MAX);
    furi_hal_random_fill_buf(e->key.sk, 32);
    if(sk_out) memcpy(sk_out, e->key.sk, 32);
    crypto_x25519_public_key(e->key.pk, e->key.sk);
    (*count)++;
    return KlOk;
}
