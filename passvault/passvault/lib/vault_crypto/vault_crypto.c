/**
 * vault_crypto.c  –  PassVault encrypted storage implementation
 *
 * Cryptographic primitives used:
 *   • SHA-256          : bcon/sha256  (compact, public-domain)
 *   • HMAC-SHA-256     : implemented here using sha256
 *   • PBKDF2-HMAC-SHA-256 : implemented here (single 32-byte block)
 *   • ChaCha20-IETF    : monocypher  (crypto_chacha20_ietf)
 */

#include "vault_crypto.h"
#include "../monocypher/monocypher.h"
#include "../bcon/sha256.h"

#include <furi.h>
#include <furi_hal_random.h>
#include <storage/storage.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Module-level session state
 * ═══════════════════════════════════════════════════════════════════════════ */

static uint8_t s_session_key[32]          = {0};
static uint8_t s_session_salt[VAULT_SALT_LEN] = {0};
static bool    s_unlocked                 = false;

/* Securely zero a buffer (compiler cannot optimise this away). */
static void safe_zero(void* buf, size_t n) {
    volatile uint8_t* p = (volatile uint8_t*)buf;
    while(n--) *p++ = 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HMAC-SHA-256  (RFC 2104)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void hmac_sha256(const uint8_t* key,  size_t key_len,
                         const uint8_t* msg,  size_t msg_len,
                         uint8_t        mac[32]) {
    /* normalise key to block size (64 bytes) */
    uint8_t k[64]    = {0};
    uint8_t inner[32];
    SHA256_CTX ctx;

    if(key_len > 64) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, k);
    } else {
        memcpy(k, key, key_len);
    }

    /* inner: H((K XOR ipad) || msg) */
    uint8_t pad[64];
    for(int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36u;
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner);

    /* outer: H((K XOR opad) || inner) */
    for(int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5cu;
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, mac);

    safe_zero(k,     sizeof(k));
    safe_zero(pad,   sizeof(pad));
    safe_zero(inner, sizeof(inner));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * PBKDF2-HMAC-SHA-256  (single 32-byte block, RFC 2898 §5.2)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void derive_key(const char*    pin,
                        const uint8_t  salt[VAULT_SALT_LEN],
                        uint8_t        key[32]) {
    /* salt_ext = salt || 0x00000001  (big-endian block counter = 1) */
    uint8_t salt_ext[VAULT_SALT_LEN + 4];
    memcpy(salt_ext, salt, VAULT_SALT_LEN);
    salt_ext[VAULT_SALT_LEN]     = 0x00;
    salt_ext[VAULT_SALT_LEN + 1] = 0x00;
    salt_ext[VAULT_SALT_LEN + 2] = 0x00;
    salt_ext[VAULT_SALT_LEN + 3] = 0x01;

    const uint8_t* pk  = (const uint8_t*)pin;
    size_t         pl  = strlen(pin);
    uint8_t        u[32];
    uint8_t        t[32];

    /* U1 = HMAC(pin, salt_ext) */
    hmac_sha256(pk, pl, salt_ext, sizeof(salt_ext), u);
    memcpy(t, u, 32);

    /* U_i = HMAC(pin, U_{i-1});  T = U1 XOR U2 XOR … */
    for(uint32_t i = 1; i < VAULT_KDF_ITER; i++) {
        hmac_sha256(pk, pl, u, 32, u);
        for(int j = 0; j < 32; j++) t[j] ^= u[j];
    }

    memcpy(key, t, 32);
    safe_zero(u, 32);
    safe_zero(t, 32);
    safe_zero(salt_ext, sizeof(salt_ext));
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Credential serialisation / deserialisation
 *
 * CSV format (one credential per line):
 *   name,username,password,bookmark_flag\n
 * Fields are backslash-escaped: literal ',' → '\,' and '\' → '\\'.
 * bookmark_flag is '1' or '0'.
 * ═══════════════════════════════════════════════════════════════════════════ */

static size_t escaped_len(const char* s) {
    size_t n = 0;
    for(; *s; s++) {
        if(*s == ',' || *s == '\\') n++; /* escape prefix */
        n++;
    }
    return n;
}

static void append_escaped(uint8_t* buf, size_t* pos, const char* s) {
    for(; *s; s++) {
        if(*s == ',' || *s == '\\') buf[(*pos)++] = (uint8_t)'\\';
        buf[(*pos)++] = (uint8_t)*s;
    }
}

/**
 * Serialise @p count credentials into a newly malloc'd buffer.
 * Sets *out_buf and returns the byte count; returns 0 on malloc failure
 * (*out_buf is NULL in that case).
 */
static size_t serialize_creds(const Credential* creds, size_t count,
                               uint8_t** out_buf) {
    /* Compute required size */
    size_t total = 0;
    for(size_t i = 0; i < count; i++) {
        total += escaped_len(creds[i].name)     + 1; /* field + comma */
        total += escaped_len(creds[i].username) + 1;
        total += escaped_len(creds[i].password) + 1;
        total += 1 + 1; /* bookmark flag + newline */
    }
    if(total == 0) total = 1; /* keep malloc(0) away */

    uint8_t* buf = malloc(total);
    if(!buf) { *out_buf = NULL; return 0; }

    size_t pos = 0;
    for(size_t i = 0; i < count; i++) {
        append_escaped(buf, &pos, creds[i].name);     buf[pos++] = ',';
        append_escaped(buf, &pos, creds[i].username); buf[pos++] = ',';
        append_escaped(buf, &pos, creds[i].password); buf[pos++] = ',';
        buf[pos++] = creds[i].bookmarked ? '1' : '0';
        buf[pos++] = '\n';
    }

    *out_buf = buf;
    return pos;
}

/**
 * Parse CSV in @p buf (length @p len) into @p out, up to @p max entries.
 * Returns the number of credentials parsed.
 */
static size_t deserialize_creds(const uint8_t* buf, size_t len,
                                  Credential* out, size_t max) {
    size_t count = 0;
    size_t i     = 0;

    while(i < len && count < max) {
        Credential* c = &out[count];
        memset(c, 0, sizeof(*c));

        /* field pointers: 0=name, 1=username, 2=password, 3=bookmark */
        char* fptr[3] = { c->name, c->username, c->password };
        char  bkm_buf[4] = {0};
        int   fi = 0, ci = 0;
        bool  esc = false, line_ok = false;

        while(i < len) {
            uint8_t ch = buf[i++];
            if(ch == '\r') continue;
            if(ch == '\n') { line_ok = (fi == 3); break; }

            if(esc) {
                if(fi < 3) {
                    if(ci < FIELD_SIZE - 1) fptr[fi][ci++] = (char)ch;
                } else {
                    if(ci < (int)sizeof(bkm_buf) - 1) bkm_buf[ci++] = (char)ch;
                }
                esc = false;
            } else if(ch == '\\') {
                esc = true;
            } else if(ch == ',' && fi < 3) {
                if(fi < 3) fptr[fi][ci] = '\0';
                fi++; ci = 0;
            } else {
                if(fi < 3) {
                    if(ci < FIELD_SIZE - 1) fptr[fi][ci++] = (char)ch;
                } else {
                    if(ci < (int)sizeof(bkm_buf) - 1) bkm_buf[ci++] = (char)ch;
                }
            }
        }

        /* null-terminate whichever field we were in */
        if(fi < 3) fptr[fi][ci] = '\0';
        else        bkm_buf[ci] = '\0';

        if(line_ok) {
            c->bookmarked = (bkm_buf[0] == '1');
            count++;
        }
    }
    return count;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Low-level vault file I/O
 * ═══════════════════════════════════════════════════════════════════════════ */

/**
 * Encrypt @p plaintext and write the vault file using @p key + @p salt.
 * A fresh random nonce is generated on every call.
 */
static VaultResult vault_write_path(const char* path,
                                const uint8_t  key[32],
                                const uint8_t  salt[VAULT_SALT_LEN],
                                const uint8_t* plaintext,
                                size_t         plen) {
    if(plen == 0) plen = 1; /* always encrypt at least one byte */

    /* malloc ciphertext buffer */
    uint8_t* ciphertext = malloc(plen);
    if(!ciphertext) return VaultNoMemory;

    /* random nonce */
    uint8_t nonce[VAULT_NONCE_LEN];
    furi_hal_random_fill_buf(nonce, VAULT_NONCE_LEN);

    /* encrypt */
    crypto_chacha20_ietf(ciphertext, plaintext, plen, key, nonce, 0);

    /* HMAC over ciphertext */
    uint8_t mac[VAULT_MAC_LEN];
    hmac_sha256(key, 32, ciphertext, plen, mac);

    /* build header */
    uint8_t hdr[VAULT_HDR_LEN];
    size_t  hp = 0;

    hdr[hp++] = 'P'; hdr[hp++] = 'V'; hdr[hp++] = 'L'; hdr[hp++] = 'T';
    hdr[hp++] = VAULT_VERSION;
    memcpy(hdr + hp, salt, VAULT_SALT_LEN);   hp += VAULT_SALT_LEN;
    memcpy(hdr + hp, nonce, VAULT_NONCE_LEN); hp += VAULT_NONCE_LEN;
    memcpy(hdr + hp, mac, VAULT_MAC_LEN);     hp += VAULT_MAC_LEN;
    uint32_t plen32 = (uint32_t)plen;
    hdr[hp++] = (uint8_t)(plen32       & 0xFFu);
    hdr[hp++] = (uint8_t)((plen32 >>  8) & 0xFFu);
    hdr[hp++] = (uint8_t)((plen32 >> 16) & 0xFFu);
    hdr[hp++] = (uint8_t)((plen32 >> 24) & 0xFFu);
    /* hp == VAULT_HDR_LEN == 69 */

    /* write to SD */
    Storage*  st = furi_record_open(RECORD_STORAGE);
    File*     f  = storage_file_alloc(st);
    VaultResult rc = VaultIoError;

    if(storage_file_open(f, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        if(storage_file_write(f, hdr, VAULT_HDR_LEN) == VAULT_HDR_LEN &&
           storage_file_write(f, ciphertext, (uint16_t)plen) == plen) {
            rc = VaultOk;
        }
        storage_file_close(f);
    }

    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    safe_zero(ciphertext, plen);
    free(ciphertext);
    return rc;
}

static VaultResult vault_write(const uint8_t  key[32],
                                const uint8_t  salt[VAULT_SALT_LEN],
                                const uint8_t* plaintext,
                                size_t         plen) {
    return vault_write_path(VAULT_FILE, key, salt, plaintext, plen);
}

/**
 * Read and decrypt the vault file using @p key.
 * On success allocates *plaintext_out (caller must free) and sets *plen_out.
 * Does NOT derive the key – the caller must supply the correct key.
 */
static VaultResult vault_read_with_key(const uint8_t  key[32],
                                        uint8_t**      plaintext_out,
                                        size_t*        plen_out) {
    Storage*    st = furi_record_open(RECORD_STORAGE);
    File*       f  = storage_file_alloc(st);
    VaultResult rc = VaultIoError;

    if(!storage_file_open(f, VAULT_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        goto cleanup_file;
    }

    /* read header */
    uint8_t hdr[VAULT_HDR_LEN];
    if(storage_file_read(f, hdr, VAULT_HDR_LEN) != VAULT_HDR_LEN) {
        goto cleanup_close;
    }

    /* verify magic + version */
    if(hdr[0] != 'P' || hdr[1] != 'V' || hdr[2] != 'L' || hdr[3] != 'T') {
        rc = VaultCorrupted; goto cleanup_close;
    }
    if(hdr[4] != VAULT_VERSION) {
        rc = VaultCorrupted; goto cleanup_close;
    }

    /* extract fields */
    uint8_t nonce[VAULT_NONCE_LEN];
    uint8_t stored_mac[VAULT_MAC_LEN];
    memcpy(nonce,      hdr + 4 + 1 + VAULT_SALT_LEN,               VAULT_NONCE_LEN);
    memcpy(stored_mac, hdr + 4 + 1 + VAULT_SALT_LEN + VAULT_NONCE_LEN, VAULT_MAC_LEN);

    uint32_t plen =
        (uint32_t)hdr[65]       |
        ((uint32_t)hdr[66] <<  8) |
        ((uint32_t)hdr[67] << 16) |
        ((uint32_t)hdr[68] << 24);

    if(plen == 0 || plen > 65536u) { /* sanity – 100 creds ≈ 20 KB */
        rc = VaultCorrupted; goto cleanup_close;
    }

    /* read ciphertext */
    uint8_t* ciphertext = malloc(plen);
    if(!ciphertext) { rc = VaultNoMemory; goto cleanup_close; }

    if(storage_file_read(f, ciphertext, plen) != plen) {
        free(ciphertext); goto cleanup_close;
    }

    /* verify HMAC */
    uint8_t expected_mac[32];
    hmac_sha256(key, 32, ciphertext, plen, expected_mac);
    bool mac_ok = (memcmp(stored_mac, expected_mac, 32) == 0);
    safe_zero(expected_mac, 32);

    if(!mac_ok) {
        rc = VaultWrongPin;
        safe_zero(ciphertext, plen);
        free(ciphertext);
        goto cleanup_close;
    }

    /* decrypt */
    uint8_t* plaintext = malloc(plen);
    if(!plaintext) {
        rc = VaultNoMemory;
        safe_zero(ciphertext, plen);
        free(ciphertext);
        goto cleanup_close;
    }

    crypto_chacha20_ietf(plaintext, ciphertext, plen, key, nonce, 0);
    safe_zero(ciphertext, plen);
    free(ciphertext);

    *plaintext_out = plaintext;
    *plen_out      = plen;
    rc = VaultOk;

cleanup_close:
    storage_file_close(f);
cleanup_file:
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static bool path_has_suffix(const char* path, const char* suffix) {
    size_t path_len = strlen(path);
    size_t suffix_len = strlen(suffix);
    if(path_len < suffix_len) return false;
    return memcmp(path + path_len - suffix_len, suffix, suffix_len) == 0;
}

static bool build_file_output_path(
    const char* input_path,
    bool encrypt,
    char* output_path,
    size_t output_size) {
    if(encrypt) {
        int written = snprintf(output_path, output_size, "%s%s", input_path, FILE_CRYPTO_EXTENSION);
        return written > 0 && (size_t)written < output_size;
    }

    if(path_has_suffix(input_path, FILE_CRYPTO_EXTENSION)) {
        size_t base_len = strlen(input_path) - strlen(FILE_CRYPTO_EXTENSION);
        int written = snprintf(output_path, output_size, "%.*s.dec", (int)base_len, input_path);
        return written > 0 && (size_t)written < output_size;
    }

    {
        int written = snprintf(output_path, output_size, "%s.dec", input_path);
        return written > 0 && (size_t)written < output_size;
    }
}

static bool should_skip_encrypt_path(const char* path) {
    return strcmp(path, VAULT_FILE) == 0 || strcmp(path, IMPORT_FILE) == 0 ||
           path_has_suffix(path, FILE_CRYPTO_EXTENSION);
}

static uint32_t read_le32_at(const uint8_t* data) {
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_le64_at(const uint8_t* data) {
    return (uint64_t)data[0] |
           ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) |
           ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) |
           ((uint64_t)data[7] << 56);
}

static void write_le32_at(uint8_t* data, uint32_t value) {
    data[0] = (uint8_t)(value & 0xFFu);
    data[1] = (uint8_t)((value >> 8) & 0xFFu);
    data[2] = (uint8_t)((value >> 16) & 0xFFu);
    data[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static void write_le64_at(uint8_t* data, uint64_t value) {
    data[0] = (uint8_t)(value & 0xFFu);
    data[1] = (uint8_t)((value >> 8) & 0xFFu);
    data[2] = (uint8_t)((value >> 16) & 0xFFu);
    data[3] = (uint8_t)((value >> 24) & 0xFFu);
    data[4] = (uint8_t)((value >> 32) & 0xFFu);
    data[5] = (uint8_t)((value >> 40) & 0xFFu);
    data[6] = (uint8_t)((value >> 48) & 0xFFu);
    data[7] = (uint8_t)((value >> 56) & 0xFFu);
}

static VaultResult remove_path_if_requested(const char* path, bool enabled) {
    Storage* storage;
    FS_Error error;

    if(!enabled) return VaultOk;
    storage = furi_record_open(RECORD_STORAGE);
    error = storage_common_remove(storage, path);
    furi_record_close(RECORD_STORAGE);
    return error == FSE_OK ? VaultOk : VaultIoError;
}

static VaultResult read_entire_file(
    const char* path,
    uint8_t** buffer_out,
    size_t* size_out) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    VaultResult rc = VaultIoError;

    *buffer_out = NULL;
    *size_out = 0;

    if(!storage_file_open(file, path, FSAM_READ, FSOM_OPEN_EXISTING)) {
        goto cleanup;
    }

    {
        uint64_t file_size = storage_file_size(file);
        uint8_t* buffer = NULL;

        if(file_size == 0 || file_size > 65536u) {
            rc = VaultCorrupted;
            goto cleanup_close;
        }

        buffer = malloc((size_t)file_size);
        if(!buffer) {
            rc = VaultNoMemory;
            goto cleanup_close;
        }

        if(storage_file_read(file, buffer, (size_t)file_size) != file_size) {
            free(buffer);
            goto cleanup_close;
        }

        *buffer_out = buffer;
        *size_out = (size_t)file_size;
        rc = VaultOk;
    }

cleanup_close:
    storage_file_close(file);
cleanup:
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult write_entire_file(const char* path, const uint8_t* buffer, size_t size) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    VaultResult rc = VaultIoError;

    if(storage_file_open(file, path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        if(storage_file_write(file, buffer, size) == size && storage_file_sync(file)) {
            rc = VaultOk;
        }
        storage_file_close(file);
    }

    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static __attribute__((unused)) VaultResult encrypt_bytes_to_file_v1(
    const uint8_t key[32],
    const uint8_t* plaintext,
    size_t plaintext_size,
    const char* output_path) {
    uint8_t nonce[VAULT_NONCE_LEN];
    uint8_t mac[VAULT_MAC_LEN];
    uint8_t* ciphertext = NULL;
    uint8_t* file_data = NULL;
    size_t total_size = VAULT_FILE_HDR_LEN + plaintext_size;
    VaultResult rc = VaultNoMemory;

    ciphertext = malloc(plaintext_size);
    file_data = malloc(total_size);
    if(!ciphertext || !file_data) goto cleanup;

    furi_hal_random_fill_buf(nonce, sizeof(nonce));
    crypto_chacha20_ietf(ciphertext, plaintext, plaintext_size, key, nonce, 0);
    hmac_sha256(key, 32, ciphertext, plaintext_size, mac);

    file_data[0] = 'P';
    file_data[1] = 'V';
    file_data[2] = 'E';
    file_data[3] = '1';
    file_data[4] = VAULT_FILE_VERSION;
    memcpy(file_data + 5, nonce, VAULT_NONCE_LEN);
    memcpy(file_data + 17, mac, VAULT_MAC_LEN);
    file_data[49] = (uint8_t)(plaintext_size & 0xFFu);
    file_data[50] = (uint8_t)((plaintext_size >> 8) & 0xFFu);
    file_data[51] = (uint8_t)((plaintext_size >> 16) & 0xFFu);
    file_data[52] = (uint8_t)((plaintext_size >> 24) & 0xFFu);
    memcpy(file_data + VAULT_FILE_HDR_LEN, ciphertext, plaintext_size);

    rc = write_entire_file(output_path, file_data, total_size);

cleanup:
    if(ciphertext) {
        safe_zero(ciphertext, plaintext_size);
        free(ciphertext);
    }
    if(file_data) {
        safe_zero(file_data, total_size);
        free(file_data);
    }
    return rc;
}

static VaultResult decrypt_file_to_bytes(
    const uint8_t key[32],
    const uint8_t* file_data,
    size_t file_size,
    uint8_t** plaintext_out,
    size_t* plaintext_size_out) {
    uint8_t expected_mac[VAULT_MAC_LEN];
    uint8_t* plaintext = NULL;
    const uint8_t* nonce = NULL;
    const uint8_t* stored_mac = NULL;
    const uint8_t* ciphertext = NULL;
    uint32_t ciphertext_size = 0;

    *plaintext_out = NULL;
    *plaintext_size_out = 0;

    if(file_size < VAULT_FILE_HDR_LEN) return VaultCorrupted;
    if(file_data[0] != 'P' || file_data[1] != 'V' || file_data[2] != 'E' || file_data[3] != '1') {
        return VaultCorrupted;
    }
    if(file_data[4] != VAULT_FILE_VERSION) return VaultCorrupted;

    nonce = file_data + 5;
    stored_mac = file_data + 17;
    ciphertext_size =
        (uint32_t)file_data[49] |
        ((uint32_t)file_data[50] << 8) |
        ((uint32_t)file_data[51] << 16) |
        ((uint32_t)file_data[52] << 24);

    if(ciphertext_size == 0 || ciphertext_size > 65536u) return VaultCorrupted;
    if((size_t)ciphertext_size + VAULT_FILE_HDR_LEN != file_size) return VaultCorrupted;

    ciphertext = file_data + VAULT_FILE_HDR_LEN;
    hmac_sha256(key, 32, ciphertext, ciphertext_size, expected_mac);
    if(memcmp(stored_mac, expected_mac, VAULT_MAC_LEN) != 0) {
        safe_zero(expected_mac, sizeof(expected_mac));
        return VaultWrongPin;
    }
    safe_zero(expected_mac, sizeof(expected_mac));

    plaintext = malloc(ciphertext_size);
    if(!plaintext) return VaultNoMemory;

    crypto_chacha20_ietf(plaintext, ciphertext, ciphertext_size, key, nonce, 0);
    *plaintext_out = plaintext;
    *plaintext_size_out = ciphertext_size;
    return VaultOk;
}

static VaultResult encrypt_file_v2_with_key(
    const char* input_path,
    const char* output_path,
    const uint8_t key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* input = storage_file_alloc(storage);
    File* output = storage_file_alloc(storage);
    uint8_t header[VAULT_FILE_V2_HDR_LEN];
    uint8_t nonce[VAULT_NONCE_LEN];
    uint8_t mac[16];
    uint8_t* plaintext = NULL;
    uint8_t* ciphertext = NULL;
    crypto_aead_ctx ctx;
    uint64_t remaining;
    VaultResult rc = VaultIoError;

    plaintext = malloc(VAULT_FILE_CHUNK_SIZE);
    ciphertext = malloc(VAULT_FILE_CHUNK_SIZE);
    if(!plaintext || !ciphertext) {
        rc = VaultNoMemory;
        goto cleanup;
    }

    if(!storage_file_open(input, input_path, FSAM_READ, FSOM_OPEN_EXISTING)) goto cleanup;
    if(!storage_file_open(output, output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) goto cleanup_input;

    remaining = storage_file_size(input);
    if(remaining == 0) {
        rc = VaultCorrupted;
        goto cleanup_output;
    }

    furi_hal_random_fill_buf(nonce, sizeof(nonce));
    header[0] = 'P';
    header[1] = 'V';
    header[2] = 'E';
    header[3] = '2';
    header[4] = VAULT_FILE_VERSION_V2;
    memcpy(header + 5, nonce, sizeof(nonce));
    write_le32_at(header + 17, VAULT_FILE_CHUNK_SIZE);
    write_le64_at(header + 21, remaining);

    if(storage_file_write(output, header, sizeof(header)) != sizeof(header)) goto cleanup_output;

    crypto_aead_init_ietf(&ctx, key, nonce);
    while(remaining > 0) {
        size_t chunk = remaining > VAULT_FILE_CHUNK_SIZE ? VAULT_FILE_CHUNK_SIZE : (size_t)remaining;
        if(storage_file_read(input, plaintext, chunk) != chunk) goto cleanup_output;
        crypto_aead_write(&ctx, ciphertext, mac, NULL, 0, plaintext, chunk);
        if(storage_file_write(output, mac, sizeof(mac)) != sizeof(mac)) goto cleanup_output;
        if(storage_file_write(output, ciphertext, chunk) != chunk) goto cleanup_output;
        remaining -= chunk;
    }

    if(!storage_file_sync(output)) goto cleanup_output;
    rc = VaultOk;

cleanup_output:
    storage_file_close(output);
cleanup_input:
    storage_file_close(input);
cleanup:
    if(plaintext) {
        safe_zero(plaintext, VAULT_FILE_CHUNK_SIZE);
        free(plaintext);
    }
    if(ciphertext) {
        safe_zero(ciphertext, VAULT_FILE_CHUNK_SIZE);
        free(ciphertext);
    }
    storage_file_free(input);
    storage_file_free(output);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult encrypt_buffer_v2_to_file(
    const uint8_t* plaintext,
    size_t plaintext_size,
    const char* output_path,
    const uint8_t key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* output = storage_file_alloc(storage);
    uint8_t header[VAULT_FILE_V2_HDR_LEN];
    uint8_t nonce[VAULT_NONCE_LEN];
    uint8_t mac[16];
    uint8_t* ciphertext = NULL;
    crypto_aead_ctx ctx;
    size_t offset = 0;
    VaultResult rc = VaultIoError;

    ciphertext = malloc(VAULT_FILE_CHUNK_SIZE);
    if(!ciphertext) {
        rc = VaultNoMemory;
        goto cleanup;
    }

    if(!storage_file_open(output, output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) goto cleanup;

    furi_hal_random_fill_buf(nonce, sizeof(nonce));
    header[0] = 'P';
    header[1] = 'V';
    header[2] = 'E';
    header[3] = '2';
    header[4] = VAULT_FILE_VERSION_V2;
    memcpy(header + 5, nonce, sizeof(nonce));
    write_le32_at(header + 17, VAULT_FILE_CHUNK_SIZE);
    write_le64_at(header + 21, plaintext_size);

    if(storage_file_write(output, header, sizeof(header)) != sizeof(header)) goto cleanup_close;

    crypto_aead_init_ietf(&ctx, key, nonce);
    while(offset < plaintext_size) {
        size_t chunk = (plaintext_size - offset) > VAULT_FILE_CHUNK_SIZE ?
            VAULT_FILE_CHUNK_SIZE : (plaintext_size - offset);
        crypto_aead_write(&ctx, ciphertext, mac, NULL, 0, plaintext + offset, chunk);
        if(storage_file_write(output, mac, sizeof(mac)) != sizeof(mac)) goto cleanup_close;
        if(storage_file_write(output, ciphertext, chunk) != chunk) goto cleanup_close;
        offset += chunk;
    }

    if(!storage_file_sync(output)) goto cleanup_close;
    rc = VaultOk;

cleanup_close:
    storage_file_close(output);
cleanup:
    if(ciphertext) {
        safe_zero(ciphertext, VAULT_FILE_CHUNK_SIZE);
        free(ciphertext);
    }
    storage_file_free(output);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult decrypt_file_v1_with_key(
    const char* input_path,
    const char* output_path,
    const uint8_t key[32]) {
    uint8_t* input = NULL;
    uint8_t* plaintext = NULL;
    size_t input_size = 0;
    size_t plaintext_size = 0;
    VaultResult rc = read_entire_file(input_path, &input, &input_size);
    if(rc != VaultOk) return rc;

    rc = decrypt_file_to_bytes(key, input, input_size, &plaintext, &plaintext_size);
    safe_zero(input, input_size);
    free(input);
    if(rc != VaultOk) return rc;

    rc = write_entire_file(output_path, plaintext, plaintext_size);
    safe_zero(plaintext, plaintext_size);
    free(plaintext);
    return rc;
}

static VaultResult decrypt_file_v2_with_key(
    const char* input_path,
    const char* output_path,
    const uint8_t key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* input = storage_file_alloc(storage);
    File* output = storage_file_alloc(storage);
    uint8_t header[VAULT_FILE_V2_HDR_LEN];
    uint8_t mac[16];
    uint8_t* ciphertext = NULL;
    uint8_t* plaintext = NULL;
    uint32_t chunk_size;
    uint64_t remaining;
    crypto_aead_ctx ctx;
    VaultResult rc = VaultIoError;

    ciphertext = malloc(VAULT_FILE_CHUNK_SIZE);
    plaintext = malloc(VAULT_FILE_CHUNK_SIZE);
    if(!ciphertext || !plaintext) {
        rc = VaultNoMemory;
        goto cleanup;
    }

    if(!storage_file_open(input, input_path, FSAM_READ, FSOM_OPEN_EXISTING)) goto cleanup;
    if(storage_file_read(input, header, sizeof(header)) != sizeof(header)) goto cleanup_input;
    if(header[0] != 'P' || header[1] != 'V' || header[2] != 'E' || header[3] != '2') {
        rc = VaultCorrupted;
        goto cleanup_input;
    }
    if(header[4] != VAULT_FILE_VERSION_V2) {
        rc = VaultCorrupted;
        goto cleanup_input;
    }

    chunk_size = read_le32_at(header + 17);
    remaining = read_le64_at(header + 21);
    if(chunk_size == 0 || chunk_size > VAULT_FILE_CHUNK_SIZE) {
        rc = VaultCorrupted;
        goto cleanup_input;
    }

    if(!storage_file_open(output, output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) goto cleanup_input;
    crypto_aead_init_ietf(&ctx, key, header + 5);

    while(remaining > 0) {
        size_t chunk = remaining > chunk_size ? chunk_size : (size_t)remaining;
        if(storage_file_read(input, mac, sizeof(mac)) != sizeof(mac)) goto cleanup_output;
        if(storage_file_read(input, ciphertext, chunk) != chunk) goto cleanup_output;
        if(crypto_aead_read(&ctx, plaintext, mac, NULL, 0, ciphertext, chunk) != 0) {
            rc = VaultWrongPin;
            goto cleanup_output;
        }
        if(storage_file_write(output, plaintext, chunk) != chunk) goto cleanup_output;
        remaining -= chunk;
    }

    if(!storage_file_sync(output)) goto cleanup_output;
    rc = VaultOk;

cleanup_output:
    storage_file_close(output);
cleanup_input:
    storage_file_close(input);
cleanup:
    if(ciphertext) {
        safe_zero(ciphertext, VAULT_FILE_CHUNK_SIZE);
        free(ciphertext);
    }
    if(plaintext) {
        safe_zero(plaintext, VAULT_FILE_CHUNK_SIZE);
        free(plaintext);
    }
    storage_file_free(input);
    storage_file_free(output);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult decrypt_file_with_key(
    const char* input_path,
    const char* output_path,
    const uint8_t key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* input = storage_file_alloc(storage);
    uint8_t header[5];
    bool is_v1 = false;
    bool is_v2 = false;

    if(!storage_file_open(input, input_path, FSAM_READ, FSOM_OPEN_EXISTING)) goto cleanup;
    if(storage_file_read(input, header, sizeof(header)) != sizeof(header)) goto cleanup_close;

    if(header[0] == 'P' && header[1] == 'V' && header[2] == 'E' && header[3] == '1') {
        is_v1 = true;
    } else if(header[0] == 'P' && header[1] == 'V' && header[2] == 'E' && header[3] == '2') {
        is_v2 = true;
    }

cleanup_close:
    storage_file_close(input);
cleanup:
    storage_file_free(input);
    furi_record_close(RECORD_STORAGE);

    if(is_v1) {
        return decrypt_file_v1_with_key(input_path, output_path, key);
    }
    if(is_v2) {
        return decrypt_file_v2_with_key(input_path, output_path, key);
    }
    return VaultCorrupted;
}

static VaultResult rekey_file_v2_stream(
    const char* input_path,
    const char* output_path,
    const uint8_t old_key[32],
    const uint8_t new_key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* input = storage_file_alloc(storage);
    File* output = storage_file_alloc(storage);
    uint8_t header[VAULT_FILE_V2_HDR_LEN];
    uint8_t new_header[VAULT_FILE_V2_HDR_LEN];
    uint8_t old_mac[16];
    uint8_t new_mac[16];
    uint8_t new_nonce[VAULT_NONCE_LEN];
    uint8_t* ciphertext = NULL;
    uint8_t* plaintext = NULL;
    uint32_t chunk_size;
    uint64_t remaining;
    crypto_aead_ctx old_ctx;
    crypto_aead_ctx new_ctx;
    VaultResult rc = VaultIoError;

    ciphertext = malloc(VAULT_FILE_CHUNK_SIZE);
    plaintext = malloc(VAULT_FILE_CHUNK_SIZE);
    if(!ciphertext || !plaintext) {
        rc = VaultNoMemory;
        goto cleanup;
    }

    if(!storage_file_open(input, input_path, FSAM_READ, FSOM_OPEN_EXISTING)) goto cleanup;
    if(storage_file_read(input, header, sizeof(header)) != sizeof(header)) goto cleanup_input;
    if(header[0] != 'P' || header[1] != 'V' || header[2] != 'E' || header[3] != '2' || header[4] != VAULT_FILE_VERSION_V2) {
        rc = VaultCorrupted;
        goto cleanup_input;
    }

    chunk_size = read_le32_at(header + 17);
    remaining = read_le64_at(header + 21);
    if(chunk_size == 0 || chunk_size > VAULT_FILE_CHUNK_SIZE) {
        rc = VaultCorrupted;
        goto cleanup_input;
    }

    if(!storage_file_open(output, output_path, FSAM_WRITE, FSOM_CREATE_ALWAYS)) goto cleanup_input;

    furi_hal_random_fill_buf(new_nonce, sizeof(new_nonce));
    new_header[0] = 'P';
    new_header[1] = 'V';
    new_header[2] = 'E';
    new_header[3] = '2';
    new_header[4] = VAULT_FILE_VERSION_V2;
    memcpy(new_header + 5, new_nonce, sizeof(new_nonce));
    write_le32_at(new_header + 17, chunk_size);
    write_le64_at(new_header + 21, remaining);
    if(storage_file_write(output, new_header, sizeof(new_header)) != sizeof(new_header)) goto cleanup_output;

    crypto_aead_init_ietf(&old_ctx, old_key, header + 5);
    crypto_aead_init_ietf(&new_ctx, new_key, new_nonce);

    while(remaining > 0) {
        size_t chunk = remaining > chunk_size ? chunk_size : (size_t)remaining;
        if(storage_file_read(input, old_mac, sizeof(old_mac)) != sizeof(old_mac)) goto cleanup_output;
        if(storage_file_read(input, ciphertext, chunk) != chunk) goto cleanup_output;
        if(crypto_aead_read(&old_ctx, plaintext, old_mac, NULL, 0, ciphertext, chunk) != 0) {
            rc = VaultWrongPin;
            goto cleanup_output;
        }
        crypto_aead_write(&new_ctx, ciphertext, new_mac, NULL, 0, plaintext, chunk);
        if(storage_file_write(output, new_mac, sizeof(new_mac)) != sizeof(new_mac)) goto cleanup_output;
        if(storage_file_write(output, ciphertext, chunk) != chunk) goto cleanup_output;
        remaining -= chunk;
    }

    if(!storage_file_sync(output)) goto cleanup_output;
    rc = VaultOk;

cleanup_output:
    storage_file_close(output);
cleanup_input:
    storage_file_close(input);
cleanup:
    if(ciphertext) {
        safe_zero(ciphertext, VAULT_FILE_CHUNK_SIZE);
        free(ciphertext);
    }
    if(plaintext) {
        safe_zero(plaintext, VAULT_FILE_CHUNK_SIZE);
        free(plaintext);
    }
    storage_file_free(input);
    storage_file_free(output);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult process_single_file_with_key(
    const char* input_path,
    const char* output_path,
    bool encrypt,
    bool delete_source,
    const uint8_t key[32]) {
    VaultResult rc = encrypt ?
        encrypt_file_v2_with_key(input_path, output_path, key) :
        decrypt_file_with_key(input_path, output_path, key);

    if(rc != VaultOk) return rc;
    return remove_path_if_requested(input_path, delete_source);
}

static VaultResult process_single_file(
    const char* input_path,
    bool encrypt,
    bool delete_source,
    char* output_path,
    size_t output_size) {
    if(!s_unlocked) return VaultIoError;
    if(!build_file_output_path(input_path, encrypt, output_path, output_size)) return VaultIoError;
    return process_single_file_with_key(input_path, output_path, encrypt, delete_source, s_session_key);
}

static void walk_tree_recursive(const char* root_path, bool encrypt, bool delete_source, VaultBatchResult* result) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);

    if(!storage_dir_open(dir, root_path)) {
        result->last_error = VaultIoError;
        goto cleanup;
    }

    while(true) {
        FileInfo file_info;
        char name[128];
        char child_path[PATH_SIZE];

        if(!storage_dir_read(dir, &file_info, name, sizeof(name))) break;
        if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if(snprintf(child_path, sizeof(child_path), "%s/%s", root_path, name) >= (int)sizeof(child_path)) {
            result->skipped++;
            continue;
        }

        if(file_info_is_dir(&file_info)) {
            walk_tree_recursive(child_path, encrypt, delete_source, result);
            continue;
        }

        if(encrypt) {
            char output_path[PATH_SIZE];
            if(should_skip_encrypt_path(child_path)) {
                result->skipped++;
                continue;
            }
            if(process_single_file(child_path, true, delete_source, output_path, sizeof(output_path)) == VaultOk) {
                result->processed++;
            } else {
                result->skipped++;
                result->last_error = VaultIoError;
            }
        } else {
            char output_path[PATH_SIZE];
            if(!path_has_suffix(child_path, FILE_CRYPTO_EXTENSION)) {
                result->skipped++;
                continue;
            }
            if(process_single_file(child_path, false, delete_source, output_path, sizeof(output_path)) == VaultOk) {
                result->processed++;
            } else {
                result->skipped++;
                result->last_error = VaultIoError;
            }
        }
    }

    storage_dir_close(dir);

cleanup:
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
}

static VaultResult rekey_single_file_prepare(
    const char* input_path,
    const char* temp_path,
    const uint8_t old_key[32],
    const uint8_t new_key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* input = storage_file_alloc(storage);
    uint8_t header[5];
    VaultResult rc = VaultIoError;

    if(!storage_file_open(input, input_path, FSAM_READ, FSOM_OPEN_EXISTING)) goto cleanup;
    if(storage_file_read(input, header, sizeof(header)) != sizeof(header)) goto cleanup_close;
    storage_file_close(input);
    storage_file_free(input);
    furi_record_close(RECORD_STORAGE);

    if(header[0] == 'P' && header[1] == 'V' && header[2] == 'E' && header[3] == '1') {
        uint8_t* plain = NULL;
        uint8_t* enc = NULL;
        size_t plain_size = 0;
        size_t enc_size = 0;

        rc = read_entire_file(input_path, &enc, &enc_size);
        if(rc != VaultOk) return rc;
        rc = decrypt_file_to_bytes(old_key, enc, enc_size, &plain, &plain_size);
        safe_zero(enc, enc_size);
        free(enc);
        if(rc != VaultOk) return rc;
        rc = encrypt_buffer_v2_to_file(plain, plain_size, temp_path, new_key);
        safe_zero(plain, plain_size);
        free(plain);
        return rc;
    }

    if(header[0] == 'P' && header[1] == 'V' && header[2] == 'E' && header[3] == '2') {
        return rekey_file_v2_stream(input_path, temp_path, old_key, new_key);
    }

    return VaultCorrupted;

cleanup_close:
    storage_file_close(input);
cleanup:
    storage_file_free(input);
    furi_record_close(RECORD_STORAGE);
    return VaultIoError;
}

static VaultResult rekey_tree_prepare_recursive(
    const char* root_path,
    const uint8_t old_key[32],
    const uint8_t new_key[32]) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);
    VaultResult rc = VaultOk;

    if(!storage_dir_open(dir, root_path)) {
        rc = VaultIoError;
        goto cleanup;
    }

    while(true) {
        FileInfo file_info;
        char name[128];
        char child_path[PATH_SIZE];
        char temp_path[PATH_SIZE];

        if(!storage_dir_read(dir, &file_info, name, sizeof(name))) break;
        if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if(snprintf(child_path, sizeof(child_path), "%s/%s", root_path, name) >= (int)sizeof(child_path)) {
            rc = VaultIoError;
            break;
        }

        if(file_info_is_dir(&file_info)) {
            rc = rekey_tree_prepare_recursive(child_path, old_key, new_key);
            if(rc != VaultOk) break;
            continue;
        }

        if(!path_has_suffix(child_path, FILE_CRYPTO_EXTENSION)) continue;
        if(snprintf(temp_path, sizeof(temp_path), "%s.rekey", child_path) >= (int)sizeof(temp_path)) {
            rc = VaultIoError;
            break;
        }
        rc = rekey_single_file_prepare(child_path, temp_path, old_key, new_key);
        if(rc != VaultOk) break;
    }

    storage_dir_close(dir);
cleanup:
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static VaultResult rekey_tree_commit_recursive(const char* root_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);
    VaultResult rc = VaultOk;

    if(!storage_dir_open(dir, root_path)) {
        rc = VaultIoError;
        goto cleanup;
    }

    while(true) {
        FileInfo file_info;
        char name[128];
        char child_path[PATH_SIZE];
        char temp_path[PATH_SIZE];

        if(!storage_dir_read(dir, &file_info, name, sizeof(name))) break;
        if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if(snprintf(child_path, sizeof(child_path), "%s/%s", root_path, name) >= (int)sizeof(child_path)) {
            rc = VaultIoError;
            break;
        }

        if(file_info_is_dir(&file_info)) {
            rc = rekey_tree_commit_recursive(child_path);
            if(rc != VaultOk) break;
            continue;
        }

        if(!path_has_suffix(child_path, FILE_CRYPTO_EXTENSION)) continue;
        if(snprintf(temp_path, sizeof(temp_path), "%s.rekey", child_path) >= (int)sizeof(temp_path)) {
            rc = VaultIoError;
            break;
        }
        if(storage_file_exists(storage, temp_path)) {
            if(storage_common_remove(storage, child_path) != FSE_OK ||
               storage_common_rename(storage, temp_path, child_path) != FSE_OK) {
                rc = VaultIoError;
                break;
            }
        }
    }

    storage_dir_close(dir);
cleanup:
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
    return rc;
}

static void rekey_tree_cleanup_recursive(const char* root_path) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* dir = storage_file_alloc(storage);

    if(!storage_dir_open(dir, root_path)) goto cleanup;

    while(true) {
        FileInfo file_info;
        char name[128];
        char child_path[PATH_SIZE];
        char temp_path[PATH_SIZE];

        if(!storage_dir_read(dir, &file_info, name, sizeof(name))) break;
        if(strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if(snprintf(child_path, sizeof(child_path), "%s/%s", root_path, name) >= (int)sizeof(child_path)) continue;

        if(file_info_is_dir(&file_info)) {
            rekey_tree_cleanup_recursive(child_path);
            continue;
        }

        if(!path_has_suffix(child_path, FILE_CRYPTO_EXTENSION)) continue;
        if(snprintf(temp_path, sizeof(temp_path), "%s.rekey", child_path) >= (int)sizeof(temp_path)) continue;
        if(storage_file_exists(storage, temp_path)) {
            storage_common_remove(storage, temp_path);
        }
    }

    storage_dir_close(dir);
cleanup:
    storage_file_free(dir);
    furi_record_close(RECORD_STORAGE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Public API
 * ═══════════════════════════════════════════════════════════════════════════ */

bool pv_vault_exists(void) {
    Storage* st  = furi_record_open(RECORD_STORAGE);
    bool     ret = storage_file_exists(st, VAULT_FILE);
    furi_record_close(RECORD_STORAGE);
    return ret;
}

VaultResult pv_vault_create(const char* pin) {
    /* Generate a fresh random salt */
    uint8_t salt[VAULT_SALT_LEN];
    furi_hal_random_fill_buf(salt, VAULT_SALT_LEN);

    /* Derive session key */
    uint8_t key[32];
    derive_key(pin, salt, key);

    /* Serialise empty credential list */
    uint8_t empty = 0;
    VaultResult rc = vault_write(key, salt, &empty, 1);

    if(rc == VaultOk) {
        memcpy(s_session_key,  key,  32);
        memcpy(s_session_salt, salt, VAULT_SALT_LEN);
        s_unlocked = true;
    }

    safe_zero(key,  32);
    return rc;
}

VaultResult pv_vault_unlock(const char*  pin,
                             Credential*  out,
                             size_t       max,
                             size_t*      count) {
    /* Read header to get salt */
    Storage* st = furi_record_open(RECORD_STORAGE);
    File*    f  = storage_file_alloc(st);
    VaultResult rc = VaultIoError;
    uint8_t  salt[VAULT_SALT_LEN];

    if(!storage_file_open(f, VAULT_FILE, FSAM_READ, FSOM_OPEN_EXISTING)) {
        goto done_hdr;
    }

    {
        uint8_t hdr[VAULT_HDR_LEN];
        if(storage_file_read(f, hdr, VAULT_HDR_LEN) != VAULT_HDR_LEN) {
            storage_file_close(f);
            goto done_hdr;
        }
        if(hdr[0] != 'P' || hdr[1] != 'V' || hdr[2] != 'L' || hdr[3] != 'T') {
            rc = VaultCorrupted;
            storage_file_close(f);
            goto done_hdr;
        }
        if(hdr[4] != VAULT_VERSION) {
            rc = VaultCorrupted;
            storage_file_close(f);
            goto done_hdr;
        }
        memcpy(salt, hdr + 5, VAULT_SALT_LEN);
        rc = VaultOk; /* header OK so far */
    }

    storage_file_close(f);
done_hdr:
    storage_file_free(f);
    furi_record_close(RECORD_STORAGE);

    if(rc != VaultOk) return rc;

    /* Derive key, then read + decrypt */
    uint8_t key[32];
    derive_key(pin, salt, key);

    uint8_t* plaintext = NULL;
    size_t   plen      = 0;
    rc = vault_read_with_key(key, &plaintext, &plen);

    if(rc == VaultOk) {
        *count = deserialize_creds(plaintext, plen, out, max);
        safe_zero(plaintext, plen);
        free(plaintext);

        /* Store session state */
        memcpy(s_session_key,  key,  32);
        memcpy(s_session_salt, salt, VAULT_SALT_LEN);
        s_unlocked = true;
    }

    safe_zero(key, 32);
    return rc;
}

VaultResult pv_vault_save_current(const Credential* creds, size_t count) {
    if(!s_unlocked) return VaultIoError;

    uint8_t* plaintext = NULL;
    size_t   plen      = serialize_creds(creds, count, &plaintext);
    if(!plaintext) return VaultNoMemory;

    VaultResult rc = vault_write(s_session_key, s_session_salt, plaintext, plen);
    safe_zero(plaintext, plen);
    free(plaintext);
    return rc;
}

VaultResult pv_vault_change_pin(const char*       new_pin,
                                 const Credential* creds,
                                 size_t            count) {
    /* Generate new salt → new key */
    uint8_t salt[VAULT_SALT_LEN];
    uint8_t old_key[32];
    char vault_temp_path[PATH_SIZE];
    furi_hal_random_fill_buf(salt, VAULT_SALT_LEN);

    uint8_t key[32];
    derive_key(new_pin, salt, key);
    memcpy(old_key, s_session_key, sizeof(old_key));

    if(snprintf(vault_temp_path, sizeof(vault_temp_path), "%s.rekey", VAULT_FILE) >= (int)sizeof(vault_temp_path)) {
        safe_zero(old_key, sizeof(old_key));
        safe_zero(key, 32);
        return VaultIoError;
    }

    if(rekey_tree_prepare_recursive(VAULT_DIR, old_key, key) != VaultOk) {
        rekey_tree_cleanup_recursive(VAULT_DIR);
        safe_zero(old_key, sizeof(old_key));
        safe_zero(key, 32);
        return VaultIoError;
    }

    uint8_t* plaintext = NULL;
    size_t   plen      = serialize_creds(creds, count, &plaintext);
    if(!plaintext) {
        rekey_tree_cleanup_recursive(VAULT_DIR);
        safe_zero(old_key, sizeof(old_key));
        safe_zero(key, 32);
        return VaultNoMemory;
    }

    VaultResult rc = vault_write_path(vault_temp_path, key, salt, plaintext, plen);
    safe_zero(plaintext, plen);
    free(plaintext);

    if(rc == VaultOk) {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        bool commit_ok = rekey_tree_commit_recursive(VAULT_DIR) == VaultOk;
        bool vault_ok = commit_ok && storage_common_remove(storage, VAULT_FILE) == FSE_OK &&
                        storage_common_rename(storage, vault_temp_path, VAULT_FILE) == FSE_OK;
        furi_record_close(RECORD_STORAGE);

        if(!vault_ok) {
            rekey_tree_cleanup_recursive(VAULT_DIR);
            {
                Storage* cleanup_storage = furi_record_open(RECORD_STORAGE);
                storage_common_remove(cleanup_storage, vault_temp_path);
                furi_record_close(RECORD_STORAGE);
            }
            safe_zero(old_key, sizeof(old_key));
            safe_zero(key, 32);
            return VaultIoError;
        }
        memcpy(s_session_key,  key,  32);
        memcpy(s_session_salt, salt, VAULT_SALT_LEN);
        s_unlocked = true;
    } else {
        rekey_tree_cleanup_recursive(VAULT_DIR);
        {
            Storage* cleanup_storage = furi_record_open(RECORD_STORAGE);
            storage_common_remove(cleanup_storage, vault_temp_path);
            furi_record_close(RECORD_STORAGE);
        }
    }

    safe_zero(old_key, sizeof(old_key));
    safe_zero(key, 32);
    return rc;
}

bool pv_vault_is_unlocked(void) {
    return s_unlocked;
}

bool pv_vault_build_file_output_path(
    const char* input_path,
    bool encrypt,
    char* output_path,
    size_t output_size) {
    return build_file_output_path(input_path, encrypt, output_path, output_size);
}

VaultResult pv_vault_encrypt_file(const char* input_path, const char* output_path, bool delete_source) {
    char generated_path[PATH_SIZE];
    if(!s_unlocked) return VaultIoError;
    if(should_skip_encrypt_path(input_path)) return VaultCorrupted;

    if(output_path) {
        VaultResult rc = process_single_file_with_key(input_path, output_path, true, delete_source, s_session_key);
        return rc;
    }

    return process_single_file(input_path, true, delete_source, generated_path, sizeof(generated_path));
}

VaultResult pv_vault_decrypt_file(const char* input_path, const char* output_path, bool delete_source) {
    char generated_path[PATH_SIZE];
    if(!s_unlocked) return VaultIoError;

    if(output_path) {
        VaultResult rc = process_single_file_with_key(input_path, output_path, false, delete_source, s_session_key);
        return rc;
    }

    return process_single_file(input_path, false, delete_source, generated_path, sizeof(generated_path));
}

VaultBatchResult pv_vault_encrypt_tree(const char* root_path, bool delete_source) {
    VaultBatchResult result = {.processed = 0, .skipped = 0, .last_error = VaultOk};
    if(!s_unlocked) {
        result.last_error = VaultIoError;
        return result;
    }
    walk_tree_recursive(root_path, true, delete_source, &result);
    return result;
}

VaultBatchResult pv_vault_decrypt_tree(const char* root_path, bool delete_source) {
    VaultBatchResult result = {.processed = 0, .skipped = 0, .last_error = VaultOk};
    if(!s_unlocked) {
        result.last_error = VaultIoError;
        return result;
    }
    walk_tree_recursive(root_path, false, delete_source, &result);
    return result;
}

void pv_vault_lock(void) {
    safe_zero(s_session_key,  sizeof(s_session_key));
    safe_zero(s_session_salt, sizeof(s_session_salt));
    s_unlocked = false;
}
