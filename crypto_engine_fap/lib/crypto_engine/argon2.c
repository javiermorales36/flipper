#include <crypto_engine.h>
#include "../monocypher/monocypher.h"

#include <stdlib.h>

int crypto_engine_argon2i(
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t nb_blocks,
    uint32_t nb_passes,
    uint8_t* key,
    size_t key_len) {
    if(!pass || !salt || !key || nb_blocks < 8 || nb_passes < 1 || key_len == 0) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    // El área de trabajo debe vivir en heap — nunca en stack
    size_t work_size = (size_t)nb_blocks * 1024u;
    void* work = malloc(work_size);
    if(!work) return CRYPTO_ENGINE_ERROR;

    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = nb_blocks,
        .nb_passes = nb_passes,
        .nb_lanes  = 1,
    };
    crypto_argon2_inputs inp = {
        .pass      = pass,
        .salt      = salt,
        .pass_size = (uint32_t)pass_len,
        .salt_size = (uint32_t)salt_len,
    };

    crypto_argon2(key, (uint32_t)key_len, work, cfg, inp, crypto_argon2_no_extras);

    // Limpiar y liberar área de trabajo con datos sensibles
    crypto_wipe(work, work_size);
    free(work);
    return CRYPTO_ENGINE_SUCCESS;
}
