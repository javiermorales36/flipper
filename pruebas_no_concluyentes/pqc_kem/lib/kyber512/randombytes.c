#include <furi_hal.h>
#include <stdint.h>
#include <stddef.h>

// Shim: Kyber ref usa randombytes() → redirigir al TRNG del STM32WB55
void randombytes(uint8_t* out, size_t outlen) {
    furi_hal_random_fill_buf(out, (uint32_t)outlen);
}
