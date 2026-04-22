#include "crypto_engine.h"
#include <string.h>

#define LZ4_MIN_MATCH 4u
#define LZ4_MAX_OFFSET 65535u

size_t crypto_engine_lz4_max_compressed_size(size_t input_size) {
    return input_size + input_size / 255 + 16;
}

static int write_length(size_t length, uint8_t** dst, size_t* dst_len) {
    while (length >= 255) {
        if (*dst_len == 0) return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
        **dst = 255;
        (*dst)++;
        (*dst_len)--;
        length -= 255;
    }
    if (*dst_len == 0) return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    **dst = (uint8_t)length;
    (*dst)++;
    (*dst_len)--;
    return CRYPTO_ENGINE_SUCCESS;
}

static size_t lz4_match_length(const uint8_t* left, const uint8_t* right, size_t max_len) {
    size_t length = 0;
    while(length < max_len && left[length] == right[length]) {
        length++;
    }
    return length;
}

static int lz4_emit_sequence(
    const uint8_t* src,
    size_t literal_start,
    size_t literal_len,
    size_t match_offset,
    size_t match_len,
    uint8_t** dst,
    size_t* dst_len) {
    if(*dst_len == 0) {
        return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    }

    uint8_t* token = *dst;
    uint8_t token_value = 0;
    size_t literal_field = literal_len < 15 ? literal_len : 15;
    size_t match_field = 0;

    if(match_len >= LZ4_MIN_MATCH) {
        size_t raw_match = match_len - LZ4_MIN_MATCH;
        match_field = raw_match < 15 ? raw_match : 15;
    }

    token_value = (uint8_t)((literal_field << 4) | match_field);
    *token = token_value;
    (*dst)++;
    (*dst_len)--;

    if(literal_len >= 15) {
        int result = write_length(literal_len - 15, dst, dst_len);
        if(result != CRYPTO_ENGINE_SUCCESS) {
            return result;
        }
    }

    if(*dst_len < literal_len) {
        return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    }

    memcpy(*dst, src + literal_start, literal_len);
    (*dst) += literal_len;
    (*dst_len) -= literal_len;

    if(match_len < LZ4_MIN_MATCH) {
        return CRYPTO_ENGINE_SUCCESS;
    }

    if(match_offset == 0 || match_offset > LZ4_MAX_OFFSET || *dst_len < 2) {
        return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
    }

    (*dst)[0] = (uint8_t)(match_offset & 0xFFu);
    (*dst)[1] = (uint8_t)((match_offset >> 8) & 0xFFu);
    (*dst) += 2;
    (*dst_len) -= 2;

    if(match_len - LZ4_MIN_MATCH >= 15) {
        int result = write_length(match_len - LZ4_MIN_MATCH - 15, dst, dst_len);
        if(result != CRYPTO_ENGINE_SUCCESS) {
            return result;
        }
    }

    return CRYPTO_ENGINE_SUCCESS;
}

int crypto_engine_lz4_compress(
    const uint8_t* src,
    size_t src_len,
    uint8_t* dst,
    size_t* dst_len) {
    if (!src || !dst || !dst_len) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    uint8_t* out_ptr = dst;
    size_t out_remaining = *dst_len;
    size_t anchor = 0;
    size_t position = 0;

    while(position + LZ4_MIN_MATCH <= src_len) {
        size_t best_length = 0;
        size_t best_offset = 0;
        size_t window_start = position > LZ4_MAX_OFFSET ? position - LZ4_MAX_OFFSET : 0;

        for(size_t candidate = window_start; candidate + LZ4_MIN_MATCH <= position; candidate++) {
            if(src[candidate] != src[position] ||
               src[candidate + 1] != src[position + 1] ||
               src[candidate + 2] != src[position + 2] ||
               src[candidate + 3] != src[position + 3]) {
                continue;
            }

            size_t max_len = src_len - position;
            size_t current_length = lz4_match_length(src + candidate, src + position, max_len);
            if(current_length >= LZ4_MIN_MATCH && current_length > best_length) {
                best_length = current_length;
                best_offset = position - candidate;
            }
        }

        if(best_length >= LZ4_MIN_MATCH) {
            size_t literal_len = position - anchor;
            int result = lz4_emit_sequence(
                src,
                anchor,
                literal_len,
                best_offset,
                best_length,
                &out_ptr,
                &out_remaining);
            if(result != CRYPTO_ENGINE_SUCCESS) {
                return result;
            }

            position += best_length;
            anchor = position;
        } else {
            position++;
        }
    }

    if(anchor <= src_len) {
        int result = lz4_emit_sequence(
            src,
            anchor,
            src_len - anchor,
            0,
            0,
            &out_ptr,
            &out_remaining);
        if(result != CRYPTO_ENGINE_SUCCESS) {
            return result;
        }
    }

    *dst_len = (size_t)(out_ptr - dst);
    return CRYPTO_ENGINE_SUCCESS;
}

int crypto_engine_lz4_decompress(
    const uint8_t* src,
    size_t src_len,
    uint8_t* dst,
    size_t* dst_len) {
    if (!src || !dst || !dst_len) {
        return CRYPTO_ENGINE_ERROR_BAD_INPUT;
    }

    const uint8_t* src_ptr = src;
    const uint8_t* src_end = src + src_len;
    size_t dst_capacity = *dst_len;
    size_t dst_used = 0;

    while(src_ptr < src_end) {
        uint8_t token = *src_ptr++;
        size_t literal_len = token >> 4;
        size_t match_len = (token & 0x0Fu) + LZ4_MIN_MATCH;

        if(literal_len == 15) {
            uint8_t extra = 0;
            do {
                if(src_ptr >= src_end) {
                    return CRYPTO_ENGINE_ERROR_BAD_INPUT;
                }
                extra = *src_ptr++;
                literal_len += extra;
            } while(extra == 255);
        }

        if((size_t)(src_end - src_ptr) < literal_len) {
            return CRYPTO_ENGINE_ERROR_BAD_INPUT;
        }
        if(dst_used + literal_len > dst_capacity) {
            return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
        }

        memcpy(dst + dst_used, src_ptr, literal_len);
        dst_used += literal_len;
        src_ptr += literal_len;

        if(src_ptr == src_end) {
            *dst_len = dst_used;
            return CRYPTO_ENGINE_SUCCESS;
        }

        if((size_t)(src_end - src_ptr) < 2) {
            return CRYPTO_ENGINE_ERROR_BAD_INPUT;
        }

        size_t match_offset = (size_t)src_ptr[0] | ((size_t)src_ptr[1] << 8);
        src_ptr += 2;
        if(match_offset == 0 || match_offset > dst_used) {
            return CRYPTO_ENGINE_ERROR_BAD_INPUT;
        }

        if((token & 0x0Fu) == 15) {
            uint8_t extra = 0;
            do {
                if(src_ptr >= src_end) {
                    return CRYPTO_ENGINE_ERROR_BAD_INPUT;
                }
                extra = *src_ptr++;
                match_len += extra;
            } while(extra == 255);
        }

        if(dst_used + match_len > dst_capacity) {
            return CRYPTO_ENGINE_ERROR_INSUFFICIENT_BUFFER;
        }

        size_t match_pos = dst_used - match_offset;
        for(size_t index = 0; index < match_len; index++) {
            dst[dst_used++] = dst[match_pos + index];
        }
    }

    *dst_len = dst_used;
    return CRYPTO_ENGINE_SUCCESS;
}
