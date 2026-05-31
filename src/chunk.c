#include "securexfer/chunk.h"

#include <stddef.h>

uint64_t sx_chunk_count(uint64_t file_size, uint32_t chunk_size) {
    if (chunk_size == 0) {
        return 0;
    }
    if (file_size == 0) {
        return 0;
    }
    /* Ceiling division without overflow. */
    return (file_size + chunk_size - 1) / chunk_size;
}

sx_status sx_chunk_hash(uint64_t index, uint64_t offset, const uint8_t *data, uint32_t len,
                        sx_chunk *out) {
    if (data == NULL || out == NULL) {
        return SX_ERR_ARGS;
    }

    sx_status status = sx_sha256(data, (size_t)len, out->hash);
    if (status != SX_OK) {
        return status;
    }

    out->index = index;
    out->offset = offset;
    out->length = len;
    return SX_OK;
}
