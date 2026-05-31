#ifndef SECUREXFER_CHUNK_H
#define SECUREXFER_CHUNK_H

#include <stddef.h>
#include <stdint.h>

#include "securexfer/sha256.h"
#include "securexfer/status.h"

/* Default chunk size: 64 KiB. Bounds per-chunk memory regardless of file size. */
#define SX_DEFAULT_CHUNK_SIZE (64u * 1024u)

/* Metadata describing one chunk of a file. */
typedef struct {
    uint64_t index;                     /* 0-based chunk index */
    uint64_t offset;                    /* byte offset in the source file */
    uint32_t length;                    /* bytes in this chunk */
    uint8_t hash[SX_SHA256_DIGEST_LEN]; /* SHA-256 of the chunk contents */
} sx_chunk;

/* Computes the number of chunks for a file of `file_size` bytes at `chunk_size`. */
uint64_t sx_chunk_count(uint64_t file_size, uint32_t chunk_size);

/* Hashes a single in-memory chunk buffer, filling `index`, `offset`, `length`,
 * and `hash`. `data`/`len` are the chunk's bytes. */
sx_status sx_chunk_hash(uint64_t index, uint64_t offset, const uint8_t *data, uint32_t len,
                        sx_chunk *out);

#endif /* SECUREXFER_CHUNK_H */
