#ifndef SECUREXFER_MANIFEST_H
#define SECUREXFER_MANIFEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h> /* for FILE * in the read/write prototypes */

#include "securexfer/chunk.h"
#include "securexfer/sha256.h"
#include "securexfer/status.h"

/* An in-memory transfer manifest: file metadata plus per-chunk hashes. */
typedef struct {
    char source_name[256];                    /* original file name (basename) */
    uint64_t file_size;                       /* total bytes */
    uint32_t chunk_size;                      /* chunk size used */
    uint64_t chunk_count;                     /* number of chunks */
    uint8_t whole_hash[SX_SHA256_DIGEST_LEN]; /* SHA-256 of the entire file */
    sx_chunk *chunks;                         /* owned array of chunk_count entries */
} sx_manifest;

/* Allocates a manifest with space for `chunk_count` chunks. */
sx_status sx_manifest_create(const char *source_name, uint64_t file_size, uint32_t chunk_size,
                             sx_manifest **out);

/* Frees a manifest and its chunk array. Safe on NULL. */
void sx_manifest_free(sx_manifest *manifest);

/* Serializes a manifest to a text form written to `fp`. */
sx_status sx_manifest_write(const sx_manifest *manifest, FILE *fp);

/* Parses a manifest from `fp`. Caller frees with sx_manifest_free. */
sx_status sx_manifest_read(FILE *fp, sx_manifest **out);

#endif /* SECUREXFER_MANIFEST_H */
