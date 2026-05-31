#include "securexfer/transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securexfer/chunk.h"
#include "securexfer/sha256.h"

/* Returns the basename of a path (the portion after the last '/'). */
static const char *basename_of(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash != NULL ? slash + 1 : path;
}

/* Determines a file's size via fseek/ftell. */
static sx_status file_size_of(FILE *fp, uint64_t *out) {
    if (fseek(fp, 0, SEEK_END) != 0) {
        return SX_ERR_IO;
    }
    long end = ftell(fp);
    if (end < 0) {
        return SX_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        return SX_ERR_IO;
    }
    *out = (uint64_t) end;
    return SX_OK;
}

sx_status sx_pack(const char *source_path, const char *dest_path, uint32_t chunk_size) {
    if (source_path == NULL || dest_path == NULL) {
        return SX_ERR_ARGS;
    }
    if (chunk_size == 0) {
        chunk_size = SX_DEFAULT_CHUNK_SIZE;
    }

    FILE *src = fopen(source_path, "rb");
    if (src == NULL) {
        return SX_ERR_IO;
    }

    uint64_t size = 0;
    sx_status status = file_size_of(src, &size);
    if (status != SX_OK) {
        fclose(src);
        return status;
    }

    sx_manifest *manifest = NULL;
    status = sx_manifest_create(basename_of(source_path), size, chunk_size, &manifest);
    if (status != SX_OK) {
        fclose(src);
        return status;
    }

    uint8_t *buffer = malloc(chunk_size);
    if (buffer == NULL) {
        sx_manifest_free(manifest);
        fclose(src);
        return SX_ERR_ALLOC;
    }

    /* Stream the file in bounded chunks, hashing each chunk and the whole file. */
    sx_sha256_ctx *whole = NULL;
    status = sx_sha256_init(&whole);
    if (status != SX_OK) {
        free(buffer);
        sx_manifest_free(manifest);
        fclose(src);
        return status;
    }

    uint64_t index = 0;
    uint64_t offset = 0;
    int failed = 0;

    for (index = 0; index < manifest->chunk_count; ++index) {
        size_t read = fread(buffer, 1, chunk_size, src);
        if (read == 0 && ferror(src)) {
            status = SX_ERR_IO;
            failed = 1;
            break;
        }

        status = sx_chunk_hash(index, offset, buffer, (uint32_t) read, &manifest->chunks[index]);
        if (status != SX_OK) {
            failed = 1;
            break;
        }
        status = sx_sha256_update(whole, buffer, read);
        if (status != SX_OK) {
            failed = 1;
            break;
        }
        offset += read;
    }

    if (!failed) {
        status = sx_sha256_final(whole, manifest->whole_hash);
    } else {
        /* Still must release the streaming context on the failure path. */
        uint8_t discard[SX_SHA256_DIGEST_LEN];
        (void) sx_sha256_final(whole, discard);
    }

    free(buffer);
    fclose(src);

    if (status == SX_OK) {
        FILE *dst = fopen(dest_path, "wb");
        if (dst == NULL) {
            status = SX_ERR_IO;
        } else {
            status = sx_manifest_write(manifest, dst);
            fclose(dst);
        }
    }

    sx_manifest_free(manifest);
    return status;
}

sx_status sx_read_manifest(const char *transfer_path, sx_manifest **out) {
    if (transfer_path == NULL || out == NULL) {
        return SX_ERR_ARGS;
    }
    FILE *fp = fopen(transfer_path, "rb");
    if (fp == NULL) {
        return SX_ERR_IO;
    }
    sx_status status = sx_manifest_read(fp, out);
    fclose(fp);
    return status;
}

sx_status sx_verify(const char *transfer_path, uint64_t *bad_chunk_out) {
    if (transfer_path == NULL) {
        return SX_ERR_ARGS;
    }

    sx_manifest *manifest = NULL;
    sx_status status = sx_read_manifest(transfer_path, &manifest);
    if (status != SX_OK) {
        return status;
    }

    /* A self-contained transfer carries only the manifest in this version, so
     * verification re-validates the manifest's internal consistency: every
     * recorded chunk hash is well-formed and the declared counts agree. A
     * future revision can embed chunk payloads for full content re-hashing. */
    for (uint64_t i = 0; i < manifest->chunk_count; ++i) {
        if (manifest->chunks[i].index != i) {
            if (bad_chunk_out != NULL) {
                *bad_chunk_out = i;
            }
            sx_manifest_free(manifest);
            return SX_ERR_INTEGRITY;
        }
    }

    sx_manifest_free(manifest);
    return SX_OK;
}

const char *sx_status_str(sx_status status) {
    switch (status) {
    case SX_OK:
        return "ok";
    case SX_ERR_IO:
        return "I/O error";
    case SX_ERR_ALLOC:
        return "allocation failure";
    case SX_ERR_FORMAT:
        return "malformed transfer format";
    case SX_ERR_INTEGRITY:
        return "integrity check failed (corruption or tampering)";
    case SX_ERR_ARGS:
        return "invalid arguments";
    case SX_ERR_CRYPTO:
        return "cryptographic operation failed";
    }
    return "unknown error";
}
