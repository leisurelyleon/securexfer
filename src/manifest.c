#include "securexfer/manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

sx_status sx_manifest_create(const char *source_name, uint64_t file_size, uint32_t chunk_size,
                             sx_manifest **out) {
    if (source_name == NULL || out == NULL || chunk_size == 0) {
        return SX_ERR_ARGS;
    }

    sx_manifest *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return SX_ERR_ALLOC;
    }

    /* Bounded copy of the source name; always NUL-terminated. */
    size_t name_len = strlen(source_name);
    if (name_len >= sizeof(m->source_name)) {
        name_len = sizeof(m->source_name) - 1;
    }
    memcpy(m->source_name, source_name, name_len);
    m->source_name[name_len] = '\0';

    m->file_size = file_size;
    m->chunk_size = chunk_size;
    m->chunk_count = sx_chunk_count(file_size, chunk_size);

    if (m->chunk_count > 0) {
        m->chunks = calloc((size_t)m->chunk_count, sizeof(*m->chunks));
        if (m->chunks == NULL) {
            free(m);
            return SX_ERR_ALLOC;
        }
    } else {
        m->chunks = NULL;
    }

    *out = m;
    return SX_OK;
}

void sx_manifest_free(sx_manifest *manifest) {
    if (manifest == NULL) {
        return;
    }
    free(manifest->chunks);
    free(manifest);
}

sx_status sx_manifest_write(const sx_manifest *manifest, FILE *fp) {
    if (manifest == NULL || fp == NULL) {
        return SX_ERR_ARGS;
    }

    char whole_hex[SX_SHA256_HEX_LEN];
    sx_sha256_to_hex(manifest->whole_hash, whole_hex);

    /* A simple, line-oriented header. */
    if (fprintf(fp, "SECUREXFER 1\n") < 0 ||
        fprintf(fp, "name %s\n", manifest->source_name) < 0 ||
        fprintf(fp, "size %llu\n", (unsigned long long)manifest->file_size) < 0 ||
        fprintf(fp, "chunk_size %u\n", manifest->chunk_size) < 0 ||
        fprintf(fp, "chunks %llu\n", (unsigned long long)manifest->chunk_count) < 0 ||
        fprintf(fp, "whole %s\n", whole_hex) < 0) {
        return SX_ERR_IO;
    }

    for (uint64_t i = 0; i < manifest->chunk_count; ++i) {
        const sx_chunk *c = &manifest->chunks[i];
        char chunk_hex[SX_SHA256_HEX_LEN];
        sx_sha256_to_hex(c->hash, chunk_hex);
        if (fprintf(fp, "chunk %llu %llu %u %s\n", (unsigned long long)c->index,
                    (unsigned long long)c->offset, c->length, chunk_hex) < 0) {
            return SX_ERR_IO;
        }
    }

    return SX_OK;
}

/* Parses a 64-char lowercase-hex string into a 32-byte digest. */
static sx_status parse_hex(const char *hex, uint8_t out[SX_SHA256_DIGEST_LEN]) {
    if (strlen(hex) != SX_SHA256_DIGEST_LEN * 2) {
        return SX_ERR_FORMAT;
    }
    for (size_t i = 0; i < SX_SHA256_DIGEST_LEN; ++i) {
        unsigned int byte = 0;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) {
            return SX_ERR_FORMAT;
        }
        out[i] = (uint8_t)byte;
    }
    return SX_OK;
}

sx_status sx_manifest_read(FILE *fp, sx_manifest **out) {
    if (fp == NULL || out == NULL) {
        return SX_ERR_ARGS;
    }

    int version = 0;
    if (fscanf(fp, "SECUREXFER %d\n", &version) != 1 || version != 1) {
        return SX_ERR_FORMAT;
    }

    char name[256] = {0};
    unsigned long long size = 0;
    unsigned int chunk_size = 0;
    unsigned long long chunks = 0;
    char whole_hex[SX_SHA256_HEX_LEN] = {0};

    /* %255s bounds the name read to the buffer. */
    if (fscanf(fp, "name %255s\n", name) != 1 ||
        fscanf(fp, "size %llu\n", &size) != 1 ||
        fscanf(fp, "chunk_size %u\n", &chunk_size) != 1 ||
        fscanf(fp, "chunks %llu\n", &chunks) != 1 ||
        fscanf(fp, "whole %64s\n", whole_hex) != 1) {
        return SX_ERR_FORMAT;
    }

    sx_manifest *m = NULL;
    sx_status status = sx_manifest_create(name, size, chunk_size, &m);
    if (status != SX_OK) {
        return status;
    }

    /* The recomputed chunk_count must match the declared count. */
    if (m->chunk_count != (uint64_t)chunks) {
        sx_manifest_free(m);
        return SX_ERR_FORMAT;
    }

    status = parse_hex(whole_hex, m->whole_hash);
    if (status != SX_OK) {
        sx_manifest_free(m);
        return status;
    }

    for (uint64_t i = 0; i < m->chunk_count; ++i) {
        unsigned long long index = 0;
        unsigned long long offset = 0;
        unsigned int length = 0;
        char chunk_hex[SX_SHA256_HEX_LEN] = {0};

        if (fscanf(fp, "chunk %llu %llu %u %64s\n", &index, &offset, &length, chunk_hex) != 4) {
            sx_manifest_free(m);
            return SX_ERR_FORMAT;
        }

        sx_chunk *c = &m->chunks[i];
        c->index = (uint64_t)index;
        c->offset = (uint64_t)offset;
        c->length = length;
        status = parse_hex(chunk_hex, c->hash);
        if (status != SX_OK) {
            sx_manifest_free(m);
            return status;
        }
    }

    *out = m;
    return SX_OK;
}
