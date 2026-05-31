#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securexfer/manifest.h"
#include "securexfer/sha256.h"
#include "securexfer/transfer.h"

static int cmd_pack(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: securexfer pack <source> <dest> [chunk_size]\n");
        return 2;
    }
    uint32_t chunk_size = 0;
    if (argc >= 5) {
        chunk_size = (uint32_t) strtoul(argv[4], NULL, 10);
    }

    sx_status status = sx_pack(argv[2], argv[3], chunk_size);
    if (status != SX_OK) {
        fprintf(stderr, "pack failed: %s\n", sx_status_str(status));
        return 1;
    }
    printf("Packed '%s' -> '%s'.\n", argv[2], argv[3]);
    return 0;
}

static int cmd_verify(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: securexfer verify <transfer>\n");
        return 2;
    }
    uint64_t bad = 0;
    sx_status status = sx_verify(argv[2], &bad);
    if (status == SX_ERR_INTEGRITY) {
        fprintf(stderr, "INTEGRITY FAILURE at chunk %llu\n", (unsigned long long) bad);
        return 1;
    }
    if (status != SX_OK) {
        fprintf(stderr, "verify failed: %s\n", sx_status_str(status));
        return 1;
    }
    printf("Transfer '%s' verified intact.\n", argv[2]);
    return 0;
}

static int cmd_info(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: securexfer info <transfer>\n");
        return 2;
    }

    sx_manifest *manifest = NULL;
    sx_status status = sx_read_manifest(argv[2], &manifest);
    if (status != SX_OK) {
        fprintf(stderr, "info failed: %s\n", sx_status_str(status));
        return 1;
    }

    char whole_hex[SX_SHA256_HEX_LEN];
    sx_sha256_to_hex(manifest->whole_hash, whole_hex);

    printf("Source name: %s\n", manifest->source_name);
    printf("File size:   %llu bytes\n", (unsigned long long) manifest->file_size);
    printf("Chunk size:  %u bytes\n", manifest->chunk_size);
    printf("Chunks:      %llu\n", (unsigned long long) manifest->chunk_count);
    printf("Whole hash:  %s\n", whole_hex);

    sx_manifest_free(manifest);
    return 0;
}

static void print_usage(void) {
    printf("securexfer - secure file transfer and integrity validator\n\n");
    printf("Commands:\n");
    printf("  pack   <source> <dest> [chunk_size]   Package a file into a transfer\n");
    printf("  verify <transfer>                     Verify a transfer's integrity\n");
    printf("  info   <transfer>                     Show transfer metadata\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 2;
    }

    if (strcmp(argv[1], "pack") == 0) {
        return cmd_pack(argc, argv);
    }
    if (strcmp(argv[1], "verify") == 0) {
        return cmd_verify(argc, argv);
    }
    if (strcmp(argv[1], "info") == 0) {
        return cmd_info(argc, argv);
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage();
        return 0;
    }

    fprintf(stderr, "unknown command: %s\n", argv[1]);
    print_usage();
    return 2;
}
