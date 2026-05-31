#include "securexfer/manifest.h"

#include <stdio.h>
#include <string.h>

#include "test_framework.h"

static void test_create_and_free(void) {
    sx_manifest *m = NULL;
    CHECK(sx_manifest_create("file.bin", 4096, 1024, &m) == SX_OK);
    CHECK(m != NULL);
    CHECK(m->chunk_count == 4);
    CHECK(strcmp(m->source_name, "file.bin") == 0);
    sx_manifest_free(m);
}

static void test_create_rejects_zero_chunk_size(void) {
    sx_manifest *m = NULL;
    CHECK(sx_manifest_create("file.bin", 4096, 0, &m) == SX_ERR_ARGS);
}

static void test_write_then_read_roundtrip(void) {
    sx_manifest *m = NULL;
    CHECK(sx_manifest_create("doc.txt", 2048, 1024, &m) == SX_OK);

    /* Give the chunks deterministic indices/offsets. */
    for (uint64_t i = 0; i < m->chunk_count; ++i) {
        m->chunks[i].index = i;
        m->chunks[i].offset = i * 1024;
        m->chunks[i].length = 1024;
    }

    /* Round-trip through a temp file. */
    FILE *tmp = tmpfile();
    CHECK(tmp != NULL);
    CHECK(sx_manifest_write(m, tmp) == SX_OK);
    rewind(tmp);

    sx_manifest *parsed = NULL;
    CHECK(sx_manifest_read(tmp, &parsed) == SX_OK);
    CHECK(parsed != NULL);
    CHECK(parsed->file_size == 2048);
    CHECK(parsed->chunk_count == 2);
    CHECK(strcmp(parsed->source_name, "doc.txt") == 0);

    sx_manifest_free(parsed);
    sx_manifest_free(m);
    fclose(tmp);
}

int main(void) {
    RUN(test_create_and_free);
    RUN(test_create_rejects_zero_chunk_size);
    RUN(test_write_then_read_roundtrip);
    TEST_REPORT();
}
