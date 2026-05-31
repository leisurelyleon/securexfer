#include "securexfer/transfer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securexfer/manifest.h"
#include "test_framework.h"

/* Writes `content` to a temp path and returns it; caller unlinks. */
static int write_temp_file(const char *path, const char *content) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) {
        return 0;
    }
    fputs(content, fp);
    fclose(fp);
    return 1;
}

static void test_pack_produces_transfer(void) {
    const char *src = "build/_test_source.txt";
    const char *dst = "build/_test_out.sxfer";

    CHECK(write_temp_file(src, "hello securexfer integrity test") == 1);
    CHECK(sx_pack(src, dst, 8) == SX_OK); /* small chunk size -> multiple chunks */

    sx_manifest *m = NULL;
    CHECK(sx_read_manifest(dst, &m) == SX_OK);
    CHECK(m != NULL);
    CHECK(m->file_size == strlen("hello securexfer integrity test"));
    CHECK(m->chunk_count > 1); /* 8-byte chunks over a 31-byte file */

    sx_manifest_free(m);
    remove(src);
    remove(dst);
}

static void test_verify_intact_transfer(void) {
    const char *src = "build/_test_source2.txt";
    const char *dst = "build/_test_out2.sxfer";

    CHECK(write_temp_file(src, "verify me") == 1);
    CHECK(sx_pack(src, dst, 0) == SX_OK); /* default chunk size */
    CHECK(sx_verify(dst, NULL) == SX_OK);

    remove(src);
    remove(dst);
}

static void test_verify_detects_corruption(void) {
    const char *src = "build/_test_source3.txt";
    const char *dst = "build/_test_out3.sxfer";

    CHECK(write_temp_file(src, "tamper target") == 1);
    CHECK(sx_pack(src, dst, 0) == SX_OK);

    /* Corrupt the transfer file's chunk index line so its index != position. */
    FILE *fp = fopen(dst, "r+");
    CHECK(fp != NULL);
    if (fp != NULL) {
        /* Append a malformed extra chunk claim by rewriting the chunks count is
         * complex; instead we corrupt by truncating mid-file to trigger a
         * format/integrity error on re-read. */
        fclose(fp);
    }

    /* A file with a deliberately wrong declared chunk index fails verify. We
     * simulate this by hand-writing an inconsistent manifest. */
    FILE *bad = fopen(dst, "wb");
    CHECK(bad != NULL);
    if (bad != NULL) {
        fputs("SECUREXFER 1\n", bad);
        fputs("name x\n", bad);
        fputs("size 10\n", bad);
        fputs("chunk_size 65536\n", bad);
        fputs("chunks 1\n", bad);
        fputs("whole e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n", bad);
        /* Chunk claims index 5, but it is at position 0 -> inconsistency. */
        fputs("chunk 5 0 10 "
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n",
              bad);
        fclose(bad);
    }

    uint64_t bad_chunk = 0;
    CHECK(sx_verify(dst, &bad_chunk) == SX_ERR_INTEGRITY);
    CHECK(bad_chunk == 0);

    remove(src);
    remove(dst);
}

int main(void) {
    RUN(test_pack_produces_transfer);
    RUN(test_verify_intact_transfer);
    RUN(test_verify_detects_corruption);
    TEST_REPORT();
}
