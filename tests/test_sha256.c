#include "securexfer/sha256.h"

#include <string.h>

#include "test_framework.h"

/* NIST / FIPS 180-4 known-answer vectors for SHA-256. */

static void test_empty_string(void) {
    /* SHA-256("") */
    uint8_t digest[SX_SHA256_DIGEST_LEN];
    CHECK(sx_sha256((const uint8_t *) "", 0, digest) == SX_OK);

    char hex[SX_SHA256_HEX_LEN];
    sx_sha256_to_hex(digest, hex);
    CHECK(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
}

static void test_abc(void) {
    /* SHA-256("abc") — the canonical FIPS 180-4 example. */
    uint8_t digest[SX_SHA256_DIGEST_LEN];
    CHECK(sx_sha256((const uint8_t *) "abc", 3, digest) == SX_OK);

    char hex[SX_SHA256_HEX_LEN];
    sx_sha256_to_hex(digest, hex);
    CHECK(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

static void test_streaming_matches_oneshot(void) {
    const char *data = "the quick brown fox";
    size_t len = strlen(data);

    uint8_t oneshot[SX_SHA256_DIGEST_LEN];
    CHECK(sx_sha256((const uint8_t *) data, len, oneshot) == SX_OK);

    /* Feed it in two pieces through the streaming API. */
    sx_sha256_ctx *ctx = NULL;
    CHECK(sx_sha256_init(&ctx) == SX_OK);
    CHECK(sx_sha256_update(ctx, (const uint8_t *) data, 9) == SX_OK);
    CHECK(sx_sha256_update(ctx, (const uint8_t *) data + 9, len - 9) == SX_OK);

    uint8_t streamed[SX_SHA256_DIGEST_LEN];
    CHECK(sx_sha256_final(ctx, streamed) == SX_OK);

    CHECK(memcmp(oneshot, streamed, SX_SHA256_DIGEST_LEN) == 0);
}

static void test_null_args_rejected(void) {
    uint8_t digest[SX_SHA256_DIGEST_LEN];
    CHECK(sx_sha256(NULL, 0, digest) == SX_ERR_ARGS);
    CHECK(sx_sha256((const uint8_t *) "x", 1, NULL) == SX_ERR_ARGS);
}

int main(void) {
    RUN(test_empty_string);
    RUN(test_abc);
    RUN(test_streaming_matches_oneshot);
    RUN(test_null_args_rejected);
    TEST_REPORT();
}
