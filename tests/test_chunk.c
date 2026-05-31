#include "securexfer/chunk.h"

#include "test_framework.h"

static void test_chunk_count_basic(void) {
    CHECK(sx_chunk_count(0, 1024) == 0);
    CHECK(sx_chunk_count(1, 1024) == 1);
    CHECK(sx_chunk_count(1024, 1024) == 1);
    CHECK(sx_chunk_count(1025, 1024) == 2);
    CHECK(sx_chunk_count(4096, 1024) == 4);
}

static void test_chunk_count_zero_size_guard(void) {
    /* A zero chunk size must not divide-by-zero; it returns 0. */
    CHECK(sx_chunk_count(100, 0) == 0);
}

static void test_chunk_hash_fills_fields(void) {
    const uint8_t data[] = {1, 2, 3, 4, 5};
    sx_chunk chunk;
    CHECK(sx_chunk_hash(7, 100, data, 5, &chunk) == SX_OK);
    CHECK(chunk.index == 7);
    CHECK(chunk.offset == 100);
    CHECK(chunk.length == 5);
}

static void test_chunk_hash_null_rejected(void) {
    sx_chunk chunk;
    CHECK(sx_chunk_hash(0, 0, NULL, 0, &chunk) == SX_ERR_ARGS);
}

int main(void) {
    RUN(test_chunk_count_basic);
    RUN(test_chunk_count_zero_size_guard);
    RUN(test_chunk_hash_fills_fields);
    RUN(test_chunk_hash_null_rejected);
    TEST_REPORT();
}
