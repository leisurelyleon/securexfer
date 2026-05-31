#ifndef SECUREXFER_TEST_FRAMEWORK_H
#define SECUREXFER_TEST_FRAMEWORK_H

#include <stdio.h>

/* A minimal test harness. Each test file defines TESTS as a sequence of
 * CHECK(...) assertions inside functions registered in main(). */

static int sx_tests_run = 0;
static int sx_tests_failed = 0;

#define CHECK(cond)                                                                    \
    do {                                                                               \
        sx_tests_run++;                                                                \
        if (!(cond)) {                                                                 \
            sx_tests_failed++;                                                          \
            fprintf(stderr, "  FAIL: %s (line %d): %s\n", __func__, __LINE__, #cond);  \
        }                                                                              \
    } while (0)

#define RUN(test_fn)                                                                   \
    do {                                                                               \
        fprintf(stderr, "- %s\n", #test_fn);                                           \
        test_fn();                                                                     \
    } while (0)

#define TEST_REPORT()                                                                  \
    do {                                                                               \
        fprintf(stderr, "%d checks, %d failed\n", sx_tests_run, sx_tests_failed);      \
        return sx_tests_failed == 0 ? 0 : 1;                                           \
    } while (0)

#endif /* SECUREXFER_TEST_FRAMEWORK_H */
