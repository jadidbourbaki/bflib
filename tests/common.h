/*
 * Tiny C test harness, no external dependency. Each test is a static
 * function returning 0 on pass and nonzero on fail. The harness
 * provides assertion macros, a runner that tracks pass/fail counts,
 * and a final report.
 *
 * Usage:
 *
 *   #include "common.h"
 *
 *   static int test_one_plus_one(void) {
 *       TEST_ASSERT(1 + 1 == 2);
 *       return 0;
 *   }
 *
 *   int main(void) {
 *       RUN_TEST(test_one_plus_one);
 *       return TEST_REPORT();
 *   }
 *
 * The harness counters and macros live at file scope, so each test
 * program should include this header in exactly one translation unit.
 *
 * To add new assertion macros, follow the pattern of TEST_ASSERT_EQ_U64
 * below: print "expected X, got Y" on failure and return 1 so the
 * RUN_TEST runner sees the fail.
 */

#pragma once

#include <stdio.h>
#include <stdint.h>

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  ASSERT failed at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

#define TEST_ASSERT_EQ_U64(actual, expected) do { \
    uint64_t _a = (actual), _e = (expected); \
    if (_a != _e) { \
        fprintf(stderr, "  ASSERT failed at %s:%d: " \
                "expected 0x%016llx, got 0x%016llx\n", \
                __FILE__, __LINE__, \
                (unsigned long long)_e, (unsigned long long)_a); \
        return 1; \
    } \
} while (0)

#define TEST_ASSERT_EQ_U32(actual, expected) do { \
    uint32_t _a = (actual), _e = (expected); \
    if (_a != _e) { \
        fprintf(stderr, "  ASSERT failed at %s:%d: " \
                "expected 0x%08x, got 0x%08x\n", \
                __FILE__, __LINE__, \
                (unsigned)_e, (unsigned)_a); \
        return 1; \
    } \
} while (0)

#define RUN_TEST(fn) do { \
    int _r = fn(); \
    if (_r == 0) { \
        printf("  PASS  %s\n", #fn); \
        g_pass++; \
    } else { \
        printf("  FAIL  %s\n", #fn); \
        g_fail++; \
    } \
} while (0)

/* Print pass/fail summary and return 0 if everything passed, 1 if
 * anything failed. Call from main: return TEST_REPORT(); */
#define TEST_REPORT() ( \
    printf("%d passed, %d failed\n", g_pass, g_fail), \
    (g_fail ? 1 : 0) \
)
