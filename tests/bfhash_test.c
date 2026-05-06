/*
 * bfhash unit tests.
 *
 * Tiny custom test harness, no external dependency. Build and run:
 *   make
 *   ./tests
 *
 * Test categories:
 *   - Determinism. Same input + same seeds yields the same output, for
 *     every variant.
 *   - Known-answer tests. Hardcoded expected outputs for canonical
 *     inputs. Catches algorithm drift during refactors.
 *   - Sensitivity. Bit-level changes to input or seed change the
 *     output.
 *   - Length disambiguation. Same prefix bytes with different len
 *     produces different hashes for variable-length variants.
 *   - Boundary sizes. Each variant called at its size boundaries to
 *     verify it routes correctly and produces non-trivial output.
 *   - Both halves used. h1 and h2 both depend on input.
 *
 * To regenerate KATs after an intentional algorithm change:
 *   1. Build and run. KATs fail, the harness prints actual values.
 *   2. Copy actual values into the kat_* test bodies.
 *   3. Build and run again; KATs should pass.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bfhash.h"
#include "common.h"

/* Fixed test seeds for reproducibility. */
static const uint64_t S_U64[BFHASH_U64_SEEDS] = {
    UINT64_C(0x1234567890abcdef),
    UINT64_C(0xfedcba0987654321),
    UINT64_C(0x0123456789abcdef),
    UINT64_C(0xa1a2a3a4a5a6a7a8),
    UINT64_C(0xb1b2b3b4b5b6b7b8),
    UINT64_C(0xc1c2c3c4c5c6c7c8),
};
static const uint64_t S_SHORT[BFHASH_SHORT_SEEDS] = {
    UINT64_C(0x1111222233334444),
    UINT64_C(0x5555666677778888),
    UINT64_C(0x9999aaaabbbbcccc),
    UINT64_C(0xddddeeeeffff0000),
    UINT64_C(0x1010101010101010),
    UINT64_C(0x2020202020202020),
};
static const uint64_t S_MEDIUM[BFHASH_MEDIUM_SEEDS] = {
    UINT64_C(0xaaaaaaaaaaaaaaaa),
    UINT64_C(0xbbbbbbbbbbbbbbbb),
    UINT64_C(0xcccccccccccccccc),
    UINT64_C(0xdddddddddddddddd),
    UINT64_C(0xeeeeeeeeeeeeeeee),
    UINT64_C(0x1111111111111111),
    UINT64_C(0x2222222222222222),
    UINT64_C(0x3333333333333333),
    UINT64_C(0x4444444444444444),
    UINT64_C(0x5555555555555555),
};
static const uint64_t S_LONG[BFHASH_LONG_SEEDS] = {
    UINT64_C(0x4242424242424242),
};

/* ============================================================
 * Determinism: same input + same seeds yields the same output.
 * ============================================================ */

static int test_determinism_u64(void) {
    uint32_t a1, a2, b1, b2;
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S_U64, &a1, &a2);
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S_U64, &b1, &b2);
    TEST_ASSERT_EQ_U32(a1, b1);
    TEST_ASSERT_EQ_U32(a2, b2);
    return 0;
}

static int test_determinism_short(void) {
    const char key[] = "12345678abc"; /* 11 bytes */
    uint32_t a1, a2, b1, b2;
    bfhash_short(key, 11, S_SHORT, &a1, &a2);
    bfhash_short(key, 11, S_SHORT, &b1, &b2);
    TEST_ASSERT_EQ_U32(a1, b1);
    TEST_ASSERT_EQ_U32(a2, b2);
    return 0;
}

static int test_determinism_medium(void) {
    const char key[] = "0123456789abcdef0123456789ab"; /* 28 bytes */
    uint32_t a1, a2, b1, b2;
    bfhash_medium(key, 28, S_MEDIUM, &a1, &a2);
    bfhash_medium(key, 28, S_MEDIUM, &b1, &b2);
    TEST_ASSERT_EQ_U32(a1, b1);
    TEST_ASSERT_EQ_U32(a2, b2);
    return 0;
}

static int test_determinism_long(void) {
    char key[256];
    for (int i = 0; i < 256; i++) key[i] = (char)i;
    uint32_t a1, a2, b1, b2;
    bfhash_long(key, 256, S_LONG, &a1, &a2);
    bfhash_long(key, 256, S_LONG, &b1, &b2);
    TEST_ASSERT_EQ_U32(a1, b1);
    TEST_ASSERT_EQ_U32(a2, b2);
    return 0;
}

/* ============================================================
 * Sensitivity: bit-level change in input or seed changes output.
 * ============================================================ */

static int test_sensitivity_u64_input(void) {
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_u64(UINT64_C(0x0000000000000000), S_U64, &h1a, &h2a);
    bfhash_u64(UINT64_C(0x0000000000000001), S_U64, &h1b, &h2b);
    /* Either h1 or h2 must differ; for a real hash both should. */
    TEST_ASSERT(h1a != h1b || h2a != h2b);
    return 0;
}

static int test_sensitivity_u64_seed(void) {
    /* Differ only in seeds[2], the offset b for h1. h1 must differ;
     * h2 uses seeds[3..5] and is unaffected.
     *
     * The two seeds[2] values differ in their high bits so the
     * difference reaches the top 32 bits of the 64-bit product after
     * the offset add. Changing only low bits of b would leave the top
     * 32 bits untouched and the test would not exercise sensitivity. */
    uint64_t S1[6] = { 1, 2, UINT64_C(0x1111111111111111), 4, 5, 6 };
    uint64_t S2[6] = { 1, 2, UINT64_C(0x2222222222222222), 4, 5, 6 };
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S1, &h1a, &h2a);
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S2, &h1b, &h2b);
    TEST_ASSERT(h1a != h1b);
    TEST_ASSERT(h2a == h2b);
    return 0;
}

static int test_sensitivity_long_input(void) {
    char buf[256];
    for (int i = 0; i < 256; i++) buf[i] = (char)i;
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_long(buf, 256, S_LONG, &h1a, &h2a);
    buf[128] ^= 0x01; /* flip one bit in the middle */
    bfhash_long(buf, 256, S_LONG, &h1b, &h2b);
    TEST_ASSERT(h1a != h1b || h2a != h2b);
    return 0;
}

/* ============================================================
 * Length disambiguation. Same prefix, different len.
 * ============================================================ */

static int test_length_disambiguation_short(void) {
    char key[16] = "12345678ABCDEFGH";
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_short(key, 8, S_SHORT, &h1a, &h2a);
    bfhash_short(key, 16, S_SHORT, &h1b, &h2b);
    TEST_ASSERT(h1a != h1b || h2a != h2b);
    return 0;
}

static int test_length_disambiguation_medium(void) {
    /* Use distinct per-position bytes so the four 64-bit reads sample
     * different bytes for len=17 vs len=32. With a uniform key the
     * x_0..x_3 chunks would be identical for both lengths and only
     * the L addend would differ, which does not reach the top 32
     * bits after the shift. */
    char key[32];
    for (int i = 0; i < 32; i++) key[i] = (char)(i + 1);
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_medium(key, 17, S_MEDIUM, &h1a, &h2a);
    bfhash_medium(key, 32, S_MEDIUM, &h1b, &h2b);
    TEST_ASSERT(h1a != h1b || h2a != h2b);
    return 0;
}

static int test_length_disambiguation_long(void) {
    char buf[256];
    memset(buf, 0, sizeof(buf));
    uint32_t h1a, h2a, h1b, h2b;
    bfhash_long(buf, 64, S_LONG, &h1a, &h2a);
    bfhash_long(buf, 128, S_LONG, &h1b, &h2b);
    TEST_ASSERT(h1a != h1b || h2a != h2b);
    return 0;
}

/* ============================================================
 * Both halves used. Output isn't trivially zero.
 * ============================================================ */

static int test_both_halves_nonzero(void) {
    uint32_t h1, h2;
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S_U64, &h1, &h2);
    TEST_ASSERT(h1 != 0);
    TEST_ASSERT(h2 != 0);
    return 0;
}

/* ============================================================
 * Boundary sizes. Routes through the right variant and produces
 * non-trivial output without crashing.
 * ============================================================ */

static int test_boundaries(void) {
    char buf[2048];
    for (int i = 0; i < 2048; i++) buf[i] = (char)i;
    uint32_t h1, h2;

    bfhash_short(buf, 8,    S_SHORT,  &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_short(buf, 16,   S_SHORT,  &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_medium(buf, 17,  S_MEDIUM, &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_medium(buf, 32,  S_MEDIUM, &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 33,    S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 112,   S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 113,   S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 128,   S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 240,   S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    bfhash_long(buf, 1024,  S_LONG,   &h1, &h2); TEST_ASSERT(h1 || h2);
    return 0;
}

/* ============================================================
 * Known-answer tests. Hardcoded outputs for canonical inputs.
 * Update if the algorithm intentionally changes.
 * ============================================================ */

static int test_kat_u64(void) {
    uint32_t h1, h2;
    bfhash_u64(UINT64_C(0xdeadbeefcafebabe), S_U64, &h1, &h2);
    TEST_ASSERT_EQ_U32(h1, 0x95573583u);
    TEST_ASSERT_EQ_U32(h2, 0x10670021u);
    return 0;
}

static int test_kat_short(void) {
    const char key[] = "12345678abc"; /* 11 bytes */
    uint32_t h1, h2;
    bfhash_short(key, 11, S_SHORT, &h1, &h2);
    TEST_ASSERT_EQ_U32(h1, 0x87241228u);
    TEST_ASSERT_EQ_U32(h2, 0x7a5bba63u);
    return 0;
}

static int test_kat_medium(void) {
    const char key[] = "0123456789abcdef0123456789ab"; /* 28 bytes */
    uint32_t h1, h2;
    bfhash_medium(key, 28, S_MEDIUM, &h1, &h2);
    TEST_ASSERT_EQ_U32(h1, 0xfce83853u);
    TEST_ASSERT_EQ_U32(h2, 0x0723263eu);
    return 0;
}

static int test_kat_long(void) {
    char key[256];
    for (int i = 0; i < 256; i++) key[i] = (char)i;
    uint32_t h1, h2;
    bfhash_long(key, 256, S_LONG, &h1, &h2);
    TEST_ASSERT_EQ_U32(h1, 0xc1460c43u);
    TEST_ASSERT_EQ_U32(h2, 0x073c6a14u);
    return 0;
}

int main(void) {
    printf("bfhash unit tests\n");

    RUN_TEST(test_determinism_u64);
    RUN_TEST(test_determinism_short);
    RUN_TEST(test_determinism_medium);
    RUN_TEST(test_determinism_long);

    RUN_TEST(test_sensitivity_u64_input);
    RUN_TEST(test_sensitivity_u64_seed);
    RUN_TEST(test_sensitivity_long_input);

    RUN_TEST(test_length_disambiguation_short);
    RUN_TEST(test_length_disambiguation_medium);
    RUN_TEST(test_length_disambiguation_long);

    RUN_TEST(test_both_halves_nonzero);

    RUN_TEST(test_boundaries);

    RUN_TEST(test_kat_u64);
    RUN_TEST(test_kat_short);
    RUN_TEST(test_kat_medium);
    RUN_TEST(test_kat_long);

    return TEST_REPORT();
}
