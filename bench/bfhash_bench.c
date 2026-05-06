/*
 * bflib latency benchmark.
 *
 * Measures per-call latency for bfhash and rapidhash across input sizes
 * relevant to Bloom filter use. Latency mode chains each call's output
 * into the next call's input pointer, so the calls cannot be pipelined
 * by the CPU. This matches how a Bloom filter actually uses the hash:
 * one key at a time, sequentially.
 *
 * Three columns:
 *   rapidhash      one call, one 64-bit output.
 *   rapidhash*2    two calls with different seeds; this is the peer
 *                  for Kirsch-Mitzenmacher use, which needs two
 *                  independent 64-bit hashes per key.
 *   bfhash         one call, two 64-bit outputs. The point of bfhash.
 *
 * The headline number is bfhash vs rapidhash*2 since both deliver two
 * Kirsch-Mitzenmacher outputs per key.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "bfhash.h"
#include "rapidhash.h"
#include "aeshash.h"

#define BUFFER_SIZE 4096
#define MARGIN 64
#define CHAIN_MASK 0x3F
#define ITERS 30000000U
#define WARMUP 100000U
#define REPS 5

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

typedef uint64_t (*hash_wrapper_t)(const void *src, size_t size, const uint64_t *seeds);

/*
 * The wrappers below are deliberately left inlinable. The compiler
 * is free to inline rapidhash_wrap and rapidhash_x2_wrap, which are
 * small one-liners, while leaving the larger size-dispatch body of
 * bfhash_wrap as a real call. That asymmetry hands rapidhash every
 * available compiler advantage: zero call overhead, cross-call
 * optimization, hoisted seed loads. We accept that handicap. The
 * point of this benchmark is to show bfhash beating rapidhash*2 even
 * when rapidhash is given the friendlier inlining environment.
 */
static uint64_t rapidhash_wrap(const void *src, size_t size, const uint64_t *seeds) {
    (void)seeds;
    return rapidhash_withSeed(src, size, UINT64_C(0xa1));
}

static uint64_t rapidhash_x2_wrap(const void *src, size_t size, const uint64_t *seeds) {
    (void)seeds;
    uint64_t a = rapidhash_withSeed(src, size, UINT64_C(0xa1));
    uint64_t b = rapidhash_withSeed(src, size, UINT64_C(0xb2));
    return a ^ b;
}

static uint64_t bfhash_wrap(const void *src, size_t size, const uint64_t *seeds) {
    uint32_t h1 = 0, h2 = 0;
    if (size == 8) {
        uint64_t k;
        memcpy(&k, src, 8);
        bfhash_u64(k, seeds, &h1, &h2);
    } else if (size <= 16) {
        bfhash_short(src, size, seeds, &h1, &h2);
    } else if (size <= 32) {
        bfhash_medium(src, size, seeds, &h1, &h2);
    } else {
        bfhash_long(src, size, seeds, &h1, &h2);
    }
    return (uint64_t)(h1 ^ h2);
}

#if AESHASH_AVAILABLE
static uint64_t aeshash_wrap(const void *src, size_t size, const uint64_t *seeds) {
    uint32_t h1 = 0, h2 = 0;
    if (size == 8) {
        uint64_t k;
        memcpy(&k, src, 8);
        aeshash_u64(k, seeds, &h1, &h2);
    } else {
        aeshash(src, size, seeds, &h1, &h2);
    }
    return (uint64_t)(h1 ^ h2);
}
#endif

/*
 * Each iteration writes one byte at buf[chain & CHAIN_MASK] and then
 * the hash reads from buf + (chain & CHAIN_MASK), so the read region
 * starts at the byte we just wrote. This forces a real memory
 * dependency through the chain.
 *
 * Why this matters. An earlier version of this loop used chain only
 * to perturb the read address. The buffer contents never changed and
 * the read window always sat in L1. Modern out-of-order cores hide
 * that kind of pure-address chain in several ways:
 *
 *   1. Memory-level parallelism. The core speculatively issues loads
 *      for iterations N+1 and N+2 in parallel with iteration N's
 *      hash work, since loads to predictable addresses are cheap to
 *      speculate on.
 *
 *   2. Load value prediction. After warmup the chain cycles through
 *      a small set of starting offsets and the load values themselves
 *      are predictable enough that downstream work can begin before
 *      the load completes.
 *
 *   3. Cache line warmth. With a 4 KiB buffer and start offsets in a
 *      64-byte window, the read region always sits in L1 and load
 *      latency is largely overlapped with arithmetic.
 *
 * Together those let some sizes pipeline implausibly fast while
 * others got penalized for unrelated reasons, producing artifacts
 * like "16 bytes runs in 1.26 ns" that are not physically achievable
 * for a multiply-based hash on this hardware.
 *
 * Writing into the read region adds a read-after-write dependency at
 * the same address. CPU memory ordering rules require the load to
 * observe the just-written byte, which it receives via store-to-load
 * forwarding from the store buffer. Forwarding is fast, around 5
 * cycles on Skylake, Zen, and Apple M-series cores, but it cannot be
 * speculated past: the load's data is unknown until the store
 * retires or forwards. The dependency chain becomes:
 *
 *   chain_N -> store address and store value
 *   store -> load via store-to-load forwarding
 *   load value -> hash inputs -> hash result
 *   hash result -> chain_{N+1}
 *
 * Iteration N+1's chain cannot start until iteration N's load
 * completes, which is exactly the per-call latency a Bloom filter
 * pays in scalar code. That is what we want to measure.
 */
static double bench_latency(hash_wrapper_t hashfn, uint8_t *buf,
                            size_t size, const uint64_t *seeds) {
    uint64_t chain = 0;

    for (uint64_t i = 0; i < WARMUP; i++) {
        buf[chain & CHAIN_MASK] = (uint8_t)chain;
        const uint8_t *p = buf + (chain & CHAIN_MASK);
        chain ^= hashfn(p, size, seeds);
    }

    uint64_t t0 = now_ns();
    for (uint64_t i = 0; i < ITERS; i++) {
        buf[chain & CHAIN_MASK] = (uint8_t)chain;
        const uint8_t *p = buf + (chain & CHAIN_MASK);
        chain ^= hashfn(p, size, seeds);
    }
    uint64_t t1 = now_ns();

    /* Prevent dead-code elimination of the hash result. */
    if (chain == UINT64_C(0xdeadbeef13579bd0)) printf("%c", (int)(chain & 0xff));

    return (double)(t1 - t0) / (double)ITERS;
}

int main(void) {
    uint8_t *buf = (uint8_t*)malloc(BUFFER_SIZE + MARGIN);
    if (!buf) { fprintf(stderr, "alloc failed\n"); return 1; }
    for (size_t i = 0; i < BUFFER_SIZE + MARGIN; i++) buf[i] = (uint8_t)(i & 0xff);

    uint64_t seeds[BFHASH_MEDIUM_SEEDS] = {
        UINT64_C(0x1234567890abcdef),
        UINT64_C(0xfedcba0987654321),
        UINT64_C(0x0123456789abcdef),
        UINT64_C(0xa5a5a5a5a5a5a5a5),
        UINT64_C(0x5a5a5a5a5a5a5a5a),
        UINT64_C(0x6c6f6f6b696e673f),
        UINT64_C(0x736565647363616e),
        UINT64_C(0x0badc0deba5edba1),
        UINT64_C(0xfacebeef13579bdf),
        UINT64_C(0x2468ace013579bdf),
    };

    static const size_t sizes[] = {
        8, 12, 16, 17, 20, 24, 28, 32, 40, 48,
        64, 96,
        112,         /* worst-spot: max ladder, no lane loop */
        128,         /* sweet spot: 1 * 112 + 16, no ladder */
        144,         /* lane + 1 ladder step */
        224,         /* worst-spot: 1 lane + max ladder */
        240,         /* sweet spot: 2 * 112 + 16 */
        256,
        352,         /* sweet spot: 3 * 112 + 16 */
        1024         /* sweet spot: 9 * 112 + 16 */
    };
    static const size_t nsizes  = sizeof(sizes) / sizeof(sizes[0]);

    /* CSV header. Latencies are in ns/call. speedup_vs_rh2 is
     * rapidhash*2 / bfhash. speedup_aes is aeshash / bfhash; values
     * > 1 mean bfhash is faster. The aeshash column is omitted on
     * builds without AES intrinsics. */
#if AESHASH_AVAILABLE
    printf("size_bytes,rapidhash_ns,rapidhash_x2_ns,bfhash_ns,aeshash_ns,speedup_vs_rh2,speedup_aes_vs_bf\n");
#else
    printf("size_bytes,rapidhash_ns,rapidhash_x2_ns,bfhash_ns,speedup_vs_rh2\n");
#endif
    fflush(stdout);

    for (size_t i = 0; i < nsizes; i++) {
        size_t size = sizes[i];
        double r1 = 1e18, r2 = 1e18, bf = 1e18;
#if AESHASH_AVAILABLE
        double ae = 1e18;
#endif
        for (int rep = 0; rep < REPS; rep++) {
            double a = bench_latency(rapidhash_wrap,    buf, size, seeds);
            double b = bench_latency(rapidhash_x2_wrap, buf, size, seeds);
            double c = bench_latency(bfhash_wrap,       buf, size, seeds);
            if (a < r1) r1 = a;
            if (b < r2) r2 = b;
            if (c < bf) bf = c;
#if AESHASH_AVAILABLE
            double d = bench_latency(aeshash_wrap, buf, size, seeds);
            if (d < ae) ae = d;
#endif
        }
        double speedup = r2 / bf;
#if AESHASH_AVAILABLE
        double aes_ratio = ae / bf;
        printf("%zu,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f\n",
               size, r1, r2, bf, ae, speedup, aes_ratio);
#else
        printf("%zu,%.4f,%.4f,%.4f,%.4f\n", size, r1, r2, bf, speedup);
#endif
        fflush(stdout);
    }

    free(buf);
    return 0;
}
