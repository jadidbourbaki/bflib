/*
 * aeshash: a minimal AES-based hash for benchmarking only.
 *
 * Not part of the public bflib API. Used by bfhash_bench to give the
 * latency benchmark a third column representing the "hardware hash"
 * design point (one full AES round per chunk).
 *
 * Interface mirrors bfhash: the function produces two 32-bit outputs
 * via output pointers, suitable for Kirsch-Mitzenmacher double hashing.
 *
 * Construction.
 *
 * The hash maintains a 128-bit state. The 16-byte input chunks are
 * absorbed by XOR-then-AES-round, mirroring AHash and MeowHash. For
 * variable-length inputs we use the same overlap-back trick as bfhash:
 * the last 16 bytes are read by overlapping the last full chunk, and
 * the byte length is mixed in to disambiguate inputs of different
 * lengths whose overlapped views coincide.
 *
 * One AES round per chunk gives full bit avalanche after two rounds
 * by the AES diffusion property (one round mixes within rows, the
 * second across columns via MixColumns). We do two final rounds on
 * the closed state to guarantee any single input bit affects all
 * output bits.
 *
 * Quality.
 *
 * AES-based hashing has empirically excellent bit mixing but no clean
 * universality proof analogous to Thorup's pair-multiply-shift. This
 * matters for production Bloom filter use where strong universality
 * gives tight false-positive bounds, but does not matter for the
 * latency comparison this header is built for.
 *
 * Portability.
 *
 * Requires AES instructions: __ARM_FEATURE_AES on AArch64 or __AES__
 * on x86_64. Apple Silicon and any modern x86 with AES-NI both qualify.
 * If neither is available the file does not define aeshash and the
 * bench omits the column.
 */

#pragma once

#include <stdint.h>
#include <string.h>

#if defined(__ARM_FEATURE_AES) || defined(__ARM_FEATURE_CRYPTO)
#  include <arm_neon.h>
#  define AESHASH_AVAILABLE 1
typedef uint8x16_t aeshash_state_t;
static inline aeshash_state_t aeshash_load(const void *p) {
    return vld1q_u8((const uint8_t *)p);
}
static inline aeshash_state_t aeshash_xor(aeshash_state_t a, aeshash_state_t b) {
    return veorq_u8(a, b);
}
/* AES round equivalent to x86 AESENC: SubBytes, ShiftRows, MixColumns,
 * AddRoundKey. ARM splits this across vaeseq_u8 (SubBytes + ShiftRows
 * + AddRoundKey, with the key XORed BEFORE the substitution) and
 * vaesmcq_u8 (MixColumns). The composition with key XOR'd first
 * matches AESENC's algebra. */
static inline aeshash_state_t aeshash_round(aeshash_state_t s, aeshash_state_t k) {
    return vaesmcq_u8(vaeseq_u8(s, k));
}
#elif defined(__AES__) && (defined(__x86_64__) || defined(_M_X64))
#  include <wmmintrin.h>
#  define AESHASH_AVAILABLE 1
typedef __m128i aeshash_state_t;
static inline aeshash_state_t aeshash_load(const void *p) {
    return _mm_loadu_si128((const __m128i *)p);
}
static inline aeshash_state_t aeshash_xor(aeshash_state_t a, aeshash_state_t b) {
    return _mm_xor_si128(a, b);
}
static inline aeshash_state_t aeshash_round(aeshash_state_t s, aeshash_state_t k) {
    return _mm_aesenc_si128(s, k);
}
#else
#  define AESHASH_AVAILABLE 0
#endif

#if AESHASH_AVAILABLE

/* Number of uint64 seeds: 4 = 32 bytes total. seeds[0..1] form the
 * initial 128-bit state; seeds[2..3] form the round key reused
 * throughout. */
#define AESHASH_SEEDS 4

/* Apples-to-apples 8-byte specialization, parallel to bfhash_u64.
 *
 * The construction is the minimum AES work that gives both outputs
 * full diffusion over all 64 input bits. ONE AESENC round is not
 * enough: ShiftRows + MixColumns mixes only within columns, so each
 * output byte after one round depends on 4 input bytes (one from
 * each input column post-ShiftRows). With the input placed in the
 * low half of the state, h1 and h2 after one round would each
 * depend on a strict subset of the 8 input bytes. TWO rounds give
 * full byte-to-byte diffusion across all 16 state bytes, so each
 * 32-bit output is a function of every input byte. This matches
 * the property bfhash_u64 provides via the multiply (which makes
 * every output bit depend on every input bit subject to the
 * lower-triangular caveat).
 *
 * State layout. The 8-byte key sits in state bytes 0..7 XOR'd with
 * seeds[0]; seeds[1] occupies bytes 8..15 to give the round key
 * material to mix into the second column pair. seeds[2..3] form
 * the AES round key reused for both rounds.
 *
 * Critical path: 1 XOR, 1 load (state init), 2 AES rounds in series.
 * On Apple M-series each AES round is ~3 cycles latency, so the
 * critical path is roughly 1 + 6 + 2 = ~9 cycles. bfhash_u64 is
 * ~6 cycles. The ~50% gap is the structural cost of doing the same
 * "mix everything into everything" work via crypto rather than via
 * a single 64x64 multiply.
 *
 * Quality. AES has empirically excellent bit mixing per round but
 * no clean universality proof. h1 and h2 are not independent in the
 * formal sense bfhash_u64 provides (which uses disjoint seed slices
 * for two independent multiply-shift constructions); they are two
 * 32-bit views of the same final AES state. For benchmark purposes
 * this is fine, since the comparison is about latency, not formal
 * collision bounds.
 *
 * @param  key    The 8-byte key, passed by value.
 * @param  seeds  Array of AESHASH_SEEDS = 4 uniform random uint64.
 * @param  h1     Output: top 32 bits of the low 64 bits of the final
 *                AES state.
 * @param  h2     Output: top 32 bits of the high 64 bits of the
 *                final AES state.
 */
static inline void aeshash_u64(uint64_t key,
                                const uint64_t *seeds,
                                uint32_t *h1, uint32_t *h2) {
    uint64_t state_init[2] = { key ^ seeds[0], seeds[1] };
    aeshash_state_t state = aeshash_load(state_init);
    aeshash_state_t rkey  = aeshash_load(seeds + 2);

    state = aeshash_round(state, rkey);
    state = aeshash_round(state, rkey);

    uint64_t out[2];
    memcpy(out, &state, 16);
    *h1 = (uint32_t)(out[0] >> 32);
    *h2 = (uint32_t)(out[1] >> 32);
}

/* Hash a key of any length >= 8 bytes into two strongly-mixed 32-bit
 * outputs.
 *
 * Strategy:
 *   1. Initialize state from seeds[0..1].
 *   2. Mix length into state.
 *   3. While at least 16 bytes remain: state = AES(state ^ chunk, key).
 *   4. If a tail remains (1..15 bytes): read the LAST 16 bytes of input
 *      via overlap-back and absorb that block. For len < 16 this is
 *      the entire input padded with the tail of the seed. For len in
 *      [8, 15] we instead read first-8 + last-8 since reading 16
 *      contiguous bytes would underflow.
 *   5. Two final AES rounds for full diffusion.
 *   6. Take the top 32 bits of each 64-bit half of the final state.
 */
static inline void aeshash(const void *key, size_t len,
                            const uint64_t *seeds,
                            uint32_t *h1, uint32_t *h2) {
    const uint8_t *p = (const uint8_t *)key;
    aeshash_state_t state = aeshash_load(seeds);
    aeshash_state_t rkey  = aeshash_load(seeds + 2);

    /* Mix length into state so equal-prefix different-length inputs
     * diverge on the first round. */
    uint64_t lenmix[2] = { (uint64_t)len, ~(uint64_t)len };
    state = aeshash_xor(state, aeshash_load(lenmix));

    size_t i = len;

    /* Main loop: full 16-byte chunks. */
    while (i >= 16) {
        state = aeshash_round(aeshash_xor(state, aeshash_load(p)), rkey);
        p += 16;
        i -= 16;
    }

    /* Tail handling. For inputs that are an exact multiple of 16 we
     * can skip this. For [8, 15] residual bytes we build a 16-byte
     * block from first-8 and last-8 of the residual. For [1, 7] (not
     * expected in Bloom filter use but covered defensively) we use
     * the same overlap with the prior chunk if available. */
    if (i > 0) {
        uint8_t tail[16];
        if (i >= 8) {
            memcpy(tail, p, 8);
            memcpy(tail + 8, p + i - 8, 8);
        } else {
            /* i in [1, 7]: read last 8 bytes of input (which may
             * reach back into the prior absorbed chunk). For our
             * Bloom filter use case len >= 8 always, so if we got
             * here there must be a prior chunk. Fall back to padding
             * with seed bytes if the input is shorter than 8 total. */
            if ((size_t)(p - (const uint8_t *)key) >= 8 - i) {
                memcpy(tail, p + i - 8, 8);
            } else {
                memset(tail, 0, 8);
                memcpy(tail, key, len);
            }
            memcpy(tail + 8, &seeds[3], 8);
        }
        state = aeshash_round(aeshash_xor(state, aeshash_load(tail)), rkey);
    }

    /* Final mixing rounds for full diffusion. */
    state = aeshash_round(state, rkey);
    state = aeshash_round(state, rkey);

    uint64_t out[2];
    memcpy(out, &state, 16);
    *h1 = (uint32_t)(out[0] >> 32);
    *h2 = (uint32_t)(out[1] >> 32);
}

#endif /* AESHASH_AVAILABLE */
