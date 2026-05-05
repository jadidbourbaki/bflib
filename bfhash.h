/*
 * bfhash is the Bloom-filter-specialized hash used by bflib. It
 * provides four entry points that produce two 64-bit outputs from one
 * 64x64 -> 128 multiply, sized for the major Bloom filter key regimes:
 *
 *     bfhash_u64      fixed 8-byte uint64 keys.
 *     bfhash_short    variable-length keys in [8, 16] bytes.
 *     bfhash_medium   variable-length keys in [17, 32] bytes.
 *     bfhash_long     variable-length keys longer than 32 bytes.
 *
 * Each variant returns h1 and h2 in a single call. The two outputs
 * are intended as the independent hashes that Kirsch-Mitzenmacher
 * double hashing requires to derive k Bloom filter indices via
 * g_i(x) = h1 + i * h2 mod m. Producing both outputs from one
 * multiply rather than from two separate hash calls is the main
 * reason a Bloom filter using bfhash is faster than one using a
 * general-purpose 64-bit hash.
 *
 * Theoretical basis.
 *
 * The short-side variants bfhash_u64, bfhash_short, and bfhash_medium
 * implement Thorup's pair-multiply-shift and prefix-pair-multiply-
 * shift constructions from his lecture notes "High Speed Hashing for
 * Integers and Strings", arXiv:1504.06804, sections 2.3 and 5.1. The
 * top 32 bits of h1 are strongly universal per Thorup theorem 3.7.
 * The high 64 bits of h2 are empirically well-mixed but not formally
 * analyzed by Thorup.
 *
 * The long variant bfhash_long is rapidhash V3's 7-lane parallel
 * mixing loop, stripped of two operations: the seed-mixing prologue
 * and the final 64-bit fold. The 7-lane structure is the entire
 * speed win for long keys, since seven multiplies pipeline through
 * the hardware multiplier port at near-peak throughput. Modern x86
 * cores have one integer multiplier port with one-multiply-per-cycle
 * throughput and three-cycle latency, so seven independent multiplies
 * complete in about ten cycles rather than the twenty-one cycles a
 * sequential dependency chain would need. AMD Zen and Apple M cores
 * expose similar single-port multiplier bottlenecks. The strip
 * removes work that Bloom filters do not need, since there is no
 * adversary to defend against and Kirsch-Mitzenmacher needs two
 * outputs rather than one strongly avalanched 64-bit output. The
 * remaining lane structure inherits rapidhash's empirical SMHasher
 * quality on extracted index bits.
 *
 * Threat model.
 *
 * bfhash assumes no adversary. The seed is fixed at Bloom filter
 * creation and is not exposed to attacker-controlled inputs. Use
 * cases that need adversarial robustness, such as hash tables with
 * untrusted keys, should use a hash designed for that, not bfhash.
 *
 * Extraction contract.
 *
 * Callers must extract Bloom indices from the high bits of h1 and h2,
 * not from the low bits. This is structural to multiplicative
 * hashing: bit i of a * x mod 2^w depends only on bits 0..i of x.
 * Use top-bit shift or Lemire's fast modulo to obtain an index. The
 * per-function comments below give the exact recipe.
 *
 * Attribution.
 *
 * Several techniques and one constant are borrowed from rapidhash V3
 * by Nicolas De Carli, used under the MIT license. Each borrowing is
 * annotated at its site. See third_party/rapidhash for the original
 * source.
 *
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2026 hayder
 *
 * This file is part of bflib. See the LICENSE file in the project
 * root for the full MIT license text.
 */

#pragma once

#include "bflib_version.h"

#include <stdint.h>
#include <string.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#  if defined(_M_X64) && !defined(_M_ARM64EC)
#    pragma intrinsic(_umul128)
#  endif
#endif

/* START OF BFLIB MACROS */
/* The BF_* macros below mirror rapidhash with RAPIDHASH_* renamed
   to BF_*. The rename keeps the namespace clear for projects that
   include both rapidhash and bflib. */
#ifdef _MSC_VER
#  define BF_ALWAYS_INLINE __forceinline
#elif defined(__GNUC__)
#  define BF_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#  define BF_ALWAYS_INLINE inline
#endif

#ifdef __cplusplus
#  define BF_NOEXCEPT noexcept
#  define BF_CONSTEXPR constexpr
#  ifndef BF_INLINE
#    define BF_INLINE BF_ALWAYS_INLINE
#  endif
#  if __cplusplus >= 201402L && !defined(_MSC_VER)
#    define BF_INLINE_CONSTEXPR BF_ALWAYS_INLINE constexpr
#  else
#    define BF_INLINE_CONSTEXPR BF_ALWAYS_INLINE
#  endif
#else
#  define BF_NOEXCEPT
#  define BF_CONSTEXPR static const
#  ifndef BF_INLINE
#    define BF_INLINE static BF_ALWAYS_INLINE
#  endif
#  define BF_INLINE_CONSTEXPR BF_INLINE
#endif


#ifndef BF_LITTLE_ENDIAN
#  if defined(_WIN32) || defined(__LITTLE_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define BF_LITTLE_ENDIAN
#  elif defined(__BIG_ENDIAN__) || \
      (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#    define BF_BIG_ENDIAN
#  else
#    warning "could not determine endianness! Falling back to little endian."
#    define BF_LITTLE_ENDIAN
#  endif
#endif
/* END OF BFLIB MACROS */

/* The starting value is rapidhash V3's secret[0]. TODO: replace this
   with a value tuned for avalanche on the bits actually extracted as
   Bloom indices. */
#ifndef BFHASH_SECRET
#define BFHASH_SECRET UINT64_C(0x2d358dccaa6c78a5)
#endif

/* Seed counts per hash function. Each bfhash_* function takes a
   seeds pointer to an array of BFHASH_*_SEEDS uniform random uint64
   values. A Bloom filter using bfhash generates this array once at
   filter creation. */
#define BFHASH_U64_SEEDS    3
#define BFHASH_SHORT_SEEDS  3
#define BFHASH_MEDIUM_SEEDS 5
#define BFHASH_LONG_SEEDS   1

/* Per-lane secrets for bfhash_long's parallel-lane mixing. Taken
   verbatim from rapidhash V3's secret[0..6]. They are file constants
   rather than per-filter seeds because their role in the long path is
   empirical lane decorrelation as opposed to any adversarial guarantees. 
   Inheriting rapidhash's tuned values means inheriting their SMHasher pass
   quality for free. */
BF_CONSTEXPR uint64_t bfhash_long_secret[7] = {
    UINT64_C(0x2d358dccaa6c78a5),
    UINT64_C(0x8bb84b93962eacc9),
    UINT64_C(0x4b33a62ed433d4a3),
    UINT64_C(0x4d5a2da51de1aa47),
    UINT64_C(0xa0761d6478bd642f),
    UINT64_C(0xe7037ed1a0b428db),
    UINT64_C(0x90ed1765281c388c),
};

/* Verbatim from rapidhash's rapid_read64 with rapid_ renamed to
   bfhash_ and RAPIDHASH_* renamed to BF_*. The rename prevents
   namespace collisions. */
#ifdef BF_LITTLE_ENDIAN
BF_INLINE uint64_t bfhash_read64(const uint8_t *p) BF_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return v;}
#elif defined(__GNUC__) || defined(__INTEL_COMPILER) || defined(__clang__)
BF_INLINE uint64_t bfhash_read64(const uint8_t *p) BF_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return __builtin_bswap64(v);}
#elif defined(_MSC_VER)
BF_INLINE uint64_t bfhash_read64(const uint8_t *p) BF_NOEXCEPT { uint64_t v; memcpy(&v, p, sizeof(uint64_t)); return _byteswap_uint64(v);}
#else
BF_INLINE uint64_t bfhash_read64(const uint8_t *p) BF_NOEXCEPT {
  uint64_t v; memcpy(&v, p, 8);
  return (((v >> 56) & 0xff)| ((v >> 40) & 0xff00)| ((v >> 24) & 0xff0000)| ((v >>  8) & 0xff000000)| ((v <<  8) & 0xff00000000)| ((v << 24) & 0xff0000000000)| ((v << 40) & 0xff000000000000)| ((v << 56) & 0xff00000000000000));
}
#endif

/* 64x64 -> 128 bit multiply.
 *
 * The body of bfhash_mul128 is the unprotected branch in rapidhash's
 * rapid_mum. The interface differs. rapid_mum takes two uint64_t
 * pointers and overwrites them with the product halves. bfhash_mul128
 * takes two uint64_t values and writes the product halves to separate
 * output pointers. The pass-by-value form keeps call sites readable
 * because callers can pass any expression as input.
 *
 * @param  a   First 64-bit input.
 * @param  b   Second 64-bit input.
 * @param  lo  Output: low 64 bits of a * b.
 * @param  hi  Output: high 64 bits of a * b.
 */
BF_INLINE_CONSTEXPR void bfhash_mul128(uint64_t a, uint64_t b,
                               uint64_t *lo, uint64_t *hi) BF_NOEXCEPT {
#if defined(__SIZEOF_INT128__)
    __uint128_t r=a; r*=b;
    *lo=(uint64_t)r; *hi=(uint64_t)(r>>64);
#elif defined(_MSC_VER) && (defined(_WIN64) || defined(_M_HYBRID_CHPE_ARM64))
#  if defined(_M_X64)
    *lo = _umul128(a, b, hi);
#  else
    uint64_t c = __umulh(a, b);
    *lo = a * b;
    *hi = c;
#  endif
#else
    uint64_t ha=a>>32, hb=b>>32, la=(uint32_t)a, lb=(uint32_t)b;
    uint64_t rh=ha*hb, rm0=ha*lb, rm1=hb*la, rl=la*lb, t=rl+(rm0<<32), c=t<rl;
    uint64_t l=t+(rm1<<32);
    c+=l<t;
    *lo=l;
    *hi=rh+(rm0>>32)+(rm1>>32)+c;
#endif
}

/* bfhash_mix: 64x64 -> 128 multiply, then XOR the halves into one
   uint64. Equivalent to rapid_mix from rapidhash. Used inside
   bfhash_long's lane mixing. */
BF_INLINE_CONSTEXPR uint64_t bfhash_mix(uint64_t a, uint64_t b) BF_NOEXCEPT {
    uint64_t lo = 0, hi = 0;
    bfhash_mul128(a, b, &lo, &hi);
    return lo ^ hi;
}

/* Hash a fixed 8-byte uint64 key into two hashes for Kirsch-Mitzenmacher
 * double hashing.
 *
 * The construction is Thorup's pair-multiply-shift specialized to
 * 64-bit keys. From the tuned C code on page 16 of [1]:
 *
 *     hash(x, l, a1, a2, b) = ((a1 + x) * (a2 + (x >> 32)) + b) >> (64 - l)
 *
 * The two operands are 64-bit. Their product mod 2^64, plus the offset
 * b, shifted to extract the top l bits, is strongly universal for
 * l <= 32. This is theorem 3.7 of [1] specialized to d = 2 with 32-bit
 * coordinates and w = 64.
 *
 * Bfhash_u64 keeps the full 128-bit product instead of truncating
 * to 64. The low 64 bits, after adding b, become h1; the top 32 bits
 * of h1 carry Thorup's strong universality bound. The high 64 bits of
 * the product become h2; h2 is a function of all 128 bits of the
 * multiply and is empirically well-mixed but not formally analyzed by
 * Thorup.
 *
 * Three random seeds are required, all uniform random uint64. The
 * Bloom filter generates them once at filter creation and passes them
 * to every hash call.
 *
 * Extracting Bloom indices.
 *
 * Callers must extract Bloom indices from the high bits of h1 and h2,
 * not from the low bits. The reason is structural to multiplicative
 * hashing. Bit i of (a * x) mod 2^w depends only on bits 0..i of x,
 * so the low bits of any multiply-based hash carry less information
 * about the input than the high bits do. Two inputs that differ only
 * in their high bits produce identical low bits in their products, so
 * extracting low bits gives a hash that is not universal.
 *
 * Two extraction methods satisfy this requirement:
 *
 *   1. Top-bit shift: index = h >> (w - log2(m)). Requires m to be
 *      a power of two.
 *
 *   2. Lemire's fast modulo from [2]: index = (h * m) >> w. Valid
 *      for any m. Computes the top bits of h scaled to the range
 *      [0, m).
 *
 * Avoid the naive index = h % m. It uses low bits and is not
 * universal under multiplicative hashing.
 *
 * [1] Mikkel Thorup, "High Speed Hashing for Integers and Strings",
 *     https://arxiv.org/pdf/1504.06804
 * [2] Daniel Lemire, "Fast Random Integer Generation in an Interval",
 *     https://arxiv.org/abs/1805.10941
 *
 * Critical path: 2 ADDs in parallel, 1 multiply, 1 ADD. About 5 to 6
 * cycles.
 *
 * @param  key    The 8-byte key to hash, passed by value.
 * @param  seeds  Array of BFHASH_U64_SEEDS = 3 uniform random
 *                uint64. seeds[0] = a1, seeds[1] = a2, seeds[2] = b
 *                in Thorup's notation.
 * @param  h1     Output: low 64 bits of (a1+key) * (a2+(key>>32)) + b.
 *                Top 32 bits are strongly universal.
 * @param  h2     Output: high 64 bits of the same product. Empirically
 *                well-mixed.
 */
BF_INLINE_CONSTEXPR void bfhash_u64(uint64_t key,
                                    const uint64_t *seeds,
                                    uint64_t *h1, uint64_t *h2) BF_NOEXCEPT {
    uint64_t lo = 0, hi = 0;
    bfhash_mul128(seeds[0] + key, seeds[1] + (key >> 32), &lo, &hi);
    *h1 = lo + seeds[2];
    *h2 = hi;
}

/* Hash a variable-length key in [8, 16] bytes into two hashes for
 * Kirsch-Mitzenmacher double hashing.
 *
 * The construction is Thorup's prefix-pair-multiply-shift, equation
 * (20) of section 5.1 of [1], specialized to d = 2 with 64-bit
 * chunks obtained from the front and back of the input via
 * rapidhash's overlap-read trick:
 *
 *     x_0 = read64(p)
 *     x_1 = read64(p + len - 8)
 *     h   = ((a_0 + x_1)(a_1 + x_0) + a_2) [w - l, w]
 *
 * Note the cross-pairing. Seed a_0 multiplies the operand containing
 * x_1, and seed a_1 multiplies the operand containing x_0. This is
 * the form proven strongly universal by Thorup. We add len to the
 * offset to disambiguate inputs of different lengths covered by the
 * same overlap-read.
 *
 * Bfhash_short keeps the full 128-bit product. The low 64 bits,
 * plus a_2 plus len, become h1; the top 32 bits of h1 are strongly
 * universal per Thorup. The high 64 bits become h2, empirically
 * well-mixed.
 *
 * Three random seeds are required, all uniform random uint64. The
 * Bloom filter generates them once at filter creation and passes them
 * to every hash call.
 *
 * For len == 8 the two reads return the same bytes. The distinct
 * seeds added to each operand, a_0 to one and a_1 to the other, make
 * the two operands differ regardless, so the multiply is never a
 * square.
 *
 * The extraction-method contract is the same as bfhash_u64. See
 * its comment for the two safe methods and the structural reason low
 * bits are not universal.
 *
 * [1] Mikkel Thorup, "High Speed Hashing for Integers and Strings",
 *     https://arxiv.org/pdf/1504.06804
 *
 * Critical path: 2 reads, 2 ADDs in parallel, 1 multiply, 1 ADD.
 * About 5 to 6 cycles plus load latency.
 *
 * @param  key    Pointer to a key of length [8, 16] bytes.
 * @param  len    Key length in bytes. Must be in [8, 16].
 * @param  seeds  Array of BFHASH_SHORT_SEEDS = 3 uniform random
 *                uint64. seeds[0] = a_0, seeds[1] = a_1, seeds[2] =
 *                a_2 in Thorup's notation.
 * @param  h1     Output: low 64 bits of (a_0 + x_1)(a_1 + x_0) plus
 *                a_2 plus len. Top 32 bits are strongly universal.
 * @param  h2     Output: high 64 bits of the same product. Empirically
 *                well-mixed.
 */
BF_INLINE_CONSTEXPR void bfhash_short(const void *key, size_t len,
                                       const uint64_t *seeds,
                                       uint64_t *h1, uint64_t *h2) BF_NOEXCEPT {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t x0 = bfhash_read64(p);
    uint64_t x1 = bfhash_read64(p + len - 8);
    uint64_t lo = 0, hi = 0;
    bfhash_mul128(seeds[0] + x1, seeds[1] + x0, &lo, &hi);
    *h1 = lo + seeds[2] + (uint64_t)len;
    *h2 = hi;
}

/* Hash a variable-length key in [17, 32] bytes into two hashes for
 * Kirsch-Mitzenmacher double hashing.
 *
 * The construction is Thorup's prefix-pair-multiply-shift, equation
 * (20) of section 5.1 of [1], specialized to d = 4 with 64-bit chunks
 * obtained from the front and back halves of the input via the
 * overlap-read trick:
 *
 *     x_0 = read64(p)
 *     x_1 = read64(p + 8)
 *     x_2 = read64(p + len - 16)
 *     x_3 = read64(p + len - 8)
 *     h   = ((a_0 + x_1)(a_1 + x_0) + (a_2 + x_3)(a_3 + x_2) + a_4)
 *
 * For len == 32 the four reads are non-overlapping and tile the input
 * exactly. For len in [17, 31] the front pair (x_0, x_1) and back
 * pair (x_2, x_3) overlap somewhere in the middle, but every byte of
 * the input appears in at least one chunk. We add len to the offset
 * to disambiguate inputs of different lengths.
 *
 * The two pair products are computed as full 128-bit values and
 * summed with full carry. h1 is the low 64 bits of the sum plus a_4
 * plus len; the top 32 bits of h1 are strongly universal per Thorup.
 * h2 is the high 64 bits of the sum, empirically well-mixed.
 *
 * Five random seeds are required, all uniform random uint64. The
 * Bloom filter generates them once at filter creation and passes them
 * to every hash call.
 *
 * The extraction-method contract is the same as bfhash_u64. See
 * its comment for details.
 *
 * [1] Mikkel Thorup, "High Speed Hashing for Integers and Strings",
 *     https://arxiv.org/pdf/1504.06804
 *
 * Critical path: 4 reads, 4 ADDs in parallel, 2 multiplies pipelined,
 * 128-bit ADD with carry, final ADD. About 7 to 8 cycles plus load
 * latency.
 *
 * @param  key    Pointer to a key of length [17, 32] bytes.
 * @param  len    Key length in bytes. Must be in [17, 32].
 * @param  seeds  Array of BFHASH_MEDIUM_SEEDS = 5 uniform random
 *                uint64. seeds[0..3] are the multipliers a_0..a_3;
 *                seeds[4] is the offset a_4.
 * @param  h1     Output: low 64 bits of the pair sum plus a_4 plus
 *                len. Top 32 bits are strongly universal.
 * @param  h2     Output: high 64 bits of the pair sum. Empirically
 *                well-mixed.
 */
BF_INLINE_CONSTEXPR void bfhash_medium(const void *key, size_t len,
                                        const uint64_t *seeds,
                                        uint64_t *h1, uint64_t *h2) BF_NOEXCEPT {
    const uint8_t *p = (const uint8_t *)key;
    uint64_t x0 = bfhash_read64(p);
    uint64_t x1 = bfhash_read64(p + 8);
    uint64_t x2 = bfhash_read64(p + len - 16);
    uint64_t x3 = bfhash_read64(p + len - 8);
    uint64_t lo1 = 0, hi1 = 0, lo2 = 0, hi2 = 0;
    bfhash_mul128(seeds[0] + x1, seeds[1] + x0, &lo1, &hi1);
    bfhash_mul128(seeds[2] + x3, seeds[3] + x2, &lo2, &hi2);
    uint64_t lo_sum = lo1 + lo2;
    uint64_t carry = (lo_sum < lo1);
    *h1 = lo_sum + seeds[4] + (uint64_t)len;
    *h2 = hi1 + hi2 + carry;
}

/* Hash a variable-length key longer than 32 bytes into two hashes for
 * Kirsch-Mitzenmacher double hashing.
 *
 * This is rapidhash V3's long-key path with two operations stripped,
 * the prologue and the final fold, and the secret table reused as
 * file constants. Below is rapidhash's long-key code from
 * rapidhash_internal in rapidhash.h, annotated line-by-line with
 * what bfhash_long does to it. Comments and braces collapsed for
 * readability.
 *
 *   seed ^= rapid_mix(seed ^ secret[2], secret[1]);
 *     [STRIPPED] Seed-mixing prologue. Defends against seed-correlation
 *     attacks. Bfhash assumes no adversary and the seed is fixed at
 *     filter creation, so this multiply plus fold serves no purpose.
 *
 *   if (len > 112) {
 *     uint64_t see1 = seed, ..., see6 = seed;
 *     do {
 *       seed = rapid_mix(read64(p +   0) ^ secret[0], read64(p +   8) ^ seed);
 *       see1 = rapid_mix(read64(p +  16) ^ secret[1], read64(p +  24) ^ see1);
 *       see2 = rapid_mix(read64(p +  32) ^ secret[2], read64(p +  40) ^ see2);
 *       see3 = rapid_mix(read64(p +  48) ^ secret[3], read64(p +  56) ^ see3);
 *       see4 = rapid_mix(read64(p +  64) ^ secret[4], read64(p +  72) ^ see4);
 *       see5 = rapid_mix(read64(p +  80) ^ secret[5], read64(p +  88) ^ see5);
 *       see6 = rapid_mix(read64(p +  96) ^ secret[6], read64(p + 104) ^ see6);
 *       p += 112; i -= 112;
 *     } while (i > 112);
 *     [KEPT verbatim, with rapid_mix renamed to bfhash_mix and
 *     secret[0..6] mapped to bfhash_long_secret[0..6]] The 7 parallel
 *     mixing lanes consuming 112 bytes per iteration. This is the
 *     entire speed win of the long-key path. Seven multiplies pipeline
 *     through the multiplier port at near-peak throughput. Each lane
 *     uses a different per-lane secret to keep the lanes from
 *     accumulating correlated state. The lane secrets are empirical
 *     lane decorrelation, not adversarial defense, so they live as
 *     file constants rather than per-filter seeds. Bfhash uses the
 *     COMPACT 112-byte iteration; rapidhash also offers an UNROLLED
 *     224-byte variant for very long inputs, which we omit for code-
 *     size reasons.
 *
 *     seed ^= see1; see2 ^= see3; see4 ^= see5;
 *     seed ^= see6; see2 ^= see4; seed ^= see2;
 *   }
 *     [KEPT verbatim] Lane combine. Folds the 7 lane states into one
 *     via a XOR chain.
 *
 *   if (i > 16) {
 *     seed = rapid_mix(read64(p +  0) ^ secret[2], read64(p +  8) ^ seed);
 *     if (i > 32) {
 *       seed = rapid_mix(read64(p + 16) ^ secret[2], read64(p + 24) ^ seed);
 *       ... up to 6 mixes total covering the remaining 17..112 bytes
 *     }
 *   }
 *     [KEPT verbatim] Tail ladder. Sequentially mixes the leftover
 *     bytes into seed. The branching structure handles each 16-byte
 *     stretch only when needed, so the cost scales with the actual
 *     remainder length.
 *
 *   a = read64(p + i - 16) ^ i;
 *   b = read64(p + i - 8);
 *   a ^= secret[1];
 *   b ^= seed;
 *     [KEPT verbatim] Final operands. The two reads cover the last 16
 *     bytes via the overlap-back trick. Length is mixed into a, the
 *     accumulated seed into b, and rapidhash's secret[1] into a as a
 *     finalization constant.
 *
 *   rapid_mum(&a, &b);
 *     [KEPT, renamed bfhash_mul128(a, b, h1, h2)] The unfolded multiply
 *     of the final operands. Both halves of the 128-bit product become
 *     h1 and h2 directly.
 *
 *   return rapid_mix(a ^ secret[7], b ^ secret[1] ^ i);
 *     [STRIPPED] Final fold. Rapidhash combines the unfolded mum's
 *     output with secret[7] and another mix to produce one strongly
 *     avalanched 64-bit output. Kirsch-Mitzenmacher needs TWO outputs,
 *     and Bloom filters need only about log2(m) uniform bits per
 *     index, so full avalanche on a single output is unnecessary. We
 *     keep both halves of the unfolded mum directly.
 *
 * Strict universality is not claimed for this path. The construction
 * is empirically validated through rapidhash's existing test suite,
 * not formally proven 2-universal in the sense of Thorup. For the
 * Bloom filter, the relevant property is that the extracted index
 * bits are well-distributed, which rapidhash has established for the
 * same 7-lane structure.
 *
 * The extraction-method contract is the same as bfhash_u64. See
 * its comment for details.
 *
 * Critical path: about 25 cycles for 256-byte input, dominated by the
 * 7 pipelined multiplies per 112-byte block. The rapidhash baseline
 * for the same input is about 33 cycles. The extra 8 cycles come from
 * the stripped prologue rapid_mix at about 4 cycles and the stripped
 * final fold rapid_mix at about 4 cycles. The savings shrink as input
 * length grows because both the prologue and the final fold are
 * constant overhead while the lane loop scales linearly with length.
 *
 * @param  key    Pointer to a key longer than 32 bytes.
 * @param  len    Key length in bytes. Must be at least 17, intended
 *                for use when len > 32. For len in [17, 32] prefer
 *                bfhash_medium.
 * @param  seeds  Array of BFHASH_LONG_SEEDS = 1 uniform random
 *                uint64. seeds[0] is the master per-filter seed; the
 *                7 lane secrets are file constants.
 * @param  h1     Output: low 64 bits of the final 128-bit product.
 * @param  h2     Output: high 64 bits of the same product.
 */
BF_INLINE_CONSTEXPR void bfhash_long(const void *key, size_t len,
                                      const uint64_t *seeds,
                                      uint64_t *h1, uint64_t *h2) BF_NOEXCEPT {
    const uint8_t *p = (const uint8_t *)key;
    size_t i = len;
    uint64_t seed = seeds[0];
    uint64_t a = 0, b = 0;

    if (i > 112) {
        uint64_t see1 = seed, see2 = seed, see3 = seed;
        uint64_t see4 = seed, see5 = seed, see6 = seed;
        do {
            seed = bfhash_mix(bfhash_read64(p +   0) ^ bfhash_long_secret[0], bfhash_read64(p +   8) ^ seed);
            see1 = bfhash_mix(bfhash_read64(p +  16) ^ bfhash_long_secret[1], bfhash_read64(p +  24) ^ see1);
            see2 = bfhash_mix(bfhash_read64(p +  32) ^ bfhash_long_secret[2], bfhash_read64(p +  40) ^ see2);
            see3 = bfhash_mix(bfhash_read64(p +  48) ^ bfhash_long_secret[3], bfhash_read64(p +  56) ^ see3);
            see4 = bfhash_mix(bfhash_read64(p +  64) ^ bfhash_long_secret[4], bfhash_read64(p +  72) ^ see4);
            see5 = bfhash_mix(bfhash_read64(p +  80) ^ bfhash_long_secret[5], bfhash_read64(p +  88) ^ see5);
            see6 = bfhash_mix(bfhash_read64(p +  96) ^ bfhash_long_secret[6], bfhash_read64(p + 104) ^ see6);
            p += 112;
            i -= 112;
        } while (i > 112);
        seed ^= see1;
        see2 ^= see3;
        see4 ^= see5;
        seed ^= see6;
        see2 ^= see4;
        seed ^= see2;
    }

    if (i > 16) {
        seed = bfhash_mix(bfhash_read64(p +  0) ^ bfhash_long_secret[2], bfhash_read64(p +  8) ^ seed);
        if (i > 32) {
            seed = bfhash_mix(bfhash_read64(p + 16) ^ bfhash_long_secret[2], bfhash_read64(p + 24) ^ seed);
            if (i > 48) {
                seed = bfhash_mix(bfhash_read64(p + 32) ^ bfhash_long_secret[1], bfhash_read64(p + 40) ^ seed);
                if (i > 64) {
                    seed = bfhash_mix(bfhash_read64(p + 48) ^ bfhash_long_secret[1], bfhash_read64(p + 56) ^ seed);
                    if (i > 80) {
                        seed = bfhash_mix(bfhash_read64(p + 64) ^ bfhash_long_secret[2], bfhash_read64(p + 72) ^ seed);
                        if (i > 96) {
                            seed = bfhash_mix(bfhash_read64(p + 80) ^ bfhash_long_secret[1], bfhash_read64(p + 88) ^ seed);
                        }
                    }
                }
            }
        }
    }
    a = bfhash_read64(p + i - 16) ^ (uint64_t)i;
    b = bfhash_read64(p + i - 8);
    a ^= bfhash_long_secret[1];
    b ^= seed;
    bfhash_mul128(a, b, h1, h2);
}
