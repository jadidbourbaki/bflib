/*
 * bflib version macros.
 *
 * Single source of truth for the bflib project version. The
 * top-level CMakeLists.txt parses this file at configure time, so
 * the values here are authoritative for both the C preprocessor and
 * the build system.
 *
 * Bump the version on every release. Follow semver:
 *   MAJOR for breaking API changes.
 *   MINOR for backwards-compatible additions.
 *   PATCH for bug fixes.
 *
 * Compile-time check example:
 *   #if BFLIB_VERSION < 000200  // require at least 0.2.0
 *   #error "bflib 0.2.0 or newer required"
 *   #endif
 */

#pragma once

#define BFLIB_VERSION_MAJOR 0
#define BFLIB_VERSION_MINOR 1
#define BFLIB_VERSION_PATCH 0

#define BFLIB_VERSION_STRING "0.1.0"

/* Numeric version for comparison: 0.1.0 -> 000100, 1.2.3 -> 010203. */
#define BFLIB_VERSION (BFLIB_VERSION_MAJOR * 10000 + \
                       BFLIB_VERSION_MINOR * 100 + \
                       BFLIB_VERSION_PATCH)
