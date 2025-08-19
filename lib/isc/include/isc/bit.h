/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

#include <limits.h>
#include <stdint.h>

#include <isc/attributes.h>
#include <isc/util.h>

#ifndef __has_header
#define __has_header(x) 0
#endif

#if __has_header(<stdbit.h>)

#include <stdbit.h>

#define ISC_POPCOUNT(x)	      stdc_count_zeros(x)
#define ISC_LEADING_ZEROS(x)  stdc_leading_zeros(x)
#define ISC_TRAILING_ZEROS(x) stdc_trailing_zeros(x)
#define ISC_LEADING_ONES(x)   stdc_leading_ones(x)
#define ISC_TRAILING_ONES(x)  stdc_trailing_ones(x)

#else /* __has_header(<stdbit.h>) */

#ifdef HAVE_BUILTIN_POPCOUNTG
#define ISC_POPCOUNT(x) __builtin_popcountg(x)
#else /* HAVE_BUILTIN_POPCOUNTG */
#define ISC_POPCOUNT(x)                             \
	_Generic((x),                               \
		unsigned int: __builtin_popcount,   \
		unsigned long: __builtin_popcountl, \
		unsigned long long: __builtin_popcountll)(x)
#endif /* HAVE_BUILTIN_POPCOUNTG */

#ifdef HAVE_BUILTIN_CLZG
#define ISC_LEADING_ZEROS(x) __builtin_clzg(x, (int)(sizeof(x) * 8))
#else /* HAVE_BUILTIN_CLZG */
#define ISC_LEADING_ZEROS(x)                           \
	((x) == 0) ? (sizeof(x) * 8)                   \
		   : _Generic((x),                     \
			unsigned int: __builtin_clz,   \
			unsigned long: __builtin_clzl, \
			unsigned long long: __builtin_clzll)(x)
#endif /* HAVE_BUILTIN_CLZG */

#ifdef HAVE_BUILTIN_CTZG
#define ISC_TRAILING_ZEROS(x) __builtin_ctzg(x, (int)sizeof(x) * 8)
#else /* HAVE_BUILTIN_CTZG */
#define ISC_TRAILING_ZEROS(x)                          \
	((x) == 0) ? (sizeof(x) * 8)                   \
		   : _Generic((x),                     \
			unsigned int: __builtin_ctz,   \
			unsigned long: __builtin_ctzl, \
			unsigned long long: __builtin_ctzll)(x)
#endif /* HAVE_BUILTIN_CTZG */

#define ISC_LEADING_ONES(x)  ISC_LEADING_ZEROS(~(x))
#define ISC_TRAILING_ONES(x) ISC_TRAILING_ZEROS(~(x))

#endif /* __has_header(<stdbit.h>) */

#if SIZE_MAX == UINT64_MAX
#define isc_rotate_leftsize(x, n)  isc_rotate_left64(x, n)
#define isc_rotate_rightsize(x, n) isc_rotate_right64(x, n)
#elif SIZE_MAX == UINT32_MAX
#define isc_rotate_leftsize(x, n)  isc_rotate_left32(x, n)
#define isc_rotate_rightsize(x, n) isc_rotate_right32(x, n)
#else
#error "size_t must be either 32 or 64-bits"
#endif

static inline uint8_t __attribute__((always_inline))
isc_rotate_left8(const uint8_t x, uint32_t n) {
	return (x << n) | (x >> (8 - n));
}

static inline uint16_t __attribute__((always_inline))
isc_rotate_left16(const uint16_t x, uint32_t n) {
	return (x << n) | (x >> (16 - n));
}

static inline uint32_t __attribute__((always_inline))
isc_rotate_left32(const uint32_t x, uint32_t n) {
	return (x << n) | (x >> (32 - n));
}

static inline uint64_t __attribute__((always_inline))
isc_rotate_left64(const uint64_t x, uint32_t n) {
	return (x << n) | (x >> (64 - n));
}

static inline uint8_t __attribute__((always_inline))
isc_rotate_right8(const uint8_t x, uint32_t n) {
	return (x >> n) | (x << (8 - n));
}

static inline uint16_t __attribute__((always_inline))
isc_rotate_right16(const uint16_t x, uint32_t n) {
	return (x >> n) | (x << (16 - n));
}

static inline uint32_t __attribute__((always_inline))
isc_rotate_right32(const uint32_t x, uint32_t n) {
	return (x >> n) | (x << (32 - n));
}

static inline uint64_t __attribute__((always_inline))
isc_rotate_right64(const uint64_t x, uint32_t n) {
	return (x >> n) | (x << (64 - n));
}
