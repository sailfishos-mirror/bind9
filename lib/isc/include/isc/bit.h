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

#if __has_header(<stdbit.h>)

#include <stdbit.h>

#else /* __has_header(<stdbit.h>) */

#ifdef HAVE_BUILTIN_POPCOUNTG
#define stdc_count_zeros(x) __builtin_popcountg(x)
#else /* HAVE_BUILTIN_POPCOUNTG */
#define stdc_count_zeros(x)                         \
	_Generic((x),                               \
		unsigned int: __builtin_popcount,   \
		unsigned long: __builtin_popcountl, \
		unsigned long long: __builtin_popcountll)(x)
#endif /* HAVE_BUILTIN_POPCOUNTG */

#ifdef HAVE_BUILTIN_CLZG
#define stdc_leading_zeros(x) __builtin_clzg(x, (int)(sizeof(x) * 8))
#else /* HAVE_BUILTIN_CLZG */
#define stdc_leading_zeros(x)                           \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_clz,   \
			 unsigned long: __builtin_clzl, \
			 unsigned long long: __builtin_clzll)(x))
#endif /* HAVE_BUILTIN_CLZG */

#ifdef HAVE_BUILTIN_CTZG
#define stdc_trailing_zeros(x) __builtin_ctzg(x, (int)sizeof(x) * 8)
#else /* HAVE_BUILTIN_CTZG */
#define stdc_trailing_zeros(x)                          \
	(((x) == 0) ? (sizeof(x) * 8)                   \
		    : _Generic((x),                     \
			 unsigned int: __builtin_ctz,   \
			 unsigned long: __builtin_ctzl, \
			 unsigned long long: __builtin_ctzll)(x))
#endif /* HAVE_BUILTIN_CTZG */

#define stdc_leading_ones(x)  stdc_leading_zeros(~(x))
#define stdc_trailing_ones(x) stdc_trailing_zeros(~(x))

#endif /* __has_header(<stdbit.h>) */

#define ISC_ROTATE_LEFT8(x, n)                                                \
	({                                                                    \
		STATIC_ASSERT(n > 0 && n < 8,                                 \
			      "rotation must be a constant between 0 and 8"); \
		STATIC_ASSERT(                                                \
			__builtin_types_compatible_p(typeof(x), uint8_t),     \
			"rotated value must be uint8_t");                     \
		((x) << (n) | (x) >> (8 - (n)));                              \
	})

#define ISC_ROTATE_LEFT16(x, n)                                                \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 16,                                 \
			      "rotation must be a constant between 0 and 16"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint16_t),     \
			"rotated value must be uint16_t");                     \
		((x) << (n) | (x) >> (16 - (n)));                              \
	})

#define ISC_ROTATE_LEFT32(x, n)                                                \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 32,                                 \
			      "rotation must be a constant between 0 and 32"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint32_t),     \
			"rotated value must be uint32_t");                     \
		((x) << (n) | (x) >> (32 - (n)));                              \
	})

#define ISC_ROTATE_LEFT64(x, n)                                                \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 64,                                 \
			      "rotation must be a constant between 0 and 64"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint64_t),     \
			"rotated value must be uint64_t");                     \
		((x) << (n) | (x) >> (64 - (n)));                              \
	})

#define ISC_ROTATE_RIGHT8(x, n)                                               \
	({                                                                    \
		STATIC_ASSERT(n > 0 && n < 8,                                 \
			      "rotation must be a constant between 0 and 8"); \
		STATIC_ASSERT(                                                \
			__builtin_types_compatible_p(typeof(x), uint8_t),     \
			"rotated value must be uint8_t");                     \
		((x) >> (n) | (x) << (8 - (n)));                              \
	})

#define ISC_ROTATE_RIGHT16(x, n)                                               \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 16,                                 \
			      "rotation must be a constant between 0 and 16"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint16_t),     \
			"rotated value must be uint16_t");                     \
		((x) >> (n) | (x) << (16 - (n)));                              \
	})

#define ISC_ROTATE_RIGHT32(x, n)                                               \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 32,                                 \
			      "rotation must be a constant between 0 and 32"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint32_t),     \
			"rotated value must be uint32_t");                     \
		((x) >> (n) | (x) << (32 - (n)));                              \
	})

#define ISC_ROTATE_RIGHT64(x, n)                                               \
	({                                                                     \
		STATIC_ASSERT(n > 0 && n < 64,                                 \
			      "rotation must be a constant between 0 and 64"); \
		STATIC_ASSERT(                                                 \
			__builtin_types_compatible_p(typeof(x), uint64_t),     \
			"rotated value must be uint64_t");                     \
		((x) >> (n) | (x) << (64 - (n)));                              \
	})

#if SIZE_MAX == UINT64_MAX
#define ISC_ROTATE_LEFTSIZE(x, n)  ISC_ROTATE_LEFT64((uint64_t)x, n)
#define ISC_ROTATE_RIGHTSIZE(x, n) ISC_ROTATE_RIGHT64((uint64_t)x, n)
#elif SIZE_MAX == UINT32_MAX
#define ISC_ROTATE_LEFTSIZE(x, n)  ISC_ROTATE_LEFT32((uint32_t)x, n)
#define ISC_ROTATE_RIGHTSIZE(x, n) ISC_ROTATE_RIGHT32((uint32_t)x, n)
#else
#error "size_t must be either 32 or 64-bits"
#endif
