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

/*! \file */

#include <pthread.h>
#include <stdlib.h>

#include <isc/atomic.h>
#include <isc/util.h>

#define SPINLOCK(sp)                                                           \
	{                                                                      \
		ISC_UTIL_TRACE(fprintf(stderr, "SPINLOCKING %p %s %d\n", (sp), \
				       __FILE__, __LINE__));                   \
		isc_spinlock_lock((sp));                                       \
		ISC_UTIL_TRACE(fprintf(stderr, "SPINLOCKED %p %s %d\n", (sp),  \
				       __FILE__, __LINE__));                   \
	}
#define SPINUNLOCK(sp)                                                    \
	{                                                                 \
		isc_spinlock_unlock((sp));                                \
		ISC_UTIL_TRACE(fprintf(stderr, "SPINUNLOCKED %p %s %d\n", \
				       (sp), __FILE__, __LINE__));        \
	}

/*
 * We use macros instead of static inline functions so that the exact code
 * location can be reported when PTHREADS_RUNTIME_CHECK() fails or when mutrace
 * reports lock contention.
 */

#ifdef ISC_TRACK_PTHREADS_OBJECTS

#define isc_spinlock_init(sp)               \
	{                                   \
		*sp = malloc(sizeof(**sp)); \
		isc__spinlock_init(*sp);    \
	}
#define isc_spinlock_lock(sp)	isc__spinlock_lock(*sp)
#define isc_spinlock_unlock(sp) isc__spinlock_unlock(*sp)
#define isc_spinlock_destroy(sp)            \
	{                                   \
		isc__spinlock_destroy(*sp); \
		free((void *)*sp);          \
	}

#else /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc_spinlock_init(sp)	 isc__spinlock_init(sp)
#define isc_spinlock_lock(sp)	 isc__spinlock_lock(sp)
#define isc_spinlock_unlock(sp)	 isc__spinlock_unlock(sp)
#define isc_spinlock_destroy(sp) isc__spinlock_destroy(sp)

#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#if HAVE_PTHREAD_SPIN_INIT

#if ISC_TRACK_PTHREADS_OBJECTS
typedef pthread_spinlock_t *isc_spinlock_t;
#else  /* ISC_TRACK_PTHREADS_OBJECTS */
typedef pthread_spinlock_t isc_spinlock_t;
#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__spinlock_init(sp)                                             \
	{                                                                  \
		int _ret = pthread_spin_init(sp, PTHREAD_PROCESS_PRIVATE); \
		PTHREADS_RUNTIME_CHECK(pthread_spin_init, _ret);           \
	}

#define isc__spinlock_lock(sp)                                   \
	{                                                        \
		int _ret = pthread_spin_lock(sp);                \
		PTHREADS_RUNTIME_CHECK(pthread_spin_lock, _ret); \
	}

#define isc__spinlock_unlock(sp)                                   \
	{                                                          \
		int _ret = pthread_spin_unlock(sp);                \
		PTHREADS_RUNTIME_CHECK(pthread_spin_unlock, _ret); \
	}

#define isc__spinlock_destroy(sp)                                   \
	{                                                           \
		int _ret = pthread_spin_destroy(sp);                \
		PTHREADS_RUNTIME_CHECK(pthread_spin_destroy, _ret); \
	}

#else /* HAVE_PTHREAD_SPIN_INIT */

#if ISC_TRACK_PTHREADS_OBJECTS
typedef atomic_uint_fast32_t *isc_spinlock_t;
#else  /* ISC_TRACK_PTHREADS_OBJECTS */
typedef atomic_uint_fast32_t isc_spinlock_t;
#endif /* ISC_TRACK_PTHREADS_OBJECTS */

#define isc__spinlock_init(sp)      \
	{                           \
		atomic_init(sp, 0); \
	}

#define isc__spinlock_lock(sp)                                  \
	{                                                       \
		while (!atomic_compare_exchange_weak_acq_rel(   \
			sp, &(uint_fast32_t){ 0 }, 1))          \
		{                                               \
			do {                                    \
				isc_pause();                    \
			} while (atomic_load_relaxed(sp) != 0); \
		}                                               \
	}

#define isc__spinlock_unlock(sp)             \
	{                                    \
		atomic_store_release(sp, 0); \
	}

#define isc__spinlock_destroy(sp)             \
	{                                     \
		INSIST(atomic_load(sp) == 0); \
	}

#endif
