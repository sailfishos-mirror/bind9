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

/*! \file */

#include <inttypes.h>
#include <string.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/os.h>
#include <isc/refcount.h>
#include <isc/stats.h>
#include <isc/statsmulti.h>
#include <isc/tid.h>
#include <isc/util.h>

#define ISC_STATSMULTI_MAGIC	ISC_MAGIC('S', 'M', 'u', 'l')
#define ISC_STATSMULTI_VALID(x) ISC_MAGIC_VALID(x, ISC_STATSMULTI_MAGIC)

/*
 * Same constraint as stats.c
 */
STATIC_ASSERT(sizeof(isc_statscounter_t) <= sizeof(uint64_t),
	      "Exported statistics must fit into the statistic counter size");

struct isc_statsmulti {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_refcount_t references;
	int n_counters;
	int per_thread_capacity;
	int num_threads_plus_one;
	isc_atomic_statscounter_t *counters;
};

static int
to_index(isc_statsmulti_t *stats, isc_tid_t tid,
	 isc_statscounter_t internal_counter) {
	int thread_id = tid + 1;
	if (thread_id >= stats->num_threads_plus_one) {
		thread_id = 0;
	}
	return thread_id * stats->per_thread_capacity + internal_counter;
}

void
isc_statsmulti_create(isc_mem_t *mctx, isc_statsmulti_t **statsp,
		      int ncounters) {
	REQUIRE(statsp != NULL && *statsp == NULL);

	size_t size_in_bytes = sizeof(isc_atomic_statscounter_t) * ncounters;
	size_t rounded_up = (size_in_bytes + 63) & ~63; /* Round up to next
							   multiple of 64 */
	int per_thread_capacity = rounded_up /
				  sizeof(isc_atomic_statscounter_t);
	int num_threads_plus_one = isc_tid_count() + 1;

	isc_statsmulti_t *stats = isc_mem_get(mctx, sizeof(*stats));
	*stats = (isc_statsmulti_t){
		.magic = ISC_STATSMULTI_MAGIC,
		.counters = isc_mem_cget(
			mctx, per_thread_capacity * num_threads_plus_one,
			sizeof(isc_atomic_statscounter_t)),
		.mctx = isc_mem_ref(mctx),
		.n_counters = ncounters,
		.num_threads_plus_one = num_threads_plus_one,
		.per_thread_capacity = per_thread_capacity,
		.references = ISC_REFCOUNT_INITIALIZER(1),

	};
	*statsp = stats;
}

static void
isc__statsmulti_destroy(isc_statsmulti_t *stats) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	size_t alloc_size = stats->per_thread_capacity *
			    stats->num_threads_plus_one *
			    sizeof(isc_atomic_statscounter_t);
	isc_mem_put(stats->mctx, stats->counters, alloc_size);
	isc_mem_putanddetach(&stats->mctx, stats, sizeof(*stats));
}

ISC_REFCOUNT_IMPL(isc_statsmulti, isc__statsmulti_destroy);

void
isc_statsmulti_increment(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->n_counters);

	int index = to_index(stats, isc_tid(), counter);
	if (isc_tid() == -1) {
		atomic_fetch_add_relaxed(&stats->counters[index], 1);
	} else {
		isc_atomic_statscounter_t *ptr = &stats->counters[index];
		atomic_store_relaxed(ptr, atomic_load_relaxed(ptr) + 1);
	}
}

void
isc_statsmulti_decrement(isc_statsmulti_t *stats, isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->n_counters);

	int index = to_index(stats, isc_tid(), counter);
	if (isc_tid() == -1) {
		atomic_fetch_sub_relaxed(&stats->counters[index], 1);
	} else {
		isc_atomic_statscounter_t *ptr = &stats->counters[index];
		int_fast64_t tmp = atomic_load_relaxed(ptr);
		atomic_store_relaxed(ptr, tmp - 1);
	}
}

void
isc_statsmulti_dump(isc_statsmulti_t *stats, isc_statsmulti_dumper_t dump_fn,
		    void *arg, unsigned int options) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	for (int counter = 0; counter < stats->n_counters; counter++) {
		isc_statscounter_t total = isc_statsmulti_get_counter(stats,
								      counter);

		if ((options & ISC_STATSMULTIDUMP_VERBOSE) == 0 && total == 0) {
			continue;
		}
		dump_fn((isc_statscounter_t)counter, total, arg);
	}
}

isc_statscounter_t
isc_statsmulti_get_counter(isc_statsmulti_t *stats,
			   isc_statscounter_t counter) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));
	REQUIRE(counter < stats->n_counters);

	int idx_0 = to_index(stats, 0, counter);
	isc_statscounter_t total = atomic_load_acquire(&stats->counters[idx_0]);

	for (int thread = 1; thread < stats->num_threads_plus_one; thread++) {
		int index = to_index(stats, thread, counter);
		total += atomic_load_relaxed(&stats->counters[index]);
	}

	return total;
}

void
isc_statsmulti_clear(isc_statsmulti_t *stats) {
	REQUIRE(ISC_STATSMULTI_VALID(stats));

	for (int idx = 0;
	     idx < stats->per_thread_capacity * stats->num_threads_plus_one;
	     idx++)
	{
		atomic_store_release(&stats->counters[idx], 0);
	}
}
