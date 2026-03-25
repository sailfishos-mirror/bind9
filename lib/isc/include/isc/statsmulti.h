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

/*! \file isc/statsmulti.h */

#include <inttypes.h>

#include <isc/refcount.h>
#include <isc/types.h>

typedef struct isc_statsmulti isc_statsmulti_t; /*%< Statistics Multi */

/*%<
 * Flag(s) for isc_statsmulti_dump().
 */
#define ISC_STATSMULTIDUMP_VERBOSE 0x00000001 /*%< dump 0-value counters */

/*%<
 * Dump callback type.
 */
typedef void (*isc_statsmulti_dumper_t)(isc_statscounter_t, uint64_t, void *);

void
isc_statsmulti_create(isc_mem_t *mctx, isc_statsmulti_t **statsp,
		      int ncounters);
/*%<
 * Create a statistics counter structure for additive counters.
 * All counters are additive (sum across threads).
 *
 * Requires:
 *\li	'mctx' must be a valid memory context.
 *
 *\li	'statsp' != NULL && '*statsp' == NULL.
 */

ISC_REFCOUNT_DECL(isc_statsmulti);

void
isc_statsmulti_increment(isc_statsmulti_t *stats, isc_statscounter_t counter);
/*%<
 * Increment the counter-th counter of stats.
 *
 * Requires:
 *\li	'stats' is a valid isc_statsmulti_t.
 *
 *\li	counter is less than ncounters.
 */

void
isc_statsmulti_decrement(isc_statsmulti_t *stats, isc_statscounter_t counter);
/*%<
 * Decrement the counter-th counter of stats.
 *
 * Requires:
 *\li	'stats' is a valid isc_statsmulti_t.
 *
 *\li	counter is less than ncounters.
 */

void
isc_statsmulti_dump(isc_statsmulti_t *stats, isc_statsmulti_dumper_t dump_fn,
		    void *arg, unsigned int options);
/*%<
 * Dump the current statistics counters in a specified way.  For each counter
 * in stats, dump_fn is called with its current value and the given argument
 * arg.  By default counters that have a value of 0 is skipped; if options has
 * the ISC_STATSMULTIDUMP_VERBOSE flag, even such counters are dumped.
 *
 * Requires:
 *\li	'stats' is a valid isc_statsmulti_t.
 */

isc_statscounter_t
isc_statsmulti_get_counter(isc_statsmulti_t *stats, isc_statscounter_t counter);
/*%<
 * Returns value currently stored in counter.
 *
 * Requires:
 *\li	'stats' is a valid isc_statsmulti_t.
 *
 *\li	counter is less than ncounters.
 */

void
isc_statsmulti_clear(isc_statsmulti_t *stats);
/*%<
 * Set all counters to zero.
 *
 * Requires:
 *\li	'stats' is a valid isc_statsmulti_t.
 */
