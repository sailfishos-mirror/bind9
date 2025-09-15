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

/*****
***** Module Info
*****/

/*! \file dns/rdatalist.h
 * \brief
 * A DNS rdatalist is a list of rdata of a common type and class.
 *
 * MP:
 *\li	Clients of this module must impose any required synchronization.
 *
 * Reliability:
 *\li	No anticipated impact.
 *
 * Resources:
 *\li	TBS
 *
 * Security:
 *\li	No anticipated impact.
 *
 * Standards:
 *\li	None.
 */

#include <dns/types.h>

/*%
 * Clients may use this type directly.
 */
struct dns_rdatalist {
	dns_rdataclass_t rdclass;
	dns_rdatatype_t	 type;
	dns_rdatatype_t	 covers;
	dns_ttl_t	 ttl;
	ISC_LIST(dns_rdata_t) rdata;
	ISC_LINK(dns_rdatalist_t) link;
	/*%<
	 * Case vector.  If the bit is set then the corresponding
	 * character in the owner name needs to be AND'd with 0x20,
	 * rendering that character upper case.
	 */
	unsigned char upper[32];
};

void
dns_rdatalist_init(dns_rdatalist_t *rdatalist);
/*%<
 * Initialize rdatalist.
 *
 * Ensures:
 *\li	All fields of rdatalist have been initialized to their default
 *	values.
 */

void
dns_rdatalist_tordataset(dns_rdatalist_t *rdatalist, dns_rdataset_t *rdataset);
/*%<
 * Make 'rdataset' refer to the rdata in 'rdatalist'.
 *
 * Note:
 *\li	The caller must ensure that 'rdatalist' remains valid and unchanged
 *	while 'rdataset' is associated with it.
 *
 * Requires:
 *
 *\li	'rdatalist' is a valid rdatalist.
 *
 *\li	'rdataset' is a valid rdataset that is not currently associated with
 *	any rdata.
 *
 * Ensures,
 *	on success,
 *
 *\li		'rdataset' is associated with the rdata in rdatalist.
 */

void
dns_rdatalist_fromrdataset(dns_rdataset_t   *rdataset,
			   dns_rdatalist_t **rdatalist);
/*%<
 * Point 'rdatalist' to the rdatalist in 'rdataset'.
 *
 * Requires:
 *
 *\li	'rdatalist' is a pointer to a NULL dns_rdatalist_t pointer.
 *
 *\li	'rdataset' is a valid rdataset associated with an rdatalist.
 *
 * Ensures,
 *	on success,
 *
 *\li		'rdatalist' is pointed to the rdatalist in rdataset.
 */

/*%
 * The following are implementation functions for list-based rdatasets.
 * They are called by rdataset implementations in rdatalist.c, sdlz.c,
 * and builtin.c. They are not meant to be used directly by callers of
 * those implmentations.
 */
void
dns_rdatalist_disassociate(dns_rdataset_t *rdatasetp DNS__DB_FLARG);
isc_result_t
dns__rdatalist_first(dns_rdataset_t *rdataset);
isc_result_t
dns__rdatalist_next(dns_rdataset_t *rdataset);
void
dns__rdatalist_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
void
dns__rdatalist_clone(dns_rdataset_t	   *source,
		     dns_rdataset_t *target DNS__DB_FLARG);
unsigned int
dns__rdatalist_count(dns_rdataset_t *rdataset);
isc_result_t
dns__rdatalist_addnoqname(dns_rdataset_t *rdataset, dns_name_t *name);
isc_result_t
dns__rdatalist_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
			  dns_rdataset_t	*neg,
			  dns_rdataset_t *negsig DNS__DB_FLARG);
isc_result_t
dns__rdatalist_addclosest(dns_rdataset_t *rdataset, dns_name_t *name);
isc_result_t
dns__rdatalist_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
			  dns_rdataset_t	*neg,
			  dns_rdataset_t *negsig DNS__DB_FLARG);
void
dns__rdatalist_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name);
void
dns__rdatalist_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);
