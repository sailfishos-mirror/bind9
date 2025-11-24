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

#include <isc/endian.h>

#include <dns/rdatavec.h>

#define CASEFULLYLOWER(header)                         \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_CASEFULLYLOWER) != 0)
#define CASESET(header)                                \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_CASESET) != 0)
#define EXISTS(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_NONEXISTENT) == 0)
#define IGNORE(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_IGNORE) != 0)
#define OPTOUT(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_OPTOUT) != 0)
#define RESIGN(header)                                 \
	((atomic_load_acquire(&(header)->attributes) & \
	  DNS_VECHEADERATTR_RESIGN) != 0)

#define peek_uint16(buffer) ISC_U8TO16_BE(buffer)
#define get_uint16(buffer)                            \
	({                                            \
		uint16_t __ret = peek_uint16(buffer); \
		buffer += sizeof(uint16_t);           \
		__ret;                                \
	})
#define put_uint16(buffer, val)               \
	{                                     \
		ISC_U16TO8_BE(buffer, val);   \
		(buffer) += sizeof(uint16_t); \
	}

dns_vecheader_t *
dns_vecheader_getheader(const dns_rdataset_t *rdataset);
/*%<
 * Return a pointer to the vecheader for a vec rdataset.
 *
 * Requires:
 * \li	'rdataset' is a valid rdataset using rdatavec methods.
 */


isc_result_t
vecheader_first(rdatavec_iter_t *iter, dns_vecheader_t *header, dns_rdataclass_t rdclass);

isc_result_t
vecheader_next(rdatavec_iter_t *iter);

void
vecheader_current(rdatavec_iter_t *iter, dns_rdata_t *rdata);
