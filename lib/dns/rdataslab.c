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

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>

#include <isc/ascii.h>
#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdataslab.h>
#include <dns/stats.h>

#include "rdataslab_p.h"

/*
 * The memory structure of an rdataslab is as follows:
 *
 *	header		(dns_slabheader_t)
 *	record count	(2 bytes)
 *	data records
 *		data length	(2 bytes)
 *		order		(2 bytes)
 *		meta data	(1 byte for RRSIG, 0 for all other types)
 *		data		(data length bytes)
 *
 * A "bare" rdataslab is everything after "header".
 *
 * When a slab is created, data records are sorted into DNSSEC order.
 */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG);
static isc_result_t
rdataset_first(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_next(dns_rdataset_t *rdataset);
static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata);
static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target DNS__DB_FLARG);
static unsigned int
rdataset_count(dns_rdataset_t *rdataset);
static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig DNS__DB_FLARG);
static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *neg, dns_rdataset_t *negsig DNS__DB_FLARG);
static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust);
static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG);
static void
rdataset_clearprefetch(dns_rdataset_t *rdataset);
static void
rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name);
static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name);
static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset);

dns_rdatasetmethods_t dns_rdataslab_rdatasetmethods = {
	.disassociate = rdataset_disassociate,
	.first = rdataset_first,
	.next = rdataset_next,
	.current = rdataset_current,
	.clone = rdataset_clone,
	.count = rdataset_count,
	.getnoqname = rdataset_getnoqname,
	.getclosest = rdataset_getclosest,
	.settrust = rdataset_settrust,
	.expire = rdataset_expire,
	.clearprefetch = rdataset_clearprefetch,
	.setownercase = rdataset_setownercase,
	.getownercase = rdataset_getownercase,
	.getheader = rdataset_getheader,
};

/*% Note: the "const void *" are just to make qsort happy.  */
static int
compare_rdata(const void *p1, const void *p2) {
	return dns_rdata_compare(p1, p2);
}

static isc_result_t
makeslab(dns_rdataset_t *rdataset, isc_mem_t *mctx, isc_region_t *region,
	 uint32_t maxrrperset) {
	/*
	 * Use &removed as a sentinel pointer for duplicate
	 * rdata as rdata.data == NULL is valid.
	 */
	static unsigned char removed;
	dns_rdata_t *rdata = NULL;
	unsigned char *rawbuf = NULL;
	unsigned int headerlen = sizeof(dns_slabheader_t);
	unsigned int buflen = headerlen + 2;
	isc_result_t result;
	unsigned int nitems;
	unsigned int nalloc;
	unsigned int length;
	size_t i;
	size_t rdatasize;

	/*
	 * If the source rdataset is also a slab, we don't need
	 * to do anything special, just copy the whole slab to a
	 * new buffer.
	 */
	if (rdataset->methods == &dns_rdataslab_rdatasetmethods) {
		dns_slabheader_t *header = dns_rdataset_getheader(rdataset);
		buflen = dns_rdataslab_size(header);

		rawbuf = isc_mem_get(mctx, buflen);
		region->base = rawbuf;
		region->length = buflen;

		memmove(rawbuf, header, buflen);
		return ISC_R_SUCCESS;
	}

	/*
	 * If there are no rdata then we just need to allocate a header
	 * with a zero record count.
	 */
	nitems = dns_rdataset_count(rdataset);
	if (nitems == 0) {
		if (rdataset->type != 0) {
			return ISC_R_FAILURE;
		}
		rawbuf = isc_mem_get(mctx, buflen);
		region->base = rawbuf;
		region->length = buflen;
		rawbuf += headerlen;
		put_uint16(rawbuf, 0);
		return ISC_R_SUCCESS;
	}

	if (maxrrperset > 0 && nitems > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	if (nitems > 0xffff) {
		return ISC_R_NOSPACE;
	}

	/*
	 * Remember the original number of items.
	 */
	nalloc = nitems;

	RUNTIME_CHECK(!ckd_mul(&rdatasize, nalloc, sizeof(rdata[0])));
	rdata = isc_mem_get(mctx, rdatasize);

	/*
	 * Save all of the rdata members into an array.
	 */
	result = dns_rdataset_first(rdataset);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOMORE) {
		goto free_rdatas;
	}
	for (i = 0; i < nalloc && result == ISC_R_SUCCESS; i++) {
		INSIST(result == ISC_R_SUCCESS);
		dns_rdata_init(&rdata[i]);
		dns_rdataset_current(rdataset, &rdata[i]);
		INSIST(rdata[i].data != &removed);
		result = dns_rdataset_next(rdataset);
	}
	if (i != nalloc || result != ISC_R_NOMORE) {
		/*
		 * Somehow we iterated over fewer rdatas than
		 * dns_rdataset_count() said there were or there
		 * were more items than dns_rdataset_count said
		 * there were.
		 */
		result = ISC_R_FAILURE;
		goto free_rdatas;
	}

	/*
	 * Put into DNSSEC order.
	 */
	if (nalloc > 1U) {
		qsort(rdata, nalloc, sizeof(rdata[0]), compare_rdata);
	}

	/*
	 * Remove duplicates and compute the total storage required.
	 *
	 * If an rdata is not a duplicate, accumulate the storage size
	 * required for the rdata.  We do not store the class, type, etc,
	 * just the rdata, so our overhead is 2 bytes for the number of
	 * records, and 2 bytes for the length of each rdata, plus the
	 * rdata itself.
	 */
	for (i = 1; i < nalloc; i++) {
		if (compare_rdata(&rdata[i - 1], &rdata[i]) == 0) {
			rdata[i - 1].data = &removed;
			nitems--;
		} else {
			buflen += (2 + rdata[i - 1].length);
			/*
			 * Provide space to store the per RR meta data.
			 */
			if (rdataset->type == dns_rdatatype_rrsig) {
				buflen++;
			}
		}
	}

	/*
	 * Don't forget the last item!
	 */
	buflen += (2 + rdata[i - 1].length);

	/*
	 * Provide space to store the per RR meta data.
	 */
	if (rdataset->type == dns_rdatatype_rrsig) {
		buflen++;
	}

	/*
	 * Ensure that singleton types are actually singletons.
	 */
	if (nitems > 1 && dns_rdatatype_issingleton(rdataset->type)) {
		/*
		 * We have a singleton type, but there's more than one
		 * RR in the rdataset.
		 */
		result = DNS_R_SINGLETON;
		goto free_rdatas;
	}

	/*
	 * Allocate the memory, set up a buffer, start copying in
	 * data.
	 */
	rawbuf = isc_mem_get(mctx, buflen);

	region->base = rawbuf;
	region->length = buflen;
	rawbuf += headerlen;
	put_uint16(rawbuf, nitems);

	for (i = 0; i < nalloc; i++) {
		if (rdata[i].data == &removed) {
			continue;
		}
		length = rdata[i].length;
		if (rdataset->type == dns_rdatatype_rrsig) {
			length++;
		}
		INSIST(length <= 0xffff);

		put_uint16(rawbuf, length);

		/*
		 * Store the per RR meta data.
		 */
		if (rdataset->type == dns_rdatatype_rrsig) {
			*rawbuf++ = (rdata[i].flags & DNS_RDATA_OFFLINE)
					    ? DNS_RDATASLAB_OFFLINE
					    : 0;
		}
		if (rdata[i].length != 0) {
			memmove(rawbuf, rdata[i].data, rdata[i].length);
		}
		rawbuf += rdata[i].length;
	}

	result = ISC_R_SUCCESS;

free_rdatas:
	isc_mem_put(mctx, rdata, rdatasize);
	return result;
}

isc_result_t
dns_rdataslab_fromrdataset(dns_rdataset_t *rdataset, isc_mem_t *mctx,
			   isc_region_t *region, uint32_t maxrrperset) {
	isc_result_t result;

	if (rdataset->type == dns_rdatatype_none &&
	    rdataset->covers == dns_rdatatype_none)
	{
		return DNS_R_DISALLOWED;
	}

	result = makeslab(rdataset, mctx, region, maxrrperset);
	if (result == ISC_R_SUCCESS) {
		dns_slabheader_t *new = (dns_slabheader_t *)region->base;
		dns_typepair_t typepair;

		if (rdataset->attributes.negative) {
			INSIST(rdataset->type == dns_rdatatype_none);
			INSIST(rdataset->covers != dns_rdatatype_none);
			typepair = DNS_TYPEPAIR_VALUE(rdataset->covers,
						      dns_rdatatype_none);
		} else {
			INSIST(rdataset->type != dns_rdatatype_none);
			INSIST(dns_rdatatype_issig(rdataset->type) ||
			       rdataset->covers == dns_rdatatype_none);
			typepair = DNS_TYPEPAIR_VALUE(rdataset->type,
						      rdataset->covers);
		}

		*new = (dns_slabheader_t){
			.typepair = typepair,
			.trust = rdataset->trust,
			.ttl = rdataset->ttl,
		};
	}

	return result;
}

unsigned int
dns_rdataslab_size(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *slab = (unsigned char *)header +
			      sizeof(dns_slabheader_t);
	INSIST(slab != NULL);

	unsigned char *current = slab;
	uint16_t count = get_uint16(current);

	while (count-- > 0) {
		uint16_t length = get_uint16(current);
		current += length;
	}

	return (unsigned int)(current - slab) + sizeof(dns_slabheader_t);
}

unsigned int
dns_rdataslab_count(dns_slabheader_t *header) {
	REQUIRE(header != NULL);

	unsigned char *current = (unsigned char *)header + sizeof(*header);
	uint16_t count = get_uint16(current);

	return count;
}

/*
 * Make the dns_rdata_t 'rdata' refer to the slab item
 * beginning at '*current' (which is part of a slab of type
 * 'type' and class 'rdclass') and advance '*current' to
 * point to the next item in the slab.
 */
static void
rdata_from_slabitem(unsigned char **current, dns_rdataclass_t rdclass,
		    dns_rdatatype_t type, dns_rdata_t *rdata) {
	unsigned char *tcurrent = *current;
	isc_region_t region;
	bool offline = false;
	uint16_t length = get_uint16(tcurrent);

	if (type == dns_rdatatype_rrsig) {
		if ((*tcurrent & DNS_RDATASLAB_OFFLINE) != 0) {
			offline = true;
		}
		length--;
		tcurrent++;
	}
	region.length = length;
	region.base = tcurrent;
	tcurrent += region.length;
	dns_rdata_fromregion(rdata, rdclass, type, &region);
	if (offline) {
		rdata->flags |= DNS_RDATA_OFFLINE;
	}
	*current = tcurrent;
}

static void
rdata_to_slabitem(unsigned char **current, dns_rdatatype_t type,
		  dns_rdata_t *rdata) {
	unsigned int length = rdata->length;
	unsigned char *data = rdata->data;
	unsigned char *p = *current;

	if (type == dns_rdatatype_rrsig) {
		length++;
		data--;
	}

	put_uint16(p, length);
	memmove(p, data, length);
	p += length;

	*current = p;
}

typedef struct slabinfo {
	unsigned char *pos;
	dns_rdata_t rdata;
	bool dup;
} slabinfo_t;

isc_result_t
dns_rdataslab_merge(dns_slabheader_t *oheader, dns_slabheader_t *nheader,
		    isc_mem_t *mctx, dns_rdataclass_t rdclass,
		    dns_rdatatype_t type, unsigned int flags,
		    uint32_t maxrrperset, dns_slabheader_t **theaderp) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char *ocurrent = NULL, *ncurrent = NULL, *tcurrent = NULL;
	unsigned int ocount, ncount, tlength, tcount = 0;
	slabinfo_t *oinfo = NULL, *ninfo = NULL;
	size_t o = 0, n = 0;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && nheader != NULL);

	ocurrent = (unsigned char *)oheader + sizeof(dns_slabheader_t);
	ocount = get_uint16(ocurrent);

	ncurrent = (unsigned char *)nheader + sizeof(dns_slabheader_t);
	ncount = get_uint16(ncurrent);

	INSIST(ocount > 0 && ncount > 0);

	if (maxrrperset > 0 && ocount + ncount > maxrrperset) {
		return DNS_R_TOOMANYRECORDS;
	}

	/*
	 * Figure out the target length. Start with the header,
	 * plus 2 octets for the count.
	 */
	tlength = sizeof(dns_slabheader_t) + 2;

	/*
	 * Gather the rdatas in the old slab and add their lengths to
	 * the larget length.
	 */
	oinfo = isc_mem_cget(mctx, ocount, sizeof(struct slabinfo));
	for (size_t i = 0; i < ocount; i++) {
		oinfo[i].pos = ocurrent;
		dns_rdata_init(&oinfo[i].rdata);
		rdata_from_slabitem(&ocurrent, rdclass, type, &oinfo[i].rdata);
		tlength += ocurrent - oinfo[i].pos;
	}

	/*
	 * Then add the length of rdatas in the new slab that aren't
	 * duplicated in the old slab.
	 */
	ninfo = isc_mem_cget(mctx, ncount, sizeof(struct slabinfo));
	for (size_t i = 0; i < ncount; i++) {
		ninfo[i].pos = ncurrent;
		dns_rdata_init(&ninfo[i].rdata);
		rdata_from_slabitem(&ncurrent, rdclass, type, &ninfo[i].rdata);

		for (size_t j = 0; j < ocount; j++) {
			if (oinfo[j].dup) {
				/*
				 * This was already found to be
				 * duplicated; no need to compare
				 * it again.
				 */
				continue;
			}

			if (dns_rdata_compare(&oinfo[j].rdata,
					      &ninfo[i].rdata) == 0)
			{
				/*
				 * Found a dup. Mark the old copy as a
				 * duplicate so we don't check it again;
				 * mark the new copy as a duplicate so we
				 * don't copy it to the target.
				 */
				oinfo[j].dup = ninfo[i].dup = true;
				break;
			}
		}

		if (ninfo[i].dup) {
			continue;
		}

		/*
		 * We will be copying this item to the target, so
		 * add its length to tlength and increment tcount.
		 */
		tlength += ncurrent - ninfo[i].pos;
		tcount++;
	}

	/*
	 * If the EXACT flag is set, there can't be any rdata in
	 * the new slab that was also in the old. If tcount is less
	 * than ncount, then we found such a duplicate.
	 */
	if (((flags & DNS_RDATASLAB_EXACT) != 0) && (tcount < ncount)) {
		result = DNS_R_NOTEXACT;
		goto cleanup;
	}

	/*
	 * If nothing's being copied in from the new slab, and the
	 * FORCE flag isn't set, we're done.
	 */
	if (tcount == 0 && (flags & DNS_RDATASLAB_FORCE) == 0) {
		result = DNS_R_UNCHANGED;
		goto cleanup;
	}

	/* Add to tcount the total number of items from the old slab. */
	tcount += ocount;

	/* Resposition ncurrent at the first item. */
	ncurrent = (unsigned char *)nheader + sizeof(dns_slabheader_t) + 2;

	/* Single types can't have more than one RR. */
	if (tcount > 1 && dns_rdatatype_issingleton(type)) {
		result = DNS_R_SINGLETON;
		goto cleanup;
	}

	if (tcount > 0xffff) {
		result = ISC_R_NOSPACE;
		goto cleanup;
	}

	/* Allocate the target buffer and copy the new slab's header */
	unsigned char *tstart = isc_mem_get(mctx, tlength);

	memmove(tstart, nheader, sizeof(dns_slabheader_t));
	tcurrent = tstart + sizeof(dns_slabheader_t);

	/* Write the new count, then start merging the slabs. */
	put_uint16(tcurrent, tcount);

	/*
	 * Now walk the sets together, adding each item in DNSSEC order,
	 * and skipping over any more dups in the new slab.
	 */
	while (o < ocount || n < ncount) {
		bool fromold;

		/* Skip to the next non-duplicate in the new slab. */
		for (; n < ncount && ninfo[n].dup; n++)
			;

		if (o == ocount) {
			fromold = false;
		} else if (n == ncount) {
			fromold = true;
		} else {
			fromold = dns_rdata_compare(&oinfo[o].rdata,
						    &ninfo[n].rdata) < 0;
		}

		if (fromold) {
			rdata_to_slabitem(&tcurrent, type, &oinfo[o].rdata);
			if (++o < ocount) {
				/* Skip to the next rdata in the old slab */
				continue;
			}
		} else {
			rdata_to_slabitem(&tcurrent, type, &ninfo[n++].rdata);
		}
	}

	INSIST(tcurrent == tstart + tlength);

	*theaderp = (dns_slabheader_t *)tstart;

cleanup:
	isc_mem_cput(mctx, oinfo, ocount, sizeof(struct slabinfo));
	isc_mem_cput(mctx, ninfo, ncount, sizeof(struct slabinfo));

	return result;
}

isc_result_t
dns_rdataslab_subtract(dns_slabheader_t *oheader, dns_slabheader_t *sheader,
		       isc_mem_t *mctx, dns_rdataclass_t rdclass,
		       dns_rdatatype_t type, unsigned int flags,
		       dns_slabheader_t **theaderp) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char *ocurrent = NULL, *scurrent = NULL;
	unsigned char *tstart = NULL, *tcurrent = NULL;
	unsigned int ocount, scount, tlength;
	unsigned int tcount = 0, rcount = 0;
	slabinfo_t *oinfo = NULL, *sinfo = NULL;

	REQUIRE(theaderp != NULL && *theaderp == NULL);
	REQUIRE(oheader != NULL && sheader != NULL);

	ocurrent = (unsigned char *)oheader + sizeof(dns_slabheader_t);
	ocount = get_uint16(ocurrent);

	scurrent = (unsigned char *)sheader + sizeof(dns_slabheader_t);
	scount = get_uint16(scurrent);

	INSIST(ocount > 0 && scount > 0);

	/* Get info about the rdatas being subtracted */
	sinfo = isc_mem_cget(mctx, scount, sizeof(struct slabinfo));
	for (size_t i = 0; i < scount; i++) {
		sinfo[i].pos = scurrent;
		dns_rdata_init(&sinfo[i].rdata);
		rdata_from_slabitem(&scurrent, rdclass, type, &sinfo[i].rdata);
	}

	/*
	 * Figure out the target length. Start with the header,
	 * plus 2 octets for the count.
	 */
	tlength = sizeof(dns_slabheader_t) + 2;

	/*
	 * Add the length of the rdatas in the old slab that
	 * aren't being subtracted.
	 */
	oinfo = isc_mem_cget(mctx, ocount, sizeof(struct slabinfo));
	for (size_t i = 0; i < ocount; i++) {
		bool matched = false;

		oinfo[i].pos = ocurrent;
		dns_rdata_init(&oinfo[i].rdata);
		rdata_from_slabitem(&ocurrent, rdclass, type, &oinfo[i].rdata);

		for (size_t j = 0; j < scount; j++) {
			if (sinfo[j].dup) {
				continue;
			} else if (dns_rdata_compare(&oinfo[i].rdata,
						     &sinfo[j].rdata) == 0)
			{
				matched = true;
				oinfo[i].dup = sinfo[j].dup = true;
				break;
			}
		}

		if (matched) {
			/* This item will be subtracted. */
			rcount++;
		} else {
			/*
			 * This rdata wasn't in the slab to be subtracted,
			 * so copy it to the target.  Add its length to
			 * tlength and increment tcount.
			 */
			tlength += ocurrent - oinfo[i].pos;
			tcount++;
		}
	}

	/*
	 * If the EXACT flag wasn't set, check that all the records that
	 * were to be subtracted actually did exist in the original slab.
	 * (The numeric check works here because rdataslabs do not contain
	 * duplicates.)
	 */
	if ((flags & DNS_RDATASLAB_EXACT) != 0 && rcount != scount) {
		result = DNS_R_NOTEXACT;
		goto cleanup;
	}

	/*
	 * If the resulting rdataslab would be empty, don't bother to
	 * create a new buffer, just return.
	 */
	if (tcount == 0) {
		result = DNS_R_NXRRSET;
		goto cleanup;
	}

	/*
	 * If nothing is going to change, stop.
	 */
	if (rcount == 0) {
		result = DNS_R_UNCHANGED;
		goto cleanup;
	}

	/*
	 * Allocate the target buffer and copy the old slab's header.
	 */
	tstart = isc_mem_get(mctx, tlength);
	memmove(tstart, oheader, sizeof(dns_slabheader_t));
	tcurrent = tstart + sizeof(dns_slabheader_t);

	/*
	 * Write the new count.
	 */
	put_uint16(tcurrent, tcount);

	/*
	 * Copy the parts of the old slab that didn't have duplicates.
	 */
	for (size_t i = 0; i < ocount; i++) {
		if (!oinfo[i].dup) {
			rdata_to_slabitem(&tcurrent, type, &oinfo[i].rdata);
		}
	}

	INSIST(tcurrent == tstart + tlength);

	*theaderp = (dns_slabheader_t *)tstart;

cleanup:
	isc_mem_cput(mctx, oinfo, ocount, sizeof(struct slabinfo));
	isc_mem_cput(mctx, sinfo, scount, sizeof(struct slabinfo));

	return result;
}

bool
dns_rdataslab_equal(dns_slabheader_t *slab1, dns_slabheader_t *slab2) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = get_uint16(current1);

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = get_uint16(current2);

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		unsigned int length1 = get_uint16(current1);
		unsigned int length2 = get_uint16(current2);

		if (length1 != length2 ||
		    memcmp(current1, current2, length1) != 0)
		{
			return false;
		}

		current1 += length1;
		current2 += length1;
	}
	return true;
}

bool
dns_rdataslab_equalx(dns_slabheader_t *slab1, dns_slabheader_t *slab2,
		     dns_rdataclass_t rdclass, dns_rdatatype_t type) {
	unsigned char *current1 = NULL, *current2 = NULL;
	unsigned int count1, count2;

	current1 = (unsigned char *)slab1 + sizeof(dns_slabheader_t);
	count1 = get_uint16(current1);

	current2 = (unsigned char *)slab2 + sizeof(dns_slabheader_t);
	count2 = get_uint16(current2);

	if (count1 != count2) {
		return false;
	} else if (count1 == 0) {
		return true;
	}

	while (count1-- > 0) {
		dns_rdata_t rdata1 = DNS_RDATA_INIT;
		dns_rdata_t rdata2 = DNS_RDATA_INIT;

		rdata_from_slabitem(&current1, rdclass, type, &rdata1);
		rdata_from_slabitem(&current2, rdclass, type, &rdata2);
		if (dns_rdata_compare(&rdata1, &rdata2) != 0) {
			return false;
		}
	}
	return true;
}

void
dns_slabheader_setownercase(dns_slabheader_t *header, const dns_name_t *name) {
	REQUIRE(!CASESET(header));

	bool casefullylower = true;

	/*
	 * We do not need to worry about label lengths as they are all
	 * less than or equal to 63.
	 */
	memset(header->upper, 0, sizeof(header->upper));
	for (size_t i = 0; i < name->length; i++) {
		if (isupper(name->ndata[i])) {
			header->upper[i / 8] |= 1 << (i % 8);
			casefullylower = false;
		}
	}
	if (casefullylower) {
		DNS_SLABHEADER_SETATTR(header,
				       DNS_SLABHEADERATTR_CASEFULLYLOWER);
	}
	DNS_SLABHEADER_SETATTR(header, DNS_SLABHEADERATTR_CASESET);
}

void
dns_slabheader_copycase(dns_slabheader_t *dest, dns_slabheader_t *src) {
	REQUIRE(!CASESET(dest));
	if (CASESET(src)) {
		memmove(dest->upper, src->upper, sizeof(src->upper));
		if (CASEFULLYLOWER(src)) {
			DNS_SLABHEADER_SETATTR(
				dest, DNS_SLABHEADERATTR_CASEFULLYLOWER);
		}
		DNS_SLABHEADER_SETATTR(dest, DNS_SLABHEADERATTR_CASESET);
	}
}

void
dns_slabheader_reset(dns_slabheader_t *h, dns_dbnode_t *node) {
	h->heap_index = 0;
	h->heap = NULL;
	h->node = node;

	atomic_init(&h->attributes, 0);
	atomic_init(&h->last_refresh_fail_ts, 0);

	STATIC_ASSERT(sizeof(h->attributes) == 2,
		      "The .attributes field of dns_slabheader_t needs to be "
		      "16-bit int type exactly.");
}

dns_slabheader_t *
dns_slabheader_new(isc_mem_t *mctx, dns_dbnode_t *node) {
	dns_slabheader_t *h = NULL;

	h = isc_mem_get(mctx, sizeof(*h));
	*h = (dns_slabheader_t){
		.node = node,
	};
	return h;
}

void
dns_slabheader_destroy(dns_slabheader_t **headerp) {
	unsigned int size;
	dns_slabheader_t *header = *headerp;

	*headerp = NULL;

	isc_mem_t *mctx = header->node->mctx;
	dns_db_deletedata(header->node, header);

	if (EXISTS(header)) {
		size = dns_rdataslab_size(header);
	} else {
		size = sizeof(*header);
	}

	isc_mem_put(mctx, header, size);
}

void
dns_slabheader_freeproof(isc_mem_t *mctx, dns_slabheader_proof_t **proofp) {
	unsigned int buflen;
	uint8_t *rawbuf;
	dns_slabheader_proof_t *proof = *proofp;
	*proofp = NULL;

	if (dns_name_dynamic(&proof->name)) {
		dns_name_free(&proof->name, mctx);
	}
	if (proof->neg != NULL) {
		rawbuf = proof->neg;
		rawbuf -= sizeof(dns_slabheader_t);
		buflen = dns_rdataslab_size((dns_slabheader_t *)rawbuf);

		isc_mem_put(mctx, rawbuf, buflen);
	}
	if (proof->negsig != NULL) {
		rawbuf = proof->negsig;
		rawbuf -= sizeof(dns_slabheader_t);
		buflen = dns_rdataslab_size((dns_slabheader_t *)rawbuf);

		isc_mem_put(mctx, rawbuf, buflen);
	}
	isc_mem_put(mctx, proof, sizeof(*proof));
}

/* Fixed RRSet helper macros */

static void
rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->slab.node;

	dns__db_detachnode(&node DNS__DB_FLARG_PASS);
}

static isc_result_t
rdataset_first(dns_rdataset_t *rdataset) {
	unsigned char *raw = rdataset->slab.raw;
	uint16_t count = peek_uint16(raw);
	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		rdataset->slab.iter_count = 0;
		return ISC_R_NOMORE;
	}

	/*
	 * iter_count is the number of rdata beyond the cursor
	 * position, so we decrement the total count by one before
	 * storing it.
	 *
	 * 'raw' points to the first record.
	 */
	rdataset->slab.iter_pos = raw + sizeof(uint16_t);
	rdataset->slab.iter_count = count - 1;

	return ISC_R_SUCCESS;
}

static isc_result_t
rdataset_next(dns_rdataset_t *rdataset) {
	uint16_t count = rdataset->slab.iter_count;
	if (count == 0) {
		rdataset->slab.iter_pos = NULL;
		return ISC_R_NOMORE;
	}
	rdataset->slab.iter_count = count - 1;

	/*
	 * Skip forward one record (length + 4) or one offset (4).
	 */
	unsigned char *raw = rdataset->slab.iter_pos;
	uint16_t length = peek_uint16(raw);
	raw += length;
	rdataset->slab.iter_pos = raw + sizeof(uint16_t);

	return ISC_R_SUCCESS;
}

static void
rdataset_current(dns_rdataset_t *rdataset, dns_rdata_t *rdata) {
	unsigned char *raw = NULL;
	unsigned int length;
	isc_region_t r;
	unsigned int flags = 0;

	raw = rdataset->slab.iter_pos;
	REQUIRE(raw != NULL);

	/*
	 * Find the start of the record if not already in iter_pos
	 * then skip the length and order fields.
	 */
	length = get_uint16(raw);

	if (rdataset->type == dns_rdatatype_rrsig) {
		if (*raw & DNS_RDATASLAB_OFFLINE) {
			flags |= DNS_RDATA_OFFLINE;
		}
		length--;
		raw++;
	}
	r.length = length;
	r.base = raw;
	dns_rdata_fromregion(rdata, rdataset->rdclass, rdataset->type, &r);
	rdata->flags |= flags;
}

static void
rdataset_clone(dns_rdataset_t *source, dns_rdataset_t *target DNS__DB_FLARG) {
	dns_dbnode_t *node = source->slab.node;
	dns_dbnode_t *cloned_node = NULL;

	dns__db_attachnode(node, &cloned_node DNS__DB_FLARG_PASS);
	INSIST(!ISC_LINK_LINKED(target, link));
	*target = *source;
	ISC_LINK_INIT(target, link);

	target->slab.iter_pos = NULL;
	target->slab.iter_count = 0;
}

static unsigned int
rdataset_count(dns_rdataset_t *rdataset) {
	unsigned char *raw = NULL;
	unsigned int count;

	raw = rdataset->slab.raw;
	count = get_uint16(raw);

	return count;
}

static isc_result_t
rdataset_getnoqname(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec,
		    dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	dns_db_t *db = rdataset->slab.db;
	dns_dbnode_t *node = rdataset->slab.node;
	const dns_slabheader_proof_t *noqname = rdataset->slab.noqname;

	/*
	 * Normally, rdataset->slab.raw points to the data immediately
	 * following a dns_slabheader in memory. Here, though, it will
	 * point to a bare rdataslab, a pointer to which is stored in
	 * the dns_slabheader's `noqname` field.
	 *
	 * The 'keepcase' attribute is set to prevent setownercase and
	 * getownercase methods from affecting the case of NSEC/NSEC3
	 * owner names.
	 */
	dns__db_attachnode(node, &(dns_dbnode_t *){ NULL } DNS__DB_FLARG_PASS);
	*nsec = (dns_rdataset_t){
		.methods = &dns_rdataslab_rdatasetmethods,
		.rdclass = db->rdclass,
		.type = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.slab.db = db,
		.slab.node = node,
		.slab.raw = noqname->neg,
		.link = nsec->link,
		.attributes = nsec->attributes,
		.magic = nsec->magic,
	};
	nsec->attributes.keepcase = true;

	dns__db_attachnode(node, &(dns_dbnode_t *){ NULL } DNS__DB_FLARG_PASS);
	*nsecsig = (dns_rdataset_t){
		.methods = &dns_rdataslab_rdatasetmethods,
		.rdclass = db->rdclass,
		.type = dns_rdatatype_rrsig,
		.covers = noqname->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.slab.db = db,
		.slab.node = node,
		.slab.raw = noqname->negsig,
		.link = nsecsig->link,
		.attributes = nsecsig->attributes,
		.magic = nsecsig->magic,
	};
	nsecsig->attributes.keepcase = true;

	dns_name_clone(&noqname->name, name);

	return ISC_R_SUCCESS;
}

static isc_result_t
rdataset_getclosest(dns_rdataset_t *rdataset, dns_name_t *name,
		    dns_rdataset_t *nsec,
		    dns_rdataset_t *nsecsig DNS__DB_FLARG) {
	dns_db_t *db = rdataset->slab.db;
	dns_dbnode_t *node = rdataset->slab.node;
	const dns_slabheader_proof_t *closest = rdataset->slab.closest;

	/*
	 * Normally, rdataset->slab.raw points to the data immediately
	 * following a dns_slabheader in memory. Here, though, it will
	 * point to a bare rdataslab, a pointer to which is stored in
	 * the dns_slabheader's `closest` field.
	 *
	 * The 'keepcase' attribute is set to prevent setownercase and
	 * getownercase methods from affecting the case of NSEC/NSEC3
	 * owner names.
	 */
	dns__db_attachnode(node, &(dns_dbnode_t *){ NULL } DNS__DB_FLARG_PASS);
	*nsec = (dns_rdataset_t){
		.methods = &dns_rdataslab_rdatasetmethods,
		.rdclass = db->rdclass,
		.type = closest->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.slab.db = db,
		.slab.node = node,
		.slab.raw = closest->neg,
		.link = nsec->link,
		.attributes = nsec->attributes,
		.magic = nsec->magic,
	};
	nsec->attributes.keepcase = true;

	dns__db_attachnode(node, &(dns_dbnode_t *){ NULL } DNS__DB_FLARG_PASS);
	*nsecsig = (dns_rdataset_t){
		.methods = &dns_rdataslab_rdatasetmethods,
		.rdclass = db->rdclass,
		.type = dns_rdatatype_rrsig,
		.covers = closest->type,
		.ttl = rdataset->ttl,
		.trust = rdataset->trust,
		.slab.db = db,
		.slab.node = node,
		.slab.raw = closest->negsig,
		.link = nsecsig->link,
		.attributes = nsecsig->attributes,
		.magic = nsecsig->magic,
	};
	nsecsig->attributes.keepcase = true;

	dns_name_clone(&closest->name, name);

	return ISC_R_SUCCESS;
}

static void
rdataset_settrust(dns_rdataset_t *rdataset, dns_trust_t trust) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);

	dns_db_locknode(header->node, isc_rwlocktype_write);
	header->trust = rdataset->trust = trust;
	dns_db_unlocknode(header->node, isc_rwlocktype_write);
}

static void
rdataset_expire(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);

	dns_db_expiredata(header->node, header);
}

static void
rdataset_clearprefetch(dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);

	dns_db_locknode(header->node, isc_rwlocktype_write);
	DNS_SLABHEADER_CLRATTR(header, DNS_SLABHEADERATTR_PREFETCH);
	dns_db_unlocknode(header->node, isc_rwlocktype_write);
}

static void
rdataset_setownercase(dns_rdataset_t *rdataset, const dns_name_t *name) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);

	/* The case could be set just once for the same header */
	if (CASESET(header)) {
		return;
	}

	dns_db_locknode(header->node, isc_rwlocktype_write);
	dns_slabheader_setownercase(header, name);
	dns_db_unlocknode(header->node, isc_rwlocktype_write);
}

static void
rdataset_getownercase(const dns_rdataset_t *rdataset, dns_name_t *name) {
	dns_slabheader_t *header = dns_rdataset_getheader(rdataset);
	uint8_t mask = (1 << 7);
	uint8_t bits = 0;

	if (!CASESET(header)) {
		return;
	}

	if (CASEFULLYLOWER(header)) {
		isc_ascii_lowercopy(name->ndata, name->ndata, name->length);
		return;
	}

	uint8_t *nd = name->ndata;
	for (size_t i = 0; i < name->length; i++) {
		if (mask == (1 << 7)) {
			bits = header->upper[i / 8];
			mask = 1;
		} else {
			mask <<= 1;
		}
		nd[i] = (bits & mask) ? isc_ascii_toupper(nd[i])
				      : isc_ascii_tolower(nd[i]);
	}
}

static dns_slabheader_t *
rdataset_getheader(const dns_rdataset_t *rdataset) {
	dns_slabheader_t *header = (dns_slabheader_t *)rdataset->slab.raw;
	return header - 1;
}

dns_slabtop_t *
dns_slabtop_new(isc_mem_t *mctx, dns_typepair_t typepair) {
	dns_slabtop_t *top = isc_mem_get(mctx, sizeof(*top));
	*top = (dns_slabtop_t){
		.typepair = typepair,
		.link = ISC_LINK_INITIALIZER,
	};

	return top;
}

void
dns_slabtop_destroy(isc_mem_t *mctx, dns_slabtop_t **topp) {
	REQUIRE(topp != NULL && *topp != NULL);
	dns_slabtop_t *top = *topp;
	*topp = NULL;
	isc_mem_put(mctx, top, sizeof(*top));
}
