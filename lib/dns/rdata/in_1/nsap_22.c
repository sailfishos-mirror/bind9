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

/* RFC1706 */

#ifndef RDATA_IN_1_NSAP_22_C
#define RDATA_IN_1_NSAP_22_C

#define RRTYPE_NSAP_ATTRIBUTES (0)

static isc_result_t
fromtext_in_nsap(ARGS_FROMTEXT) {
	isc_token_t token;
	isc_textregion_t *sr;
	int n;
	bool valid = false;
	int digits = 0;
	unsigned char c = 0;

	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/* 0x<hex.string.with.periods> */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));
	sr = &token.value.as_textregion;
	if (sr->length < 2) {
		RETTOK(ISC_R_UNEXPECTEDEND);
	}
	if (sr->base[0] != '0' || (sr->base[1] != 'x' && sr->base[1] != 'X')) {
		RETTOK(DNS_R_SYNTAX);
	}
	isc_textregion_consume(sr, 2);
	while (sr->length > 0) {
		if (sr->base[0] == '.') {
			isc_textregion_consume(sr, 1);
			continue;
		}
		if ((n = hexvalue(sr->base[0])) == -1) {
			RETTOK(DNS_R_SYNTAX);
		}
		c <<= 4;
		c += n;
		if (++digits == 2) {
			RETERR(mem_tobuffer(target, &c, 1));
			valid = true;
			digits = 0;
			c = 0;
		}
		isc_textregion_consume(sr, 1);
	}
	if (digits != 0 || !valid) {
		RETTOK(ISC_R_UNEXPECTEDEND);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_in_nsap(ARGS_TOTEXT) {
	isc_region_t region;
	char buf[sizeof("xx")];

	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	RETERR(str_totext("0x", target));
	while (region.length != 0) {
		snprintf(buf, sizeof(buf), "%02x", region.base[0]);
		isc_region_consume(&region, 1);
		RETERR(str_totext(buf, target));
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
fromwire_in_nsap(ARGS_FROMWIRE) {
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);

	isc_buffer_activeregion(source, &region);
	if (region.length < 1) {
		return ISC_R_UNEXPECTEDEND;
	}

	RETERR(mem_tobuffer(target, region.base, region.length));
	isc_buffer_forward(source, region.length);
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_in_nsap(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}

static int
compare_in_nsap(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_nsap);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return isc_region_compare(&r1, &r2);
}

static isc_result_t
fromstruct_in_nsap(ARGS_FROMSTRUCT) {
	dns_rdata_in_nsap_t *nsap = source;

	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(nsap != NULL);
	REQUIRE(nsap->common.rdtype == type);
	REQUIRE(nsap->common.rdclass == rdclass);
	REQUIRE(nsap->nsap != NULL || nsap->nsap_len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	return mem_tobuffer(target, nsap->nsap, nsap->nsap_len);
}

static isc_result_t
tostruct_in_nsap(ARGS_TOSTRUCT) {
	dns_rdata_in_nsap_t *nsap = target;
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(nsap != NULL);
	REQUIRE(rdata->length != 0);

	nsap->common.rdclass = rdata->rdclass;
	nsap->common.rdtype = rdata->type;

	dns_rdata_toregion(rdata, &r);
	nsap->nsap_len = r.length;
	nsap->nsap = mem_maybedup(mctx, r.base, r.length);
	nsap->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_in_nsap(ARGS_FREESTRUCT) {
	dns_rdata_in_nsap_t *nsap = source;

	REQUIRE(nsap != NULL);
	REQUIRE(nsap->common.rdclass == dns_rdataclass_in);
	REQUIRE(nsap->common.rdtype == dns_rdatatype_nsap);

	if (nsap->mctx == NULL) {
		return;
	}

	if (nsap->nsap != NULL) {
		isc_mem_free(nsap->mctx, nsap->nsap);
	}
	nsap->mctx = NULL;
}

static isc_result_t
additionaldata_in_nsap(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_in_nsap(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &r);

	return (digest)(arg, &r);
}

static bool
checkowner_in_nsap(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_nsap);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_in_nsap(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_nsap);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_in_nsap(ARGS_COMPARE) {
	return compare_in_nsap(rdata1, rdata2);
}

#endif /* RDATA_IN_1_NSAP_22_C */
