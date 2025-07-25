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

/* RFC 7477 */

#ifndef RDATA_GENERIC_CSYNC_62_C
#define RDATA_GENERIC_CSYNC_62_C

#define RRTYPE_CSYNC_ATTRIBUTES 0

static isc_result_t
fromtext_csync(ARGS_FROMTEXT) {
	isc_token_t token;

	REQUIRE(type == dns_rdatatype_csync);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	/* Serial. */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	/* Flags. */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	/* Type Map */
	return typemap_fromtext(lexer, target, true);
}

static isc_result_t
totext_csync(ARGS_TOTEXT) {
	unsigned long num;
	char buf[sizeof("0123456789")]; /* Also TYPE65535 */
	isc_region_t sr;

	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(rdata->length >= 6);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &sr);

	num = uint32_fromregion(&sr);
	isc_region_consume(&sr, 4);
	snprintf(buf, sizeof(buf), "%lu", num);
	RETERR(str_totext(buf, target));

	RETERR(str_totext(" ", target));

	num = uint16_fromregion(&sr);
	isc_region_consume(&sr, 2);
	snprintf(buf, sizeof(buf), "%lu", num);
	RETERR(str_totext(buf, target));

	/*
	 * Don't leave a trailing space when there's no typemap present.
	 */
	if (sr.length > 0) {
		RETERR(str_totext(" ", target));
	}
	return typemap_totext(&sr, NULL, target);
}

static isc_result_t
fromwire_csync(ARGS_FROMWIRE) {
	isc_region_t sr;

	REQUIRE(type == dns_rdatatype_csync);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(dctx);

	/*
	 * Serial + Flags
	 */
	isc_buffer_activeregion(source, &sr);
	if (sr.length < 6) {
		return ISC_R_UNEXPECTEDEND;
	}

	RETERR(mem_tobuffer(target, sr.base, 6));
	isc_buffer_forward(source, 6);
	isc_region_consume(&sr, 6);

	RETERR(typemap_test(&sr, true));

	RETERR(mem_tobuffer(target, sr.base, sr.length));
	isc_buffer_forward(source, sr.length);
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_csync(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(rdata->length >= 6);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}

static int
compare_csync(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_csync);
	REQUIRE(rdata1->length >= 6);
	REQUIRE(rdata2->length >= 6);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return isc_region_compare(&r1, &r2);
}

static isc_result_t
fromstruct_csync(ARGS_FROMSTRUCT) {
	dns_rdata_csync_t *csync = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_csync);
	REQUIRE(csync != NULL);
	REQUIRE(csync->common.rdtype == type);
	REQUIRE(csync->common.rdclass == rdclass);
	REQUIRE(csync->typebits != NULL || csync->len == 0);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint32_tobuffer(csync->serial, target));
	RETERR(uint16_tobuffer(csync->flags, target));

	region.base = csync->typebits;
	region.length = csync->len;
	RETERR(typemap_test(&region, true));
	return mem_tobuffer(target, csync->typebits, csync->len);
}

static isc_result_t
tostruct_csync(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_csync_t *csync = target;

	REQUIRE(rdata->type == dns_rdatatype_csync);
	REQUIRE(csync != NULL);
	REQUIRE(rdata->length != 0);

	csync->common.rdclass = rdata->rdclass;
	csync->common.rdtype = rdata->type;

	dns_rdata_toregion(rdata, &region);

	csync->serial = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	csync->flags = uint16_fromregion(&region);
	isc_region_consume(&region, 2);

	csync->len = region.length;
	csync->typebits = mem_maybedup(mctx, region.base, region.length);
	csync->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_csync(ARGS_FREESTRUCT) {
	dns_rdata_csync_t *csync = source;

	REQUIRE(csync != NULL);
	REQUIRE(csync->common.rdtype == dns_rdatatype_csync);

	if (csync->mctx == NULL) {
		return;
	}

	if (csync->typebits != NULL) {
		isc_mem_free(csync->mctx, csync->typebits);
	}
	csync->mctx = NULL;
}

static isc_result_t
additionaldata_csync(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_csync);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_csync(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_csync);

	dns_rdata_toregion(rdata, &r);
	return (digest)(arg, &r);
}

static bool
checkowner_csync(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_csync);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_csync(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_csync);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_csync(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_csync);
	REQUIRE(rdata1->length >= 6);
	REQUIRE(rdata2->length >= 6);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);
	return isc_region_compare(&region1, &region2);
}
#endif /* RDATA_GENERIC_CSYNC_62_C */
