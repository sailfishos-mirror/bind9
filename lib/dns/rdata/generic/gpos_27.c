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

/* RFC1712 */

#ifndef RDATA_GENERIC_GPOS_27_C
#define RDATA_GENERIC_GPOS_27_C

#define RRTYPE_GPOS_ATTRIBUTES (0)

static isc_result_t
fromtext_gpos(ARGS_FROMTEXT) {
	isc_token_t token;
	int i;

	REQUIRE(type == dns_rdatatype_gpos);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	for (i = 0; i < 3; i++) {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_qstring, false));
		RETTOK(txt_fromtext(&token.value.as_textregion, target));
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_gpos(ARGS_TOTEXT) {
	isc_region_t region;
	int i;

	REQUIRE(rdata->type == dns_rdatatype_gpos);
	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);

	for (i = 0; i < 3; i++) {
		RETERR(txt_totext(&region, true, target));
		if (i != 2) {
			RETERR(str_totext(" ", target));
		}
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
fromwire_gpos(ARGS_FROMWIRE) {
	int i;

	REQUIRE(type == dns_rdatatype_gpos);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);

	for (i = 0; i < 3; i++) {
		RETERR(txt_fromwire(source, target));
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
towire_gpos(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_gpos);
	REQUIRE(rdata->length != 0);

	UNUSED(cctx);

	return mem_tobuffer(target, rdata->data, rdata->length);
}

static int
compare_gpos(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_gpos);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return isc_region_compare(&r1, &r2);
}

static isc_result_t
fromstruct_gpos(ARGS_FROMSTRUCT) {
	dns_rdata_gpos_t *gpos = source;

	REQUIRE(type == dns_rdatatype_gpos);
	REQUIRE(gpos != NULL);
	REQUIRE(gpos->common.rdtype == type);
	REQUIRE(gpos->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(gpos->long_len, target));
	RETERR(mem_tobuffer(target, gpos->longitude, gpos->long_len));
	RETERR(uint8_tobuffer(gpos->lat_len, target));
	RETERR(mem_tobuffer(target, gpos->latitude, gpos->lat_len));
	RETERR(uint8_tobuffer(gpos->alt_len, target));
	return mem_tobuffer(target, gpos->altitude, gpos->alt_len);
}

static isc_result_t
tostruct_gpos(ARGS_TOSTRUCT) {
	dns_rdata_gpos_t *gpos = target;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_gpos);
	REQUIRE(gpos != NULL);
	REQUIRE(rdata->length != 0);

	gpos->common.rdclass = rdata->rdclass;
	gpos->common.rdtype = rdata->type;

	dns_rdata_toregion(rdata, &region);
	gpos->long_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	gpos->longitude = mem_maybedup(mctx, region.base, gpos->long_len);
	isc_region_consume(&region, gpos->long_len);

	gpos->lat_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	gpos->latitude = mem_maybedup(mctx, region.base, gpos->lat_len);
	isc_region_consume(&region, gpos->lat_len);

	gpos->alt_len = uint8_fromregion(&region);
	isc_region_consume(&region, 1);
	if (gpos->lat_len > 0) {
		gpos->altitude = mem_maybedup(mctx, region.base, gpos->alt_len);
	} else {
		gpos->altitude = NULL;
	}

	gpos->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_gpos(ARGS_FREESTRUCT) {
	dns_rdata_gpos_t *gpos = source;

	REQUIRE(gpos != NULL);
	REQUIRE(gpos->common.rdtype == dns_rdatatype_gpos);

	if (gpos->mctx == NULL) {
		return;
	}

	if (gpos->longitude != NULL) {
		isc_mem_free(gpos->mctx, gpos->longitude);
	}
	if (gpos->latitude != NULL) {
		isc_mem_free(gpos->mctx, gpos->latitude);
	}
	if (gpos->altitude != NULL) {
		isc_mem_free(gpos->mctx, gpos->altitude);
	}
	gpos->mctx = NULL;
}

static isc_result_t
additionaldata_gpos(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_gpos);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_gpos(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_gpos);

	dns_rdata_toregion(rdata, &r);

	return (digest)(arg, &r);
}

static bool
checkowner_gpos(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_gpos);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_gpos(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_gpos);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_gpos(ARGS_COMPARE) {
	return compare_gpos(rdata1, rdata2);
}

#endif /* RDATA_GENERIC_GPOS_27_C */
