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

/* RFC1183 */

#ifndef RDATA_GENERIC_ISDN_20_C
#define RDATA_GENERIC_ISDN_20_C

#define RRTYPE_ISDN_ATTRIBUTES (0)

static isc_result_t
fromtext_isdn(ARGS_FROMTEXT) {
	isc_token_t token;

	REQUIRE(type == dns_rdatatype_isdn);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(origin);
	UNUSED(options);
	UNUSED(callbacks);

	/* ISDN-address */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
				      false));
	RETTOK(txt_fromtext(&token.value.as_textregion, target));

	/* sa: optional */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
				      true));
	if (token.type != isc_tokentype_string &&
	    token.type != isc_tokentype_qstring)
	{
		isc_lex_ungettoken(lexer, &token);
		return ISC_R_SUCCESS;
	}
	RETTOK(txt_fromtext(&token.value.as_textregion, target));
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_isdn(ARGS_TOTEXT) {
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_isdn);
	REQUIRE(rdata->length != 0);

	UNUSED(tctx);

	dns_rdata_toregion(rdata, &region);
	RETERR(txt_totext(&region, true, target));
	if (region.length == 0) {
		return ISC_R_SUCCESS;
	}
	RETERR(str_totext(" ", target));
	return txt_totext(&region, true, target);
}

static isc_result_t
fromwire_isdn(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_isdn);

	UNUSED(type);
	UNUSED(dctx);
	UNUSED(rdclass);

	RETERR(txt_fromwire(source, target));
	if (buffer_empty(source)) {
		return ISC_R_SUCCESS;
	}
	return txt_fromwire(source, target);
}

static isc_result_t
towire_isdn(ARGS_TOWIRE) {
	UNUSED(cctx);

	REQUIRE(rdata->type == dns_rdatatype_isdn);
	REQUIRE(rdata->length != 0);

	return mem_tobuffer(target, rdata->data, rdata->length);
}

static int
compare_isdn(ARGS_COMPARE) {
	isc_region_t r1;
	isc_region_t r2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_isdn);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &r1);
	dns_rdata_toregion(rdata2, &r2);
	return isc_region_compare(&r1, &r2);
}

static isc_result_t
fromstruct_isdn(ARGS_FROMSTRUCT) {
	dns_rdata_isdn_t *isdn = source;

	REQUIRE(type == dns_rdatatype_isdn);
	REQUIRE(isdn != NULL);
	REQUIRE(isdn->common.rdtype == type);
	REQUIRE(isdn->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint8_tobuffer(isdn->isdn_len, target));
	RETERR(mem_tobuffer(target, isdn->isdn, isdn->isdn_len));
	if (isdn->subaddress == NULL) {
		return ISC_R_SUCCESS;
	}
	RETERR(uint8_tobuffer(isdn->subaddress_len, target));
	return mem_tobuffer(target, isdn->subaddress, isdn->subaddress_len);
}

static isc_result_t
tostruct_isdn(ARGS_TOSTRUCT) {
	dns_rdata_isdn_t *isdn = target;
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_isdn);
	REQUIRE(isdn != NULL);
	REQUIRE(rdata->length != 0);

	isdn->common.rdclass = rdata->rdclass;
	isdn->common.rdtype = rdata->type;

	dns_rdata_toregion(rdata, &r);

	isdn->isdn_len = uint8_fromregion(&r);
	isc_region_consume(&r, 1);
	isdn->isdn = mem_maybedup(mctx, r.base, isdn->isdn_len);
	isc_region_consume(&r, isdn->isdn_len);

	if (r.length == 0) {
		isdn->subaddress_len = 0;
		isdn->subaddress = NULL;
	} else {
		isdn->subaddress_len = uint8_fromregion(&r);
		isc_region_consume(&r, 1);
		isdn->subaddress = mem_maybedup(mctx, r.base,
						isdn->subaddress_len);
	}

	isdn->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_isdn(ARGS_FREESTRUCT) {
	dns_rdata_isdn_t *isdn = source;

	REQUIRE(isdn != NULL);

	if (isdn->mctx == NULL) {
		return;
	}

	if (isdn->isdn != NULL) {
		isc_mem_free(isdn->mctx, isdn->isdn);
	}
	if (isdn->subaddress != NULL) {
		isc_mem_free(isdn->mctx, isdn->subaddress);
	}
	isdn->mctx = NULL;
}

static isc_result_t
additionaldata_isdn(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_isdn);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_isdn(ARGS_DIGEST) {
	isc_region_t r;

	REQUIRE(rdata->type == dns_rdatatype_isdn);

	dns_rdata_toregion(rdata, &r);

	return (digest)(arg, &r);
}

static bool
checkowner_isdn(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_isdn);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_isdn(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_isdn);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_isdn(ARGS_COMPARE) {
	return compare_isdn(rdata1, rdata2);
}

#endif /* RDATA_GENERIC_ISDN_20_C */
