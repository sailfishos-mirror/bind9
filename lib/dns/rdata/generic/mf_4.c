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

#ifndef RDATA_GENERIC_MF_4_C
#define RDATA_GENERIC_MF_4_C

#define RRTYPE_MF_ATTRIBUTES (0)

static isc_result_t
fromtext_mf(ARGS_FROMTEXT) {
	isc_token_t token;
	isc_buffer_t buffer;

	REQUIRE(type == dns_rdatatype_mf);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_wirefromtext(&buffer, origin, options, target));
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_mf(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	unsigned int opts;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name);
	dns_name_init(&prefix);

	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	opts = name_prefix(&name, tctx->origin, &prefix) ? DNS_NAME_OMITFINALDOT
							 : 0;
	return dns_name_totext(&prefix, opts, target);
}

static isc_result_t
fromwire_mf(ARGS_FROMWIRE) {
	dns_name_t name;

	REQUIRE(type == dns_rdatatype_mf);

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, true);

	dns_name_init(&name);
	return dns_name_fromwire(&name, source, dctx, target);
}

static isc_result_t
towire_mf(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}

static int
compare_mf(ARGS_COMPARE) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_mf);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_name_init(&name1);
	dns_name_init(&name2);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return dns_name_rdatacompare(&name1, &name2);
}

static isc_result_t
fromstruct_mf(ARGS_FROMSTRUCT) {
	dns_rdata_mf_t *mf = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_mf);
	REQUIRE(mf != NULL);
	REQUIRE(mf->common.rdtype == type);
	REQUIRE(mf->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&mf->mf, &region);
	return isc_buffer_copyregion(target, &region);
}

static isc_result_t
tostruct_mf(ARGS_TOSTRUCT) {
	dns_rdata_mf_t *mf = target;
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mf);
	REQUIRE(mf != NULL);
	REQUIRE(rdata->length != 0);

	mf->common.rdclass = rdata->rdclass;
	mf->common.rdtype = rdata->type;

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &r);
	dns_name_fromregion(&name, &r);
	dns_name_init(&mf->mf);
	name_duporclone(&name, mctx, &mf->mf);
	mf->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_mf(ARGS_FREESTRUCT) {
	dns_rdata_mf_t *mf = source;

	REQUIRE(mf != NULL);
	REQUIRE(mf->common.rdtype == dns_rdatatype_mf);

	if (mf->mctx == NULL) {
		return;
	}
	dns_name_free(&mf->mf, mf->mctx);
	mf->mctx = NULL;
}

static isc_result_t
additionaldata_mf(ARGS_ADDLDATA) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mf);

	UNUSED(owner);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	dns_name_fromregion(&name, &region);

	return (add)(arg, &name, dns_rdatatype_a, NULL DNS__DB_FILELINE);
}

static isc_result_t
digest_mf(ARGS_DIGEST) {
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mf);

	dns_rdata_toregion(rdata, &r);
	dns_name_init(&name);
	dns_name_fromregion(&name, &r);

	return dns_name_digest(&name, digest, arg);
}

static bool
checkowner_mf(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_mf);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_mf(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_mf);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(bad);

	return true;
}

static int
casecompare_mf(ARGS_COMPARE) {
	return compare_mf(rdata1, rdata2);
}

#endif /* RDATA_GENERIC_MF_4_C */
