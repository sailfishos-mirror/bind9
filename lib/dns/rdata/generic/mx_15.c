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

#ifndef RDATA_GENERIC_MX_15_C
#define RDATA_GENERIC_MX_15_C

#include <string.h>

#include <isc/net.h>

#include <dns/fixedname.h>

#define RRTYPE_MX_ATTRIBUTES (0)

static bool
check_mx(isc_token_t *token) {
	char tmp[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:123.123.123.123.")];
	struct in_addr addr;
	struct in6_addr addr6;

	if (strlcpy(tmp, DNS_AS_STR(*token), sizeof(tmp)) >= sizeof(tmp)) {
		return true;
	}

	if (tmp[strlen(tmp) - 1] == '.') {
		tmp[strlen(tmp) - 1] = '\0';
	}
	if (inet_pton(AF_INET, tmp, &addr) == 1 ||
	    inet_pton(AF_INET6, tmp, &addr6) == 1)
	{
		return false;
	}

	return true;
}

static isc_result_t
fromtext_mx(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_fixedname_t fn;
	dns_name_t *name = dns_fixedname_initname(&fn);
	isc_buffer_t buffer;
	bool ok;

	REQUIRE(type == dns_rdatatype_mx);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_string,
				      false));

	ok = true;
	if ((options & DNS_RDATA_CHECKMX) != 0) {
		ok = check_mx(&token);
	}
	if (!ok && (options & DNS_RDATA_CHECKMXFAIL) != 0) {
		RETTOK(DNS_R_MXISADDRESS);
	}
	if (!ok && callbacks != NULL) {
		warn_badmx(&token, lexer, callbacks);
	}

	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_fromtext(name, &buffer, origin, options));
	RETTOK(dns_name_towire(name, NULL, target));
	ok = true;
	if ((options & DNS_RDATA_CHECKNAMES) != 0) {
		ok = dns_name_ishostname(name, false);
	}
	if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
		RETTOK(DNS_R_BADNAME);
	}
	if (!ok && callbacks != NULL) {
		warn_badname(name, lexer, callbacks);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
totext_mx(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	unsigned int opts;
	char buf[sizeof("64000")];
	unsigned short num;

	REQUIRE(rdata->type == dns_rdatatype_mx);
	REQUIRE(rdata->length != 0);

	dns_name_init(&name);
	dns_name_init(&prefix);

	dns_rdata_toregion(rdata, &region);
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	snprintf(buf, sizeof(buf), "%u", num);
	RETERR(str_totext(buf, target));

	RETERR(str_totext(" ", target));

	dns_name_fromregion(&name, &region);
	opts = name_prefix(&name, tctx->origin, &prefix) ? DNS_NAME_OMITFINALDOT
							 : 0;
	return dns_name_totext(&prefix, opts, target);
}

static isc_result_t
fromwire_mx(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t sregion;

	REQUIRE(type == dns_rdatatype_mx);

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, true);

	dns_name_init(&name);

	isc_buffer_activeregion(source, &sregion);
	if (sregion.length < 2) {
		return ISC_R_UNEXPECTEDEND;
	}
	RETERR(mem_tobuffer(target, sregion.base, 2));
	isc_buffer_forward(source, 2);
	return dns_name_fromwire(&name, source, dctx, target);
}

static isc_result_t
towire_mx(ARGS_TOWIRE) {
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mx);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);

	return dns_name_towire(&name, cctx, target);
}

static int
compare_mx(ARGS_COMPARE) {
	dns_name_t name1;
	dns_name_t name2;
	isc_region_t region1;
	isc_region_t region2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_mx);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	order = memcmp(rdata1->data, rdata2->data, 2);
	if (order != 0) {
		return order < 0 ? -1 : 1;
	}

	dns_name_init(&name1);
	dns_name_init(&name2);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	isc_region_consume(&region1, 2);
	isc_region_consume(&region2, 2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	return dns_name_rdatacompare(&name1, &name2);
}

static isc_result_t
fromstruct_mx(ARGS_FROMSTRUCT) {
	dns_rdata_mx_t *mx = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_mx);
	REQUIRE(mx != NULL);
	REQUIRE(mx->common.rdtype == type);
	REQUIRE(mx->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint16_tobuffer(mx->pref, target));
	dns_name_toregion(&mx->mx, &region);
	return isc_buffer_copyregion(target, &region);
}

static isc_result_t
tostruct_mx(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_mx_t *mx = target;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mx);
	REQUIRE(mx != NULL);
	REQUIRE(rdata->length != 0);

	mx->common.rdclass = rdata->rdclass;
	mx->common.rdtype = rdata->type;

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	mx->pref = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);
	dns_name_init(&mx->mx);
	name_duporclone(&name, mctx, &mx->mx);
	mx->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_mx(ARGS_FREESTRUCT) {
	dns_rdata_mx_t *mx = source;

	REQUIRE(mx != NULL);
	REQUIRE(mx->common.rdtype == dns_rdatatype_mx);

	if (mx->mctx == NULL) {
		return;
	}

	dns_name_free(&mx->mx, mx->mctx);
	mx->mctx = NULL;
}

static unsigned char port25_ndata[] = "\003_25\004_tcp";
static dns_name_t port25 = DNS_NAME_INITNONABSOLUTE(port25_ndata);

static isc_result_t
additionaldata_mx(ARGS_ADDLDATA) {
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t name;
	isc_region_t region;

	REQUIRE(rdata->type == dns_rdatatype_mx);

	UNUSED(owner);

	dns_name_init(&name);
	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);

	if (dns_name_equal(&name, dns_rootname)) {
		return ISC_R_SUCCESS;
	}

	result = (add)(arg, &name, dns_rdatatype_a, NULL DNS__DB_FILELINE);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	dns_fixedname_init(&fixed);
	result = dns_name_concatenate(&port25, &name,
				      dns_fixedname_name(&fixed));
	if (result != ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	return (add)(arg, dns_fixedname_name(&fixed), dns_rdatatype_tlsa,
		     NULL DNS__DB_FILELINE);
}

static isc_result_t
digest_mx(ARGS_DIGEST) {
	isc_region_t r1, r2;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mx);

	dns_rdata_toregion(rdata, &r1);
	r2 = r1;
	isc_region_consume(&r2, 2);
	r1.length = 2;
	RETERR((digest)(arg, &r1));
	dns_name_init(&name);
	dns_name_fromregion(&name, &r2);
	return dns_name_digest(&name, digest, arg);
}

static bool
checkowner_mx(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_mx);

	UNUSED(type);
	UNUSED(rdclass);

	return dns_name_ishostname(name, wildcard);
}

static bool
checknames_mx(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_mx);

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 2);
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return false;
	}
	return true;
}

static int
casecompare_mx(ARGS_COMPARE) {
	return compare_mx(rdata1, rdata2);
}

#endif /* RDATA_GENERIC_MX_15_C */
