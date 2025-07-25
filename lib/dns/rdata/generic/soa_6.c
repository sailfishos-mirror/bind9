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

#ifndef RDATA_GENERIC_SOA_6_C
#define RDATA_GENERIC_SOA_6_C

#define RRTYPE_SOA_ATTRIBUTES (DNS_RDATATYPEATTR_SINGLETON)

static isc_result_t
fromtext_soa(ARGS_FROMTEXT) {
	isc_token_t token;
	isc_buffer_t buffer;
	int i;
	uint32_t n;
	bool ok;

	REQUIRE(type == dns_rdatatype_soa);

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	if (origin == NULL) {
		origin = dns_rootname;
	}

	for (i = 0; i < 2; i++) {
		dns_fixedname_t fn;
		dns_name_t *name = dns_fixedname_initname(&fn);

		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, false));

		buffer_fromregion(&buffer, &token.value.as_region);
		RETTOK(dns_name_fromtext(name, &buffer, origin, options));
		RETTOK(dns_name_towire(name, NULL, target));
		ok = true;
		if ((options & DNS_RDATA_CHECKNAMES) != 0) {
			switch (i) {
			case 0:
				ok = dns_name_ishostname(name, false);
				break;
			case 1:
				ok = dns_name_ismailbox(name);
				break;
			}
		}
		if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
			RETTOK(DNS_R_BADNAME);
		}
		if (!ok && callbacks != NULL) {
			warn_badname(name, lexer, callbacks);
		}
	}

	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	RETERR(uint32_tobuffer(token.value.as_ulong, target));

	for (i = 0; i < 4; i++) {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_string, false));
		RETTOK(dns_counter_fromtext(&token.value.as_textregion, &n));
		RETERR(uint32_tobuffer(n, target));
	}

	return ISC_R_SUCCESS;
}

static const char *soa_fieldnames[5] = { "serial", "refresh", "retry", "expire",
					 "minimum" };

static isc_result_t
totext_soa(ARGS_TOTEXT) {
	isc_region_t dregion;
	dns_name_t mname;
	dns_name_t rname;
	dns_name_t prefix;
	unsigned int opts;
	int i;
	bool multiline;
	bool comm;

	REQUIRE(rdata->type == dns_rdatatype_soa);
	REQUIRE(rdata->length != 0);

	multiline = ((tctx->flags & DNS_STYLEFLAG_MULTILINE) != 0);
	if (multiline) {
		comm = ((tctx->flags & DNS_STYLEFLAG_RRCOMMENT) != 0);
	} else {
		comm = false;
	}

	dns_name_init(&mname);
	dns_name_init(&rname);
	dns_name_init(&prefix);

	dns_rdata_toregion(rdata, &dregion);

	dns_name_fromregion(&mname, &dregion);
	isc_region_consume(&dregion, name_length(&mname));

	dns_name_fromregion(&rname, &dregion);
	isc_region_consume(&dregion, name_length(&rname));

	opts = name_prefix(&mname, tctx->origin, &prefix)
		       ? DNS_NAME_OMITFINALDOT
		       : 0;
	RETERR(dns_name_totext(&prefix, opts, target));

	RETERR(str_totext(" ", target));

	opts = name_prefix(&rname, tctx->origin, &prefix)
		       ? DNS_NAME_OMITFINALDOT
		       : 0;
	RETERR(dns_name_totext(&prefix, opts, target));

	if (multiline) {
		RETERR(str_totext(" (", target));
	}
	RETERR(str_totext(tctx->linebreak, target));

	for (i = 0; i < 5; i++) {
		char buf[sizeof("0123456789 ; ")];
		unsigned long num;
		num = uint32_fromregion(&dregion);
		isc_region_consume(&dregion, 4);
		snprintf(buf, sizeof(buf), comm ? "%-10lu ; " : "%lu", num);
		RETERR(str_totext(buf, target));
		if (comm) {
			RETERR(str_totext(soa_fieldnames[i], target));
			/* Print times in week/day/hour/minute/second form */
			if (i >= 1) {
				RETERR(str_totext(" (", target));
				RETERR(dns_ttl_totext(num, true, true, target));
				RETERR(str_totext(")", target));
			}
			RETERR(str_totext(tctx->linebreak, target));
		} else if (i < 4) {
			RETERR(str_totext(tctx->linebreak, target));
		}
	}

	if (multiline) {
		RETERR(str_totext(")", target));
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
fromwire_soa(ARGS_FROMWIRE) {
	dns_name_t mname;
	dns_name_t rname;
	isc_region_t sregion;
	isc_region_t tregion;

	REQUIRE(type == dns_rdatatype_soa);

	UNUSED(type);
	UNUSED(rdclass);

	dctx = dns_decompress_setpermitted(dctx, true);

	dns_name_init(&mname);
	dns_name_init(&rname);

	RETERR(dns_name_fromwire(&mname, source, dctx, target));
	RETERR(dns_name_fromwire(&rname, source, dctx, target));

	isc_buffer_activeregion(source, &sregion);
	isc_buffer_availableregion(target, &tregion);

	if (sregion.length < 20) {
		return ISC_R_UNEXPECTEDEND;
	}
	if (tregion.length < 20) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 20);
	isc_buffer_forward(source, 20);
	isc_buffer_add(target, 20);

	return ISC_R_SUCCESS;
}

static isc_result_t
towire_soa(ARGS_TOWIRE) {
	isc_region_t sregion;
	isc_region_t tregion;
	dns_name_t mname;
	dns_name_t rname;

	REQUIRE(rdata->type == dns_rdatatype_soa);
	REQUIRE(rdata->length != 0);

	dns_compress_setpermitted(cctx, true);

	dns_name_init(&mname);
	dns_name_init(&rname);

	dns_rdata_toregion(rdata, &sregion);

	dns_name_fromregion(&mname, &sregion);
	isc_region_consume(&sregion, name_length(&mname));
	RETERR(dns_name_towire(&mname, cctx, target));

	dns_name_fromregion(&rname, &sregion);
	isc_region_consume(&sregion, name_length(&rname));
	RETERR(dns_name_towire(&rname, cctx, target));

	isc_buffer_availableregion(target, &tregion);
	if (tregion.length < 20) {
		return ISC_R_NOSPACE;
	}

	memmove(tregion.base, sregion.base, 20);
	isc_buffer_add(target, 20);
	return ISC_R_SUCCESS;
}

static int
compare_soa(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;
	dns_name_t name1;
	dns_name_t name2;
	int order;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_soa);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_name_init(&name1);
	dns_name_init(&name2);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0) {
		return order;
	}

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	dns_name_init(&name1);
	dns_name_init(&name2);

	dns_name_fromregion(&name1, &region1);
	dns_name_fromregion(&name2, &region2);

	order = dns_name_rdatacompare(&name1, &name2);
	if (order != 0) {
		return order;
	}

	isc_region_consume(&region1, name_length(&name1));
	isc_region_consume(&region2, name_length(&name2));

	return isc_region_compare(&region1, &region2);
}

static isc_result_t
fromstruct_soa(ARGS_FROMSTRUCT) {
	dns_rdata_soa_t *soa = source;
	isc_region_t region;

	REQUIRE(type == dns_rdatatype_soa);
	REQUIRE(soa != NULL);
	REQUIRE(soa->common.rdtype == type);
	REQUIRE(soa->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	dns_name_toregion(&soa->origin, &region);
	RETERR(isc_buffer_copyregion(target, &region));
	dns_name_toregion(&soa->contact, &region);
	RETERR(isc_buffer_copyregion(target, &region));
	RETERR(uint32_tobuffer(soa->serial, target));
	RETERR(uint32_tobuffer(soa->refresh, target));
	RETERR(uint32_tobuffer(soa->retry, target));
	RETERR(uint32_tobuffer(soa->expire, target));
	return uint32_tobuffer(soa->minimum, target);
}

static isc_result_t
tostruct_soa(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_soa_t *soa = target;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_soa);
	REQUIRE(soa != NULL);
	REQUIRE(rdata->length != 0);

	soa->common.rdclass = rdata->rdclass;
	soa->common.rdtype = rdata->type;

	dns_rdata_toregion(rdata, &region);

	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	dns_name_init(&soa->origin);
	name_duporclone(&name, mctx, &soa->origin);

	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	dns_name_init(&soa->contact);
	name_duporclone(&name, mctx, &soa->contact);

	soa->serial = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->refresh = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->retry = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->expire = uint32_fromregion(&region);
	isc_region_consume(&region, 4);

	soa->minimum = uint32_fromregion(&region);

	soa->mctx = mctx;
	return ISC_R_SUCCESS;
}

static void
freestruct_soa(ARGS_FREESTRUCT) {
	dns_rdata_soa_t *soa = source;

	REQUIRE(soa != NULL);
	REQUIRE(soa->common.rdtype == dns_rdatatype_soa);

	if (soa->mctx == NULL) {
		return;
	}

	dns_name_free(&soa->origin, soa->mctx);
	dns_name_free(&soa->contact, soa->mctx);
	soa->mctx = NULL;
}

static isc_result_t
additionaldata_soa(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_soa);

	UNUSED(rdata);
	UNUSED(owner);
	UNUSED(add);
	UNUSED(arg);

	return ISC_R_SUCCESS;
}

static isc_result_t
digest_soa(ARGS_DIGEST) {
	isc_region_t r;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_soa);

	dns_rdata_toregion(rdata, &r);

	dns_name_init(&name);
	dns_name_fromregion(&name, &r);
	RETERR(dns_name_digest(&name, digest, arg));
	isc_region_consume(&r, name_length(&name));

	dns_name_init(&name);
	dns_name_fromregion(&name, &r);
	RETERR(dns_name_digest(&name, digest, arg));
	isc_region_consume(&r, name_length(&name));

	return (digest)(arg, &r);
}

static bool
checkowner_soa(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_soa);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return true;
}

static bool
checknames_soa(ARGS_CHECKNAMES) {
	isc_region_t region;
	dns_name_t name;

	REQUIRE(rdata->type == dns_rdatatype_soa);

	UNUSED(owner);

	dns_rdata_toregion(rdata, &region);
	dns_name_init(&name);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return false;
	}
	isc_region_consume(&region, name_length(&name));
	dns_name_fromregion(&name, &region);
	if (!dns_name_ismailbox(&name)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return false;
	}
	return true;
}

static int
casecompare_soa(ARGS_COMPARE) {
	return compare_soa(rdata1, rdata2);
}

#endif /* RDATA_GENERIC_SOA_6_C */
