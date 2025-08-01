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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <isc/buffer.h>
#include <isc/file.h>
#include <isc/hash.h>
#include <isc/hex.h>
#include <isc/lex.h>
#include <isc/log.h>
#include <isc/managers.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/os.h>
#include <isc/random.h>
#include <isc/result.h>
#include <isc/stdio.h>
#include <isc/string.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/callbacks.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/view.h>
#include <dns/zone.h>

#include <tests/dns.h>

dns_zonemgr_t *zonemgr = NULL;

/*
 * Create a view.
 */
isc_result_t
dns_test_makeview(const char *name, bool with_dispatchmgr, bool with_cache,
		  dns_view_t **viewp) {
	isc_result_t result;
	dns_view_t *view = NULL;
	dns_cache_t *cache = NULL;
	dns_dispatchmgr_t *dispatchmgr = NULL;

	if (with_dispatchmgr) {
		result = dns_dispatchmgr_create(mctx, &dispatchmgr);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	dns_view_create(mctx, dispatchmgr, dns_rdataclass_in, name, &view);

	if (dispatchmgr != NULL) {
		dns_dispatchmgr_detach(&dispatchmgr);
	}

	if (with_cache) {
		result = dns_cache_create(dns_rdataclass_in, "", mctx, &cache);
		if (result != ISC_R_SUCCESS) {
			dns_view_detach(&view);
			return result;
		}

		dns_view_setcache(view, cache, false);
		/*
		 * Reference count for "cache" is now at 2, so decrement it in
		 * order for the cache to be automatically freed when "view"
		 * gets freed.
		 */
		dns_cache_detach(&cache);
	}

	*viewp = view;

	return ISC_R_SUCCESS;
}

isc_result_t
dns_test_makezone(const char *name, dns_zone_t **zonep, dns_view_t *view,
		  bool createview) {
	dns_fixedname_t fixed_origin;
	dns_zone_t *zone = NULL;
	isc_result_t result;
	dns_name_t *origin;

	REQUIRE(view == NULL || !createview);

	/*
	 * Create the zone structure.
	 */
	dns_zone_create(&zone, mctx, 0);

	/*
	 * Set zone type and origin.
	 */
	dns_zone_settype(zone, dns_zone_primary);
	origin = dns_fixedname_initname(&fixed_origin);
	result = dns_name_fromstring(origin, name, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		goto detach_zone;
	}
	dns_zone_setorigin(zone, origin);

	/*
	 * If requested, create a view.
	 */
	if (createview) {
		result = dns_test_makeview("view", false, false, &view);
		if (result != ISC_R_SUCCESS) {
			goto detach_zone;
		}
	}

	/*
	 * If a view was passed as an argument or created above, attach the
	 * created zone to it.  Otherwise, set the zone's class to IN.
	 */
	if (view != NULL) {
		dns_zone_setview(zone, view);
		dns_zone_setclass(zone, view->rdclass);
		dns_view_addzone(view, zone);
	} else {
		dns_zone_setclass(zone, dns_rdataclass_in);
	}

	*zonep = zone;

	return ISC_R_SUCCESS;

detach_zone:
	dns_zone_detach(&zone);

	return result;
}

void
dns_test_setupzonemgr(void) {
	REQUIRE(zonemgr == NULL);

	dns_zonemgr_create(mctx, &zonemgr);
}

isc_result_t
dns_test_managezone(dns_zone_t *zone) {
	isc_result_t result;
	REQUIRE(zonemgr != NULL);

	result = dns_zonemgr_managezone(zonemgr, zone);
	return result;
}

void
dns_test_releasezone(dns_zone_t *zone) {
	REQUIRE(zonemgr != NULL);
	dns_zonemgr_releasezone(zonemgr, zone);
}

void
dns_test_closezonemgr(void) {
	REQUIRE(zonemgr != NULL);

	dns_zonemgr_shutdown(zonemgr);
	dns_zonemgr_detach(&zonemgr);
}

/*
 * Sleep for 'usec' microseconds.
 */
void
dns_test_nap(uint32_t usec) {
	struct timespec ts;

	ts.tv_sec = usec / (long)US_PER_SEC;
	ts.tv_nsec = (usec % (long)US_PER_SEC) * (long)NS_PER_US;
	nanosleep(&ts, NULL);
}

isc_result_t
dns_test_loaddb(dns_db_t **db, dns_dbtype_t dbtype, const char *origin,
		const char *testfile) {
	isc_result_t result;
	dns_fixedname_t fixed;
	dns_name_t *name = NULL;
	const char *dbimp = (dbtype == dns_dbtype_zone) ? ZONEDB_DEFAULT
							: CACHEDB_DEFAULT;

	name = dns_fixedname_initname(&fixed);

	result = dns_name_fromstring(name, origin, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_db_create(mctx, dbimp, name, dbtype, dns_rdataclass_in, 0,
			       NULL, db);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	result = dns_db_load(*db, testfile, dns_masterformat_text, 0);
	return result;
}

static int
fromhex(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}

	printf("bad input format: %02x\n", c);
	exit(3);
}

/*
 * Format contents of given memory region as a hex string, using the buffer
 * of length 'buflen' pointed to by 'buf'. 'buflen' must be at least three
 * times 'len'. Always returns 'buf'.
 */
char *
dns_test_tohex(const unsigned char *data, size_t len, char *buf,
	       size_t buflen) {
	isc_constregion_t source = { .base = data, .length = len };
	isc_buffer_t target;
	isc_result_t result;

	memset(buf, 0, buflen);
	isc_buffer_init(&target, buf, buflen);
	result = isc_hex_totext((isc_region_t *)&source, 1, " ", &target);
	INSIST(result == ISC_R_SUCCESS);

	return buf;
}

isc_result_t
dns_test_getdata(const char *file, unsigned char *buf, size_t bufsiz,
		 size_t *sizep) {
	isc_result_t result;
	unsigned char *bp;
	char *rp, *wp;
	char s[BUFSIZ];
	size_t len, i;
	FILE *f = NULL;
	int n;

	result = isc_stdio_open(file, "r", &f);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	bp = buf;
	while (fgets(s, sizeof(s), f) != NULL) {
		rp = s;
		wp = s;
		len = 0;
		while (*rp != '\0') {
			if (*rp == '#') {
				break;
			}
			if (*rp != ' ' && *rp != '\t' && *rp != '\r' &&
			    *rp != '\n')
			{
				*wp++ = *rp;
				len++;
			}
			rp++;
		}
		if (len == 0U) {
			continue;
		}
		if (len % 2 != 0U) {
			result = ISC_R_UNEXPECTEDEND;
			break;
		}
		if (len > bufsiz * 2) {
			result = ISC_R_NOSPACE;
			break;
		}
		rp = s;
		for (i = 0; i < len; i += 2) {
			n = fromhex(*rp++);
			n *= 16;
			n += fromhex(*rp++);
			*bp++ = n;
		}
	}

	if (result == ISC_R_SUCCESS) {
		*sizep = bp - buf;
	}

	isc_stdio_close(f);
	return result;
}

static void
nullmsg(dns_rdatacallbacks_t *cb, const char *fmt, ...) {
	UNUSED(cb);
	UNUSED(fmt);
}

isc_result_t
dns_test_rdatafromstring(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
			 dns_rdatatype_t rdtype, unsigned char *dst,
			 size_t dstlen, const char *src, bool warnings) {
	dns_rdatacallbacks_t callbacks;
	isc_buffer_t source, target;
	isc_lex_t *lex = NULL;
	isc_lexspecials_t specials = { 0 };
	isc_result_t result;
	size_t length;

	REQUIRE(rdata != NULL);
	REQUIRE(DNS_RDATA_INITIALIZED(rdata));
	REQUIRE(dst != NULL);
	REQUIRE(src != NULL);

	/*
	 * Set up source to hold the input string.
	 */
	length = strlen(src);
	isc_buffer_constinit(&source, src, length);
	isc_buffer_add(&source, length);

	/*
	 * Create a lexer as one is required by dns_rdata_fromtext().
	 */
	isc_lex_create(mctx, 64, &lex);

	/*
	 * Set characters which will be treated as valid multi-line RDATA
	 * delimiters while reading the source string.  These should match
	 * specials from lib/dns/master.c.
	 */
	specials[0] = 1;
	specials['('] = 1;
	specials[')'] = 1;
	specials['"'] = 1;
	isc_lex_setspecials(lex, specials);

	/*
	 * Expect DNS masterfile comments.
	 */
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	/*
	 * Point lexer at source.
	 */
	result = isc_lex_openbuffer(lex, &source);
	if (result != ISC_R_SUCCESS) {
		goto destroy_lexer;
	}

	/*
	 * Set up target for storing uncompressed wire form of provided RDATA.
	 */
	isc_buffer_init(&target, dst, dstlen);

	/*
	 * Set up callbacks so warnings and errors are not printed.
	 */
	if (!warnings) {
		dns_rdatacallbacks_init(&callbacks);
		callbacks.warn = callbacks.error = nullmsg;
	}

	/*
	 * Parse input string, determining result.
	 */
	result = dns_rdata_fromtext(rdata, rdclass, rdtype, lex, dns_rootname,
				    0, mctx, &target, &callbacks);

destroy_lexer:
	isc_lex_destroy(&lex);

	return result;
}

void
dns_test_namefromstring(const char *namestr, dns_fixedname_t *fname) {
	size_t length;
	isc_buffer_t *b = NULL;
	isc_result_t result;
	dns_name_t *name;

	length = strlen(namestr);

	name = dns_fixedname_initname(fname);

	isc_buffer_allocate(mctx, &b, length);

	isc_buffer_putmem(b, (const unsigned char *)namestr, length);
	result = dns_name_fromtext(name, b, NULL, 0);
	INSIST(result == ISC_R_SUCCESS);

	isc_buffer_free(&b);
}

isc_result_t
dns_test_difffromchanges(dns_diff_t *diff, const zonechange_t *changes,
			 bool warnings) {
	isc_result_t result = ISC_R_SUCCESS;
	unsigned char rdata_buf[1024];
	dns_difftuple_t *tuple = NULL;
	isc_consttextregion_t region;
	dns_rdatatype_t rdatatype;
	dns_fixedname_t fixedname;
	dns_rdata_t rdata;
	dns_name_t *name;
	size_t i;

	REQUIRE(diff != NULL);
	REQUIRE(changes != NULL);

	dns_diff_init(mctx, diff);

	for (i = 0; changes[i].owner != NULL; i++) {
		/*
		 * Parse owner name.
		 */
		name = dns_fixedname_initname(&fixedname);
		result = dns_name_fromstring(name, changes[i].owner,
					     dns_rootname, 0, mctx);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Parse RDATA type.
		 */
		region.base = changes[i].type;
		region.length = strlen(changes[i].type);
		result = dns_rdatatype_fromtext(&rdatatype,
						(isc_textregion_t *)&region);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Parse RDATA.
		 */
		dns_rdata_init(&rdata);
		result = dns_test_rdatafromstring(
			&rdata, dns_rdataclass_in, rdatatype, rdata_buf,
			sizeof(rdata_buf), changes[i].rdata, warnings);
		if (result != ISC_R_SUCCESS) {
			break;
		}

		/*
		 * Create a diff tuple for the parsed change and append it to
		 * the diff.
		 */
		dns_difftuple_create(mctx, changes[i].op, name, changes[i].ttl,
				     &rdata, &tuple);
		dns_diff_append(diff, &tuple);
	}

	if (result != ISC_R_SUCCESS) {
		dns_diff_clear(diff);
	}

	return result;
}
