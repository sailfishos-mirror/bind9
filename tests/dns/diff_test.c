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

/* sched.h must be imported before cmocka to avoid redefinition errors */
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include "isc/list.h"

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/lib.h>

#include <dns/diff.h>
#include <dns/lib.h>

#include <tests/dns.h>

unsigned char data_1[] = "\006name_1";
dns_name_t name_1 = DNS_NAME_INITABSOLUTE(data_1);

unsigned char data_2[] = "\006name_2";
dns_name_t name_2 = DNS_NAME_INITABSOLUTE(data_2);

unsigned char data_3[] = "\006name_3";
dns_name_t name_3 = DNS_NAME_INITABSOLUTE(data_3);

unsigned char data_dup[] = "\006name_1";
dns_name_t name_dup = DNS_NAME_INITABSOLUTE(data_dup);

unsigned char data_nodup[] = "\006name_1";
dns_name_t name_nodup = DNS_NAME_INITABSOLUTE(data_nodup);

static size_t
count_elements(dns_diff_t *diff) {
	size_t count = 0;

	ISC_LIST_FOREACH(diff->tuples, ot, link) {
		++count;
	}

	return count;
}

static void
prepare_rdata(dns_rdata_t *rdata, unsigned char *dest, size_t dest_size) {
	dns_rdataclass_t rdclass = dns_rdataclass_in;
	dns_rdatatype_t type = dns_rdatatype_wallet;
	const char text[] = "cid-example wid-example";

	*rdata = (dns_rdata_t)DNS_RDATA_INIT;
	isc_result_t result = dns_test_rdatafromstring(
		rdata, rdclass, type, dest, dest_size, text, false);
	INSIST(result == ISC_R_SUCCESS);
}

ISC_RUN_TEST_IMPL(dns_diff_size) {
	dns_diff_t diff;
	dns_diff_init(isc_g_mctx, &diff);

	assert_true(dns_diff_size(&diff) == 0);

	dns_rdata_t rdatas[5] = { 0 };
	unsigned char bufs[sizeof(rdatas) / sizeof(*rdatas)][128] = { 0 };
	size_t buf_len = sizeof(bufs[0]);

	for (size_t idx = 0; idx < sizeof(rdatas) / sizeof(*rdatas); ++idx) {
		prepare_rdata(&rdatas[idx], bufs[idx], buf_len);
	}

	dns_difftuple_t *tup_1 = NULL, *tup_2 = NULL, *tup_3 = NULL;
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_ADD, &name_1, 1, &rdatas[0],
			     &tup_1);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_2, 1, &rdatas[1],
			     &tup_2);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_3, 1, &rdatas[2],
			     &tup_3);

	dns_difftuple_t *tup_dup = NULL, *tup_nodup = NULL;
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_DEL, &name_dup, 1,
			     &rdatas[3], &tup_dup);
	dns_difftuple_create(isc_g_mctx, DNS_DIFFOP_ADD, &name_nodup, 1,
			     &rdatas[4], &tup_nodup);

	dns_diff_append(&diff, &tup_1);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_append(&diff, &tup_2);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_appendminimal(&diff, &tup_dup);
	assert_true(dns_diff_size(&diff) == 1);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_append(&diff, &tup_3);
	assert_true(dns_diff_size(&diff) == 2);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_appendminimal(&diff, &tup_nodup);
	assert_true(dns_diff_size(&diff) == 3);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_diff_clear(&diff);
	assert_true(dns_diff_size(&diff) == 0);
	assert_true(dns_diff_size(&diff) == count_elements(&diff));

	dns_difftuple_t *to_clear[] = { tup_1, tup_2, tup_3, tup_dup,
					tup_nodup };
	size_t to_clear_size = sizeof(to_clear) / sizeof(*to_clear);

	for (size_t idx = 0; idx < to_clear_size; ++idx) {
		if (to_clear[idx] != NULL) {
			dns_difftuple_free(&to_clear[idx]);
		}
	}
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY(dns_diff_size)
ISC_TEST_LIST_END

ISC_TEST_MAIN
