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

#include <inttypes.h>
#include <sched.h> /* IWYU pragma: keep */
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/atomic.h>
#include <isc/lib.h>

#include <dns/lib.h>
#include <dns/view.h>

#include <tests/dns.h>

typedef struct {
	const char *name, *input, *expected;
} zonefile_test_params_t;

static int
setup_test(void **state) {
	setup_loopmgr(state);
	return 0;
}

static int
teardown_test(void **state) {
	teardown_loopmgr(state);
	return 0;
}

ISC_LOOP_TEST_IMPL(filename) {
	isc_result_t result;
	dns_zone_t *zone = NULL;
	const zonefile_test_params_t tests[] = {
		{ "example.COM", "$name", "example.com" },
		{ "example.COM", "$name.db", "example.com.db" },
		{ "example.COM", "./dir/$name.db", "./dir/example.com.db" },
		{ "example.COM", "%s", "example.com" },
		{ "example.COM", "%s.db", "example.com.db" },
		{ "example.COM", "./dir/%s.db", "./dir/example.com.db" },
		{ "example.COM", "$type", "primary" },
		{ "example.COM", "$type-file", "primary-file" },
		{ "example.COM", "./dir/$type", "./dir/primary" },
		{ "example.COM", "./$type/$name.db",
		  "./primary/example.com.db" },
		{ "example.COM", "%t", "primary" },
		{ "example.COM", "%t-file", "primary-file" },
		{ "example.COM", "./dir/%t", "./dir/primary" },
		{ "example.COM", "./%t/%s.db", "./primary/example.com.db" },
		{ "example.COM", "./$TyPe/$NAmE.db",
		  "./primary/example.com.db" },
		{ "example.COM", "./$name/$type", "./example.com/primary" },
		{ "example.COM", "$name.$type", "example.com.primary" },
		{ "example.COM", "$type$name", "primaryexample.com" },
		{ "example.COM", "$type$type", "primary$type" },
		{ "example.COM", "$name$name", "example.com$name" },
		{ "example.COM", "typename", "typename" },
		{ "example.COM", "$view", "local" },
		{ "example.COM", "%v", "local" },
		{ "example.COM", "./$type/$view-$name.db",
		  "./primary/local-example.com.db" },
		{ "example.COM", "./$view/$type-$name.db",
		  "./local/primary-example.com.db" },
		{ "example.COM", "./$name/$view-$type.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "./%s/%v-%t.db",
		  "./example.com/local-primary.db" },
		{ "example.COM", "", "" },
		{ "example.COM", "$char1", "e" },
		{ "example.COM", "$char2", "x" },
		{ "example.COM", "$char3", "a" },
		{ "example.COM", "%1", "e" },
		{ "example.COM", "%2", "x" },
		{ "example.COM", "%3", "a" },
		{ "example.COM", "$label1", "com" },
		{ "example.COM", "$label2", "example" },
		{ "example.COM", "$label3", "." },
		{ "example.COM", "%z", "com" },
		{ "example.COM", "%y", "example" },
		{ "example.COM", "%x", "." },
		{ "example", "$label1", "example" },
		{ "example", "$label2", "." },
		{ "example", "$label3", "." },
		{ "a.b.c.d.e", "$label1", "e" },
		{ "a.b.c.d.e", "$label2", "d" },
		{ "a.b.c.d.e", "$label3", "c" },
		{ "a.b.c", "$char1", "a" },
		{ "a.b.c", "$char2", "." },
		{ "a.b.c", "$char3", "b" },
		{ "a.b.c", "%1", "a" },
		{ "a.b.c", "%2", "." },
		{ "a.b.c", "%3", "b" },
		{ "a", "%1", "a" },
		{ "a", "%2", "." },
		{ "a", "%3", "." },
		{ "a.b.c.d", "%1$char2%3$label1%x", "a.bdb" }
	};

	dns_view_t *view = NULL;
	result = dns_test_makeview("local", false, false, &view);
	assert_int_equal(result, ISC_R_SUCCESS);

	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		result = dns_test_makezone(tests[i].name, &zone, view, false);
		assert_int_equal(result, ISC_R_SUCCESS);

		dns_zone_setview(zone, view);
		dns_zone_setfile(zone, tests[i].input, NULL,
				 dns_masterformat_text,
				 &dns_master_style_default);
		assert_string_equal(dns_zone_getfile(zone), tests[i].expected);

		dns_zone_detach(&zone);
	}

	/* use .COM here to test that the name is correctly downcased */
	result = dns_test_makezone("example.COM", &zone, view, false);
	assert_int_equal(result, ISC_R_SUCCESS);

	dns_zone_setview(zone, view);
	dns_view_detach(&view);

	/* test PATH_MAX overrun */
	char longname[PATH_MAX] = { 0 };
	memset(longname, 'x', sizeof(longname) - 1);
	dns_zone_setfile(zone, longname, NULL, dns_masterformat_text,
			 &dns_master_style_default);
	assert_string_equal(dns_zone_getfile(zone), longname);

	/*
	 * overwrite the beginning of the long name with $name. when
	 * it's expanded to the zone name, the resulting string should
	 * still be capped at PATH_MAX characters.
	 */
	memmove(longname, "$name", 5);
	dns_zone_setfile(zone, longname, NULL, dns_masterformat_text,
			 &dns_master_style_default);
	assert_int_equal(strlen(longname), PATH_MAX - 1);
	memmove(longname, "example.com", 11);
	assert_string_equal(dns_zone_getfile(zone), longname);

	dns_zone_detach(&zone);
	isc_loopmgr_shutdown();
}

ISC_TEST_LIST_START
ISC_TEST_ENTRY_CUSTOM(filename, setup_test, teardown_test)
ISC_TEST_LIST_END

ISC_TEST_MAIN
