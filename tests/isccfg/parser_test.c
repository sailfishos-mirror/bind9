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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UNIT_TESTING
#include <cmocka.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/lib.h>
#include <isc/log.h>
#include <isc/mem.h>
#include <isc/string.h>
#include <isc/types.h>
#include <isc/util.h>

#include <isccfg/cfg.h>
#include <isccfg/grammar.h>
#include <isccfg/namedconf.h>

#include <tests/isc.h>

ISC_SETUP_TEST_IMPL(group) {
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(
		logconfig, "default_stderr", ISC_LOG_TOFILEDESC,
		ISC_LOG_DYNAMIC, ISC_LOGDESTINATION_STDERR, 0,
		ISC_LOGCATEGORY_DEFAULT, ISC_LOGMODULE_DEFAULT);

	return 0;
}

/* mimic calling nzf_append() */
static void
append(void *arg, const char *str, int len) {
	char *buf = arg;
	size_t l = strlen(buf);
	snprintf(buf + l, 1024 - l, "%.*s", len, str);
}

ISC_RUN_TEST_IMPL(addzoneconf) {
	isc_result_t result;
	isc_buffer_t b;
	const char *tests[] = {
		"zone \"test4.baz\" { type primary; file \"e.db\"; };",
		"zone \"test/.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\\".baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\\\.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\032.baz\" { type primary; file \"e.db\"; };",
		"zone \"test\\010.baz\" { type primary; file \"e.db\"; };"
	};
	char buf[1024];

	/* Parse with default line numbering */
	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		cfg_obj_t *conf = NULL;
		const cfg_obj_t *obj = NULL, *zlist = NULL;

		isc_buffer_constinit(&b, tests[i], strlen(tests[i]));
		isc_buffer_add(&b, strlen(tests[i]));

		result = cfg_parse_buffer(isc_g_mctx, &b, "text1", 0,
					  &cfg_type_namedconf, 0, &conf);
		assert_int_equal(result, ISC_R_SUCCESS);

		/*
		 * Mimic calling nzf_append() from bin/named/server.c
		 * and check that the output matches the input.
		 */
		result = cfg_map_get(conf, "zone", &zlist);
		assert_int_equal(result, ISC_R_SUCCESS);

		obj = cfg_listelt_value(cfg_list_first(zlist));
		assert_ptr_not_equal(obj, NULL);

		strlcpy(buf, "zone ", sizeof(buf));
		cfg_printx(obj, CFG_PRINTER_ONELINE, append, buf);
		strlcat(buf, ";", sizeof(buf));
		assert_string_equal(tests[i], buf);

		cfg_obj_detach(&conf);
	}
}

/* test cfg_parse_buffer() */
ISC_RUN_TEST_IMPL(parse_buffer) {
	isc_result_t result;
	int fresult;
	unsigned char text[] = "options\n{\nidonotexists yes;\n};\n";
	char logfilebuf[512];
	size_t logfilelen;
	isc_buffer_t buf;
	cfg_obj_t *c = NULL;

	/*
	 * Redirect parser errors into a specific file for checking the output
	 * later.
	 */
	constexpr char logfilename[] = "./cfglog.out";
	FILE *logfile = fopen(logfilename, "w+");
	assert_non_null(logfile);

	isc_logdestination_t *logdest = ISC_LOGDESTINATION_FILE(logfile);
	isc_logconfig_t *logconfig = isc_logconfig_get();
	isc_log_createandusechannel(logconfig, "default_stderr",
				    ISC_LOG_TOFILEDESC, ISC_LOG_DYNAMIC,
				    logdest, 0, ISC_LOGCATEGORY_DEFAULT,
				    ISC_LOGMODULE_DEFAULT);

	/* Parse with default line numbering. */
	isc_buffer_init(&buf, &text[0], sizeof(text) - 1);
	isc_buffer_add(&buf, sizeof(text) - 1);
	result = cfg_parse_buffer(isc_g_mctx, &buf, "text1", 0,
				  &cfg_type_namedconf, 0, &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Parse with changed line number. */
	isc_buffer_first(&buf);
	result = cfg_parse_buffer(isc_g_mctx, &buf, "text2", 100,
				  &cfg_type_namedconf, 0, &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Parse with changed line number and no name. */
	isc_buffer_first(&buf);
	result = cfg_parse_buffer(isc_g_mctx, &buf, NULL, 100,
				  &cfg_type_namedconf, 0, &c);
	assert_int_equal(result, ISC_R_FAILURE);
	assert_null(c);

	/* Check log values (and, specifically, line numbers). */
	logfilelen = ftell(logfile);
	assert_in_range(logfilelen, 0, sizeof(logfilebuf));

	fresult = fseek(logfile, 0, SEEK_SET);
	assert_int_equal(fresult, 0);

	fresult = fread(logfilebuf, 1, logfilelen, logfile);
	assert_int_equal(fresult, logfilelen);

	logfilebuf[logfilelen] = 0;

	assert_non_null(
		strstr(logfilebuf, "text1:3: unknown option 'idonotexists'"));
	assert_non_null(
		strstr(logfilebuf, "text2:102: unknown option 'idonotexists'"));
	assert_non_null(
		strstr(logfilebuf, "none:102: unknown option 'idonotexists'"));

	fclose(logfile);
	remove(logfilename);
}

/* test cfg_map_firstclause() */
ISC_RUN_TEST_IMPL(cfg_map_firstclause) {
	const char *name = NULL;
	const void *clauses = NULL;
	unsigned int idx;

	name = cfg_map_firstclause(&cfg_type_zoneopts, &clauses, &idx);
	assert_non_null(name);
	assert_non_null(clauses);
	assert_int_equal(idx, 0);
}

/* test cfg_map_nextclause() */
ISC_RUN_TEST_IMPL(cfg_map_nextclause) {
	const char *name = NULL;
	const void *clauses = NULL;
	unsigned int idx;

	name = cfg_map_firstclause(&cfg_type_zoneopts, &clauses, &idx);
	assert_non_null(name);
	assert_non_null(clauses);
	assert_int_equal(idx, ISC_R_SUCCESS);

	do {
		name = cfg_map_nextclause(&cfg_type_zoneopts, &clauses, &idx);
		if (name != NULL) {
			assert_non_null(clauses);
		} else {
			assert_null(clauses);
			assert_int_equal(idx, 0);
		}
	} while (name != NULL);
}

ISC_TEST_LIST_START

ISC_TEST_ENTRY(addzoneconf)
ISC_TEST_ENTRY(parse_buffer)
ISC_TEST_ENTRY(cfg_map_firstclause)
ISC_TEST_ENTRY(cfg_map_nextclause)

ISC_TEST_LIST_END

ISC_TEST_MAIN_CUSTOM(setup_test_group, NULL)
