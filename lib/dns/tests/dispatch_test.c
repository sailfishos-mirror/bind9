/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#if HAVE_CMOCKA

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

#include <isc/app.h>
#include <isc/buffer.h>
#include <isc/refcount.h>
#include <isc/socket.h>
#include <isc/task.h>
#include <isc/util.h>

#include <dns/dispatch.h>
#include <dns/name.h>
#include <dns/view.h>

#include "dnstest.h"

dns_dispatchmgr_t *dispatchmgr = NULL;
dns_dispatchset_t *dset = NULL;

static int
_setup(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = dns_test_begin(NULL, true);
	assert_int_equal(result, ISC_R_SUCCESS);

	return (0);
}

static int
_teardown(void **state) {
	UNUSED(state);

	dns_test_end();

	return (0);
}

static isc_result_t
make_dispatchset(unsigned int ndisps) {
	isc_result_t result;
	isc_sockaddr_t any;
	dns_dispatch_t *disp = NULL;

	result = dns_dispatchmgr_create(dt_mctx, nm, &dispatchmgr);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	isc_sockaddr_any(&any);
	result = dns_dispatch_createudp(dispatchmgr, taskmgr, &any, 0, &disp);
	if (result != ISC_R_SUCCESS) {
		return (result);
	}

	result = dns_dispatchset_create(dt_mctx, taskmgr, disp, &dset, ndisps);
	dns_dispatch_detach(&disp);

	return (result);
}

static void
reset(void) {
	if (dset != NULL) {
		dns_dispatchset_destroy(&dset);
	}
	if (dispatchmgr != NULL) {
		dns_dispatchmgr_destroy(&dispatchmgr);
	}
}

/* create dispatch set */
static void
dispatchset_create(void **state) {
	isc_result_t result;

	UNUSED(state);

	result = make_dispatchset(1);
	assert_int_equal(result, ISC_R_SUCCESS);
	reset();

	result = make_dispatchset(10);
	assert_int_equal(result, ISC_R_SUCCESS);
	reset();
}

/* test dispatch set round-robin */
static void
dispatchset_get(void **state) {
	isc_result_t result;
	dns_dispatch_t *d1, *d2, *d3, *d4, *d5;

	UNUSED(state);

	result = make_dispatchset(1);
	assert_int_equal(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	assert_ptr_equal(d1, d2);
	assert_ptr_equal(d2, d3);
	assert_ptr_equal(d3, d4);
	assert_ptr_equal(d4, d5);

	reset();

	result = make_dispatchset(4);
	assert_int_equal(result, ISC_R_SUCCESS);

	d1 = dns_dispatchset_get(dset);
	d2 = dns_dispatchset_get(dset);
	d3 = dns_dispatchset_get(dset);
	d4 = dns_dispatchset_get(dset);
	d5 = dns_dispatchset_get(dset);

	assert_ptr_equal(d1, d5);
	assert_ptr_not_equal(d1, d2);
	assert_ptr_not_equal(d2, d3);
	assert_ptr_not_equal(d3, d4);
	assert_ptr_not_equal(d4, d5);

	reset();
}

struct {
	isc_nmhandle_t *handle;
	atomic_uint_fast32_t responses;
} testdata;

static dns_dispatch_t *dispatch = NULL;
static dns_dispentry_t *dispentry = NULL;
static atomic_bool first = ATOMIC_VAR_INIT(true);
static isc_sockaddr_t local;

static void
senddone(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	UNUSED(handle);
	UNUSED(eresult);
	UNUSED(cbarg);

	return;
}

static void
nameserver(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	   void *cbarg) {
	isc_region_t response;
	static unsigned char buf1[16];
	static unsigned char buf2[16];

	UNUSED(eresult);
	UNUSED(cbarg);

	memmove(buf1, region->base, 12);
	memset(buf1 + 12, 0, 4);
	buf1[2] |= 0x80; /* qr=1 */

	memmove(buf2, region->base, 12);
	memset(buf2 + 12, 1, 4);
	buf2[2] |= 0x80; /* qr=1 */

	/*
	 * send message to be discarded.
	 */
	response.base = buf1;
	response.length = sizeof(buf1);
	isc_nm_send(handle, &response, senddone, NULL);

	/*
	 * send nextitem message.
	 */
	response.base = buf2;
	response.length = sizeof(buf2);
	isc_nm_send(handle, &response, senddone, NULL);
}

static void
response(isc_task_t *task, isc_event_t *event) {
	dns_dispatchevent_t *devent = (dns_dispatchevent_t *)event;
	bool exp_true = true;

	UNUSED(task);

	atomic_fetch_add_relaxed(&testdata.responses, 1);
	if (atomic_compare_exchange_strong(&first, &exp_true, false)) {
		isc_result_t result = dns_dispatch_getnext(dispentry, &devent);
		assert_int_equal(result, ISC_R_SUCCESS);
	} else {
		dns_dispatch_removeresponse(&dispentry, &devent);
		isc_nmhandle_detach(&testdata.handle);
		isc_app_shutdown();
	}
}

static void
connected(isc_nmhandle_t *handle, isc_result_t eresult, void *cbarg) {
	isc_region_t *r = (isc_region_t *)cbarg;

	UNUSED(eresult);

	isc_nmhandle_attach(handle, &testdata.handle);
	dns_dispatch_send(dispentry, r, -1);
}

static void
startit(isc_task_t *task, isc_event_t *event) {
	UNUSED(task);
	dns_dispatch_connect(dispentry);
	isc_event_free(&event);
}

/* test dispatch getnext */
static void
dispatch_getnext(void **state) {
	isc_result_t result;
	isc_region_t region;
	isc_nmsocket_t *sock = NULL;
	isc_task_t *task = NULL;
	uint16_t id;
	struct in_addr ina;
	unsigned char message[12];
	unsigned char rbuf[12];

	UNUSED(state);

	testdata.handle = NULL;
	atomic_init(&testdata.responses, 0);

	result = isc_task_create(taskmgr, 0, &task);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = dns_dispatchmgr_create(dt_mctx, nm, &dispatchmgr);
	assert_int_equal(result, ISC_R_SUCCESS);

	ina.s_addr = htonl(INADDR_LOOPBACK);
	isc_sockaddr_fromin(&local, &ina, 0);
	result = dns_dispatch_createudp(dispatchmgr, taskmgr, &local, 0,
					&dispatch);
	assert_int_equal(result, ISC_R_SUCCESS);

	/*
	 * Create a local udp nameserver on the loopback.
	 */
	result = isc_nm_listenudp(nm, (isc_nmiface_t *)&local, nameserver, NULL,
				  0, &sock);
	assert_int_equal(result, ISC_R_SUCCESS);

	region.base = rbuf;
	region.length = sizeof(rbuf);
	result = dns_dispatch_addresponse(dispatch, 0, 10000, &local, task,
					  connected, senddone, response, NULL,
					  &region, &id, &dispentry);
	assert_int_equal(result, ISC_R_SUCCESS);

	memset(message, 0, sizeof(message));
	message[0] = (id >> 8) & 0xff;
	message[1] = id & 0xff;

	region.base = message;
	region.length = sizeof(message);

	result = isc_app_onrun(dt_mctx, task, startit, NULL);
	assert_int_equal(result, ISC_R_SUCCESS);

	result = isc_app_run();
	assert_int_equal(result, ISC_R_SUCCESS);

	assert_int_equal(atomic_load_acquire(&testdata.responses), 2);

	/*
	 * Shutdown nameserver.
	 */
	isc_task_detach(&task);

	/*
	 * Shutdown the dispatch.
	 */
	dns_dispatch_detach(&dispatch);
	dns_dispatchmgr_destroy(&dispatchmgr);
}

int
main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(dispatchset_create, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(dispatchset_get, _setup,
						_teardown),
		cmocka_unit_test_setup_teardown(dispatch_getnext, _setup,
						_teardown),
	};

	return (cmocka_run_group_tests(tests, NULL, NULL));
}

#else /* HAVE_CMOCKA */

#include <stdio.h>

int
main(void) {
	printf("1..0 # Skipped: cmocka not available\n");
	return (SKIPPED_TEST_EXIT_CODE);
}

#endif /* if HAVE_CMOCKA */
