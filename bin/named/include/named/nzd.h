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

#pragma once

#include <lmdb.h>

#include <isc/buffer.h>
#include <isc/magic.h>
#include <isc/result.h>

#include <dns/view.h>

#define DZARG_MAGIC ISC_MAGIC('D', 'z', 'a', 'r')

typedef struct {
	unsigned int  magic;
	isc_buffer_t *text;
	isc_result_t  result;
} ns_dzarg_t;

isc_result_t
nzd_writable(dns_view_t *view);

isc_result_t
nzd_open(dns_view_t *view, unsigned int flags, MDB_txn **txnp, MDB_dbi *dbi);

isc_result_t
nzd_env_reopen(dns_view_t *view);

void
nzd_env_close(dns_view_t *view);

isc_result_t
nzd_close(MDB_txn **txnp, bool commit);

isc_result_t
nzd_save(MDB_txn **txnp, MDB_dbi dbi, dns_zone_t *zone,
	 const cfg_obj_t *zconfig);

isc_result_t
nzd_load_nzf(dns_view_t *view);

void
nzd_setkey(MDB_val *key, dns_name_t *name, char *namebuf, size_t buflen);
