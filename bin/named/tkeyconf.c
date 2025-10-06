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

#include <isc/mem.h>

#include <dns/tkey.h>

#include <dst/gssapi.h>

#include <isccfg/cfg.h>

#include <named/tkeyconf.h>

isc_result_t
named_tkeyctx_fromconfig(const cfg_obj_t *options, isc_mem_t *mctx,
			 dns_tkeyctx_t **tctxp) {
	isc_result_t result;
	dns_tkeyctx_t *tctx = NULL;
	const char *s;
	const cfg_obj_t *obj;

	dns_tkeyctx_create(mctx, &tctx);

	obj = NULL;
	result = cfg_map_get(options, "tkey-gssapi-keytab", &obj);
	if (result == ISC_R_SUCCESS) {
		s = cfg_obj_asstring(obj);
		tctx->gssapi_keytab = isc_mem_strdup(mctx, s);
	}

	*tctxp = tctx;
	return ISC_R_SUCCESS;
}
