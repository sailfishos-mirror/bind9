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

/*! \file */

#include <isc/types.h>

isc_result_t
named_tsigkeyring_fromconfig(const cfg_obj_t *config, const cfg_obj_t *vconfig,
			     isc_mem_t *mctx, dns_tsigkeyring_t **ringp);
/*%<
 * Create a TSIG key ring and configure it according to the 'key'
 * statements in the global and view configuration objects.
 *
 *	Requires:
 *	\li	'config' is not NULL.
 *	\li	'vconfig' is not NULL.
 *	\li	'mctx' is not NULL
 *	\li	'ringp' is not NULL, and '*ringp' is NULL
 *
 *	Returns:
 *	\li	ISC_R_SUCCESS
 *	\li	DNS_R_BADALG
 *	\li	return codes from dns_name_fromtext()
 */
