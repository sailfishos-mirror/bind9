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

#include <isccfg/cfg.h>

void
named_tkeyctx_fromconfig(const cfg_obj_t *options, isc_mem_t *mctx,
			 dns_tkeyctx_t **tctxp);
/*%<
 * 	Create a TKEY context and configure it, according to 'options'.
 *
 *	Requires:
 *\li		'cfg' is a valid configuration options object.
 *\li		'mctx' is not NULL
 *\li		'tctxp' is not NULL
 *\li		'*tctxp' is NULL
 */
