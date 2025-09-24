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

#include <isccfg/cfg.h>

#define ISCCFG_KASPCONF_CHECK_ALGORITHMS 0x01
#define ISCCFG_KASPCONF_CHECK_KEYLIST	 0x02
#define ISCCFG_KASPCONF_LOG_ERRORS	 0x04

/***
 *** Functions
 ***/

isc_result_t
cfg_kasp_fromconfig(const cfg_obj_t *config, dns_kasp_t *default_kasp,
		    unsigned int options, isc_mem_t *mctx,
		    dns_keystorelist_t *keystorelist, dns_kasplist_t *kasplist,
		    dns_kasp_t **kaspp);
/*%<
 * Create and configure a KASP. If 'default_kasp' is not NULL, the built-in
 * default configuration is used to set values that are not explicitly set in
 * the policy.
 *
 * If a 'kasplist' is provided, a lookup happens and if a KASP already exists
 * with the same name, no new KASP is created, and no attach to 'kaspp' happens.
 *
 * The 'keystorelist' is where to lookup key stores if KASP keys are using them.
 *
 * If 'options' has ISCCFG_KASPCONF_CHECK_ALGORITHMS set, then the dnssec-policy
 * DNSSEC key algorithms are checked against those supported by the crypto
 * provider.
 *
 * If 'options' has ISCCFG_KASPCONF_CHECK_KEYLIST set, then this function
 * insists that the key list is not empty, unless the policy is "insecure"
 * (then the key list must be empty).
 *
 * If 'options' has ISCCFG_KASPCONF_LOG_ERRORS set, then configuration errors
 * and warnings are logged to the global logging context.
 *
 * Requires:
 *
 *\li  'name' is either NULL, or a valid C string.
 *
 *\li  'mctx' is a valid memory context.
 *
 *\li  'logctx' is a valid logging context.
 *
 *\li  kaspp != NULL && *kaspp == NULL
 *
 * Returns:
 *
 *\li  #ISC_R_SUCCESS  If creating and configuring the KASP succeeds.
 *\li  #ISC_R_EXISTS   If 'kasplist' already has a kasp structure with 'name'.
 *
 *\li  Other errors are possible.
 */

isc_result_t
cfg_keystore_fromconfig(const cfg_obj_t *config, isc_mem_t *mctx,
			dns_keystorelist_t *keystorelist,
			dns_keystore_t	  **kspp);
/*%<
 * Create and configure a key store. If a 'keystorelist' is provided, a lookup
 * happens and if a keystore already exists with the same name, no new one is
 * created, and no attach to 'kspp' happens.
 *
 * Requires:
 *
 *\li  config != NULL

 *\li  'mctx' is a valid memory context.
 *
 *\li  'logctx' is a valid logging context.
 *
 *\li  kspp == NULL || *kspp == NULL
 *
 * Returns:
 *
 *\li  #ISC_R_SUCCESS  If creating and configuring the keystore succeeds.
 *\li  #ISC_R_EXISTS   If 'keystorelist' already has a keystore with 'name'.
 *
 *\li  Other errors are possible.
 */
