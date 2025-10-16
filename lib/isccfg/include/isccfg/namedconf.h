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

/*! \file isccfg/namedconf.h
 * \brief
 * This module defines the named.conf, rndc.conf, and rndc.key grammars.
 */

#include <isccfg/cfg.h>

/*
 * Configuration object types.
 */
extern cfg_type_t cfg_type_namedconf;
/*%< A complete named.conf file. */

extern cfg_type_t cfg_type_bindkeys;
/*%< A bind.keys file. */

extern cfg_type_t cfg_type_addzoneconf;
/*%< A single zone passed via the addzone rndc command. */

extern cfg_type_t cfg_type_rndcconf;
/*%< A complete rndc.conf file. */

extern cfg_type_t cfg_type_rndckey;
/*%< A complete rndc.key file. */

extern cfg_type_t cfg_type_sessionkey;
/*%< A complete session.key file. */

extern cfg_type_t cfg_type_keyref;
/*%< A key reference, used as an ACL element */

/*%< Zone options */
extern cfg_type_t cfg_type_zoneopts;

/*%< DNSSEC Key and Signing Policy options */
extern cfg_type_t cfg_type_dnssecpolicyopts;

/*%<
 * Build the effective configuration, by cloning the user configuration then
 * applying (merging) the default configuration on top of it (based on various
 * specific rules regarding how a default statement is used/overridden when the
 * user provides it, and possibly how some user provided statement might be
 * internally changed).
 */
cfg_obj_t *
cfg_effective_config(const cfg_obj_t *userconfig,
		     const cfg_obj_t *defaultconfig);
