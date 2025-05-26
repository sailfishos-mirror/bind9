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

#include <isccfg/aclconf.h>
#include <isccfg/cfg.h>
#include <isccfg/grammar.h>

#include <ns/hooks.h>

static ns_hookresult_t
syncplugin_hook(void *arg, void *cbdata, isc_result_t *resp) {
	UNUSED(arg);
	UNUSED(cbdata);
	UNUSED(resp);

	return NS_HOOK_CONTINUE;
}

isc_result_t
plugin_register(const char *parameters, const void *cfg, const char *cfgfile,
		unsigned long cfgline, isc_mem_t *mctx, void *actx,
		ns_hooktable_t *hooktable, void **instp) {
	ns_hook_t hook;

	UNUSED(parameters);
	UNUSED(cfg);
	UNUSED(cfgfile);
	UNUSED(cfgline);
	UNUSED(mctx);
	UNUSED(actx);
	UNUSED(hooktable);
	UNUSED(instp);

	hook = (ns_hook_t){ .action = syncplugin_hook,
			    .action_data = NULL };
	ns_hook_add(hooktable, mctx, NS_QUERY_NODATA_BEGIN, &hook);

	return ISC_R_SUCCESS;
}

isc_result_t
plugin_check(const char *parameters, const void *cfg, const char *cfgfile,
	     unsigned long cfgline, isc_mem_t *mctx, void *actx) {
	UNUSED(parameters);
	UNUSED(cfg);
	UNUSED(cfgfile);
	UNUSED(cfgline);
	UNUSED(mctx);
	UNUSED(actx);

	return ISC_R_SUCCESS;
}

void
plugin_destroy(void **instp) {
	UNUSED(instp);
}

int
plugin_version(void) {
	return NS_PLUGIN_VERSION;
}
