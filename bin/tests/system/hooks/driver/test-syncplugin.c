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

typedef struct {
	isc_mem_t *mctx;
	uint8_t rcode;

	/*
	 * Plugin will bails out without altering the response if qname first
	 * label matches `firstlbl`.
	 */
	char *firstlbl;
} syncplugin_t;

#define CHECK(op)                              \
	do {                                   \
		result = (op);                 \
		if (result != ISC_R_SUCCESS) { \
			goto cleanup;          \
		}                              \
	} while (0)

static ns_hookresult_t
syncplugin__hook(void *arg, void *cbdata, isc_result_t *resp) {
	query_ctx_t *qctx = (query_ctx_t *)arg;
	syncplugin_t *inst = cbdata;

	UNUSED(resp);

	if (inst->firstlbl != NULL) {
		const dns_name_t *qname = qctx->client->query.qname;
		dns_label_t label;

		dns_name_getlabel(qname, 0, &label);

		/*
		 * +1 because the first label byte is the length of the label
		 * itself
		 */
		if (strncmp(inst->firstlbl, (char *)label.base + 1,
			    strlen(inst->firstlbl)) == 0)
		{
			return NS_HOOK_CONTINUE;
		}
	}

	qctx->client->message->rcode = inst->rcode;
	*resp = ns_query_done(qctx);
	return NS_HOOK_RETURN;
}

static cfg_clausedef_t syncplugin__cfgclauses[] = {
	{ "rcode", &cfg_type_astring, 0 },
	{ "firstlbl", &cfg_type_qstring, CFG_CLAUSEFLAG_OPTIONAL }
};

static cfg_clausedef_t *syncplugin__cfgparamsclausesets[] = {
	syncplugin__cfgclauses, NULL
};

static cfg_type_t syncplugin__cfgparams = {
	"syncplugin-params", cfg_parse_mapbody, cfg_print_mapbody,
	cfg_doc_mapbody,     &cfg_rep_map,	syncplugin__cfgparamsclausesets
};

static isc_result_t
syncplugin__parse_rcode(const cfg_obj_t *syncplugincfg, uint8_t *rcode) {
	isc_result_t result;
	const cfg_obj_t *obj = NULL;
	const char *rcodestr = NULL;

	result = cfg_map_get(syncplugincfg, "rcode", &obj);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	rcodestr = obj->value.string.base;

	if (strcmp("servfail", rcodestr) == 0) {
		*rcode = dns_rcode_servfail;
	} else if (strcmp("notimp", rcodestr) == 0) {
		*rcode = dns_rcode_notimp;
	} else if (strcmp("noerror", rcodestr) == 0) {
		*rcode = dns_rcode_noerror;
	} else if (strcmp("notauth", rcodestr) == 0) {
		*rcode = dns_rcode_notauth;
	} else if (strcmp("notzone", rcodestr) == 0) {
		*rcode = dns_rcode_notzone;
	} else {
		result = ISC_R_FAILURE;
	}

	return result;
}

isc_result_t
plugin_register(const char *parameters, const void *cfg, const char *cfgfile,
		unsigned long cfgline, isc_mem_t *mctx, void *actx,
		ns_hooktable_t *hooktable, void **instp) {
	isc_result_t result;
	cfg_parser_t *parser = NULL;
	cfg_obj_t *syncplugincfg = NULL;
	const cfg_obj_t *obj = NULL;
	isc_buffer_t b;
	ns_hook_t hook;
	syncplugin_t *inst = NULL;

	UNUSED(cfg);
	UNUSED(actx);

	inst = isc_mem_get(mctx, sizeof(*inst));
	*inst = (syncplugin_t){ .mctx = mctx };
	*instp = inst;

	CHECK(cfg_parser_create(mctx, &parser));

	isc_buffer_constinit(&b, parameters, strlen(parameters));
	isc_buffer_add(&b, strlen(parameters));

	CHECK(cfg_parse_buffer(parser, &b, cfgfile, cfgline,
			       &syncplugin__cfgparams, 0, &syncplugincfg));

	CHECK(syncplugin__parse_rcode(syncplugincfg, &inst->rcode));

	if (cfg_map_get(syncplugincfg, "firstlbl", &obj) == ISC_R_SUCCESS) {
		const char *firstlbl = cfg_obj_asstring(obj);
		size_t len = strlen(firstlbl) + 1;

		inst->firstlbl = isc_mem_allocate(mctx, len);
		strncpy(inst->firstlbl, firstlbl, len);
	}

	hook = (ns_hook_t){ .action = syncplugin__hook, .action_data = inst };
	ns_hook_add(hooktable, mctx, NS_QUERY_NXDOMAIN_BEGIN, &hook);

cleanup:
	if (syncplugincfg != NULL) {
		cfg_obj_destroy(parser, &syncplugincfg);
	}

	if (parser != NULL) {
		cfg_parser_destroy(&parser);
	}

	return result;
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
	syncplugin_t *inst = *instp;
	isc_mem_t *mctx = inst->mctx;

	if (inst->firstlbl != NULL) {
		isc_mem_free(mctx, inst->firstlbl);
	}

	isc_mem_put(mctx, inst, sizeof(*inst));
	*instp = NULL;
}

int
plugin_version(void) {
	return NS_PLUGIN_VERSION;
}
