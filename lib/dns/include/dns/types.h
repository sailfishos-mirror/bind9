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

/*! \file dns/types.h
 * \brief
 * Including this file gives you type declarations suitable for use in
 * .h files, which lets us avoid circular type reference problems.
 * \brief
 * To actually use a type or get declarations of its methods, you must
 * include the appropriate .h file too.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include <isc/types.h>

#include <dns/trace.h>

typedef struct dns_acl	       dns_acl_t;
typedef struct dns_aclelement  dns_aclelement_t;
typedef struct dns_aclenv      dns_aclenv_t;
typedef struct dns_adb	       dns_adb_t;
typedef struct dns_adbaddrinfo dns_adbaddrinfo_t;
typedef ISC_LIST(dns_adbaddrinfo_t) dns_adbaddrinfolist_t;
typedef struct dns_adbentry dns_adbentry_t;
typedef struct dns_adbfind  dns_adbfind_t;
typedef ISC_LIST(dns_adbfind_t) dns_adbfindlist_t;
typedef struct dns_badcache	       dns_badcache_t;
typedef struct dns_byaddr	       dns_byaddr_t;
typedef struct dns_catz_zonemodmethods dns_catz_zonemodmethods_t;
typedef struct dns_catz_entry_options  dns_catz_options_t;
typedef struct dns_catz_entry	       dns_catz_entry_t;
typedef struct dns_catz_coo	       dns_catz_coo_t;
typedef struct dns_catz_zone	       dns_catz_zone_t;
typedef struct dns_catz_changed	       dns_catz_changed_t;
typedef struct dns_catz_zones	       dns_catz_zones_t;
typedef struct dns_client	       dns_client_t;
typedef void			       dns_clientrestrans_t;
typedef void			       dns_clientreqtrans_t;
typedef void			       dns_clientupdatetrans_t;
typedef struct dns_cache	       dns_cache_t;
typedef uint16_t		       dns_cert_t;
typedef struct dns_compress	       dns_compress_t;
typedef enum dns_compress_flags	       dns_compress_flags_t;
typedef struct dns_compress_slot       dns_compress_slot_t;
typedef struct dns_db		       dns_db_t;
typedef struct dns_dbimplementation    dns_dbimplementation_t;
typedef struct dns_dbiterator	       dns_dbiterator_t;
typedef void			       dns_dbload_t;
typedef struct dns_dbnode dns_dbnode_t; /* this is dummy struct for proper type
					   checking */
typedef struct dns_dbonupdatelistener dns_dbonupdatelistener_t;
typedef struct dns_dbversion	      dns_dbversion_t;
typedef struct dns_dlzimplementation  dns_dlzimplementation_t;
typedef struct dns_dlzdb	      dns_dlzdb_t;
typedef ISC_LIST(dns_dlzdb_t) dns_dlzdblist_t;
typedef struct dns_dyndbctx	      dns_dyndbctx_t;
typedef struct dns_sdlzimplementation dns_sdlzimplementation_t;
typedef enum dns_decompress	      dns_decompress_t;
typedef struct dns_dispatch	      dns_dispatch_t;
typedef struct dns_dispatchlist	      dns_dispatchlist_t;
typedef struct dns_dispatchset	      dns_dispatchset_t;
typedef struct dns_dispatchmgr	      dns_dispatchmgr_t;
typedef struct dns_dispentry	      dns_dispentry_t;
typedef struct dns_dns64	      dns_dns64_t;
typedef ISC_LIST(dns_dns64_t) dns_dns64list_t;
typedef struct dns_dnsseckey dns_dnsseckey_t;
typedef ISC_LIST(dns_dnsseckey_t) dns_dnsseckeylist_t;
typedef uint8_t			   dns_dsdigest_t;
typedef struct dns_dtdata	   dns_dtdata_t;
typedef struct dns_dtenv	   dns_dtenv_t;
typedef struct dns_dtmsg	   dns_dtmsg_t;
typedef uint16_t		   dns_dtmsgtype_t;
typedef struct dns_dumpctx	   dns_dumpctx_t;
typedef struct dns_ecs		   dns_ecs_t;
typedef struct dns_ednsopt	   dns_ednsopt_t;
typedef struct dns_fetch	   dns_fetch_t;
typedef struct dns_fixedname	   dns_fixedname_t;
typedef struct dns_forwarders	   dns_forwarders_t;
typedef struct dns_forwarder	   dns_forwarder_t;
typedef struct dns_fwdtable	   dns_fwdtable_t;
typedef struct dns_geoip_databases dns_geoip_databases_t;
typedef struct dns_glue		   dns_glue_t;
typedef struct dns_gluelist	   dns_gluelist_t;
typedef struct dns_iptable	   dns_iptable_t;
typedef uint32_t		   dns_iterations_t;
typedef struct dns_kasp		   dns_kasp_t;
typedef ISC_LIST(dns_kasp_t) dns_kasplist_t;
typedef struct dns_kasp_digest dns_kasp_digest_t;
typedef ISC_LIST(dns_kasp_digest_t) dns_kasp_digestlist_t;
typedef struct dns_kasp_key dns_kasp_key_t;
typedef ISC_LIST(dns_kasp_key_t) dns_kasp_keylist_t;
typedef struct dns_kasp_nsec3param dns_kasp_nsec3param_t;
typedef uint16_t		   dns_keyflags_t;
typedef struct dns_keynode	   dns_keynode_t;
typedef ISC_LIST(dns_keynode_t) dns_keynodelist_t;
typedef struct dns_keytable dns_keytable_t;
typedef uint16_t	    dns_keytag_t;
typedef struct dns_keystore dns_keystore_t;
typedef ISC_LIST(dns_keystore_t) dns_keystorelist_t;
typedef struct dns_loadctx	   dns_loadctx_t;
typedef struct dns_loadmgr	   dns_loadmgr_t;
typedef struct dns_masterrawheader dns_masterrawheader_t;
typedef uint64_t		   dns_masterstyle_flags_t;
typedef struct dns_message	   dns_message_t;
typedef uint16_t		   dns_messageid_t;
typedef isc_region_t		   dns_label_t;
typedef struct dns_name		   dns_name_t;
typedef struct dns_nametree	   dns_nametree_t;
typedef ISC_LIST(dns_name_t) dns_namelist_t;
typedef struct dns_ntatable	    dns_ntatable_t;
typedef struct dns_ntnode	    dns_ntnode_t;
typedef enum dns_opcode		    dns_opcode_t;
typedef struct dns_order	    dns_order_t;
typedef struct dns_peer		    dns_peer_t;
typedef struct dns_peerlist	    dns_peerlist_t;
typedef struct dns_slabheader_proof dns_slabheader_proof_t;
typedef struct dns_rbt		    dns_rbt_t;
typedef struct dns_rbtdb	    dns_rbtdb_t;
typedef struct dns_rbtdb_version    dns_rbtdb_version_t;
typedef struct dns_rbtnode	    dns_rbtnode_t;
typedef ISC_LIST(dns_rbtnode_t) dns_rbtnodelist_t;
typedef uint16_t		  dns_rcode_t;
typedef struct dns_rdata	  dns_rdata_t;
typedef struct dns_rdatacallbacks dns_rdatacallbacks_t;
typedef uint16_t		  dns_rdataclass_t;
typedef struct dns_rdatalist	  dns_rdatalist_t;
typedef struct dns_rdataset	  dns_rdataset_t;
typedef ISC_LIST(dns_rdataset_t) dns_rdatasetlist_t;
typedef struct dns_rdatasetiter	   dns_rdatasetiter_t;
typedef struct dns_rdatasetmethods dns_rdatasetmethods_t;
typedef uint16_t		   dns_rdatatype_t;
typedef struct dns_remote	   dns_remote_t;
typedef struct dns_request	   dns_request_t;
typedef struct dns_requestmgr	   dns_requestmgr_t;
typedef struct dns_resolver	   dns_resolver_t;
typedef struct dns_qpnode	   dns_qpnode_t;
typedef uint8_t			   dns_secalg_t;
typedef uint8_t			   dns_secproto_t;
typedef struct dns_signature	   dns_signature_t;
typedef struct dns_skr		   dns_skr_t;
typedef struct dns_slabheader	   dns_slabheader_t;
typedef ISC_LIST(dns_slabheader_t) dns_slabheaderlist_t;
typedef struct dns_ssurule	  dns_ssurule_t;
typedef struct dns_ssutable	  dns_ssutable_t;
typedef struct dns_stats	  dns_stats_t;
typedef uint32_t		  dns_rdatastatstype_t;
typedef struct dns_tkeyctx	  dns_tkeyctx_t;
typedef struct dns_transport	  dns_transport_t;
typedef struct dns_transport_list dns_transport_list_t;
typedef uint16_t		  dns_trust_t;
typedef struct dns_tsigkeyring	  dns_tsigkeyring_t;
typedef struct dns_tsigkey	  dns_tsigkey_t;
typedef uint32_t		  dns_ttl_t;
typedef uint32_t		  dns_typepair_t;
typedef struct dns_unreachcache	  dns_unreachcache_t;
typedef struct dns_update_state	  dns_update_state_t;
typedef struct dns_validator	  dns_validator_t;
typedef struct dns_view		  dns_view_t;
typedef ISC_LIST(dns_view_t) dns_viewlist_t;
typedef struct dns_zone dns_zone_t;
typedef ISC_LIST(dns_zone_t) dns_zonelist_t;
typedef struct dns_zonemgr   dns_zonemgr_t;
typedef struct dns_zt	     dns_zt_t;
typedef struct dns_ipkeylist dns_ipkeylist_t;

typedef struct dst_gssapi_signverifyctx dst_gssapi_signverifyctx_t;

typedef enum { dns_hash_sha1 = 1 } dns_hash_t;

typedef enum {
	dns_fwdpolicy_none = 0,
	dns_fwdpolicy_first = 1,
	dns_fwdpolicy_only = 2
} dns_fwdpolicy_t;

typedef enum {
	dns_namereln_none = 0,
	dns_namereln_contains = 1,
	dns_namereln_subdomain = 2,
	dns_namereln_equal = 3,
	dns_namereln_commonancestor = 4
} dns_namereln_t;

typedef enum { dns_one_answer, dns_many_answers } dns_transfer_format_t;

typedef enum {
	dns_dbtype_zone = 0,
	dns_dbtype_cache = 1,
	dns_dbtype_stub = 3
} dns_dbtype_t;

typedef enum {
	dns_dbtree_main = 0,
	dns_dbtree_nsec = 1,
	dns_dbtree_nsec3 = 2
} dns_dbtree_t;

typedef enum {
	dns_checkdstype_no = 0,
	dns_checkdstype_yes = 1,
	dns_checkdstype_explicit = 2
} dns_checkdstype_t;

typedef enum {
	dns_notifytype_no = 0,
	dns_notifytype_yes = 1,
	dns_notifytype_explicit = 2,
	dns_notifytype_masteronly = 3
} dns_notifytype_t;

typedef enum {
	dns_minimal_no = 0,
	dns_minimal_yes = 1,
	dns_minimal_noauth = 2,
	dns_minimal_noauthrec = 3
} dns_minimaltype_t;

typedef enum {
	dns_masterformat_none = 0,
	dns_masterformat_text = 1,
	dns_masterformat_raw = 2,
} dns_masterformat_t;

typedef enum {
	dns_order_none,
	dns_order_cyclic,
	dns_order_randomize
} dns_orderopt_t;

typedef enum {
	dns_expire_lru = 0,
	dns_expire_ttl = 1,
	dns_expire_flush = 2,
} dns_expire_t;

/*
 * These are generated by gen.c.
 */
#include <dns/enumclass.h> /* Provides dns_rdataclass_t. */
#include <dns/enumtype.h>  /* Provides dns_rdatatype_t. */

/*%
 * rcodes.
 */
enum {
	/*
	 * Standard rcodes.
	 */
	dns_rcode_noerror = 0,
#define dns_rcode_noerror ((dns_rcode_t)dns_rcode_noerror)
	dns_rcode_formerr = 1,
#define dns_rcode_formerr ((dns_rcode_t)dns_rcode_formerr)
	dns_rcode_servfail = 2,
#define dns_rcode_servfail ((dns_rcode_t)dns_rcode_servfail)
	dns_rcode_nxdomain = 3,
#define dns_rcode_nxdomain ((dns_rcode_t)dns_rcode_nxdomain)
	dns_rcode_notimp = 4,
#define dns_rcode_notimp ((dns_rcode_t)dns_rcode_notimp)
	dns_rcode_refused = 5,
#define dns_rcode_refused ((dns_rcode_t)dns_rcode_refused)
	dns_rcode_yxdomain = 6,
#define dns_rcode_yxdomain ((dns_rcode_t)dns_rcode_yxdomain)
	dns_rcode_yxrrset = 7,
#define dns_rcode_yxrrset ((dns_rcode_t)dns_rcode_yxrrset)
	dns_rcode_nxrrset = 8,
#define dns_rcode_nxrrset ((dns_rcode_t)dns_rcode_nxrrset)
	dns_rcode_notauth = 9,
#define dns_rcode_notauth ((dns_rcode_t)dns_rcode_notauth)
	dns_rcode_notzone = 10,
#define dns_rcode_notzone ((dns_rcode_t)dns_rcode_notzone)
	/*
	 * Extended rcodes.
	 */
	dns_rcode_badvers = 16,
#define dns_rcode_badvers ((dns_rcode_t)dns_rcode_badvers)
	dns_rcode_badcookie = 23
#define dns_rcode_badcookie ((dns_rcode_t)dns_rcode_badcookie)
	/*
	 * Update dns_rcodestats_create() and
	 *dns_rcodestats_increment()
	 * and this comment if a rcode >
	 *dns_rcode_badcookie is assigned.
	 */
	/* Private space [3841..4095] */
};

/*%
 * TSIG errors.
 */
enum {
	dns_tsigerror_badsig = 16,
	dns_tsigerror_badkey = 17,
	dns_tsigerror_badtime = 18,
	dns_tsigerror_badmode = 19,
	dns_tsigerror_badname = 20,
	dns_tsigerror_badalg = 21,
	dns_tsigerror_badtrunc = 22
};

/*%
 * Opcodes.
 */
enum dns_opcode {
	dns_opcode_query = 0,
	dns_opcode_iquery = 1,
	dns_opcode_status = 2,
	dns_opcode_notify = 4,
	dns_opcode_update = 5, /* dynamic update */
	dns_opcode_max = 6,
	dns__opcode_expand = UINT16_MAX,
} __attribute__((__packed__));
/* Absent attribute packed, the enum will be sized as an int */
STATIC_ASSERT(sizeof(uint16_t) == sizeof(dns_opcode_t),
	      "sizeof(dns_opecode)t) is not 16-bit");

/*%
 * Trust levels.  Must be kept in sync with trustnames[] in masterdump.c.
 */
enum {
	/* Sentinel value; no data should have this trust level. */
	dns_trust_none = 0,
#define dns_trust_none ((dns_trust_t)dns_trust_none)

	/*%
	 * Subject to DNSSEC validation but has not yet been validated
	 * dns_trust_pending_additional (from the additional section).
	 */
	dns_trust_pending_additional = 1,
#define dns_trust_pending_additional ((dns_trust_t)dns_trust_pending_additional)

	dns_trust_pending_answer = 2,
#define dns_trust_pending_answer ((dns_trust_t)dns_trust_pending_answer)

	/*% Received in the additional section of a response. */
	dns_trust_additional = 3,
#define dns_trust_additional ((dns_trust_t)dns_trust_additional)

	/* Received in a referral response. */
	dns_trust_glue = 4,
#define dns_trust_glue ((dns_trust_t)dns_trust_glue)

	/* Answer from a non-authoritative server */
	dns_trust_answer = 5,
#define dns_trust_answer ((dns_trust_t)dns_trust_answer)

	/*  Received in the authority section as part of an
	 *  authoritative response */
	dns_trust_authauthority = 6,
#define dns_trust_authauthority ((dns_trust_t)dns_trust_authauthority)

	/* Answer from an authoritative server */
	dns_trust_authanswer = 7,
#define dns_trust_authanswer ((dns_trust_t)dns_trust_authanswer)

	/* Successfully DNSSEC validated */
	dns_trust_secure = 8,
#define dns_trust_secure ((dns_trust_t)dns_trust_secure)

	/* This server is authoritative */
	dns_trust_ultimate = 9
#define dns_trust_ultimate ((dns_trust_t)dns_trust_ultimate)
};

#define DNS_TRUST_PENDING(x) \
	((x) == dns_trust_pending_answer || (x) == dns_trust_pending_additional)
#define DNS_TRUST_ADDITIONAL(x) \
	((x) == dns_trust_additional || (x) == dns_trust_pending_additional)
#define DNS_TRUST_GLUE(x)   ((x) == dns_trust_glue)
#define DNS_TRUST_ANSWER(x) ((x) == dns_trust_answer)

/*%
 * Name checking severities.
 */
typedef enum {
	dns_severity_ignore,
	dns_severity_warn,
	dns_severity_fail
} dns_severity_t;

/*%
 * DNS Serial Number Update Method.
 *
 * \li	_none:		Keep the current serial.
 * \li	_increment:	Add one to the current serial, skipping 0.
 * \li	_unixtime:	Set to the seconds since 00:00 Jan 1, 1970,
 *			if possible.
 * \li	_date:		Set to today's date in YYYYMMDDVV format:
 *                      (Year, Month, Day, Version)
 */
typedef enum {
	dns_updatemethod_none = 0,
	dns_updatemethod_increment,
	dns_updatemethod_unixtime,
	dns_updatemethod_date
} dns_updatemethod_t;

typedef enum {
	dns_stale_answer_no,
	dns_stale_answer_yes,
	dns_stale_answer_conf
} dns_stale_answer_t;

typedef struct {
	const char *string;
	size_t	    count;
} dns_indent_t;

/*
 * Functions.
 */
typedef void (*dns_dumpdonefunc_t)(void *, isc_result_t);

typedef void (*dns_loaddonefunc_t)(void *, isc_result_t);

typedef void (*dns_rawdatafunc_t)(dns_zone_t *, dns_masterrawheader_t *);

typedef isc_result_t (*dns_addrdatasetfunc_t)(void *arg, const dns_name_t *name,
					      dns_rdataset_t *rdataset
						      DNS__DB_FLARG);
typedef void (*dns_transactionfunc_t)(void *arg);

typedef isc_result_t (*dns_additionaldatafunc_t)(
	void *arg, const dns_name_t *name, dns_rdatatype_t type,
	dns_rdataset_t *rdataset DNS__DB_FLARG);

typedef isc_result_t (*dns_digestfunc_t)(void *, isc_region_t *);

typedef void (*dns_xfrindone_t)(dns_zone_t *, uint32_t *, isc_result_t);

typedef void (*dns_updatecallback_t)(void *, isc_result_t, dns_message_t *);

typedef int (*dns_rdatasetorderfunc_t)(const dns_rdata_t *, const void *);

typedef bool (*dns_checkmxfunc_t)(dns_zone_t *, const dns_name_t *,
				  const dns_name_t *);

typedef bool (*dns_checksrvfunc_t)(dns_zone_t *, const dns_name_t *,
				   const dns_name_t *);

typedef bool (*dns_checknsfunc_t)(dns_zone_t *, const dns_name_t *,
				  const dns_name_t *, dns_rdataset_t *,
				  dns_rdataset_t *);

typedef bool (*dns_checkisservedbyfunc_t)(dns_zone_t *, dns_rdatatype_t type,
					  const dns_name_t *);

typedef bool (*dns_isselffunc_t)(dns_view_t *, dns_tsigkey_t *,
				 const isc_sockaddr_t *, const isc_sockaddr_t *,
				 dns_rdataclass_t, void *);

typedef void (*dns_nseclog_t)(void *val, int, const char *, ...);
