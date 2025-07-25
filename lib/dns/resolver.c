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

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include <isc/ascii.h>
#include <isc/async.h>
#include <isc/atomic.h>
#include <isc/counter.h>
#include <isc/hash.h>
#include <isc/hashmap.h>
#include <isc/hex.h>
#include <isc/log.h>
#include <isc/loop.h>
#include <isc/mutex.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/result.h>
#include <isc/rwlock.h>
#include <isc/siphash.h>
#include <isc/stats.h>
#include <isc/string.h>
#include <isc/tid.h>
#include <isc/time.h>
#include <isc/timer.h>
#include <isc/util.h>

#include <dns/acl.h>
#include <dns/adb.h>
#include <dns/cache.h>
#include <dns/db.h>
#include <dns/dispatch.h>
#include <dns/dns64.h>
#include <dns/dnstap.h>
#include <dns/ds.h>
#include <dns/ede.h>
#include <dns/edns.h>
#include <dns/forward.h>
#include <dns/keytable.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/nametree.h>
#include <dns/ncache.h>
#include <dns/nsec.h>
#include <dns/nsec3.h>
#include <dns/opcode.h>
#include <dns/peer.h>
#include <dns/rcode.h>
#include <dns/rdata.h>
#include <dns/rdataclass.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/resolver.h>
#include <dns/rootns.h>
#include <dns/stats.h>
#include <dns/tsig.h>
#include <dns/validator.h>
#include <dns/zone.h>

#ifdef WANT_QUERYTRACE
#define RTRACE(m)                                                       \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, \
		      ISC_LOG_DEBUG(3), "res %p: %s", res, (m))
#define RRTRACE(r, m)                                                   \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, \
		      ISC_LOG_DEBUG(3), "res %p: %s", (r), (m))
#define FCTXTRACE(m)                                                         \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,      \
		      ISC_LOG_DEBUG(3), "fctx %p(%s): %s", fctx, fctx->info, \
		      (m))
#define FCTXTRACE2(m1, m2)                                              \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, \
		      ISC_LOG_DEBUG(3), "fctx %p(%s): %s %s", fctx,     \
		      fctx->info, (m1), (m2))
#define FCTXTRACE3(m, res)                                                    \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,       \
		      ISC_LOG_DEBUG(3), "fctx %p(%s): [result: %s] %s", fctx, \
		      fctx->info, isc_result_totext(res), (m))
#define FCTXTRACE4(m1, m2, res)                                            \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,    \
		      ISC_LOG_DEBUG(3), "fctx %p(%s): [result: %s] %s %s", \
		      fctx, fctx->info, isc_result_totext(res), (m1), (m2))
#define FCTXTRACE5(m1, m2, v)                                           \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, \
		      ISC_LOG_DEBUG(3), "fctx %p(%s): %s %s%u", fctx,   \
		      fctx->info, (m1), (m2), (v))
#define FCTXTRACEN(m1, name, res)                                    \
	do {                                                         \
		if (isc_log_wouldlog(ISC_LOG_DEBUG(3))) {            \
			char dbuf[DNS_NAME_FORMATSIZE];              \
			dns_name_format((name), dbuf, sizeof(dbuf)); \
			FCTXTRACE4((m1), dbuf, (res));               \
		}                                                    \
	} while (0)
#define FTRACE(m)                                                            \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,      \
		      ISC_LOG_DEBUG(3), "fetch %p (fctx %p(%s)): %s", fetch, \
		      fetch->private, fetch->private->info, (m))
#define QTRACE(m)                                                        \
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,  \
		      ISC_LOG_DEBUG(3), "resquery %p (fctx %p(%s)): %s", \
		      query, query->fctx, query->fctx->info, (m))
#else /* ifdef WANT_QUERYTRACE */
#define RTRACE(m)          \
	do {               \
		UNUSED(m); \
	} while (0)
#define RRTRACE(r, m)      \
	do {               \
		UNUSED(r); \
		UNUSED(m); \
	} while (0)
#define FCTXTRACE(m)          \
	do {                  \
		UNUSED(fctx); \
		UNUSED(m);    \
	} while (0)
#define FCTXTRACE2(m1, m2)    \
	do {                  \
		UNUSED(fctx); \
		UNUSED(m1);   \
		UNUSED(m2);   \
	} while (0)
#define FCTXTRACE3(m1, res)   \
	do {                  \
		UNUSED(fctx); \
		UNUSED(m1);   \
		UNUSED(res);  \
	} while (0)
#define FCTXTRACE4(m1, m2, res) \
	do {                    \
		UNUSED(fctx);   \
		UNUSED(m1);     \
		UNUSED(m2);     \
		UNUSED(res);    \
	} while (0)
#define FCTXTRACE5(m1, m2, v) \
	do {                  \
		UNUSED(fctx); \
		UNUSED(m1);   \
		UNUSED(m2);   \
		UNUSED(v);    \
	} while (0)
#define FCTXTRACEN(m1, name, res) FCTXTRACE4(m1, name, res)
#define FTRACE(m)          \
	do {               \
		UNUSED(m); \
	} while (0)
#define QTRACE(m)          \
	do {               \
		UNUSED(m); \
	} while (0)
#endif /* WANT_QUERYTRACE */

/*
 * The maximum time we will wait for a single query.
 */
#define MAX_SINGLE_QUERY_TIMEOUT    9000U
#define MAX_SINGLE_QUERY_TIMEOUT_US (MAX_SINGLE_QUERY_TIMEOUT * US_PER_MS)

/*
 * The default maximum number of validations and validation failures per-fetch
 */
#ifndef DEFAULT_MAX_VALIDATIONS
#define DEFAULT_MAX_VALIDATIONS 16
#endif
#ifndef DEFAULT_MAX_VALIDATION_FAILURES
#define DEFAULT_MAX_VALIDATION_FAILURES 1
#endif

/*
 * A minumum sane timeout value for the whole query to live when e.g. talking to
 * a backend server and a quick timeout is preferred by the user.
 *
 * IMPORTANT: if changing this value, note there is a documented behavior when
 * values of 'resolver-query-timeout' less than or equal to 300 are treated as
 * seconds and converted to milliseconds before applying the limits, that's
 * why the value of 301 was chosen as the absolute minimum in order to not break
 * backward compatibility.
 */
#define MINIMUM_QUERY_TIMEOUT 301U

/*
 * The default time in seconds for the whole query to live.
 * We want to allow an individual query time to complete / timeout.
 */
#ifndef DEFAULT_QUERY_TIMEOUT
#define DEFAULT_QUERY_TIMEOUT (MAX_SINGLE_QUERY_TIMEOUT + 1000U)
#endif /* ifndef DEFAULT_QUERY_TIMEOUT */

/* The maximum time in seconds for the whole query to live. */
#ifndef MAXIMUM_QUERY_TIMEOUT
#define MAXIMUM_QUERY_TIMEOUT 30000
#endif /* ifndef MAXIMUM_QUERY_TIMEOUT */

/* The default maximum number of recursions to follow before giving up. */
#ifndef DEFAULT_RECURSION_DEPTH
#define DEFAULT_RECURSION_DEPTH 7
#endif /* ifndef DEFAULT_RECURSION_DEPTH */

/* The default maximum number of iterative queries to allow before giving up. */
#ifndef DEFAULT_MAX_QUERIES
#define DEFAULT_MAX_QUERIES 50
#endif /* ifndef DEFAULT_MAX_QUERIES */

/*
 * After NS_FAIL_LIMIT attempts to fetch a name server address,
 * if the number of addresses in the NS RRset exceeds NS_RR_LIMIT,
 * stop trying to fetch, in order to avoid wasting resources.
 */
#define NS_FAIL_LIMIT 4
#define NS_RR_LIMIT   5
/*
 * IP address lookups are performed for at most NS_PROCESSING_LIMIT NS RRs in
 * any NS RRset encountered, to avoid excessive resource use while processing
 * large delegations.
 */
#define NS_PROCESSING_LIMIT 20

STATIC_ASSERT(NS_PROCESSING_LIMIT > NS_RR_LIMIT,
	      "The maximum number of NS RRs processed for each "
	      "delegation "
	      "(NS_PROCESSING_LIMIT) must be larger than the large "
	      "delegation "
	      "threshold (NS_RR_LIMIT).");

/* Hash table for zone counters */
#ifndef RES_DOMAIN_HASH_BITS
#define RES_DOMAIN_HASH_BITS 12
#endif /* ifndef RES_DOMAIN_HASH_BITS */

/*%
 * Maximum EDNS0 input packet size.
 */
#define RECV_BUFFER_SIZE 4096 /* XXXRTH  Constant. */

/*%
 * This defines the maximum number of timeouts we will permit before we
 * disable EDNS0 on the query.
 */
#define MAX_EDNS0_TIMEOUTS 3

typedef struct fetchctx fetchctx_t;

typedef struct query {
	/* Locked by loop event serialization. */
	unsigned int magic;
	isc_refcount_t references;
	fetchctx_t *fctx;
	dns_message_t *rmessage;
	dns_dispatchmgr_t *dispatchmgr;
	dns_dispatch_t *dispatch;
	dns_adbaddrinfo_t *addrinfo;
	isc_time_t start;
	dns_messageid_t id;
	dns_dispentry_t *dispentry;
	ISC_LINK(struct query) link;
	isc_buffer_t buffer;
	isc_buffer_t *tsig;
	dns_tsigkey_t *tsigkey;
	int ednsversion;
	unsigned int options;
	unsigned int attributes;
	unsigned int udpsize;
	unsigned char data[512];
} resquery_t;

#if DNS_RESOLVER_TRACE
#define resquery_ref(ptr)   resquery__ref(ptr, __func__, __FILE__, __LINE__)
#define resquery_unref(ptr) resquery__unref(ptr, __func__, __FILE__, __LINE__)
#define resquery_attach(ptr, ptrp) \
	resquery__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define resquery_detach(ptrp) \
	resquery__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(resquery);
#else
ISC_REFCOUNT_DECL(resquery);
#endif

struct tried {
	isc_sockaddr_t addr;
	unsigned int count;
	ISC_LINK(struct tried) link;
};

#define QUERY_MAGIC	   ISC_MAGIC('Q', '!', '!', '!')
#define VALID_QUERY(query) ISC_MAGIC_VALID(query, QUERY_MAGIC)

#define RESQUERY_ATTR_CANCELED 0x02

#define RESQUERY_CONNECTING(q) ((q)->connects > 0)
#define RESQUERY_CANCELED(q)   (((q)->attributes & RESQUERY_ATTR_CANCELED) != 0)
#define RESQUERY_SENDING(q)    ((q)->sends > 0)

typedef enum {
	fetchstate_active,
	fetchstate_done /*%< Fetch completion events posted. */
} fetchstate_t;

typedef enum {
	badns_unreachable = 0,
	badns_response,
	badns_validation,
	badns_forwarder,
} badnstype_t;

#define FCTXCOUNT_MAGIC		 ISC_MAGIC('F', 'C', 'n', 't')
#define VALID_FCTXCOUNT(counter) ISC_MAGIC_VALID(counter, FCTXCOUNT_MAGIC)

typedef struct fctxcount fctxcount_t;
struct fctxcount {
	unsigned int magic;
	isc_mem_t *mctx;
	isc_mutex_t lock;
	dns_fixedname_t dfname;
	dns_name_t *domain;
	uint_fast32_t count;
	uint_fast32_t allowed;
	uint_fast32_t dropped;
	isc_stdtime_t logged;
};

struct fetchctx {
	/*% Not locked. */
	unsigned int magic;
	dns_resolver_t *res;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_rdatatype_t type;
	unsigned int options;
	fctxcount_t *counter;
	char *info;
	isc_mem_t *mctx;
	isc_stdtime_t now;

	isc_loop_t *loop;
	isc_tid_t tid;

	dns_edectx_t edectx;

	/* Atomic */
	isc_refcount_t references;

	/*% Locked by lock. */
	isc_mutex_t lock;
	fetchstate_t state;
	bool cloned;
	bool spilled;
	uint_fast32_t allowed;
	uint_fast32_t dropped;
	ISC_LIST(dns_fetchresponse_t) resps;

	/*% Locked by loop event serialization. */
	dns_fixedname_t dfname;
	dns_name_t *domain;
	dns_rdataset_t nameservers;
	atomic_uint_fast32_t attributes;
	isc_timer_t *timer;
	isc_time_t expires;
	isc_interval_t interval;
	dns_message_t *qmessage;
	ISC_LIST(resquery_t) queries;
	dns_adbfindlist_t finds;
	dns_adbfind_t *find;
	/*
	 * altfinds are names and/or addresses of dual stack servers that
	 * should be used when iterative resolution to a server is not
	 * possible because the address family of that server is not usable.
	 */
	dns_adbfindlist_t altfinds;
	dns_adbfind_t *altfind;
	dns_adbaddrinfolist_t forwaddrs;
	dns_adbaddrinfolist_t altaddrs;
	dns_forwarderlist_t forwarders;
	dns_fwdpolicy_t fwdpolicy;
	isc_sockaddrlist_t bad;
	ISC_LIST(struct tried) edns;
	ISC_LIST(dns_validator_t) validators;
	dns_db_t *cache;
	dns_adb_t *adb;
	bool ns_ttl_ok;
	uint32_t ns_ttl;
	isc_counter_t *qc;
	isc_counter_t *gqc;
	bool minimized;
	unsigned int qmin_labels;
	isc_result_t qmin_warning;
	bool force_qmin_warning;
	bool ip6arpaskip;
	bool forwarding;
	dns_fixedname_t qminfname;
	dns_name_t *qminname;
	dns_rdatatype_t qmintype;
	dns_fetch_t *qminfetch;
	dns_rdataset_t qminrrset;
	dns_rdataset_t qminsigrrset;
	dns_fixedname_t qmindcfname;
	dns_name_t *qmindcname;
	dns_fixedname_t fwdfname;
	dns_name_t *fwdname;

	/*%
	 * The number of events we're waiting for.
	 */
	atomic_uint_fast32_t pending;

	/*%
	 * The number of times we've "restarted" the current
	 * nameserver set.  This acts as a failsafe to prevent
	 * us from pounding constantly on a particular set of
	 * servers that, for whatever reason, are not giving
	 * us useful responses, but are responding in such a
	 * way that they are not marked "bad".
	 */
	unsigned int restarts;

	/*%
	 * The number of timeouts that have occurred since we
	 * last successfully received a response packet.  This
	 * is used for EDNS0 black hole detection.
	 */
	unsigned int timeouts;

	/*%
	 * Look aside state for DS lookups.
	 */
	dns_fixedname_t nsfname;
	dns_name_t *nsname;

	dns_fetch_t *nsfetch;
	dns_rdataset_t nsrrset;

	/*%
	 * Number of queries that reference this context.
	 */
	atomic_uint_fast32_t nqueries; /* Bucket lock. */

	/*%
	 * Random numbers to use for mixing up server addresses.
	 */
	uint32_t rand_buf;
	uint32_t rand_bits;

	/*%
	 * Fetch-local statistics for detailed logging.
	 */
	isc_result_t result;  /*%< fetch result */
	isc_result_t vresult; /*%< validation result */
	isc_time_t start;
	uint64_t duration;
	bool logged;
	unsigned int querysent;
	unsigned int referrals;
	unsigned int lamecount;
	unsigned int quotacount;
	unsigned int neterr;
	unsigned int badresp;
	unsigned int adberr;
	unsigned int findfail;
	unsigned int valfail;
	bool timeout;
	dns_adbaddrinfo_t *addrinfo;
	unsigned int depth;
	char clientstr[ISC_SOCKADDR_FORMATSIZE];

	isc_counter_t *nvalidations;
	isc_counter_t *nfails;
};

#define FCTX_MAGIC	 ISC_MAGIC('F', '!', '!', '!')
#define VALID_FCTX(fctx) ISC_MAGIC_VALID(fctx, FCTX_MAGIC)

#define FCTX_ATTR_HAVEANSWER 0x0001
#define FCTX_ATTR_GLUING     0x0002
#define FCTX_ATTR_ADDRWAIT   0x0004
#define FCTX_ATTR_WANTCACHE  0x0010
#define FCTX_ATTR_WANTNCACHE 0x0020
#define FCTX_ATTR_NEEDEDNS0  0x0040
#define FCTX_ATTR_TRIEDFIND  0x0080
#define FCTX_ATTR_TRIEDALT   0x0100

#define HAVE_ANSWER(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_HAVEANSWER) != 0)
#define GLUING(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_GLUING) != 0)
#define ADDRWAIT(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_ADDRWAIT) != 0)
#define SHUTTINGDOWN(f) ((f)->state == fetchstate_done)
#define WANTCACHE(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_WANTCACHE) != 0)
#define WANTNCACHE(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_WANTNCACHE) != 0)
#define NEEDEDNS0(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_NEEDEDNS0) != 0)
#define TRIEDFIND(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_TRIEDFIND) != 0)
#define TRIEDALT(f) \
	((atomic_load_acquire(&(f)->attributes) & FCTX_ATTR_TRIEDALT) != 0)

#define FCTX_ATTR_SET(f, a) atomic_fetch_or_release(&(f)->attributes, (a))
#define FCTX_ATTR_CLR(f, a) atomic_fetch_and_release(&(f)->attributes, ~(a))

typedef struct {
	dns_adbaddrinfo_t *addrinfo;
	fetchctx_t *fctx;
} dns_valarg_t;

struct dns_fetch {
	unsigned int magic;
	isc_mem_t *mctx;
	dns_resolver_t *res;
	fetchctx_t *private;
};

#define DNS_FETCH_MAGIC	       ISC_MAGIC('F', 't', 'c', 'h')
#define DNS_FETCH_VALID(fetch) ISC_MAGIC_VALID(fetch, DNS_FETCH_MAGIC)

typedef struct alternate {
	bool isaddress;
	union {
		isc_sockaddr_t addr;
		struct {
			dns_name_t name;
			in_port_t port;
		} _n;
	} _u;
	ISC_LINK(struct alternate) link;
} alternate_t;

struct dns_resolver {
	/* Unlocked. */
	unsigned int magic;
	isc_mem_t *mctx;
	isc_mutex_t lock;
	isc_mutex_t primelock;
	dns_rdataclass_t rdclass;
	dns_view_t *view;
	bool frozen;
	unsigned int options;
	isc_tlsctx_cache_t *tlsctx_cache;
	dns_dispatchset_t *dispatches4;
	dns_dispatchset_t *dispatches6;

	isc_hashmap_t *fctxs;
	isc_rwlock_t fctxs_lock;

	isc_hashmap_t *counters;
	isc_rwlock_t counters_lock;

	uint32_t lame_ttl;
	ISC_LIST(alternate_t) alternates;
	dns_nametree_t *algorithms;
	dns_nametree_t *digests;
	unsigned int spillatmax;
	unsigned int spillatmin;
	isc_timer_t *spillattimer;
	bool zero_no_soa_ttl;
	unsigned int query_timeout;
	unsigned int maxdepth;
	unsigned int maxqueries;
	isc_result_t quotaresp[2];
	isc_stats_t *stats;
	dns_stats_t *querystats;

	/* Additions for serve-stale feature. */
	unsigned int retryinterval; /* in milliseconds */
	unsigned int nonbackofftries;

	/* Atomic */
	isc_refcount_t references;
	atomic_uint_fast32_t zspill; /* fetches-per-zone */
	atomic_bool exiting;
	atomic_bool priming;

	atomic_uint_fast32_t maxvalidations;
	atomic_uint_fast32_t maxvalidationfails;

	/* Locked by lock. */
	unsigned int spillat; /* clients-per-query */

	/* Locked by primelock. */
	dns_fetch_t *primefetch;

	uint32_t nloops;

	isc_mempool_t **namepools;
	isc_mempool_t **rdspools;
};

#define RES_MAGIC	    ISC_MAGIC('R', 'e', 's', '!')
#define VALID_RESOLVER(res) ISC_MAGIC_VALID(res, RES_MAGIC)

/*%
 * Private addrinfo flags.
 */
enum {
	FCTX_ADDRINFO_MARK = 1 << 0,
	FCTX_ADDRINFO_FORWARDER = 1 << 1,
	FCTX_ADDRINFO_EDNSOK = 1 << 2,
	FCTX_ADDRINFO_NOCOOKIE = 1 << 3,
	FCTX_ADDRINFO_BADCOOKIE = 1 << 4,
	FCTX_ADDRINFO_DUALSTACK = 1 << 5,
	FCTX_ADDRINFO_NOEDNS0 = 1 << 6,
};

#define UNMARKED(a)    (((a)->flags & FCTX_ADDRINFO_MARK) == 0)
#define ISFORWARDER(a) (((a)->flags & FCTX_ADDRINFO_FORWARDER) != 0)
#define NOCOOKIE(a)    (((a)->flags & FCTX_ADDRINFO_NOCOOKIE) != 0)
#define EDNSOK(a)      (((a)->flags & FCTX_ADDRINFO_EDNSOK) != 0)
#define BADCOOKIE(a)   (((a)->flags & FCTX_ADDRINFO_BADCOOKIE) != 0)
#define ISDUALSTACK(a) (((a)->flags & FCTX_ADDRINFO_DUALSTACK) != 0)

#define NXDOMAIN(r)   (((r)->attributes.nxdomain))
#define NEGATIVE(r)   (((r)->attributes.negative))
#define STATICSTUB(r) (((r)->attributes.staticstub))

#ifdef ENABLE_AFL
bool dns_fuzzing_resolver = false;
void
dns_resolver_setfuzzing(void) {
	dns_fuzzing_resolver = true;
}
#endif /* ifdef ENABLE_AFL */

static unsigned char ip6_arpa_data[] = "\003IP6\004ARPA";
static const dns_name_t ip6_arpa = DNS_NAME_INITABSOLUTE(ip6_arpa_data);

static void
dns_resolver__destroy(dns_resolver_t *res);
static isc_result_t
resquery_send(resquery_t *query);
static void
resquery_response(isc_result_t eresult, isc_region_t *region, void *arg);
static void
resquery_response_continue(void *arg, isc_result_t result);
static void
resquery_connected(isc_result_t eresult, isc_region_t *region, void *arg);
static void
fctx_try(fetchctx_t *fctx, bool retrying);
static void
fctx_shutdown(void *arg);
static void
fctx_minimize_qname(fetchctx_t *fctx);
static void
fctx_destroy(fetchctx_t *fctx);
static isc_result_t
ncache_adderesult(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
		  dns_rdatatype_t covers, isc_stdtime_t now, dns_ttl_t minttl,
		  dns_ttl_t maxttl, bool optout, bool secure,
		  dns_rdataset_t *ardataset, isc_result_t *eresultp);
static void
validated(void *arg);
static void
maybe_cancel_validators(fetchctx_t *fctx);
static void
add_bad(fetchctx_t *fctx, dns_message_t *rmessage, dns_adbaddrinfo_t *addrinfo,
	isc_result_t reason, badnstype_t badtype);
static isc_result_t
findnoqname(fetchctx_t *fctx, dns_message_t *message, dns_name_t *name,
	    dns_rdatatype_t type, dns_name_t **noqname);

#define fctx_done_detach(fctxp, result)                                 \
	if (fctx__done(*fctxp, result, __func__, __FILE__, __LINE__)) { \
		fetchctx_detach(fctxp);                                 \
	}

#define fctx_done_unref(fctx, result)                                 \
	if (fctx__done(fctx, result, __func__, __FILE__, __LINE__)) { \
		fetchctx_unref(fctx);                                 \
	}

#if DNS_RESOLVER_TRACE
#define fetchctx_ref(ptr)   fetchctx__ref(ptr, __func__, __FILE__, __LINE__)
#define fetchctx_unref(ptr) fetchctx__unref(ptr, __func__, __FILE__, __LINE__)
#define fetchctx_attach(ptr, ptrp) \
	fetchctx__attach(ptr, ptrp, __func__, __FILE__, __LINE__)
#define fetchctx_detach(ptrp) \
	fetchctx__detach(ptrp, __func__, __FILE__, __LINE__)
ISC_REFCOUNT_TRACE_DECL(fetchctx);
#else
ISC_REFCOUNT_DECL(fetchctx);
#endif

static bool
fctx__done(fetchctx_t *fctx, isc_result_t result, const char *func,
	   const char *file, unsigned int line);

static void
resume_qmin(void *arg);

static void
clone_results(fetchctx_t *fctx);

static isc_result_t
get_attached_fctx(dns_resolver_t *res, isc_loop_t *loop, const dns_name_t *name,
		  dns_rdatatype_t type, const dns_name_t *domain,
		  dns_rdataset_t *nameservers, const isc_sockaddr_t *client,
		  unsigned int options, unsigned int depth, isc_counter_t *qc,
		  isc_counter_t *gqc, fetchctx_t **fctxp, bool *new_fctx);

/*%
 * The structure and functions defined below implement the resolver
 * query (resquery) response handling logic.
 *
 * When a resolver query is sent and a response is received, the
 * resquery_response() event handler is run, which calls the rctx_*()
 * functions.  The respctx_t structure maintains state from function
 * to function.
 *
 * The call flow is described below:
 *
 * 1. resquery_response():
 *    - Initialize a respctx_t structure (rctx_respinit()).
 *    - Check for dispatcher failure (rctx_dispfail()).
 *    - Parse the response (rctx_parse()).
 *    - Log the response (rctx_logpacket()).
 *    - Check the parsed response for an OPT record and handle
 *      EDNS (rctx_opt(), rctx_edns()).
 *    - Check for a bad or lame server (rctx_badserver(), rctx_lameserver()).
 *    - If RCODE and ANCOUNT suggest this is a positive answer, and
 *      if so, call rctx_answer(): go to step 2.
 *    - If RCODE and NSCOUNT suggest this is a negative answer or a
 *      referral, call rctx_answer_none(): go to step 4.
 *    - Check the additional section for data that should be cached
 *      (rctx_additional()).
 *    - Clean up and finish by calling rctx_done(): go to step 5.
 *
 * 2. rctx_answer():
 *    - If the answer appears to be positive, call rctx_answer_positive():
 *      go to step 3.
 *    - If the response is a malformed delegation (with glue or NS records
 *      in the answer section), call rctx_answer_none(): go to step 4.
 *
 * 3. rctx_answer_positive():
 *    - Initialize the portions of respctx_t needed for processing an answer
 *      (rctx_answer_init()).
 *    - Scan the answer section to find records that are responsive to the
 *      query (rctx_answer_scan()).
 *    - For whichever type of response was found, call a separate routine
 *      to handle it: matching QNAME/QTYPE (rctx_answer_match()),
 *      CNAME (rctx_answer_cname()), covering DNAME (rctx_answer_dname()),
 *      or any records returned in response to a query of type ANY
 *      (rctx_answer_any()).
 *    - Scan the authority section for NS or other records that may be
 *      included with a positive answer (rctx_authority_scan()).
 *
 * 4. rctx_answer_none():
 *    - Determine whether this is an NXDOMAIN, NXRRSET, or referral.
 *    - If referral, set up the resolver to follow the delegation
 *      (rctx_referral()).
 *    - If NXDOMAIN/NXRRSET, scan the authority section for NS and SOA
 *      records included with a negative response (rctx_authority_negative()),
 *      then for DNSSEC proof of nonexistence (rctx_authority_dnssec()).
 *
 * 5. rctx_done():
 *    - Set up chasing of DS records if needed (rctx_chaseds()).
 *    - If the response wasn't intended for us, wait for another response
 *      from the dispatcher (rctx_next()).
 *    - If there is a problem with the responding server, set up another
 *      query to a different server (rctx_nextserver()).
 *    - If there is a problem that might be temporary or dependent on
 *      EDNS options, set up another query to the same server with changed
 *      options (rctx_resend()).
 *    - Shut down the fetch context.
 */

typedef struct respctx {
	resquery_t *query;
	fetchctx_t *fctx;
	isc_mem_t *mctx;
	isc_result_t result;
	isc_buffer_t buffer;
	unsigned int retryopts; /* updated options to pass to
				 * fctx_query() when resending */

	dns_rdatatype_t type; /* type being sought (set to
			       * ANY if qtype was SIG or RRSIG) */
	bool aa;	      /* authoritative answer? */
	dns_trust_t trust;    /* answer trust level */
	bool chaining;	      /* CNAME/DNAME processing? */
	bool next_server;     /* give up, try the next server
			       * */

	badnstype_t broken_type; /* type of name server problem
				  * */
	isc_result_t broken_server;

	bool get_nameservers; /* get a new NS rrset at
			       * zone cut? */
	bool resend;	      /* resend this query? */
	bool nextitem;	      /* invalid response; keep
			       * listening for the correct one */
	bool truncated;	      /* response was truncated */
	bool no_response;     /* no response was received */
	bool negative;	      /* is this a negative response? */

	isc_stdtime_t now; /* time info */
	isc_time_t tnow;
	isc_time_t *finish;

	unsigned int dname_labels;
	unsigned int domain_labels; /* range of permissible number
				     * of
				     * labels in a DNAME */

	dns_name_t *aname;	   /* answer name */
	dns_rdataset_t *ardataset; /* answer rdataset */

	dns_name_t *cname;	   /* CNAME name */
	dns_rdataset_t *crdataset; /* CNAME rdataset */

	dns_name_t *dname;	   /* DNAME name */
	dns_rdataset_t *drdataset; /* DNAME rdataset */

	dns_name_t *ns_name;	     /* NS name */
	dns_rdataset_t *ns_rdataset; /* NS rdataset */

	dns_name_t *soa_name; /* SOA name in a negative answer */
	dns_name_t *ds_name;  /* DS name in a negative answer */

	dns_name_t *found_name;	    /* invalid name in negative
				     * response */
	dns_rdatatype_t found_type; /* invalid type in negative
				     * response */

	dns_rdataset_t *opt; /* OPT rdataset */
} respctx_t;

static void
rctx_respinit(resquery_t *query, fetchctx_t *fctx, isc_result_t result,
	      isc_region_t *region, respctx_t *rctx);

static void
rctx_answer_init(respctx_t *rctx);

static void
rctx_answer_scan(respctx_t *rctx);

static void
rctx_authority_positive(respctx_t *rctx);

static isc_result_t
rctx_answer_any(respctx_t *rctx);

static isc_result_t
rctx_answer_match(respctx_t *rctx);

static isc_result_t
rctx_answer_cname(respctx_t *rctx);

static isc_result_t
rctx_answer_dname(respctx_t *rctx);

static isc_result_t
rctx_answer_positive(respctx_t *rctx);

static isc_result_t
rctx_authority_negative(respctx_t *rctx);

static isc_result_t
rctx_authority_dnssec(respctx_t *rctx);

static void
rctx_additional(respctx_t *rctx);

static isc_result_t
rctx_referral(respctx_t *rctx);

static isc_result_t
rctx_answer_none(respctx_t *rctx);

static void
rctx_nextserver(respctx_t *rctx, dns_message_t *message,
		dns_adbaddrinfo_t *addrinfo, isc_result_t result);

static void
rctx_resend(respctx_t *rctx, dns_adbaddrinfo_t *addrinfo);

static isc_result_t
rctx_next(respctx_t *rctx);

static void
rctx_chaseds(respctx_t *rctx, dns_message_t *message,
	     dns_adbaddrinfo_t *addrinfo, isc_result_t result);

static void
rctx_done(respctx_t *rctx, isc_result_t result);

static void
rctx_logpacket(respctx_t *rctx);

static void
rctx_opt(respctx_t *rctx);

static void
rctx_edns(respctx_t *rctx);

static isc_result_t
rctx_parse(respctx_t *rctx);

static isc_result_t
rctx_badserver(respctx_t *rctx, isc_result_t result);

static isc_result_t
rctx_answer(respctx_t *rctx);

static isc_result_t
rctx_lameserver(respctx_t *rctx);

static isc_result_t
rctx_dispfail(respctx_t *rctx);

static isc_result_t
rctx_timedout(respctx_t *rctx);

static void
rctx_ncache(respctx_t *rctx);

/*%
 * Increment resolver-related statistics counters.
 */
static void
inc_stats(dns_resolver_t *res, isc_statscounter_t counter) {
	if (res->stats != NULL) {
		isc_stats_increment(res->stats, counter);
	}
}

static void
dec_stats(dns_resolver_t *res, isc_statscounter_t counter) {
	if (res->stats != NULL) {
		isc_stats_decrement(res->stats, counter);
	}
}

static void
set_stats(dns_resolver_t *res, isc_statscounter_t counter, uint64_t val) {
	if (res->stats != NULL) {
		isc_stats_set(res->stats, val, counter);
	}
}

static isc_result_t
valcreate(fetchctx_t *fctx, dns_message_t *message, dns_adbaddrinfo_t *addrinfo,
	  dns_name_t *name, dns_rdatatype_t type, dns_rdataset_t *rdataset,
	  dns_rdataset_t *sigrdataset, unsigned int valoptions) {
	dns_validator_t *validator = NULL;
	dns_valarg_t *valarg = NULL;
	isc_result_t result;

	valarg = isc_mem_get(fctx->mctx, sizeof(*valarg));
	*valarg = (dns_valarg_t){
		.addrinfo = addrinfo,
	};

	fetchctx_attach(fctx, &valarg->fctx);

	if (!ISC_LIST_EMPTY(fctx->validators)) {
		valoptions |= DNS_VALIDATOR_DEFER;
	} else {
		valoptions &= ~DNS_VALIDATOR_DEFER;
	}

	result = dns_validator_create(
		fctx->res->view, name, type, rdataset, sigrdataset, message,
		valoptions, fctx->loop, validated, valarg, fctx->nvalidations,
		fctx->nfails, fctx->qc, fctx->gqc, &fctx->edectx, &validator);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	inc_stats(fctx->res, dns_resstatscounter_val);
	ISC_LIST_APPEND(fctx->validators, validator, link);
	return ISC_R_SUCCESS;
}

static void
resquery_destroy(resquery_t *query) {
	fetchctx_t *fctx = query->fctx;

	query->magic = 0;

	if (ISC_LINK_LINKED(query, link)) {
		ISC_LIST_UNLINK(fctx->queries, query, link);
	}

	if (query->tsig != NULL) {
		isc_buffer_free(&query->tsig);
	}

	if (query->tsigkey != NULL) {
		dns_tsigkey_detach(&query->tsigkey);
	}

	if (query->dispentry != NULL) {
		dns_dispatch_done(&query->dispentry);
	}

	if (query->dispatch != NULL) {
		dns_dispatch_detach(&query->dispatch);
	}

	LOCK(&fctx->lock);
	atomic_fetch_sub_release(&fctx->nqueries, 1);
	UNLOCK(&fctx->lock);

	if (query->rmessage != NULL) {
		dns_message_detach(&query->rmessage);
	}

	isc_mem_put(fctx->mctx, query, sizeof(*query));

	fetchctx_detach(&fctx);
}

#if DNS_RESOLVER_TRACE
ISC_REFCOUNT_TRACE_IMPL(resquery, resquery_destroy);
#else
ISC_REFCOUNT_IMPL(resquery, resquery_destroy);
#endif

/*%
 * Update EDNS statistics for a server after not getting a response to a UDP
 * query sent to it.
 */
static void
update_edns_stats(resquery_t *query) {
	fetchctx_t *fctx = query->fctx;

	if ((query->options & DNS_FETCHOPT_TCP) != 0) {
		return;
	}

	if ((query->options & DNS_FETCHOPT_NOEDNS0) == 0) {
		dns_adb_ednsto(fctx->adb, query->addrinfo);
	} else {
		dns_adb_timeout(fctx->adb, query->addrinfo);
	}
}

static void
fctx_expired(void *arg);

/*
 * Start the maximum lifetime timer for the fetch. This will
 * trigger if, for example, some ADB or validator dependency
 * loop occurs and causes a fetch to hang.
 */
static void
fctx_starttimer(fetchctx_t *fctx) {
	isc_interval_t interval;
	isc_time_t now;
	isc_time_t expires;

	isc_interval_set(&interval, 2, 0);
	isc_time_add(&fctx->expires, &interval, &expires);

	now = isc_time_now();
	if (isc_time_compare(&expires, &now) <= 0) {
		isc_interval_set(&interval, 0, 1);
	} else {
		isc_time_subtract(&expires, &now, &interval);
	}

	isc_timer_start(fctx->timer, isc_timertype_once, &interval);
}

static void
fctx_stoptimer(fetchctx_t *fctx) {
	isc_timer_stop(fctx->timer);
}

static void
fctx_cancelquery(resquery_t **queryp, isc_time_t *finish, bool no_response,
		 bool age_untried) {
	resquery_t *query = NULL;
	fetchctx_t *fctx = NULL;
	isc_stdtime_t now = isc_stdtime_now();

	REQUIRE(queryp != NULL);

	query = *queryp;
	fctx = query->fctx;

	if (RESQUERY_CANCELED(query)) {
		return;
	}

	FCTXTRACE("cancelquery");

	query->attributes |= RESQUERY_ATTR_CANCELED;

	/*
	 * Should we update the RTT?
	 */
	if (finish != NULL || no_response) {
		unsigned int rtt, factor;
		if (finish != NULL) {
			/*
			 * We have both the start and finish times for this
			 * packet, so we can compute a real RTT.
			 */
			unsigned int rttms;

			rtt = (unsigned int)isc_time_microdiff(finish,
							       &query->start);
			rttms = rtt / US_PER_MS;
			factor = DNS_ADB_RTTADJDEFAULT;

			if (rttms < DNS_RESOLVER_QRYRTTCLASS0) {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt0);
			} else if (rttms < DNS_RESOLVER_QRYRTTCLASS1) {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt1);
			} else if (rttms < DNS_RESOLVER_QRYRTTCLASS2) {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt2);
			} else if (rttms < DNS_RESOLVER_QRYRTTCLASS3) {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt3);
			} else if (rttms < DNS_RESOLVER_QRYRTTCLASS4) {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt4);
			} else {
				inc_stats(fctx->res,
					  dns_resstatscounter_queryrtt5);
			}
		} else {
			uint32_t value;
			uint32_t mask;

			update_edns_stats(query);

			/*
			 * If "forward first;" is used and a forwarder timed
			 * out, do not attempt to query it again in this fetch
			 * context.
			 */
			if (fctx->fwdpolicy == dns_fwdpolicy_first &&
			    ISFORWARDER(query->addrinfo))
			{
				add_bad(fctx, query->rmessage, query->addrinfo,
					ISC_R_TIMEDOUT, badns_forwarder);
			}

			/*
			 * We don't have an RTT for this query.  Maybe the
			 * packet was lost, or maybe this server is very
			 * slow.  We don't know.  Increase the RTT.
			 */
			INSIST(no_response);
			value = isc_random32();
			if (query->addrinfo->srtt > 800000) {
				mask = 0x3fff;
			} else if (query->addrinfo->srtt > 400000) {
				mask = 0x7fff;
			} else if (query->addrinfo->srtt > 200000) {
				mask = 0xffff;
			} else if (query->addrinfo->srtt > 100000) {
				mask = 0x1ffff;
			} else if (query->addrinfo->srtt > 50000) {
				mask = 0x3ffff;
			} else if (query->addrinfo->srtt > 25000) {
				mask = 0x7ffff;
			} else {
				mask = 0xfffff;
			}

			/*
			 * Don't adjust timeout on EDNS queries unless we have
			 * seen a EDNS response.
			 */
			if ((query->options & DNS_FETCHOPT_NOEDNS0) == 0 &&
			    !EDNSOK(query->addrinfo))
			{
				mask >>= 2;
			}

			rtt = query->addrinfo->srtt + (value & mask);
			if (rtt > MAX_SINGLE_QUERY_TIMEOUT_US) {
				rtt = MAX_SINGLE_QUERY_TIMEOUT_US;
			}
			if (rtt > fctx->res->query_timeout * US_PER_MS) {
				rtt = fctx->res->query_timeout * US_PER_MS;
			}

			/*
			 * Replace the current RTT with our value.
			 */
			factor = DNS_ADB_RTTADJREPLACE;
		}

		dns_adb_adjustsrtt(fctx->adb, query->addrinfo, rtt, factor);
	}

	if ((query->options & DNS_FETCHOPT_TCP) == 0) {
		/* Inform the ADB that we're ending a UDP fetch */
		dns_adb_endudpfetch(fctx->adb, query->addrinfo);
	}

	/*
	 * Age RTTs of servers not tried.
	 */
	if (finish != NULL || age_untried) {
		ISC_LIST_FOREACH (fctx->forwaddrs, addrinfo, publink) {
			if (UNMARKED(addrinfo)) {
				dns_adb_agesrtt(fctx->adb, addrinfo, now);
			}
		}
	}

	if ((finish != NULL || age_untried) && TRIEDFIND(fctx)) {
		ISC_LIST_FOREACH (fctx->finds, find, publink) {
			ISC_LIST_FOREACH (find->list, addrinfo, publink) {
				if (UNMARKED(addrinfo)) {
					dns_adb_agesrtt(fctx->adb, addrinfo,
							now);
				}
			}
		}
	}

	if ((finish != NULL || age_untried) && TRIEDALT(fctx)) {
		ISC_LIST_FOREACH (fctx->altaddrs, addrinfo, publink) {
			if (UNMARKED(addrinfo)) {
				dns_adb_agesrtt(fctx->adb, addrinfo, now);
			}
		}
		ISC_LIST_FOREACH (fctx->altfinds, find, publink) {
			ISC_LIST_FOREACH (find->list, addrinfo, publink) {
				if (UNMARKED(addrinfo)) {
					dns_adb_agesrtt(fctx->adb, addrinfo,
							now);
				}
			}
		}
	}

	/*
	 * Check for any outstanding dispatch responses and if they
	 * exist, cancel them.
	 */
	if (query->dispentry != NULL) {
		dns_dispatch_done(&query->dispentry);
	}

	LOCK(&fctx->lock);
	if (ISC_LINK_LINKED(query, link)) {
		ISC_LIST_UNLINK(fctx->queries, query, link);
	}
	UNLOCK(&fctx->lock);

	resquery_detach(queryp);
}

static void
fctx_cleanup(fetchctx_t *fctx) {
	REQUIRE(ISC_LIST_EMPTY(fctx->queries));

	ISC_LIST_FOREACH (fctx->finds, find, publink) {
		ISC_LIST_UNLINK(fctx->finds, find, publink);
		dns_adb_destroyfind(&find);
		fetchctx_unref(fctx);
	}
	fctx->find = NULL;

	ISC_LIST_FOREACH (fctx->altfinds, find, publink) {
		ISC_LIST_UNLINK(fctx->altfinds, find, publink);
		dns_adb_destroyfind(&find);
		fetchctx_unref(fctx);
	}
	fctx->altfind = NULL;

	ISC_LIST_FOREACH (fctx->forwaddrs, addr, publink) {
		ISC_LIST_UNLINK(fctx->forwaddrs, addr, publink);
		dns_adb_freeaddrinfo(fctx->adb, &addr);
	}

	ISC_LIST_FOREACH (fctx->altaddrs, addr, publink) {
		ISC_LIST_UNLINK(fctx->altaddrs, addr, publink);
		dns_adb_freeaddrinfo(fctx->adb, &addr);
	}
}

static void
fctx_cancelqueries(fetchctx_t *fctx, bool no_response, bool age_untried) {
	ISC_LIST(resquery_t) queries;

	FCTXTRACE("cancelqueries");

	ISC_LIST_INIT(queries);

	/*
	 * Move the queries to a local list so we can cancel
	 * them without holding the lock.
	 */
	LOCK(&fctx->lock);
	ISC_LIST_MOVE(queries, fctx->queries);
	UNLOCK(&fctx->lock);

	ISC_LIST_FOREACH (queries, query, link) {
		/*
		 * Note that we have to unlink the query here,
		 * because if it's still linked in fctx_cancelquery(),
		 * then it will try to unlink it from fctx->queries.
		 */
		ISC_LIST_UNLINK(queries, query, link);
		fctx_cancelquery(&query, NULL, no_response, age_untried);
	}
}

static void
fcount_logspill(fetchctx_t *fctx, fctxcount_t *counter, bool final) {
	char dbuf[DNS_NAME_FORMATSIZE];
	isc_stdtime_t now;

	if (!isc_log_wouldlog(ISC_LOG_INFO)) {
		return;
	}

	/* Do not log a message if there were no dropped fetches. */
	if (counter->dropped == 0) {
		return;
	}

	/* Do not log the cumulative message if the previous log is recent. */
	now = isc_stdtime_now();
	if (!final && counter->logged > now - 60) {
		return;
	}

	dns_name_format(fctx->domain, dbuf, sizeof(dbuf));

	if (!final) {
		isc_log_write(DNS_LOGCATEGORY_SPILL, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_INFO,
			      "too many simultaneous fetches for %s "
			      "(allowed %" PRIuFAST32 " spilled %" PRIuFAST32
			      "; %s)",
			      dbuf, counter->allowed, counter->dropped,
			      counter->dropped == 1 ? "initial trigger event"
						    : "cumulative since "
						      "initial trigger event");
	} else {
		isc_log_write(DNS_LOGCATEGORY_SPILL, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_INFO,
			      "fetch counters for %s now being discarded "
			      "(allowed %" PRIuFAST32 " spilled %" PRIuFAST32
			      "; cumulative since initial trigger event)",
			      dbuf, counter->allowed, counter->dropped);
	}

	counter->logged = now;
}

static bool
fcount_match(void *node, const void *key) {
	const fctxcount_t *counter = node;
	const dns_name_t *domain = key;

	return dns_name_equal(counter->domain, domain);
}

static isc_result_t
fcount_incr(fetchctx_t *fctx, bool force) {
	isc_result_t result = ISC_R_SUCCESS;
	dns_resolver_t *res = NULL;
	fctxcount_t *counter = NULL;
	uint32_t hashval;
	uint_fast32_t spill;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;

	REQUIRE(fctx != NULL);
	res = fctx->res;
	REQUIRE(res != NULL);
	INSIST(fctx->counter == NULL);

	/* Skip any counting if fetches-per-zone is disabled */
	spill = atomic_load_acquire(&res->zspill);
	if (spill == 0) {
		return ISC_R_SUCCESS;
	}

	hashval = dns_name_hash(fctx->domain);

	RWLOCK(&res->counters_lock, locktype);
	result = isc_hashmap_find(res->counters, hashval, fcount_match,
				  fctx->domain, (void **)&counter);
	switch (result) {
	case ISC_R_SUCCESS:
		break;
	case ISC_R_NOTFOUND:
		counter = isc_mem_get(fctx->mctx, sizeof(*counter));
		*counter = (fctxcount_t){
			.magic = FCTXCOUNT_MAGIC,
		};
		isc_mem_attach(fctx->mctx, &counter->mctx);
		isc_mutex_init(&counter->lock);
		counter->domain = dns_fixedname_initname(&counter->dfname);
		dns_name_copy(fctx->domain, counter->domain);

		UPGRADELOCK(&res->counters_lock, locktype);

		void *found = NULL;
		result = isc_hashmap_add(res->counters, hashval, fcount_match,
					 counter->domain, counter, &found);
		if (result == ISC_R_EXISTS) {
			isc_mutex_destroy(&counter->lock);
			isc_mem_putanddetach(&counter->mctx, counter,
					     sizeof(*counter));
			counter = found;
			result = ISC_R_SUCCESS;
		}

		INSIST(result == ISC_R_SUCCESS);
		break;
	default:
		UNREACHABLE();
	}
	INSIST(VALID_FCTXCOUNT(counter));

	INSIST(spill > 0);
	LOCK(&counter->lock);
	if (++counter->count > spill && !force) {
		counter->count--;
		INSIST(counter->count > 0);
		counter->dropped++;
		fcount_logspill(fctx, counter, false);
		result = ISC_R_QUOTA;
	} else {
		counter->allowed++;
		fctx->counter = counter;
	}
	UNLOCK(&counter->lock);
	RWUNLOCK(&res->counters_lock, locktype);

	return result;
}

static bool
match_ptr(void *node, const void *key) {
	return node == key;
}

static void
fcount_decr(fetchctx_t *fctx) {
	REQUIRE(fctx != NULL);

	fctxcount_t *counter = fctx->counter;
	if (counter == NULL) {
		return;
	}
	fctx->counter = NULL;

	/*
	 * FIXME: This should not require a write lock, but should be
	 * implemented using reference counting later, otherwise we would could
	 * encounter ABA problem here - the count could go up and down when we
	 * switch from read to write lock.
	 */
	RWLOCK(&fctx->res->counters_lock, isc_rwlocktype_write);

	LOCK(&counter->lock);
	INSIST(VALID_FCTXCOUNT(counter));
	INSIST(counter->count > 0);
	if (--counter->count > 0) {
		UNLOCK(&counter->lock);
		RWUNLOCK(&fctx->res->counters_lock, isc_rwlocktype_write);
		return;
	}

	isc_result_t result = isc_hashmap_delete(fctx->res->counters,
						 dns_name_hash(counter->domain),
						 match_ptr, counter);
	INSIST(result == ISC_R_SUCCESS);

	fcount_logspill(fctx, counter, true);
	UNLOCK(&counter->lock);

	isc_mutex_destroy(&counter->lock);
	isc_mem_putanddetach(&counter->mctx, counter, sizeof(*counter));

	RWUNLOCK(&fctx->res->counters_lock, isc_rwlocktype_write);
}

static void
spillattimer_countdown(void *arg);

static void
fctx_sendevents(fetchctx_t *fctx, isc_result_t result) {
	unsigned int count = 0;
	bool logit = false;
	isc_time_t now;
	unsigned int old_spillat;
	unsigned int new_spillat = 0; /* initialized to silence
				       * compiler warnings */

	LOCK(&fctx->lock);

	REQUIRE(fctx->state == fetchstate_done);

	FCTXTRACE("sendevents");

	/*
	 * Keep some record of fetch result for logging later (if required).
	 */
	fctx->result = result;
	now = isc_time_now();
	fctx->duration = isc_time_microdiff(&now, &fctx->start);

	ISC_LIST_FOREACH (fctx->resps, resp, link) {
		ISC_LIST_UNLINK(fctx->resps, resp, link);

		count++;

		resp->vresult = fctx->vresult;
		if (!HAVE_ANSWER(fctx)) {
			resp->result = result;
		}

		INSIST(resp->result != ISC_R_SUCCESS ||
		       dns_rdataset_isassociated(resp->rdataset) ||
		       dns_rdatatype_ismulti(fctx->type));

		/*
		 * Negative results must be indicated in resp->result.
		 */
		if (dns_rdataset_isassociated(resp->rdataset) &&
		    NEGATIVE(resp->rdataset))
		{
			INSIST(resp->result == DNS_R_NCACHENXDOMAIN ||
			       resp->result == DNS_R_NCACHENXRRSET);
		}

		/*
		 * Finalize the EDE context, so it becomes "constant" and assign
		 * it to all clients.
		 */
		if (resp->edectx != NULL) {
			dns_ede_copy(resp->edectx, &fctx->edectx);
		}

		FCTXTRACE("post response event");
		isc_async_run(resp->loop, resp->cb, resp);
	}
	UNLOCK(&fctx->lock);

	if (HAVE_ANSWER(fctx) && fctx->spilled &&
	    (count < fctx->res->spillatmax || fctx->res->spillatmax == 0))
	{
		LOCK(&fctx->res->lock);
		if (count == fctx->res->spillat &&
		    !atomic_load_acquire(&fctx->res->exiting))
		{
			old_spillat = fctx->res->spillat;
			fctx->res->spillat += 5;
			if (fctx->res->spillat > fctx->res->spillatmax &&
			    fctx->res->spillatmax != 0)
			{
				fctx->res->spillat = fctx->res->spillatmax;
			}
			new_spillat = fctx->res->spillat;
			if (new_spillat != old_spillat) {
				logit = true;
			}

			/* Timer not running */
			if (fctx->res->spillattimer == NULL) {
				isc_interval_t i;

				isc_timer_create(
					isc_loop(), spillattimer_countdown,
					fctx->res, &fctx->res->spillattimer);

				isc_interval_set(&i, 20 * 60, 0);
				isc_timer_start(fctx->res->spillattimer,
						isc_timertype_ticker, &i);
			}
		}
		UNLOCK(&fctx->res->lock);
		if (logit) {
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_NOTICE,
				      "clients-per-query increased to %u",
				      new_spillat);
		}
	}
}

static uint32_t
fctx_hash(fetchctx_t *fctx) {
	isc_hash32_t hash32;
	isc_hash32_init(&hash32);
	isc_hash32_hash(&hash32, fctx->name->ndata, fctx->name->length, false);
	isc_hash32_hash(&hash32, &fctx->options, sizeof(fctx->options), true);
	isc_hash32_hash(&hash32, &fctx->type, sizeof(fctx->type), true);
	return isc_hash32_finalize(&hash32);
}

static bool
fctx_match(void *node, const void *key) {
	const fetchctx_t *fctx0 = node;
	const fetchctx_t *fctx1 = key;

	return fctx0->options == fctx1->options && fctx0->type == fctx1->type &&
	       dns_name_equal(fctx0->name, fctx1->name);
}

static bool
fctx__done(fetchctx_t *fctx, isc_result_t result, const char *func,
	   const char *file, unsigned int line) {
	bool no_response = false;
	bool age_untried = false;

	REQUIRE(fctx != NULL);
	REQUIRE(fctx->tid == isc_tid());

	FCTXTRACE("done");

#ifdef DNS_RESOLVER_TRACE
	fprintf(stderr, "%s:%s:%s:%u:(%p): %s\n", __func__, func, file, line,
		fctx, isc_result_totext(result));
#else
	UNUSED(file);
	UNUSED(line);
	UNUSED(func);
#endif

	LOCK(&fctx->lock);
	/* We need to do this under the lock for intra-thread synchronization */
	if (fctx->state == fetchstate_done) {
		UNLOCK(&fctx->lock);
		return false;
	}
	fctx->state = fetchstate_done;
	FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
	UNLOCK(&fctx->lock);

	/* The fctx will get deleted either here or in get_attached_fctx() */
	RWLOCK(&fctx->res->fctxs_lock, isc_rwlocktype_write);
	(void)isc_hashmap_delete(fctx->res->fctxs, fctx_hash(fctx), match_ptr,
				 fctx);
	RWUNLOCK(&fctx->res->fctxs_lock, isc_rwlocktype_write);

	if (result == ISC_R_SUCCESS) {
		if (fctx->qmin_warning != ISC_R_SUCCESS) {
			isc_log_write(DNS_LOGCATEGORY_LAME_SERVERS,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_INFO,
				      "success resolving '%s' after disabling "
				      "qname minimization due to '%s'",
				      fctx->info,
				      isc_result_totext(fctx->qmin_warning));
		}

		/*
		 * A success result indicates we got a response to a
		 * query. That query should be canceled already. If
		 * there still are any outstanding queries attached to the
		 * same fctx, then those have *not* gotten a response,
		 * so we set 'no_response' to true here: that way, when
		 * we run fctx_cancelqueries() below, the SRTTs will
		 * be adjusted.
		 */
		no_response = true;
	} else if (result == ISC_R_TIMEDOUT) {
		age_untried = true;
	}

	fctx->qmin_warning = ISC_R_SUCCESS;

	fctx_cancelqueries(fctx, no_response, age_untried);
	fctx_stoptimer(fctx);

	/*
	 * Cancel all pending validators.  Note that this must be done
	 * without the fctx lock held, since that could cause
	 * deadlock.
	 */
	maybe_cancel_validators(fctx);

	if (fctx->nsfetch != NULL) {
		dns_resolver_cancelfetch(fctx->nsfetch);
	}

	if (fctx->qminfetch != NULL) {
		dns_resolver_cancelfetch(fctx->qminfetch);
	}

	/*
	 * Shut down anything still running on behalf of this
	 * fetch, and clean up finds and addresses.
	 */
	fctx_sendevents(fctx, result);
	fctx_cleanup(fctx);

	isc_timer_destroy(&fctx->timer);

	return true;
}

static void
resquery_senddone(isc_result_t eresult, isc_region_t *region, void *arg) {
	resquery_t *query = (resquery_t *)arg;
	resquery_t *copy = query;
	fetchctx_t *fctx = NULL;

	QTRACE("senddone");

	UNUSED(region);

	REQUIRE(VALID_QUERY(query));
	fctx = query->fctx;
	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->tid == isc_tid());

	if (RESQUERY_CANCELED(query)) {
		goto detach;
	}

	/*
	 * See the note in resquery_connected() about reference
	 * counting on error conditions.
	 */
	switch (eresult) {
	case ISC_R_SUCCESS:
	case ISC_R_CANCELED:
	case ISC_R_SHUTTINGDOWN:
		break;

	case ISC_R_HOSTDOWN:
	case ISC_R_HOSTUNREACH:
	case ISC_R_NETDOWN:
	case ISC_R_NETUNREACH:
	case ISC_R_NOPERM:
	case ISC_R_ADDRNOTAVAIL:
	case ISC_R_CONNREFUSED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_TIMEDOUT:
		/* No route to remote. */
		FCTXTRACE3("query canceled in resquery_senddone(): "
			   "no route to host; no response",
			   eresult);
		add_bad(fctx, query->rmessage, query->addrinfo, eresult,
			badns_unreachable);
		fctx_cancelquery(&copy, NULL, true, false);
		FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
		fctx_try(fctx, true);
		break;

	default:
		FCTXTRACE3("query canceled in resquery_senddone() "
			   "due to unexpected result; responding",
			   eresult);
		fctx_cancelquery(&copy, NULL, false, false);
		fctx_done_detach(&fctx, eresult);
		break;
	}

detach:
	resquery_detach(&query);
}

static isc_result_t
fctx_addopt(dns_message_t *message, unsigned int version, uint16_t udpsize,
	    dns_ednsopt_t *ednsopts, size_t count) {
	dns_rdataset_t *rdataset = NULL;
	isc_result_t result;

	result = dns_message_buildopt(message, &rdataset, version, udpsize,
				      DNS_MESSAGEEXTFLAG_DO, ednsopts, count);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	return dns_message_setopt(message, rdataset);
}

static void
fctx_setretryinterval(fetchctx_t *fctx, unsigned int rtt) {
	unsigned int seconds, us;
	uint64_t limit;
	isc_time_t now;

	/*
	 * Has this fetch already expired?
	 */
	now = isc_time_now();
	limit = isc_time_microdiff(&fctx->expires, &now);
	if (limit < US_PER_MS) {
		FCTXTRACE("fetch already expired");
		isc_interval_set(&fctx->interval, 0, 0);
		return;
	}

	us = fctx->res->retryinterval * US_PER_MS;

	/*
	 * Exponential backoff after the first few tries.
	 */
	if (fctx->restarts > fctx->res->nonbackofftries) {
		int shift = fctx->restarts - fctx->res->nonbackofftries;
		if (shift > 6) {
			shift = 6;
		}
		us <<= shift;
	}

	/*
	 * Add a fudge factor to the expected rtt based on the current
	 * estimate.
	 */
	if (rtt < 50000) {
		rtt += 50000;
	} else if (rtt < 100000) {
		rtt += 100000;
	} else {
		rtt += 200000;
	}

	/*
	 * Always wait for at least the expected rtt.
	 */
	if (us < rtt) {
		us = rtt;
	}

	/*
	 * But don't wait past the the final expiration of the fetch,
	 * or for more than 10 seconds total.
	 */
	if (us > limit) {
		us = limit;
	}
	if (us > MAX_SINGLE_QUERY_TIMEOUT_US) {
		us = MAX_SINGLE_QUERY_TIMEOUT_US;
	}
	if (us > fctx->res->query_timeout * US_PER_MS) {
		us = fctx->res->query_timeout * US_PER_MS;
	}

	seconds = us / US_PER_SEC;
	us -= seconds * US_PER_SEC;
	isc_interval_set(&fctx->interval, seconds, us * NS_PER_US);
}

static isc_result_t
fctx_query(fetchctx_t *fctx, dns_adbaddrinfo_t *addrinfo,
	   unsigned int options) {
	isc_result_t result;
	dns_resolver_t *res = NULL;
	dns_dns64_t *dns64 = NULL;
	resquery_t *query = NULL;
	isc_sockaddr_t addr, sockaddr;
	bool have_addr = false;
	unsigned int srtt;
	isc_tlsctx_cache_t *tlsctx_cache = NULL;

	FCTXTRACE("query");

	res = fctx->res;

	srtt = addrinfo->srtt;

	if (addrinfo->transport != NULL) {
		switch (dns_transport_get_type(addrinfo->transport)) {
		case DNS_TRANSPORT_TLS:
			options |= DNS_FETCHOPT_TCP;
			tlsctx_cache = res->tlsctx_cache;
			break;
		case DNS_TRANSPORT_TCP:
		case DNS_TRANSPORT_HTTP:
			options |= DNS_FETCHOPT_TCP;
			break;
		default:
			break;
		}
	}

	/*
	 * Maybe apply DNS64 mappings to IPv4 addresses.
	 */
	sockaddr = addrinfo->sockaddr;
	dns64 = ISC_LIST_HEAD(fctx->res->view->dns64);
	if (isc_sockaddr_pf(&sockaddr) == AF_INET &&
	    fctx->res->view->usedns64 && dns64 != NULL)
	{
		struct in6_addr aaaa;

		result = dns_dns64_aaaafroma(
			dns64, NULL, NULL, fctx->res->view->aclenv, 0,
			(unsigned char *)&sockaddr.type.sin.sin_addr.s_addr,
			aaaa.s6_addr);
		if (result == ISC_R_SUCCESS) {
			char sockaddrbuf1[ISC_SOCKADDR_FORMATSIZE];
			char sockaddrbuf2[ISC_SOCKADDR_FORMATSIZE];

			/* format old address */
			isc_sockaddr_format(&sockaddr, sockaddrbuf1,
					    sizeof(sockaddrbuf1));

			/* replace address */
			isc_sockaddr_fromin6(&sockaddr, &aaaa,
					     ntohs(sockaddr.type.sin.sin_port));
			addrinfo->sockaddr = sockaddr;

			/* format new address */
			isc_sockaddr_format(&sockaddr, sockaddrbuf2,
					    sizeof(sockaddrbuf2));
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_DEBUG(3),
				      "Using DNS64 address %s to talk to %s\n",
				      sockaddrbuf2, sockaddrbuf1);
		}
	}

	/*
	 * Check if the address is in the peers list and has a special
	 * confguration.
	 */
	if (res->view->peers != NULL) {
		dns_peer_t *peer = NULL;
		isc_netaddr_t dstip;
		bool usetcp = false;
		isc_netaddr_fromsockaddr(&dstip, &sockaddr);
		result = dns_peerlist_peerbyaddr(res->view->peers, &dstip,
						 &peer);
		if (result == ISC_R_SUCCESS) {
			result = dns_peer_getquerysource(peer, &addr);
			if (result == ISC_R_SUCCESS) {
				have_addr = true;
			}
			result = dns_peer_getforcetcp(peer, &usetcp);
			if (result == ISC_R_SUCCESS && usetcp) {
				options |= DNS_FETCHOPT_TCP;
			}
		}
	}

	/*
	 * Allow an additional second for the kernel to resend the SYN
	 * (or SYN without ECN in the case of stupid firewalls blocking
	 * ECN negotiation) over the current RTT estimate.
	 */
	if ((options & DNS_FETCHOPT_TCP) != 0) {
		srtt += US_PER_SEC;
	}

	/*
	 * A forwarder needs to make multiple queries. Give it at least
	 * a second to do these in.
	 */
	if (ISFORWARDER(addrinfo) && srtt < US_PER_SEC) {
		srtt = US_PER_SEC;
	}

	fctx_setretryinterval(fctx, srtt);
	if (isc_interval_iszero(&fctx->interval)) {
		FCTXTRACE("fetch expired");
		dns_ede_add(&fctx->edectx, DNS_EDE_NOREACHABLEAUTH, NULL);
		return ISC_R_TIMEDOUT;
	}

	INSIST(ISC_LIST_EMPTY(fctx->validators));

	query = isc_mem_get(fctx->mctx, sizeof(*query));
	*query = (resquery_t){
		.options = options,
		.addrinfo = addrinfo,
		.dispatchmgr = res->view->dispatchmgr,
		.link = ISC_LINK_INITIALIZER,
	};

#if DNS_RESOLVER_TRACE
	fprintf(stderr, "rctx_init:%s:%s:%d:%p->references = 1\n", __func__,
		__FILE__, __LINE__, query);
#endif
	isc_refcount_init(&query->references, 1);

	/*
	 * Note that the caller MUST guarantee that 'addrinfo' will
	 * remain valid until this query is canceled.
	 */

	dns_message_create(fctx->mctx, fctx->res->namepools[fctx->tid],
			   fctx->res->rdspools[fctx->tid],
			   DNS_MESSAGE_INTENTPARSE, &query->rmessage);
	query->start = isc_time_now();

	/*
	 * If this is a TCP query, then we need to make a socket and
	 * a dispatch for it here.  Otherwise we use the resolver's
	 * shared dispatch.
	 */
	if ((query->options & DNS_FETCHOPT_TCP) != 0) {
		int pf;

		pf = isc_sockaddr_pf(&sockaddr);
		if (!have_addr) {
			switch (pf) {
			case PF_INET:
				result = dns_dispatch_getlocaladdress(
					res->dispatches4->dispatches[0], &addr);
				break;
			case PF_INET6:
				result = dns_dispatch_getlocaladdress(
					res->dispatches6->dispatches[0], &addr);
				break;
			default:
				result = ISC_R_NOTIMPLEMENTED;
				break;
			}
			if (result != ISC_R_SUCCESS) {
				goto cleanup_query;
			}
		}
		isc_sockaddr_setport(&addr, 0);

		result = dns_dispatch_createtcp(res->view->dispatchmgr, &addr,
						&sockaddr, addrinfo->transport,
						DNS_DISPATCHOPT_UNSHARED,
						&query->dispatch);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_query;
		}

		FCTXTRACE("connecting via TCP");
	} else {
		if (have_addr) {
			result = dns_dispatch_createudp(res->view->dispatchmgr,
							&addr,
							&query->dispatch);
			if (result != ISC_R_SUCCESS) {
				goto cleanup_query;
			}
		} else {
			switch (isc_sockaddr_pf(&sockaddr)) {
			case PF_INET:
				dns_dispatch_attach(
					dns_resolver_dispatchv4(res),
					&query->dispatch);
				break;
			case PF_INET6:
				dns_dispatch_attach(
					dns_resolver_dispatchv6(res),
					&query->dispatch);
				break;
			default:
				result = ISC_R_NOTIMPLEMENTED;
				goto cleanup_query;
			}
		}

		/*
		 * We should always have a valid dispatcher here.  If we
		 * don't support a protocol family, then its dispatcher
		 * will be NULL, but we shouldn't be finding addresses
		 * for protocol types we don't support, so the
		 * dispatcher we found should never be NULL.
		 */
		INSIST(query->dispatch != NULL);
	}

	LOCK(&fctx->lock);
	INSIST(!SHUTTINGDOWN(fctx));
	fetchctx_attach(fctx, &query->fctx);
	query->magic = QUERY_MAGIC;

	if ((query->options & DNS_FETCHOPT_TCP) == 0) {
		if (dns_adb_overquota(fctx->adb, addrinfo)) {
			UNLOCK(&fctx->lock);
			result = ISC_R_QUOTA;
			goto cleanup_dispatch;
		}

		/* Inform the ADB that we're starting a UDP fetch */
		dns_adb_beginudpfetch(fctx->adb, addrinfo);
	}

	ISC_LIST_APPEND(fctx->queries, query, link);
	atomic_fetch_add_relaxed(&fctx->nqueries, 1);
	UNLOCK(&fctx->lock);

	/* Set up the dispatch and set the query ID */
	const unsigned int timeout_ms = isc_interval_ms(&fctx->interval);
	result = dns_dispatch_add(query->dispatch, fctx->loop, 0, timeout_ms,
				  timeout_ms, &sockaddr, addrinfo->transport,
				  tlsctx_cache, resquery_connected,
				  resquery_senddone, resquery_response, query,
				  &query->id, &query->dispentry);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_udpfetch;
	}

	/* Connect the socket */
	resquery_ref(query);
	result = dns_dispatch_connect(query->dispentry);

	if (result != ISC_R_SUCCESS && (query->options & DNS_FETCHOPT_TCP) != 0)
	{
		int log_level = ISC_LOG_NOTICE;
		if (isc_log_wouldlog(log_level)) {
			char peerbuf[ISC_SOCKADDR_FORMATSIZE];

			isc_sockaddr_format(&sockaddr, peerbuf,
					    ISC_SOCKADDR_FORMATSIZE);

			isc_log_write(
				DNS_LOGCATEGORY_RESOLVER,
				DNS_LOGMODULE_RESOLVER, log_level,
				"Unable to establish a connection to %s: %s\n",
				peerbuf, isc_result_totext(result));
		}
		dns_dispatch_done(&query->dispentry);
		goto cleanup_fetch;
	} else {
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
	}

	return result;

cleanup_udpfetch:
	if (!RESQUERY_CANCELED(query)) {
		if ((query->options & DNS_FETCHOPT_TCP) == 0) {
			/* Inform the ADB that we're ending a UDP fetch */
			dns_adb_endudpfetch(fctx->adb, addrinfo);
		}
	}

cleanup_fetch:
	LOCK(&fctx->lock);
	if (ISC_LINK_LINKED(query, link)) {
		atomic_fetch_sub_release(&fctx->nqueries, 1);
		ISC_LIST_UNLINK(fctx->queries, query, link);
	}
	UNLOCK(&fctx->lock);

cleanup_dispatch:
	fetchctx_detach(&query->fctx);

	if (query->dispatch != NULL) {
		dns_dispatch_detach(&query->dispatch);
	}

cleanup_query:
	query->magic = 0;
	dns_message_detach(&query->rmessage);
	isc_mem_put(fctx->mctx, query, sizeof(*query));

	return result;
}

static struct tried *
triededns(fetchctx_t *fctx, isc_sockaddr_t *address) {
	ISC_LIST_FOREACH (fctx->edns, tried, link) {
		if (isc_sockaddr_equal(&tried->addr, address)) {
			return tried;
		}
	}

	return NULL;
}

static void
add_triededns(fetchctx_t *fctx, isc_sockaddr_t *address) {
	struct tried *tried = triededns(fctx, address);
	if (tried != NULL) {
		tried->count++;
		return;
	}

	tried = isc_mem_get(fctx->mctx, sizeof(*tried));
	tried->addr = *address;
	tried->count = 1;
	ISC_LIST_INITANDAPPEND(fctx->edns, tried, link);
}

static size_t
addr2buf(void *buf, const size_t bufsize, const isc_sockaddr_t *sockaddr) {
	isc_netaddr_t netaddr;
	isc_netaddr_fromsockaddr(&netaddr, sockaddr);
	switch (netaddr.family) {
	case AF_INET:
		INSIST(bufsize >= 4);
		memmove(buf, &netaddr.type.in, 4);
		return 4;
	case AF_INET6:
		INSIST(bufsize >= 16);
		memmove(buf, &netaddr.type.in6, 16);
		return 16;
	default:
		UNREACHABLE();
	}
	return 0;
}

static size_t
add_serveraddr(uint8_t *buf, const size_t bufsize, const resquery_t *query) {
	return addr2buf(buf, bufsize, &query->addrinfo->sockaddr);
}

/*
 * Client cookie is 8 octets.
 * Server cookie is [8..32] octets.
 */
#define CLIENT_COOKIE_SIZE 8U
#define COOKIE_BUFFER_SIZE (8U + 32U)

static void
compute_cc(const resquery_t *query, uint8_t *cookie, const size_t len) {
	INSIST(len >= CLIENT_COOKIE_SIZE);
	STATIC_ASSERT(sizeof(query->fctx->res->view->secret) >=
			      ISC_SIPHASH24_KEY_LENGTH,
		      "The view->secret size can't fit SipHash 2-4 key "
		      "length");

	uint8_t buf[16] ISC_NONSTRING = { 0 };
	size_t buflen = add_serveraddr(buf, sizeof(buf), query);

	uint8_t digest[ISC_SIPHASH24_TAG_LENGTH] ISC_NONSTRING = { 0 };
	isc_siphash24(query->fctx->res->view->secret, buf, buflen, true,
		      digest);
	memmove(cookie, digest, CLIENT_COOKIE_SIZE);
}

static isc_result_t
issecuredomain(dns_view_t *view, const dns_name_t *name, dns_rdatatype_t type,
	       isc_stdtime_t now, bool checknta, bool *ntap, bool *issecure) {
	dns_name_t suffix;
	unsigned int labels;

	/*
	 * For DS variants we need to check fom the parent domain,
	 * since there may be a negative trust anchor for the name,
	 * while the enclosing domain where the DS record lives is
	 * under a secure entry point.
	 */
	labels = dns_name_countlabels(name);
	if (dns_rdatatype_atparent(type) && labels > 1) {
		dns_name_init(&suffix);
		dns_name_getlabelsequence(name, 1, labels - 1, &suffix);
		name = &suffix;
	}

	return dns_view_issecuredomain(view, name, now, checknta, ntap,
				       issecure);
}

static isc_result_t
resquery_send(resquery_t *query) {
	isc_result_t result;
	fetchctx_t *fctx = query->fctx;
	dns_resolver_t *res = fctx->res;
	isc_buffer_t buffer;
	dns_name_t *qname = NULL;
	dns_rdataset_t *qrdataset = NULL;
	isc_region_t r;
	isc_netaddr_t ipaddr;
	dns_tsigkey_t *tsigkey = NULL;
	dns_peer_t *peer = NULL;
	dns_compress_t cctx;
	bool useedns;
	bool tcp = ((query->options & DNS_FETCHOPT_TCP) != 0);
	dns_ednsopt_t ednsopts[DNS_EDNSOPTIONS];
	unsigned int ednsopt = 0;
	uint16_t hint = 0, udpsize = 0; /* No EDNS */
	isc_sockaddr_t localaddr, *la = NULL;
#ifdef HAVE_DNSTAP
	unsigned char zone[DNS_NAME_MAXWIRE];
	dns_transport_type_t transport_type;
	dns_dtmsgtype_t dtmsgtype;
	isc_region_t zr;
	isc_buffer_t zb;
#endif /* HAVE_DNSTAP */

	QTRACE("send");

	if (atomic_load_acquire(&res->exiting)) {
		FCTXTRACE("resquery_send: resolver shutting down");
		return ISC_R_SHUTTINGDOWN;
	}

	dns_message_gettempname(fctx->qmessage, &qname);
	dns_message_gettemprdataset(fctx->qmessage, &qrdataset);

	fctx->qmessage->opcode = dns_opcode_query;

	/*
	 * Set up question.
	 */
	dns_name_clone(fctx->name, qname);
	dns_rdataset_makequestion(qrdataset, res->rdclass, fctx->type);
	ISC_LIST_APPEND(qname->list, qrdataset, link);
	dns_message_addname(fctx->qmessage, qname, DNS_SECTION_QUESTION);

	/*
	 * Set RD if the client has requested that we do a recursive
	 * query, or if we're sending to a forwarder.
	 */
	if ((query->options & DNS_FETCHOPT_RECURSIVE) != 0 ||
	    ISFORWARDER(query->addrinfo))
	{
		fctx->qmessage->flags |= DNS_MESSAGEFLAG_RD;
	}

	/*
	 * Set CD if the client says not to validate, or if the
	 * question is under a secure entry point and this is a
	 * recursive/forward query -- unless the client said not to.
	 */
	if ((query->options & DNS_FETCHOPT_NOCDFLAG) != 0) {
		/* Do nothing */
	} else if ((query->options & DNS_FETCHOPT_NOVALIDATE) != 0 ||
		   (query->options & DNS_FETCHOPT_TRYCD) != 0)
	{
		fctx->qmessage->flags |= DNS_MESSAGEFLAG_CD;
	} else if (res->view->enablevalidation &&
		   ((fctx->qmessage->flags & DNS_MESSAGEFLAG_RD) != 0))
	{
		query->options |= DNS_FETCHOPT_TRYCD;
	}

	/*
	 * We don't have to set opcode because it defaults to query.
	 */
	fctx->qmessage->id = query->id;

	/*
	 * Convert the question to wire format.
	 */
	dns_compress_init(&cctx, fctx->mctx, 0);

	isc_buffer_init(&buffer, query->data, sizeof(query->data));
	result = dns_message_renderbegin(fctx->qmessage, &cctx, &buffer);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_message;
	}

	result = dns_message_rendersection(fctx->qmessage, DNS_SECTION_QUESTION,
					   0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_message;
	}

	isc_netaddr_fromsockaddr(&ipaddr, &query->addrinfo->sockaddr);
	(void)dns_peerlist_peerbyaddr(fctx->res->view->peers, &ipaddr, &peer);

	/*
	 * The ADB does not know about servers with "edns no".  Check
	 * this, and then inform the ADB for future use.
	 */
	if ((query->addrinfo->flags & FCTX_ADDRINFO_NOEDNS0) == 0 &&
	    peer != NULL &&
	    dns_peer_getsupportedns(peer, &useedns) == ISC_R_SUCCESS &&
	    !useedns)
	{
		query->options |= DNS_FETCHOPT_NOEDNS0;
		dns_adb_changeflags(fctx->adb, query->addrinfo,
				    FCTX_ADDRINFO_NOEDNS0,
				    FCTX_ADDRINFO_NOEDNS0);
	}

	/* Sync NOEDNS0 flag in addrinfo->flags and options now. */
	if ((query->addrinfo->flags & FCTX_ADDRINFO_NOEDNS0) != 0) {
		query->options |= DNS_FETCHOPT_NOEDNS0;
	}

	if (fctx->timeout && (query->options & DNS_FETCHOPT_NOEDNS0) == 0) {
		isc_sockaddr_t *sockaddr = &query->addrinfo->sockaddr;
		struct tried *tried;

		/*
		 * If this is the first timeout for this server in this
		 * fetch context, try setting EDNS UDP buffer size to
		 * the largest UDP response size we have seen from this
		 * server so far.
		 *
		 * If this server has already timed out twice or more in
		 * this fetch context, force TCP.
		 */
		if ((tried = triededns(fctx, sockaddr)) != NULL) {
			if (tried->count == 1U) {
				hint = dns_adb_getudpsize(fctx->adb,
							  query->addrinfo);
			} else if (tried->count >= 2U) {
				if ((query->options & DNS_FETCHOPT_TCP) == 0) {
					/*
					 * Inform the ADB that we're ending a
					 * UDP fetch, and turn the query into
					 * a TCP query.
					 */
					dns_adb_endudpfetch(fctx->adb,
							    query->addrinfo);
					query->options |= DNS_FETCHOPT_TCP;
				}
			}
		}
	}
	fctx->timeout = false;

	/*
	 * Use EDNS0, unless the caller doesn't want it, or we know that
	 * the remote server doesn't like it.
	 */
	if ((query->options & DNS_FETCHOPT_NOEDNS0) == 0) {
		if ((query->addrinfo->flags & FCTX_ADDRINFO_NOEDNS0) == 0) {
			uint16_t peerudpsize = 0;
			unsigned int version = DNS_EDNS_VERSION;
			unsigned int flags = query->addrinfo->flags;
			bool reqnsid = res->view->requestnsid;
			bool sendcookie = res->view->sendcookie;
			bool reqzoneversion = res->view->requestzoneversion;
			bool tcpkeepalive = false;
			unsigned char cookie[COOKIE_BUFFER_SIZE];
			uint16_t padding = 0;

			/*
			 * Set the default UDP size to what was
			 * configured as 'edns-buffer-size'
			 */
			udpsize = res->view->udpsize;

			/*
			 * This server timed out for the first time in
			 * this fetch context and we received a response
			 * from it before (either in this fetch context
			 * or in a different one).  Set 'udpsize' to the
			 * size of the largest UDP response we have
			 * received from this server so far.
			 */
			if (hint != 0U) {
				udpsize = hint;
			}

			/*
			 * If a fixed EDNS UDP buffer size is configured
			 * for this server, make sure we obey that.
			 */
			if (peer != NULL) {
				(void)dns_peer_getudpsize(peer, &peerudpsize);
				if (peerudpsize != 0) {
					udpsize = peerudpsize;
				}
			}

			if ((flags & DNS_FETCHOPT_EDNSVERSIONSET) != 0) {
				version = flags & DNS_FETCHOPT_EDNSVERSIONMASK;
				version >>= DNS_FETCHOPT_EDNSVERSIONSHIFT;
			}

			/* Request NSID/COOKIE/VERSION for current peer?
			 */
			if (peer != NULL) {
				uint8_t ednsversion;
				result = dns_peer_getednsversion(peer,
								 &ednsversion);
				if (result == ISC_R_SUCCESS &&
				    ednsversion < version)
				{
					version = ednsversion;
				}
				(void)dns_peer_getrequestnsid(peer, &reqnsid);
				(void)dns_peer_getrequestzoneversion(
					peer, &reqzoneversion);
				(void)dns_peer_getsendcookie(peer, &sendcookie);
			}
			if (NOCOOKIE(query->addrinfo)) {
				sendcookie = false;
			}
			if (reqnsid) {
				INSIST(ednsopt < DNS_EDNSOPTIONS);
				ednsopts[ednsopt].code = DNS_OPT_NSID;
				ednsopts[ednsopt].length = 0;
				ednsopts[ednsopt].value = NULL;
				ednsopt++;
			}
			if (reqzoneversion) {
				INSIST(ednsopt < DNS_EDNSOPTIONS);
				ednsopts[ednsopt].code = DNS_OPT_ZONEVERSION;
				ednsopts[ednsopt].length = 0;
				ednsopts[ednsopt].value = NULL;
				ednsopt++;
			}
			if (sendcookie) {
				INSIST(ednsopt < DNS_EDNSOPTIONS);
				ednsopts[ednsopt].code = DNS_OPT_COOKIE;
				ednsopts[ednsopt].length =
					(uint16_t)dns_adb_getcookie(
						query->addrinfo, cookie,
						sizeof(cookie));
				if (ednsopts[ednsopt].length != 0) {
					ednsopts[ednsopt].value = cookie;
					inc_stats(
						fctx->res,
						dns_resstatscounter_cookieout);
				} else {
					compute_cc(query, cookie,
						   CLIENT_COOKIE_SIZE);
					ednsopts[ednsopt].value = cookie;
					ednsopts[ednsopt].length =
						CLIENT_COOKIE_SIZE;
					inc_stats(
						fctx->res,
						dns_resstatscounter_cookienew);
				}
				ednsopt++;
			}

			/* Add TCP keepalive option if appropriate */
			if ((peer != NULL) && tcp) {
				(void)dns_peer_gettcpkeepalive(peer,
							       &tcpkeepalive);
			}
			if (tcpkeepalive) {
				INSIST(ednsopt < DNS_EDNSOPTIONS);
				ednsopts[ednsopt].code = DNS_OPT_TCP_KEEPALIVE;
				ednsopts[ednsopt].length = 0;
				ednsopts[ednsopt].value = NULL;
				ednsopt++;
			}

			/* Add PAD for current peer? Require TCP for now
			 */
			if ((peer != NULL) && tcp) {
				(void)dns_peer_getpadding(peer, &padding);
			}
			if (padding != 0) {
				INSIST(ednsopt < DNS_EDNSOPTIONS);
				ednsopts[ednsopt].code = DNS_OPT_PAD;
				ednsopts[ednsopt].length = 0;
				ednsopt++;
				dns_message_setpadding(fctx->qmessage, padding);
			}

			query->ednsversion = version;
			result = fctx_addopt(fctx->qmessage, version, udpsize,
					     ednsopts, ednsopt);
			if (result == ISC_R_SUCCESS) {
				if (reqnsid) {
					query->options |= DNS_FETCHOPT_WANTNSID;
				}
				if (reqzoneversion) {
					query->options |=
						DNS_FETCHOPT_WANTZONEVERSION;
				}
			} else if (result != ISC_R_SUCCESS) {
				/*
				 * We couldn't add the OPT, but we'll
				 * press on. We're not using EDNS0, so
				 * set the NOEDNS0 bit.
				 */
				query->options |= DNS_FETCHOPT_NOEDNS0;
				query->ednsversion = -1;
				udpsize = 0;
			}
		} else {
			/*
			 * We know this server doesn't like EDNS0, so we
			 * won't use it.  Set the NOEDNS0 bit since
			 * we're not using EDNS0.
			 */
			query->options |= DNS_FETCHOPT_NOEDNS0;
			query->ednsversion = -1;
		}
	} else {
		query->ednsversion = -1;
	}

	/*
	 * Record the UDP EDNS size chosen.
	 */
	query->udpsize = udpsize;

	/*
	 * If we need EDNS0 to do this query and aren't using it, we
	 * lose.
	 */
	if (NEEDEDNS0(fctx) && (query->options & DNS_FETCHOPT_NOEDNS0) != 0) {
		result = DNS_R_SERVFAIL;
		goto cleanup_message;
	}

	add_triededns(fctx, &query->addrinfo->sockaddr);

	/*
	 * Clear CD if EDNS is not in use.
	 */
	if ((query->options & DNS_FETCHOPT_NOEDNS0) != 0) {
		fctx->qmessage->flags &= ~DNS_MESSAGEFLAG_CD;
	}

	/*
	 * Add TSIG record tailored to the current recipient.
	 */
	result = dns_view_getpeertsig(fctx->res->view, &ipaddr, &tsigkey);
	if (result != ISC_R_SUCCESS && result != ISC_R_NOTFOUND) {
		goto cleanup_message;
	}

	if (tsigkey != NULL) {
		result = dns_message_settsigkey(fctx->qmessage, tsigkey);
		dns_tsigkey_detach(&tsigkey);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_message;
		}
	}

	result = dns_message_rendersection(fctx->qmessage,
					   DNS_SECTION_ADDITIONAL, 0);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_message;
	}

	result = dns_message_renderend(fctx->qmessage);
	if (result != ISC_R_SUCCESS) {
		goto cleanup_message;
	}

#ifdef HAVE_DNSTAP
	memset(&zr, 0, sizeof(zr));
	isc_buffer_init(&zb, zone, sizeof(zone));
	dns_compress_setpermitted(&cctx, false);
	result = dns_name_towire(fctx->domain, &cctx, &zb);
	if (result == ISC_R_SUCCESS) {
		isc_buffer_usedregion(&zb, &zr);
	}
#endif /* HAVE_DNSTAP */

	if (dns_message_gettsigkey(fctx->qmessage) != NULL) {
		dns_tsigkey_attach(dns_message_gettsigkey(fctx->qmessage),
				   &query->tsigkey);
		result = dns_message_getquerytsig(fctx->qmessage, fctx->mctx,
						  &query->tsig);
		if (result != ISC_R_SUCCESS) {
			goto cleanup_message;
		}
	}

	/*
	 * Log the outgoing packet.
	 */
	result = dns_dispentry_getlocaladdress(query->dispentry, &localaddr);
	if (result == ISC_R_SUCCESS) {
		la = &localaddr;
	}

	dns_message_logpacketfromto(
		fctx->qmessage, "sending packet", la,
		&query->addrinfo->sockaddr, DNS_LOGCATEGORY_RESOLVER,
		DNS_LOGMODULE_PACKETS, ISC_LOG_DEBUG(11), fctx->mctx);

	/*
	 * We're now done with the query message.
	 */
	dns_compress_invalidate(&cctx);
	dns_message_reset(fctx->qmessage, DNS_MESSAGE_INTENTRENDER);

	isc_buffer_usedregion(&buffer, &r);

	resquery_ref(query);
	dns_dispatch_send(query->dispentry, &r);

	QTRACE("sent");

#ifdef HAVE_DNSTAP
	/*
	 * Log the outgoing query via dnstap.
	 */
	if ((fctx->qmessage->flags & DNS_MESSAGEFLAG_RD) != 0) {
		dtmsgtype = DNS_DTTYPE_FQ;
	} else {
		dtmsgtype = DNS_DTTYPE_RQ;
	}

	if (query->addrinfo->transport != NULL) {
		transport_type =
			dns_transport_get_type(query->addrinfo->transport);
	} else if ((query->options & DNS_FETCHOPT_TCP) != 0) {
		transport_type = DNS_TRANSPORT_TCP;
	} else {
		transport_type = DNS_TRANSPORT_UDP;
	}

	dns_dt_send(fctx->res->view, dtmsgtype, la, &query->addrinfo->sockaddr,
		    transport_type, &zr, &query->start, NULL, &buffer);
#endif /* HAVE_DNSTAP */

	return ISC_R_SUCCESS;

cleanup_message:
	dns_compress_invalidate(&cctx);

	dns_message_reset(fctx->qmessage, DNS_MESSAGE_INTENTRENDER);

	/*
	 * Stop the dispatcher from listening.
	 */
	dns_dispatch_done(&query->dispentry);

	return result;
}

static void
resquery_connected(isc_result_t eresult, isc_region_t *region, void *arg) {
	resquery_t *query = (resquery_t *)arg;
	resquery_t *copy = query;
	isc_result_t result;
	fetchctx_t *fctx = NULL;
	dns_resolver_t *res = NULL;
	int pf;

	REQUIRE(VALID_QUERY(query));

	QTRACE("connected");

	UNUSED(region);

	fctx = query->fctx;

	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->tid == isc_tid());

	res = fctx->res;

	if (RESQUERY_CANCELED(query)) {
		goto detach;
	}

	if (atomic_load_acquire(&fctx->res->exiting)) {
		eresult = ISC_R_SHUTTINGDOWN;
	}

	/*
	 * The reference counting of resquery objects is complex:
	 *
	 * 1. attached in fctx_query()
	 * 2. attached prior to dns_dispatch_connect(), detached in
	 *    resquery_connected()
	 * 3. attached prior to dns_dispatch_send(), detached in
	 *    resquery_senddone()
	 * 4. finally detached in fctx_cancelquery()
	 *
	 * On error conditions, it's necessary to call fctx_cancelquery()
	 * from resquery_connected() or _senddone(), detaching twice
	 * within the same function. To make it clear that's what's
	 * happening, we cancel-and-detach 'copy' and detach 'query',
	 * which are both pointing to the same object.
	 */
	switch (eresult) {
	case ISC_R_SUCCESS:
		/*
		 * We are connected. Send the query.
		 */

		result = resquery_send(query);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE("query canceled: resquery_send() failed; "
				  "responding");

			fctx_cancelquery(&copy, NULL, false, false);
			fctx_done_detach(&fctx, result);
			break;
		}

		fctx->querysent++;

		pf = isc_sockaddr_pf(&query->addrinfo->sockaddr);
		if (pf == PF_INET) {
			inc_stats(res, dns_resstatscounter_queryv4);
		} else {
			inc_stats(res, dns_resstatscounter_queryv6);
		}
		if (res->querystats != NULL) {
			dns_rdatatypestats_increment(res->querystats,
						     fctx->type);
		}
		break;

	case ISC_R_CANCELED:
	case ISC_R_SHUTTINGDOWN:
		FCTXTRACE3("shutdown in resquery_connected()", eresult);
		fctx_cancelquery(&copy, NULL, true, false);
		fctx_done_detach(&fctx, eresult);
		break;

	case ISC_R_HOSTDOWN:
	case ISC_R_HOSTUNREACH:
	case ISC_R_NETDOWN:
	case ISC_R_NETUNREACH:
	case ISC_R_CONNREFUSED:
	case ISC_R_NOPERM:
	case ISC_R_ADDRNOTAVAIL:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_TIMEDOUT:
		/*
		 * Do not query this server again in this fetch context.
		 */
		FCTXTRACE3("query failed in resquery_connected(): "
			   "no response",
			   eresult);
		add_bad(fctx, query->rmessage, query->addrinfo, eresult,
			badns_unreachable);
		fctx_cancelquery(&copy, NULL, true, false);

		FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
		fctx_try(fctx, true);
		break;

	default:
		FCTXTRACE3("query canceled in resquery_connected() "
			   "due to unexpected result; responding",
			   eresult);

		fctx_cancelquery(&copy, NULL, false, false);
		fctx_done_detach(&fctx, eresult);
		break;
	}

detach:
	resquery_detach(&query);
}

static void
fctx_finddone(void *arg) {
	dns_adbfind_t *find = (dns_adbfind_t *)arg;
	fetchctx_t *fctx = (fetchctx_t *)find->cbarg;
	bool want_try = false;
	bool want_done = false;
	uint_fast32_t pending;

	REQUIRE(VALID_FCTX(fctx));

	FCTXTRACE("finddone");

	REQUIRE(fctx->tid == isc_tid());

	LOCK(&fctx->lock);
	pending = atomic_fetch_sub_release(&fctx->pending, 1);
	INSIST(pending > 0);

	if (ADDRWAIT(fctx)) {
		/*
		 * The fetch is waiting for a name to be found.
		 */
		INSIST(!SHUTTINGDOWN(fctx));
		if (dns_adb_findstatus(find) == DNS_ADB_MOREADDRESSES) {
			FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
			want_try = true;
		} else {
			fctx->findfail++;
			if (atomic_load_acquire(&fctx->pending) == 0) {
				FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
				if (!ISC_LIST_EMPTY(fctx->res->alternates)) {
					want_try = true;
				} else {
					/*
					 * We've got nothing else to wait for
					 * and don't know the answer.  There's
					 * nothing to do but fail the fctx.
					 */
					want_done = true;
				}
			}
		}
	}

	UNLOCK(&fctx->lock);

	dns_adb_destroyfind(&find);

	if (want_done) {
		FCTXTRACE("fetch failed in finddone(); return "
			  "ISC_R_FAILURE");

		fctx_done_unref(fctx, ISC_R_FAILURE);
	} else if (want_try) {
		fctx_try(fctx, true);
	}

	fetchctx_detach(&fctx);
}

static bool
bad_server(fetchctx_t *fctx, isc_sockaddr_t *address) {
	ISC_LIST_FOREACH (fctx->bad, sa, link) {
		if (isc_sockaddr_equal(sa, address)) {
			return true;
		}
	}

	return false;
}

static bool
mark_bad(fetchctx_t *fctx) {
	bool all_bad = true;

#ifdef ENABLE_AFL
	if (dns_fuzzing_resolver) {
		return false;
	}
#endif /* ifdef ENABLE_AFL */

	/*
	 * Mark all known bad servers, so we don't try to talk to them
	 * again.
	 */

	/*
	 * Mark any bad nameservers.
	 */
	ISC_LIST_FOREACH (fctx->finds, curr, publink) {
		ISC_LIST_FOREACH (curr->list, addrinfo, publink) {
			if (bad_server(fctx, &addrinfo->sockaddr)) {
				addrinfo->flags |= FCTX_ADDRINFO_MARK;
			} else {
				all_bad = false;
			}
		}
	}

	/*
	 * Mark any bad forwarders.
	 */
	ISC_LIST_FOREACH (fctx->forwaddrs, addrinfo, publink) {
		if (bad_server(fctx, &addrinfo->sockaddr)) {
			addrinfo->flags |= FCTX_ADDRINFO_MARK;
		} else {
			all_bad = false;
		}
	}

	/*
	 * Mark any bad alternates.
	 */
	ISC_LIST_FOREACH (fctx->altfinds, curr, publink) {
		ISC_LIST_FOREACH (curr->list, addrinfo, publink) {
			if (bad_server(fctx, &addrinfo->sockaddr)) {
				addrinfo->flags |= FCTX_ADDRINFO_MARK;
			} else {
				all_bad = false;
			}
		}
	}

	ISC_LIST_FOREACH (fctx->altaddrs, addrinfo, publink) {
		if (bad_server(fctx, &addrinfo->sockaddr)) {
			addrinfo->flags |= FCTX_ADDRINFO_MARK;
		} else {
			all_bad = false;
		}
	}

	return all_bad;
}

static void
add_bad(fetchctx_t *fctx, dns_message_t *rmessage, dns_adbaddrinfo_t *addrinfo,
	isc_result_t reason, badnstype_t badtype) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];
	char classbuf[64];
	char typebuf[64];
	char code[64];
	isc_buffer_t b;
	isc_sockaddr_t *sa;
	const char *spc = "";
	isc_sockaddr_t *address = &addrinfo->sockaddr;

#ifdef ENABLE_AFL
	if (dns_fuzzing_resolver) {
		return;
	}
#endif /* ifdef ENABLE_AFL */

	if (reason == DNS_R_LAME) {
		fctx->lamecount++;
	} else {
		switch (badtype) {
		case badns_unreachable:
			fctx->neterr++;
			break;
		case badns_response:
			fctx->badresp++;
			break;
		case badns_validation:
			break; /* counted as 'valfail' */
		case badns_forwarder:
			/*
			 * We were called to prevent the given forwarder
			 * from being used again for this fetch context.
			 */
			break;
		}
	}

	if (bad_server(fctx, address)) {
		/*
		 * We already know this server is bad.
		 */
		return;
	}

	FCTXTRACE("add_bad");

	sa = isc_mem_get(fctx->mctx, sizeof(*sa));
	*sa = *address;
	ISC_LIST_INITANDAPPEND(fctx->bad, sa, link);

	if (reason == DNS_R_LAME) { /* already logged */
		return;
	}

	if (reason == DNS_R_UNEXPECTEDRCODE &&
	    rmessage->rcode == dns_rcode_servfail && ISFORWARDER(addrinfo))
	{
		return;
	}

	if (reason == DNS_R_UNEXPECTEDRCODE) {
		isc_buffer_init(&b, code, sizeof(code) - 1);
		dns_rcode_totext(rmessage->rcode, &b);
		code[isc_buffer_usedlength(&b)] = '\0';
		spc = " ";
	} else if (reason == DNS_R_UNEXPECTEDOPCODE) {
		isc_buffer_init(&b, code, sizeof(code) - 1);
		dns_opcode_totext((dns_opcode_t)rmessage->opcode, &b);
		code[isc_buffer_usedlength(&b)] = '\0';
		spc = " ";
	} else {
		code[0] = '\0';
	}
	dns_name_format(fctx->name, namebuf, sizeof(namebuf));
	dns_rdatatype_format(fctx->type, typebuf, sizeof(typebuf));
	dns_rdataclass_format(fctx->res->rdclass, classbuf, sizeof(classbuf));
	isc_sockaddr_format(address, addrbuf, sizeof(addrbuf));
	isc_log_write(DNS_LOGCATEGORY_LAME_SERVERS, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_INFO, "%s%s%s resolving '%s/%s/%s': %s", code,
		      spc, isc_result_totext(reason), namebuf, typebuf,
		      classbuf, addrbuf);
}

/*
 * Sort addrinfo list by RTT.
 */
static void
sort_adbfind(dns_adbfind_t *find, unsigned int bias) {
	dns_adbaddrinfo_t *best, *curr;
	dns_adbaddrinfolist_t sorted;

	/* Lame N^2 bubble sort. */
	ISC_LIST_INIT(sorted);
	while (!ISC_LIST_EMPTY(find->list)) {
		unsigned int best_srtt;
		best = ISC_LIST_HEAD(find->list);
		best_srtt = best->srtt;
		if (isc_sockaddr_pf(&best->sockaddr) != AF_INET6) {
			best_srtt += bias;
		}
		curr = ISC_LIST_NEXT(best, publink);
		while (curr != NULL) {
			unsigned int curr_srtt = curr->srtt;
			if (isc_sockaddr_pf(&curr->sockaddr) != AF_INET6) {
				curr_srtt += bias;
			}
			if (curr_srtt < best_srtt) {
				best = curr;
				best_srtt = curr_srtt;
			}
			curr = ISC_LIST_NEXT(curr, publink);
		}
		ISC_LIST_UNLINK(find->list, best, publink);
		ISC_LIST_APPEND(sorted, best, publink);
	}
	find->list = sorted;
}

/*
 * Sort a list of finds by server RTT.
 */
static void
sort_finds(dns_adbfindlist_t *findlist, unsigned int bias) {
	dns_adbfind_t *best = NULL;
	dns_adbfindlist_t sorted;
	dns_adbaddrinfo_t *addrinfo, *bestaddrinfo;

	/* Sort each find's addrinfo list by SRTT. */
	ISC_LIST_FOREACH (*findlist, curr, publink) {
		sort_adbfind(curr, bias);
	}

	/* Lame N^2 bubble sort. */
	ISC_LIST_INIT(sorted);
	while (!ISC_LIST_EMPTY(*findlist)) {
		dns_adbfind_t *curr = NULL;
		unsigned int best_srtt;

		best = ISC_LIST_HEAD(*findlist);
		bestaddrinfo = ISC_LIST_HEAD(best->list);
		INSIST(bestaddrinfo != NULL);
		best_srtt = bestaddrinfo->srtt;
		if (isc_sockaddr_pf(&bestaddrinfo->sockaddr) != AF_INET6) {
			best_srtt += bias;
		}
		curr = ISC_LIST_NEXT(best, publink);
		while (curr != NULL) {
			unsigned int curr_srtt;
			addrinfo = ISC_LIST_HEAD(curr->list);
			INSIST(addrinfo != NULL);
			curr_srtt = addrinfo->srtt;
			if (isc_sockaddr_pf(&addrinfo->sockaddr) != AF_INET6) {
				curr_srtt += bias;
			}
			if (curr_srtt < best_srtt) {
				best = curr;
				best_srtt = curr_srtt;
			}
			curr = ISC_LIST_NEXT(curr, publink);
		}
		ISC_LIST_UNLINK(*findlist, best, publink);
		ISC_LIST_APPEND(sorted, best, publink);
	}
	*findlist = sorted;
}

/*
 * Return true iff the ADB find has a pending fetch for 'type'.  This is
 * used to find out whether we're in a loop, where a fetch is waiting for a
 * find which is waiting for that same fetch.
 *
 * Note: This could be done with either an equivalence check (e.g.,
 * query_pending == DNS_ADBFIND_INET) or with a bit check, as below.  If
 * we checked for equivalence, that would mean we could only detect a loop
 * when there is exactly one pending fetch, and we're it. If there were
 * pending fetches for *both* address families, then a loop would be
 * undetected.
 *
 * However, using a bit check means that in theory, an ADB find might be
 * aborted that could have succeeded, if the other fetch had returned an
 * answer.
 *
 * Since there's a good chance the server is broken and won't answer either
 * query, and since an ADB find with two pending fetches is a very rare
 * occurrance anyway, we regard this theoretical SERVFAIL as the lesser
 * evil.
 */
static bool
waiting_for(dns_adbfind_t *find, dns_rdatatype_t type) {
	switch (type) {
	case dns_rdatatype_a:
		return (find->query_pending & DNS_ADBFIND_INET) != 0;
	case dns_rdatatype_aaaa:
		return (find->query_pending & DNS_ADBFIND_INET6) != 0;
	default:
		return false;
	}
}

static void
findname(fetchctx_t *fctx, const dns_name_t *name, in_port_t port,
	 unsigned int options, unsigned int flags, isc_stdtime_t now,
	 bool *overquota, bool *need_alternate, unsigned int *no_addresses) {
	dns_adbfind_t *find = NULL;
	dns_resolver_t *res = fctx->res;
	bool unshared = ((fctx->options & DNS_FETCHOPT_UNSHARED) != 0);
	isc_result_t result;

	FCTXTRACE("FINDNAME");

	/*
	 * If this name is a subdomain of the query domain, tell
	 * the ADB to start looking using zone/hint data. This keeps us
	 * from getting stuck if the nameserver is beneath the zone cut
	 * and we don't know its address (e.g. because the A record has
	 * expired).
	 */
	if (dns_name_issubdomain(name, fctx->domain)) {
		options |= DNS_ADBFIND_STARTATZONE;
	}

	/*
	 * Exempt prefetches from ADB quota.
	 */
	if ((fctx->options & DNS_FETCHOPT_PREFETCH) != 0) {
		options |= DNS_ADBFIND_QUOTAEXEMPT;
	}

	/*
	 * Pass through NOVALIDATE to any lookups ADB makes.
	 */
	if ((fctx->options & DNS_FETCHOPT_NOVALIDATE) != 0) {
		options |= DNS_ADBFIND_NOVALIDATE;
	}

	/*
	 * See what we know about this address.
	 */
	INSIST(!SHUTTINGDOWN(fctx));
	fetchctx_ref(fctx);
	result = dns_adb_createfind(fctx->adb, fctx->loop, fctx_finddone, fctx,
				    name, fctx->name, fctx->type, options, now,
				    res->view->dstport, fctx->depth + 1,
				    fctx->qc, fctx->gqc, &find);

	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_DEBUG(3), "fctx %p(%s): createfind for %s - %s",
		      fctx, fctx->info, fctx->clientstr,
		      isc_result_totext(result));

	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_ALIAS) {
			char namebuf[DNS_NAME_FORMATSIZE];

			/*
			 * XXXRTH  Follow the CNAME/DNAME chain?
			 */
			dns_adb_destroyfind(&find);
			fctx->adberr++;
			dns_name_format(name, namebuf, sizeof(namebuf));
			isc_log_write(DNS_LOGCATEGORY_CNAME,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_INFO,
				      "skipping nameserver '%s' because it "
				      "is a CNAME, while resolving '%s'",
				      namebuf, fctx->info);
		}
		fetchctx_detach(&fctx);
		return;
	}

	if (!ISC_LIST_EMPTY(find->list)) {
		/*
		 * We have at least some of the addresses for the
		 * name.
		 */
		INSIST((find->options & DNS_ADBFIND_WANTEVENT) == 0);
		if (flags != 0 || port != 0) {
			ISC_LIST_FOREACH (find->list, ai, publink) {
				ai->flags |= flags;
				if (port != 0) {
					isc_sockaddr_setport(&ai->sockaddr,
							     port);
				}
			}
		}
		if ((flags & FCTX_ADDRINFO_DUALSTACK) != 0) {
			ISC_LIST_APPEND(fctx->altfinds, find, publink);
		} else {
			ISC_LIST_APPEND(fctx->finds, find, publink);
		}
		return;
	}

	/*
	 * We don't know any of the addresses for this name.
	 *
	 * The find may be waiting on a resolver fetch for a server
	 * address. We need to make sure it isn't waiting on *this*
	 * fetch, because if it is, we won't be answering it and it
	 * won't be answering us.
	 */
	if (waiting_for(find, fctx->type) && dns_name_equal(name, fctx->name)) {
		fctx->adberr++;
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_INFO, "loop detected resolving '%s'",
			      fctx->info);

		if ((find->options & DNS_ADBFIND_WANTEVENT) != 0) {
			atomic_fetch_add_relaxed(&fctx->pending, 1);
			dns_adb_cancelfind(find);
		} else {
			dns_adb_destroyfind(&find);
			fetchctx_detach(&fctx);
		}
		return;
	}

	/*
	 * We may be waiting for another fetch to complete, and
	 * we'll get an event later when the find has what it needs.
	 */
	if ((find->options & DNS_ADBFIND_WANTEVENT) != 0) {
		atomic_fetch_add_relaxed(&fctx->pending, 1);

		/*
		 * Bootstrap.
		 */
		if (need_alternate != NULL && !*need_alternate && unshared &&
		    ((res->dispatches4 == NULL &&
		      find->result_v6 != DNS_R_NXDOMAIN) ||
		     (res->dispatches6 == NULL &&
		      find->result_v4 != DNS_R_NXDOMAIN)))
		{
			*need_alternate = true;
		}
		if (no_addresses != NULL) {
			(*no_addresses)++;
		}
		return;
	}

	/*
	 * No addresses and no pending events: the find failed.
	 */
	if ((find->options & DNS_ADBFIND_OVERQUOTA) != 0) {
		if (overquota != NULL) {
			*overquota = true;
		}
		fctx->quotacount++; /* quota exceeded */
	} else {
		fctx->adberr++; /* unreachable server, etc. */
	}

	/*
	 * If we know there are no addresses for the family we are using then
	 * try to add an alternative server.
	 */
	if (need_alternate != NULL && !*need_alternate &&
	    ((res->dispatches4 == NULL && find->result_v6 == DNS_R_NXRRSET) ||
	     (res->dispatches6 == NULL && find->result_v4 == DNS_R_NXRRSET)))
	{
		*need_alternate = true;
	}
	dns_adb_destroyfind(&find);
	fetchctx_detach(&fctx);
}

static bool
isstrictsubdomain(const dns_name_t *name1, const dns_name_t *name2) {
	int order;
	unsigned int nlabels;
	dns_namereln_t namereln;

	namereln = dns_name_fullcompare(name1, name2, &order, &nlabels);
	return namereln == dns_namereln_subdomain;
}

static isc_result_t
fctx_getaddresses(fetchctx_t *fctx) {
	isc_result_t result;
	dns_resolver_t *res;
	isc_stdtime_t now;
	unsigned int stdoptions = 0;
	dns_forwarder_t *fwd;
	dns_adbaddrinfo_t *ai;
	bool all_bad;
	dns_rdata_ns_t ns;
	bool need_alternate = false;
	bool all_spilled = false;
	unsigned int no_addresses = 0;
	unsigned int ns_processed = 0;

	FCTXTRACE5("getaddresses", "fctx->depth=", fctx->depth);

	/*
	 * Don't pound on remote servers.  (Failsafe!)
	 */
	fctx->restarts++;
	if (fctx->restarts > 100) {
		FCTXTRACE("too many restarts");
		return DNS_R_SERVFAIL;
	}

	res = fctx->res;

	if (fctx->depth > res->maxdepth) {
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(3),
			      "too much NS indirection resolving '%s' "
			      "(depth=%u, maxdepth=%u)",
			      fctx->info, fctx->depth, res->maxdepth);
		return DNS_R_SERVFAIL;
	}

	/*
	 * Forwarders.
	 */

	INSIST(ISC_LIST_EMPTY(fctx->forwaddrs));
	INSIST(ISC_LIST_EMPTY(fctx->altaddrs));

	/*
	 * If we have DNS_FETCHOPT_NOFORWARD set and forwarding policy
	 * allows us to not forward - skip forwarders and go straight
	 * to NSes. This is currently used to make sure that priming
	 * query gets root servers' IP addresses in ADDITIONAL section.
	 */
	if ((fctx->options & DNS_FETCHOPT_NOFORWARD) != 0 &&
	    (fctx->fwdpolicy != dns_fwdpolicy_only))
	{
		goto normal_nses;
	}

	/*
	 * If this fctx has forwarders, use them; otherwise use any
	 * selective forwarders specified in the view; otherwise use the
	 * resolver's forwarders (if any).
	 */
	fwd = ISC_LIST_HEAD(fctx->forwarders);
	if (fwd == NULL) {
		dns_forwarders_t *forwarders = NULL;
		dns_name_t *name = fctx->name;
		dns_name_t suffix;

		/*
		 * DS records are found in the parent server.
		 * Strip label to get the correct forwarder (if any).
		 */
		if (dns_rdatatype_atparent(fctx->type) &&
		    dns_name_countlabels(name) > 1)
		{
			unsigned int labels;
			dns_name_init(&suffix);
			labels = dns_name_countlabels(name);
			dns_name_getlabelsequence(name, 1, labels - 1, &suffix);
			name = &suffix;
		}

		result = dns_fwdtable_find(res->view->fwdtable, name,
					   &forwarders);
		if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
			fwd = ISC_LIST_HEAD(forwarders->fwdrs);
			fctx->fwdpolicy = forwarders->fwdpolicy;
			dns_name_copy(&forwarders->name, fctx->fwdname);
			if (fctx->fwdpolicy == dns_fwdpolicy_only &&
			    isstrictsubdomain(&forwarders->name, fctx->domain))
			{
				fcount_decr(fctx);
				dns_name_copy(&forwarders->name, fctx->domain);
				result = fcount_incr(fctx, true);
				if (result != ISC_R_SUCCESS) {
					dns_forwarders_detach(&forwarders);
					return result;
				}
			}
			dns_forwarders_detach(&forwarders);
		}
	}

	while (fwd != NULL) {
		if ((isc_sockaddr_pf(&fwd->addr) == AF_INET &&
		     res->dispatches4 == NULL) ||
		    (isc_sockaddr_pf(&fwd->addr) == AF_INET6 &&
		     res->dispatches6 == NULL))
		{
			fwd = ISC_LIST_NEXT(fwd, link);
			continue;
		}
		ai = NULL;
		result = dns_adb_findaddrinfo(fctx->adb, &fwd->addr, &ai, 0);
		if (result == ISC_R_SUCCESS) {
			dns_adbaddrinfo_t *cur;
			ai->flags |= FCTX_ADDRINFO_FORWARDER;
			if (fwd->tlsname != NULL) {
				result = dns_view_gettransport(
					res->view, DNS_TRANSPORT_TLS,
					fwd->tlsname, &ai->transport);
				if (result != ISC_R_SUCCESS) {
					dns_adb_freeaddrinfo(fctx->adb, &ai);
					goto next;
				}
			}
			cur = ISC_LIST_HEAD(fctx->forwaddrs);
			while (cur != NULL && cur->srtt < ai->srtt) {
				cur = ISC_LIST_NEXT(cur, publink);
			}
			if (cur != NULL) {
				ISC_LIST_INSERTBEFORE(fctx->forwaddrs, cur, ai,
						      publink);
			} else {
				ISC_LIST_APPEND(fctx->forwaddrs, ai, publink);
			}
		}
	next:
		fwd = ISC_LIST_NEXT(fwd, link);
	}

	/*
	 * If the forwarding policy is "only", we don't need the
	 * addresses of the nameservers.
	 */
	if (fctx->fwdpolicy == dns_fwdpolicy_only) {
		goto out;
	}

	/*
	 * Normal nameservers.
	 */
normal_nses:
	stdoptions = DNS_ADBFIND_WANTEVENT | DNS_ADBFIND_EMPTYEVENT;
	if (fctx->restarts == 1) {
		/*
		 * To avoid sending out a flood of queries likely to
		 * result in NXRRSET, we suppress fetches for address
		 * families we don't have the first time through,
		 * provided that we have addresses in some family we
		 * can use.
		 *
		 * We don't want to set this option all the time, since
		 * if fctx->restarts > 1, we've clearly been having
		 * trouble with the addresses we had, so getting more
		 * could help.
		 */
		stdoptions |= DNS_ADBFIND_AVOIDFETCHES;
	}
	if (res->dispatches4 != NULL) {
		stdoptions |= DNS_ADBFIND_INET;
	}
	if (res->dispatches6 != NULL) {
		stdoptions |= DNS_ADBFIND_INET6;
	}

	if ((stdoptions & DNS_ADBFIND_ADDRESSMASK) == 0) {
		return DNS_R_SERVFAIL;
	}

	now = isc_stdtime_now();
	all_spilled = true; /* resets to false below after the first success */

	INSIST(ISC_LIST_EMPTY(fctx->finds));
	INSIST(ISC_LIST_EMPTY(fctx->altfinds));

	DNS_RDATASET_FOREACH (&fctx->nameservers) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		bool overquota = false;
		unsigned int static_stub = 0;

		dns_rdataset_current(&fctx->nameservers, &rdata);
		/*
		 * Extract the name from the NS record.
		 */
		result = dns_rdata_tostruct(&rdata, &ns, NULL);
		if (result != ISC_R_SUCCESS) {
			continue;
		}

		if (STATICSTUB(&fctx->nameservers) &&
		    dns_name_equal(&ns.name, fctx->domain))
		{
			static_stub = DNS_ADBFIND_STATICSTUB;
		}

		if (no_addresses > NS_FAIL_LIMIT &&
		    dns_rdataset_count(&fctx->nameservers) > NS_RR_LIMIT)
		{
			stdoptions |= DNS_ADBFIND_NOFETCH;
		}
		findname(fctx, &ns.name, 0, stdoptions | static_stub, 0, now,
			 &overquota, &need_alternate, &no_addresses);

		if (!overquota) {
			all_spilled = false;
		}

		dns_rdata_reset(&rdata);
		dns_rdata_freestruct(&ns);

		if (++ns_processed >= NS_PROCESSING_LIMIT) {
			break;
		}
	}

	/*
	 * Do we need to use 6 to 4?
	 */
	if (need_alternate) {
		int family;
		family = (res->dispatches6 != NULL) ? AF_INET6 : AF_INET;
		ISC_LIST_FOREACH (res->alternates, a, link) {
			if (!a->isaddress) {
				findname(fctx, &a->_u._n.name, a->_u._n.port,
					 stdoptions, FCTX_ADDRINFO_DUALSTACK,
					 now, NULL, NULL, NULL);
				continue;
			}
			if (isc_sockaddr_pf(&a->_u.addr) != family) {
				continue;
			}
			ai = NULL;
			result = dns_adb_findaddrinfo(fctx->adb, &a->_u.addr,
						      &ai, 0);
			if (result == ISC_R_SUCCESS) {
				dns_adbaddrinfo_t *cur;
				ai->flags |= FCTX_ADDRINFO_FORWARDER;
				ai->flags |= FCTX_ADDRINFO_DUALSTACK;
				cur = ISC_LIST_HEAD(fctx->altaddrs);
				while (cur != NULL && cur->srtt < ai->srtt) {
					cur = ISC_LIST_NEXT(cur, publink);
				}
				if (cur != NULL) {
					ISC_LIST_INSERTBEFORE(fctx->altaddrs,
							      cur, ai, publink);
				} else {
					ISC_LIST_APPEND(fctx->altaddrs, ai,
							publink);
				}
			}
		}
	}

out:
	/*
	 * Mark all known bad servers.
	 */
	all_bad = mark_bad(fctx);

	/*
	 * How are we doing?
	 */
	if (all_bad) {
		/*
		 * We've got no addresses.
		 */
		if (atomic_load_acquire(&fctx->pending) > 0) {
			/*
			 * We're fetching the addresses, but don't have
			 * any yet.   Tell the caller to wait for an
			 * answer.
			 */
			result = DNS_R_WAIT;
		} else {
			/*
			 * We've lost completely.  We don't know any
			 * addresses, and the ADB has told us it can't
			 * get them.
			 */
			FCTXTRACE("no addresses");

			result = ISC_R_FAILURE;

			/*
			 * If all of the addresses found were over the
			 * fetches-per-server quota, increase the ServerQuota
			 * counter and return the configured response.
			 */
			if (all_spilled) {
				result = res->quotaresp[dns_quotatype_server];
				inc_stats(res, dns_resstatscounter_serverquota);
			}

			/*
			 * If we are using a 'forward only' policy, and all
			 * the forwarders are bad, increase the ForwardOnlyFail
			 * counter.
			 */
			if (fctx->fwdpolicy == dns_fwdpolicy_only) {
				inc_stats(res,
					  dns_resstatscounter_forwardonlyfail);
			}
		}
	} else {
		/*
		 * We've found some addresses.  We might still be
		 * looking for more addresses.
		 */
		sort_finds(&fctx->finds, res->view->v6bias);
		sort_finds(&fctx->altfinds, 0);
		result = ISC_R_SUCCESS;
	}

	return result;
}

static void
possibly_mark(fetchctx_t *fctx, dns_adbaddrinfo_t *addr) {
	isc_netaddr_t na;
	isc_sockaddr_t *sa = &addr->sockaddr;
	bool aborted = false;
	bool bogus;
	dns_acl_t *blackhole;
	isc_netaddr_t ipaddr;
	dns_peer_t *peer = NULL;
	dns_resolver_t *res = fctx->res;
	const char *msg = NULL;

	isc_netaddr_fromsockaddr(&ipaddr, sa);
	blackhole = dns_dispatchmgr_getblackhole(res->view->dispatchmgr);
	(void)dns_peerlist_peerbyaddr(res->view->peers, &ipaddr, &peer);

	if (blackhole != NULL) {
		int match;

		if ((dns_acl_match(&ipaddr, NULL, blackhole, res->view->aclenv,
				   &match, NULL) == ISC_R_SUCCESS) &&
		    match > 0)
		{
			aborted = true;
		}
	}

	if (peer != NULL && dns_peer_getbogus(peer, &bogus) == ISC_R_SUCCESS &&
	    bogus)
	{
		aborted = true;
	}

	if (aborted) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring blackholed / bogus server: ";
	} else if (isc_sockaddr_isnetzero(sa)) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring net zero address: ";
	} else if (isc_sockaddr_ismulticast(sa)) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring multicast address: ";
	} else if (isc_sockaddr_isexperimental(sa)) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring experimental address: ";
	} else if (sa->type.sa.sa_family != AF_INET6) {
		return;
	} else if (IN6_IS_ADDR_V4MAPPED(&sa->type.sin6.sin6_addr)) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring IPv6 mapped IPV4 address: ";
	} else if (IN6_IS_ADDR_V4COMPAT(&sa->type.sin6.sin6_addr)) {
		addr->flags |= FCTX_ADDRINFO_MARK;
		msg = "ignoring IPv6 compatibility IPV4 address: ";
	} else {
		return;
	}

	if (isc_log_wouldlog(ISC_LOG_DEBUG(3))) {
		char buf[ISC_NETADDR_FORMATSIZE];
		isc_netaddr_fromsockaddr(&na, sa);
		isc_netaddr_format(&na, buf, sizeof(buf));
		FCTXTRACE2(msg, buf);
	}
}

static dns_adbaddrinfo_t *
fctx_nextaddress(fetchctx_t *fctx) {
	dns_adbfind_t *find = NULL, *start = NULL;
	dns_adbaddrinfo_t *addrinfo = NULL, *faddrinfo = NULL;

	/*
	 * Return the next untried address, if any.
	 */

	/*
	 * Find the first unmarked forwarder (if any).
	 */
	ISC_LIST_FOREACH (fctx->forwaddrs, ai, publink) {
		if (!UNMARKED(ai)) {
			continue;
		}
		possibly_mark(fctx, ai);
		if (UNMARKED(ai)) {
			ai->flags |= FCTX_ADDRINFO_MARK;
			fctx->find = NULL;
			fctx->forwarding = true;

			/*
			 * QNAME minimization is disabled when
			 * forwarding, and has to remain disabled if
			 * we switch back to normal recursion; otherwise
			 * forwarding could leave us in an inconsistent
			 * state.
			 */
			fctx->minimized = false;
			return ai;
		}
	}

	/*
	 * No forwarders.  Move to the next find.
	 */
	fctx->forwarding = false;
	FCTX_ATTR_SET(fctx, FCTX_ATTR_TRIEDFIND);

	find = fctx->find;
	if (find == NULL) {
		find = ISC_LIST_HEAD(fctx->finds);
	} else {
		find = ISC_LIST_NEXT(find, publink);
		if (find == NULL) {
			find = ISC_LIST_HEAD(fctx->finds);
		}
	}

	/*
	 * Find the first unmarked addrinfo.
	 */
	if (find != NULL) {
		start = find;
		do {
			ISC_LIST_FOREACH (find->list, ai, publink) {
				if (!UNMARKED(ai)) {
					continue;
				}
				possibly_mark(fctx, ai);
				if (UNMARKED(ai)) {
					ai->flags |= FCTX_ADDRINFO_MARK;
					faddrinfo = ai;
					break;
				}
			}
			if (faddrinfo != NULL) {
				break;
			}
			find = ISC_LIST_NEXT(find, publink);
			if (find == NULL) {
				find = ISC_LIST_HEAD(fctx->finds);
			}
		} while (find != start);
	}

	fctx->find = find;
	if (faddrinfo != NULL) {
		return faddrinfo;
	}

	/*
	 * No nameservers left.  Try alternates.
	 */

	FCTX_ATTR_SET(fctx, FCTX_ATTR_TRIEDALT);

	find = fctx->altfind;
	if (find == NULL) {
		find = ISC_LIST_HEAD(fctx->altfinds);
	} else {
		find = ISC_LIST_NEXT(find, publink);
		if (find == NULL) {
			find = ISC_LIST_HEAD(fctx->altfinds);
		}
	}

	/*
	 * Find the first unmarked addrinfo.
	 */
	if (find != NULL) {
		start = find;
		do {
			ISC_LIST_FOREACH (find->list, ai, publink) {
				if (!UNMARKED(ai)) {
					continue;
				}
				possibly_mark(fctx, ai);
				if (UNMARKED(ai)) {
					ai->flags |= FCTX_ADDRINFO_MARK;
					faddrinfo = ai;
					break;
				}
			}
			if (faddrinfo != NULL) {
				break;
			}
			find = ISC_LIST_NEXT(find, publink);
			if (find == NULL) {
				find = ISC_LIST_HEAD(fctx->altfinds);
			}
		} while (find != start);
	}

	/*
	 * See if we have a better alternate server by address.
	 */
	ISC_LIST_FOREACH (fctx->altaddrs, ai, publink) {
		if (!UNMARKED(ai)) {
			continue;
		}
		possibly_mark(fctx, ai);
		if (UNMARKED(ai) &&
		    (faddrinfo == NULL || ai->srtt < faddrinfo->srtt))
		{
			if (faddrinfo != NULL) {
				faddrinfo->flags &= ~FCTX_ADDRINFO_MARK;
			}
			ai->flags |= FCTX_ADDRINFO_MARK;
			addrinfo = ai;
			break;
		}
	}

	if (addrinfo == NULL) {
		addrinfo = faddrinfo;
		fctx->altfind = find;
	}

	return addrinfo;
}

static void
fctx_try(fetchctx_t *fctx, bool retrying) {
	isc_result_t result;
	dns_adbaddrinfo_t *addrinfo = NULL;
	dns_resolver_t *res = NULL;

	FCTXTRACE5("try", "fctx->qc=", isc_counter_used(fctx->qc));
	if (fctx->gqc != NULL) {
		FCTXTRACE5("try", "fctx->gqc=", isc_counter_used(fctx->gqc));
	}

	REQUIRE(!ADDRWAIT(fctx));
	REQUIRE(fctx->tid == isc_tid());

	res = fctx->res;

	/* We've already exceeded maximum query count */
	if (isc_counter_used(fctx->qc) > isc_counter_getlimit(fctx->qc)) {
		isc_log_write(
			DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			ISC_LOG_DEBUG(3),
			"exceeded max queries resolving '%s' "
			"(max-recursion-queries, querycount=%u, maxqueries=%u)",
			fctx->info, isc_counter_used(fctx->qc),
			isc_counter_getlimit(fctx->qc));
		result = DNS_R_SERVFAIL;
		goto done;
	}

	if (fctx->gqc != NULL &&
	    isc_counter_used(fctx->gqc) > isc_counter_getlimit(fctx->gqc))
	{
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(3),
			      "exceeded global max queries resolving '%s' "
			      "(max-query-count, querycount=%u, maxqueries=%u)",
			      fctx->info, isc_counter_used(fctx->gqc),
			      isc_counter_getlimit(fctx->gqc));
		result = DNS_R_SERVFAIL;
		goto done;
	}

	addrinfo = fctx_nextaddress(fctx);

	/* Try to find an address that isn't over quota */
	while (addrinfo != NULL && dns_adb_overquota(fctx->adb, addrinfo)) {
		addrinfo = fctx_nextaddress(fctx);
	}

	if (addrinfo == NULL) {
		/* We have no more addresses.  Start over. */
		fctx_cancelqueries(fctx, true, false);
		fctx_cleanup(fctx);
		result = fctx_getaddresses(fctx);
		switch (result) {
		case ISC_R_SUCCESS:
			break;
		case DNS_R_WAIT:
			/* Sleep waiting for addresses. */
			FCTXTRACE("addrwait");
			FCTX_ATTR_SET(fctx, FCTX_ATTR_ADDRWAIT);
			return;
		default:
			goto done;
		}

		addrinfo = fctx_nextaddress(fctx);

		while (addrinfo != NULL &&
		       dns_adb_overquota(fctx->adb, addrinfo))
		{
			addrinfo = fctx_nextaddress(fctx);
		}

		/*
		 * While we may have addresses from the ADB, they
		 * might be bad ones.  In this case, return SERVFAIL.
		 */
		if (addrinfo == NULL) {
			result = DNS_R_SERVFAIL;
			goto done;
		}
	}
	/*
	 * We're minimizing and we're not yet at the final NS -
	 * we need to launch a query for NS for 'upper' domain
	 */
	if (fctx->minimized && !fctx->forwarding) {
		unsigned int options = fctx->options;

		options &= ~DNS_FETCHOPT_QMINIMIZE;

		/*
		 * Is another QNAME minimization fetch still running?
		 */
		if (fctx->qminfetch != NULL) {
			bool validfctx = (DNS_FETCH_VALID(fctx->qminfetch) &&
					  VALID_FCTX(fctx->qminfetch->private));
			char namebuf[DNS_NAME_FORMATSIZE];
			char typebuf[DNS_RDATATYPE_FORMATSIZE];

			dns_name_format(fctx->qminname, namebuf,
					sizeof(namebuf));
			dns_rdatatype_format(fctx->qmintype, typebuf,
					     sizeof(typebuf));
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_ERROR,
				      "fctx %p(%s): attempting QNAME "
				      "minimization fetch for %s/%s but "
				      "fetch %p(%s) still running",
				      fctx, fctx->info, namebuf, typebuf,
				      fctx->qminfetch,
				      validfctx ? fctx->qminfetch->private->info
						: "<invalid>");
			result = DNS_R_SERVFAIL;
			goto done;
		}

		/*
		 * Turn on NOFOLLOW in relaxed mode so that QNAME minimization
		 * doesn't cause additional queries to resolve the target of the
		 * QNAME minimization request when a referral is returned.  This
		 * will also reduce the impact of mis-matched NS RRsets where
		 * the child's NS RRset is garbage.  If a delegation is
		 * discovered DNS_R_DELEGATION will be returned to resume_qmin.
		 */
		if ((options & DNS_FETCHOPT_QMIN_STRICT) == 0) {
			options |= DNS_FETCHOPT_NOFOLLOW;
		}

		fetchctx_ref(fctx);
		result = dns_resolver_createfetch(
			fctx->res, fctx->qminname, fctx->qmintype, fctx->domain,
			&fctx->nameservers, NULL, NULL, 0,
			options | DNS_FETCHOPT_QMINFETCH, 0, fctx->qc,
			fctx->gqc, fctx->loop, resume_qmin, fctx, &fctx->edectx,
			&fctx->qminrrset, &fctx->qminsigrrset,
			&fctx->qminfetch);
		if (result != ISC_R_SUCCESS) {
			fetchctx_unref(fctx);
			goto done;
		}
		return;
	}

	result = isc_counter_increment(fctx->qc);
	if (result != ISC_R_SUCCESS) {
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(3),
			      "exceeded max queries resolving '%s' "
			      "(max-recursion-queries, querycount=%u)",
			      fctx->info, isc_counter_used(fctx->qc));
		goto done;
	}

	if (fctx->gqc != NULL) {
		result = isc_counter_increment(fctx->gqc);
		if (result != ISC_R_SUCCESS) {
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_DEBUG(3),
				      "exceeded global max queries resolving "
				      "'%s' (max-query-count, querycount=%u)",
				      fctx->info, isc_counter_used(fctx->gqc));
			goto done;
		}
	}

	result = fctx_query(fctx, addrinfo, fctx->options);
	if (result != ISC_R_SUCCESS) {
		goto done;
	}
	if (retrying) {
		inc_stats(res, dns_resstatscounter_retry);
	}

done:
	if (result != ISC_R_SUCCESS) {
		fctx_done_detach(&fctx, result);
	}
}

static void
resume_qmin(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	fetchctx_t *fctx = resp->arg;
	dns_resolver_t *res = NULL;
	isc_result_t result;
	unsigned int findoptions = 0;
	dns_name_t *fname = NULL, *dcname = NULL;
	dns_fixedname_t ffixed, dcfixed;
	dns_rdataset_t rdataset;
	dns_rdataset_t sigrdataset;
	dns_db_t *db = NULL;
	dns_dbnode_t *node = NULL;
	bool fixup_result = false;

	REQUIRE(VALID_FCTX(fctx));

	res = fctx->res;

	REQUIRE(fctx->tid == isc_tid());

	FCTXTRACE("resume_qmin");

	fname = dns_fixedname_initname(&ffixed);
	dcname = dns_fixedname_initname(&dcfixed);

	dns_rdataset_init(&rdataset);
	dns_rdataset_init(&sigrdataset);

	if (resp->node != NULL) {
		dns_db_attachnode(resp->db, resp->node, &node);
		dns_db_detachnode(resp->db, &resp->node);
	}
	if (resp->db != NULL) {
		dns_db_attach(resp->db, &db);
		dns_db_detach(&resp->db);
	}

	if (dns_rdataset_isassociated(resp->rdataset)) {
		dns_rdataset_clone(resp->rdataset, &rdataset);
		dns_rdataset_disassociate(resp->rdataset);
	}
	if (dns_rdataset_isassociated(resp->sigrdataset)) {
		dns_rdataset_clone(resp->sigrdataset, &sigrdataset);
		dns_rdataset_disassociate(resp->sigrdataset);
	}
	dns_name_copy(resp->foundname, fname);

	result = resp->result;

	dns_resolver_freefresp(&resp);

	LOCK(&fctx->lock);
	if (SHUTTINGDOWN(fctx)) {
		result = ISC_R_SHUTTINGDOWN;
	}
	UNLOCK(&fctx->lock);

	dns_resolver_destroyfetch(&fctx->qminfetch);

	/*
	 * Beware, the switch() below is little bit tricky - the order of the
	 * branches is important.
	 */
	switch (result) {
	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		goto cleanup;

	case DNS_R_NXDOMAIN:
	case DNS_R_NCACHENXDOMAIN:
	case DNS_R_FORMERR:
	case DNS_R_REMOTEFORMERR:
	case ISC_R_FAILURE:
	case ISC_R_TIMEDOUT:
		if ((fctx->options & DNS_FETCHOPT_QMIN_STRICT) != 0) {
			/* These results cause a hard fail in strict mode */
			goto cleanup;
		}

		if (result == DNS_R_NXDOMAIN &&
		    fctx->qmin_labels == dns_name_countlabels(fctx->name))
		{
			LOCK(&fctx->lock);
			resp = ISC_LIST_HEAD(fctx->resps);
			if (resp != NULL) {
				if (dns_rdataset_isassociated(&rdataset)) {
					dns_rdataset_clone(&rdataset,
							   resp->rdataset);
				}
				if (dns_rdataset_isassociated(&sigrdataset) &&
				    resp->sigrdataset != NULL)
				{
					dns_rdataset_clone(&sigrdataset,
							   resp->sigrdataset);
				}
				if (db != NULL) {
					dns_db_attach(db, &resp->db);
				}
				if (node != NULL) {
					dns_db_attachnode(db, node,
							  &resp->node);
				}
				dns_name_copy(fname, resp->foundname);
				clone_results(fctx);
				UNLOCK(&fctx->lock);
				goto cleanup;
			}
			UNLOCK(&fctx->lock);
		}

		/* ...or disable minimization in relaxed mode */
		fctx->qmin_labels = DNS_NAME_MAXLABELS;

		/*
		 * We store the result. If we succeed in the end
		 * we'll issue a warning that the server is
		 * broken.
		 */
		fctx->qmin_warning = result;
		break;

	case ISC_R_SUCCESS:
	case DNS_R_DELEGATION:
	case DNS_R_NXRRSET:
	case DNS_R_NCACHENXRRSET:
	case DNS_R_CNAME:
	case DNS_R_DNAME:
		/*
		 * We have previously detected a possible error of an
		 * incorrect NXDOMAIN and now have a response that
		 * indicates that it was an actual error.
		 */
		if (fctx->qmin_warning == DNS_R_NCACHENXDOMAIN ||
		    fctx->qmin_warning == DNS_R_NXDOMAIN)
		{
			fctx->force_qmin_warning = true;
		}

		/*
		 * We have got a CNAME or DNAME respone to the NS query
		 * so we are done in almost all cases.
		 */
		if ((result == DNS_R_CNAME || result == DNS_R_DNAME) &&
		    fctx->qmin_labels == dns_name_countlabels(fctx->name) &&
		    fctx->type != dns_rdatatype_key &&
		    fctx->type != dns_rdatatype_nsec &&
		    fctx->type != dns_rdatatype_any &&
		    fctx->type != dns_rdatatype_sig &&
		    fctx->type != dns_rdatatype_rrsig)
		{
			LOCK(&fctx->lock);
			resp = ISC_LIST_HEAD(fctx->resps);
			if (resp != NULL) {
				if (dns_rdataset_isassociated(&rdataset)) {
					dns_rdataset_clone(&rdataset,
							   resp->rdataset);
				}
				if (dns_rdataset_isassociated(&sigrdataset) &&
				    resp->sigrdataset != NULL)
				{
					dns_rdataset_clone(&sigrdataset,
							   resp->sigrdataset);
				}
				if (db != NULL) {
					dns_db_attach(db, &resp->db);
				}
				if (node != NULL) {
					dns_db_attachnode(db, node,
							  &resp->node);
				}
				dns_name_copy(fname, resp->foundname);
				if (result == DNS_R_CNAME &&
				    dns_rdataset_isassociated(&rdataset) &&
				    fctx->type == dns_rdatatype_cname)
				{
					fixup_result = true;
				}
				clone_results(fctx);
				UNLOCK(&fctx->lock);
				goto cleanup;
			}
			UNLOCK(&fctx->lock);
		}

		/*
		 * Any other result will *not* cause a failure in strict
		 * mode, or cause minimization to be disabled in relaxed
		 * mode.
		 *
		 * If DNS_R_DELEGATION is set here, it implies that
		 * DNS_FETCHOPT_NOFOLLOW was set, and a delegation was
		 * discovered but not followed; we will do so now.
		 */
		break;

	default:
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(5),
			      "QNAME minimization: unexpected result %s",
			      isc_result_totext(result));
		break;
	}

	if (dns_rdataset_isassociated(&fctx->nameservers)) {
		dns_rdataset_disassociate(&fctx->nameservers);
	}

	if (dns_rdatatype_atparent(fctx->type)) {
		findoptions |= DNS_DBFIND_NOEXACT;
	}
	result = dns_view_findzonecut(res->view, fctx->name, fname, dcname,
				      fctx->now, findoptions, true, true,
				      &fctx->nameservers, NULL);
	FCTXTRACEN("resume_qmin findzonecut", fname, result);

	/*
	 * DNS_R_NXDOMAIN here means we have not loaded the root zone
	 * mirror yet - but DNS_R_NXDOMAIN is not a valid return value
	 * when doing recursion, we need to patch it.
	 *
	 * CNAME or DNAME means zone were added with that record
	 * after the start of a recursion. It means we do not have
	 * initialized correct hevent->foundname and have to fail.
	 */
	if (result == DNS_R_NXDOMAIN || result == DNS_R_CNAME ||
	    result == DNS_R_DNAME)
	{
		result = DNS_R_SERVFAIL;
	}

	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}
	fcount_decr(fctx);

	dns_name_copy(fname, fctx->domain);

	result = fcount_incr(fctx, false);
	if (result != ISC_R_SUCCESS) {
		goto cleanup;
	}

	dns_name_copy(dcname, fctx->qmindcname);
	fctx->ns_ttl = fctx->nameservers.ttl;
	fctx->ns_ttl_ok = true;

	fctx_minimize_qname(fctx);

	if (!fctx->minimized) {
		/*
		 * We have finished minimizing, but fctx->finds was
		 * filled at the beginning of the run - now we need to
		 * clear it before sending the final query to use proper
		 * nameservers.
		 */
		fctx_cancelqueries(fctx, false, false);
		fctx_cleanup(fctx);
	}

	fctx_try(fctx, true);

cleanup:
	if (node != NULL) {
		dns_db_detachnode(db, &node);
	}
	if (db != NULL) {
		dns_db_detach(&db);
	}
	if (dns_rdataset_isassociated(&rdataset)) {
		dns_rdataset_disassociate(&rdataset);
	}
	if (dns_rdataset_isassociated(&sigrdataset)) {
		dns_rdataset_disassociate(&sigrdataset);
	}
	if (result != ISC_R_SUCCESS) {
		/* An error occurred, tear down whole fctx */
		fctx_done_unref(fctx, fixup_result ? ISC_R_SUCCESS : result);
	}
	fetchctx_detach(&fctx);
}

static void
fctx_destroy(fetchctx_t *fctx) {
	dns_resolver_t *res = NULL;

	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(ISC_LIST_EMPTY(fctx->resps));
	REQUIRE(ISC_LIST_EMPTY(fctx->queries));
	REQUIRE(ISC_LIST_EMPTY(fctx->finds));
	REQUIRE(ISC_LIST_EMPTY(fctx->altfinds));
	REQUIRE(atomic_load_acquire(&fctx->pending) == 0);
	REQUIRE(ISC_LIST_EMPTY(fctx->validators));
	REQUIRE(fctx->state != fetchstate_active);

	FCTXTRACE("destroy");

	fctx->magic = 0;

	res = fctx->res;

	dec_stats(res, dns_resstatscounter_nfetch);

	/* Free bad */
	ISC_LIST_FOREACH (fctx->bad, sa, link) {
		ISC_LIST_UNLINK(fctx->bad, sa, link);
		isc_mem_put(fctx->mctx, sa, sizeof(*sa));
	}

	ISC_LIST_FOREACH (fctx->edns, tried, link) {
		ISC_LIST_UNLINK(fctx->edns, tried, link);
		isc_mem_put(fctx->mctx, tried, sizeof(*tried));
	}

	if (fctx->nfails != NULL) {
		isc_counter_detach(&fctx->nfails);
	}
	if (fctx->nvalidations != NULL) {
		isc_counter_detach(&fctx->nvalidations);
	}
	isc_counter_detach(&fctx->qc);
	if (fctx->gqc != NULL) {
		isc_counter_detach(&fctx->gqc);
	}
	fcount_decr(fctx);
	dns_message_detach(&fctx->qmessage);
	if (dns_rdataset_isassociated(&fctx->nameservers)) {
		dns_rdataset_disassociate(&fctx->nameservers);
	}
	dns_db_detach(&fctx->cache);
	dns_adb_detach(&fctx->adb);

	dns_resolver_detach(&fctx->res);

	dns_ede_invalidate(&fctx->edectx);

	isc_mutex_destroy(&fctx->lock);

	isc_mem_free(fctx->mctx, fctx->info);
	isc_mem_putanddetach(&fctx->mctx, fctx, sizeof(*fctx));
}

static void
fctx_expired(void *arg) {
	fetchctx_t *fctx = (fetchctx_t *)arg;

	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->tid == isc_tid());

	FCTXTRACE(isc_result_totext(ISC_R_TIMEDOUT));
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_INFO, "gave up on resolving '%s'", fctx->info);

	dns_ede_add(&fctx->edectx, DNS_EDE_NOREACHABLEAUTH, NULL);

	fctx_done_detach(&fctx, DNS_R_SERVFAIL);
}

static void
fctx_shutdown(void *arg) {
	fetchctx_t *fctx = arg;

	REQUIRE(VALID_FCTX(fctx));

	fctx_done_unref(fctx, ISC_R_SHUTTINGDOWN);
	fetchctx_detach(&fctx);
}

static void
fctx_start(void *arg) {
	fetchctx_t *fctx = (fetchctx_t *)arg;

	REQUIRE(VALID_FCTX(fctx));

	FCTXTRACE("start");

	LOCK(&fctx->lock);
	if (SHUTTINGDOWN(fctx)) {
		UNLOCK(&fctx->lock);
		goto detach;
	}

	/*
	 * Normal fctx startup.
	 */
	fctx->state = fetchstate_active;
	UNLOCK(&fctx->lock);

	/*
	 * As a backstop, we also set a timer to stop the fetch
	 * if in-band netmgr timeouts don't work. It will fire two
	 * seconds after the fetch should have finished. (This
	 * should be enough of a gap to avoid the timer firing
	 * while a response is being processed normally.)
	 */
	fctx_starttimer(fctx);
	fctx_try(fctx, false);

detach:
	fetchctx_detach(&fctx);
}

/*
 * Fetch Creation, Joining, and Cancellation.
 */

static void
fctx_add_event(fetchctx_t *fctx, isc_loop_t *loop, const isc_sockaddr_t *client,
	       dns_messageid_t id, isc_job_cb cb, void *arg,
	       dns_edectx_t *edectx, dns_rdataset_t *rdataset,
	       dns_rdataset_t *sigrdataset, dns_fetch_t *fetch) {
	dns_fetchresponse_t *resp = NULL;

	FCTXTRACE("addevent");

	resp = isc_mem_get(fctx->mctx, sizeof(*resp));
	*resp = (dns_fetchresponse_t){
		.result = DNS_R_SERVFAIL,
		.qtype = fctx->type,
		.rdataset = rdataset,
		.sigrdataset = sigrdataset,
		.fetch = fetch,
		.client = client,
		.id = id,
		.loop = loop,
		.cb = cb,
		.arg = arg,
		.link = ISC_LINK_INITIALIZER,
		.edectx = edectx,
	};
	isc_mem_attach(fctx->mctx, &resp->mctx);

	resp->foundname = dns_fixedname_initname(&resp->fname);

	/*
	 * Store the sigrdataset in the first resp in case it is needed
	 * by any of the events.
	 */
	if (resp->sigrdataset != NULL) {
		ISC_LIST_PREPEND(fctx->resps, resp, link);
	} else {
		ISC_LIST_APPEND(fctx->resps, resp, link);
	}
}

static void
fctx_join(fetchctx_t *fctx, isc_loop_t *loop, const isc_sockaddr_t *client,
	  dns_messageid_t id, isc_job_cb cb, void *arg, dns_edectx_t *edectx,
	  dns_rdataset_t *rdataset, dns_rdataset_t *sigrdataset,
	  dns_fetch_t *fetch) {
	FCTXTRACE("join");

	REQUIRE(!SHUTTINGDOWN(fctx));

	fctx_add_event(fctx, loop, client, id, cb, arg, edectx, rdataset,
		       sigrdataset, fetch);

	fetch->magic = DNS_FETCH_MAGIC;
	fetchctx_attach(fctx, &fetch->private);
}

static void
log_ns_ttl(fetchctx_t *fctx, const char *where) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char domainbuf[DNS_NAME_FORMATSIZE];

	dns_name_format(fctx->name, namebuf, sizeof(namebuf));
	dns_name_format(fctx->domain, domainbuf, sizeof(domainbuf));
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_DEBUG(10),
		      "log_ns_ttl: fctx %p: %s: %s (in '%s'?): %u %u", fctx,
		      where, namebuf, domainbuf, fctx->ns_ttl_ok, fctx->ns_ttl);
}

static isc_result_t
fctx_create(dns_resolver_t *res, isc_loop_t *loop, const dns_name_t *name,
	    dns_rdatatype_t type, const dns_name_t *domain,
	    dns_rdataset_t *nameservers, const isc_sockaddr_t *client,
	    unsigned int options, unsigned int depth, isc_counter_t *qc,
	    isc_counter_t *gqc, fetchctx_t **fctxp) {
	fetchctx_t *fctx = NULL;
	isc_result_t result;
	isc_result_t iresult;
	isc_interval_t interval;
	unsigned int findoptions = 0;
	char buf[DNS_NAME_FORMATSIZE + DNS_RDATATYPE_FORMATSIZE + 1];
	isc_mem_t *mctx = isc_loop_getmctx(loop);
	size_t p;
	uint32_t nvalidations = atomic_load_relaxed(&res->maxvalidations);
	uint32_t nfails = atomic_load_relaxed(&res->maxvalidationfails);

	/*
	 * Caller must be holding the lock for 'bucket'
	 */
	REQUIRE(fctxp != NULL && *fctxp == NULL);

	fctx = isc_mem_get(mctx, sizeof(*fctx));
	*fctx = (fetchctx_t){
		.type = type,
		.qmintype = type,
		.options = options,
		.tid = isc_tid(),
		.state = fetchstate_active,
		.depth = depth,
		.qmin_labels = 1,
		.fwdpolicy = dns_fwdpolicy_none,
		.result = ISC_R_FAILURE,
		.loop = loop,
	};

	isc_mem_attach(mctx, &fctx->mctx);
	dns_resolver_attach(res, &fctx->res);

	isc_mutex_init(&fctx->lock);

	dns_ede_init(fctx->mctx, &fctx->edectx);

	/*
	 * Make fctx->info point to a copy of a formatted string
	 * "name/type". FCTXTRACE won't work until this is done.
	 */
	dns_name_format(name, buf, sizeof(buf));
	p = strlcat(buf, "/", sizeof(buf));
	INSIST(p + DNS_RDATATYPE_FORMATSIZE < sizeof(buf));
	dns_rdatatype_format(type, buf + p, sizeof(buf) - p);
	fctx->info = isc_mem_strdup(fctx->mctx, buf);

	FCTXTRACE("create");

	if (nfails > 0) {
		isc_counter_create(mctx, nfails, &fctx->nfails);
	}

	if (nvalidations > 0) {
		isc_counter_create(mctx, nvalidations, &fctx->nvalidations);
	}

	if (qc != NULL) {
		isc_counter_attach(qc, &fctx->qc);
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(9),
			      "fctx %p(%s): attached to counter %p (%d)", fctx,
			      fctx->info, fctx->qc, isc_counter_used(fctx->qc));
	} else {
		isc_counter_create(fctx->mctx, res->maxqueries, &fctx->qc);
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(9),
			      "fctx %p(%s): created counter %p", fctx,
			      fctx->info, fctx->qc);
	}

	if (gqc != NULL) {
		isc_counter_attach(gqc, &fctx->gqc);
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(9),
			      "fctx %p(%s): attached to counter %p (%d)", fctx,
			      fctx->info, fctx->gqc,
			      isc_counter_used(fctx->gqc));
	}

#if DNS_RESOLVER_TRACE
	fprintf(stderr, "fetchctx__init:%s:%s:%d:%p:%p->references = 1\n",
		__func__, __FILE__, __LINE__, fctx, fctx);
#endif
	isc_refcount_init(&fctx->references, 1);

	ISC_LIST_INIT(fctx->queries);
	ISC_LIST_INIT(fctx->finds);
	ISC_LIST_INIT(fctx->altfinds);
	ISC_LIST_INIT(fctx->forwaddrs);
	ISC_LIST_INIT(fctx->altaddrs);
	ISC_LIST_INIT(fctx->forwarders);
	ISC_LIST_INIT(fctx->bad);
	ISC_LIST_INIT(fctx->edns);
	ISC_LIST_INIT(fctx->validators);

	atomic_init(&fctx->attributes, 0);

	fctx->name = dns_fixedname_initname(&fctx->fname);
	fctx->nsname = dns_fixedname_initname(&fctx->nsfname);
	fctx->domain = dns_fixedname_initname(&fctx->dfname);
	fctx->qminname = dns_fixedname_initname(&fctx->qminfname);
	fctx->qmindcname = dns_fixedname_initname(&fctx->qmindcfname);
	fctx->fwdname = dns_fixedname_initname(&fctx->fwdfname);

	dns_name_copy(name, fctx->name);
	dns_name_copy(name, fctx->qminname);

	dns_rdataset_init(&fctx->nameservers);
	dns_rdataset_init(&fctx->qminrrset);
	dns_rdataset_init(&fctx->qminsigrrset);
	dns_rdataset_init(&fctx->nsrrset);

	fctx->start = isc_time_now();
	fctx->now = (isc_stdtime_t)fctx->start.seconds;

	if (client != NULL) {
		isc_sockaddr_format(client, fctx->clientstr,
				    sizeof(fctx->clientstr));
	} else {
		strlcpy(fctx->clientstr, "<unknown>", sizeof(fctx->clientstr));
	}

	if (domain == NULL) {
		dns_forwarders_t *forwarders = NULL;
		unsigned int labels;
		const dns_name_t *fwdname = name;
		dns_name_t suffix;

		/*
		 * DS records are found in the parent server. Strip one
		 * leading label from the name (to be used in finding
		 * the forwarder).
		 */
		if (dns_rdatatype_atparent(fctx->type) &&
		    dns_name_countlabels(name) > 1)
		{
			dns_name_init(&suffix);
			labels = dns_name_countlabels(name);
			dns_name_getlabelsequence(name, 1, labels - 1, &suffix);
			fwdname = &suffix;
		}

		/* Find the forwarder for this name. */
		result = dns_fwdtable_find(fctx->res->view->fwdtable, fwdname,
					   &forwarders);
		if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
			fctx->fwdpolicy = forwarders->fwdpolicy;
			dns_name_copy(&forwarders->name, fctx->fwdname);
			dns_forwarders_detach(&forwarders);
		}

		if (fctx->fwdpolicy == dns_fwdpolicy_only) {
			/*
			 * We're in forward-only mode.  Set the query
			 * domain.
			 */
			dns_name_copy(fctx->fwdname, fctx->domain);
			dns_name_copy(fctx->fwdname, fctx->qmindcname);
			/*
			 * Disable query minimization
			 */
			options &= ~DNS_FETCHOPT_QMINIMIZE;
		} else {
			dns_fixedname_t dcfixed;
			dns_name_t *dcname = dns_fixedname_initname(&dcfixed);

			/*
			 * The caller didn't supply a query domain and
			 * nameservers, and we're not in forward-only
			 * mode, so find the best nameservers to use.
			 */
			if (dns_rdatatype_atparent(fctx->type)) {
				findoptions |= DNS_DBFIND_NOEXACT;
			}
			result = dns_view_findzonecut(
				res->view, name, fctx->fwdname, dcname,
				fctx->now, findoptions, true, true,
				&fctx->nameservers, NULL);
			if (result != ISC_R_SUCCESS) {
				goto cleanup_nameservers;
			}

			dns_name_copy(fctx->fwdname, fctx->domain);
			dns_name_copy(dcname, fctx->qmindcname);
			fctx->ns_ttl = fctx->nameservers.ttl;
			fctx->ns_ttl_ok = true;
		}
	} else {
		dns_name_copy(domain, fctx->domain);
		dns_name_copy(domain, fctx->qmindcname);
		dns_rdataset_clone(nameservers, &fctx->nameservers);
		fctx->ns_ttl = fctx->nameservers.ttl;
		fctx->ns_ttl_ok = true;
	}

	/*
	 * Exempt prefetch queries from the fetches-per-zone quota check
	 * also exempt QMIN fetches as the calling fetch has already
	 * successfully called fcount_incr for this zone.
	 */
	if ((fctx->options & DNS_FETCHOPT_PREFETCH) == 0 &&
	    (fctx->options & DNS_FETCHOPT_QMINFETCH) == 0)
	{
		/*
		 * Are there too many simultaneous queries for this domain?
		 */
		result = fcount_incr(fctx, false);
		if (result != ISC_R_SUCCESS) {
			result = fctx->res->quotaresp[dns_quotatype_zone];
			inc_stats(res, dns_resstatscounter_zonequota);
			goto cleanup_nameservers;
		}
	}

	log_ns_ttl(fctx, "fctx_create");

	if (!dns_name_issubdomain(fctx->name, fctx->domain)) {
		dns_name_format(fctx->domain, buf, sizeof(buf));
		UNEXPECTED_ERROR("'%s' is not subdomain of '%s'", fctx->info,
				 buf);
		result = ISC_R_UNEXPECTED;
		goto cleanup_fcount;
	}

	dns_message_create(fctx->mctx, fctx->res->namepools[fctx->tid],
			   fctx->res->rdspools[fctx->tid],
			   DNS_MESSAGE_INTENTRENDER, &fctx->qmessage);

	/*
	 * Compute an expiration time for the entire fetch.
	 */
	isc_interval_set(&interval, res->query_timeout / 1000,
			 res->query_timeout % 1000 * 1000000);
	iresult = isc_time_nowplusinterval(&fctx->expires, &interval);
	if (iresult != ISC_R_SUCCESS) {
		UNEXPECTED_ERROR("isc_time_nowplusinterval: %s",
				 isc_result_totext(iresult));
		result = ISC_R_UNEXPECTED;
		goto cleanup_qmessage;
	}

	/*
	 * Default retry interval initialization.  We set the interval
	 * now mostly so it won't be uninitialized.  It will be set to
	 * the correct value before a query is issued.
	 */
	isc_interval_set(&fctx->interval, 2, 0);

	/*
	 * Attach to the view's cache and adb.
	 */
	dns_db_attach(res->view->cachedb, &fctx->cache);
	dns_view_getadb(res->view, &fctx->adb);

	ISC_LIST_INIT(fctx->resps);
	fctx->magic = FCTX_MAGIC;

	/*
	 * If qname minimization is enabled we need to trim
	 * the name in fctx to proper length.
	 */
	if ((options & DNS_FETCHOPT_QMINIMIZE) != 0) {
		fctx->ip6arpaskip = (options & DNS_FETCHOPT_QMIN_SKIP_IP6A) !=
					    0 &&
				    dns_name_issubdomain(fctx->name, &ip6_arpa);
		fctx_minimize_qname(fctx);
	}

	inc_stats(res, dns_resstatscounter_nfetch);

	isc_timer_create(fctx->loop, fctx_expired, fctx, &fctx->timer);

	*fctxp = fctx;

	return ISC_R_SUCCESS;

cleanup_qmessage:
	dns_message_detach(&fctx->qmessage);

cleanup_fcount:
	fcount_decr(fctx);

cleanup_nameservers:
	if (dns_rdataset_isassociated(&fctx->nameservers)) {
		dns_rdataset_disassociate(&fctx->nameservers);
	}
	isc_mem_free(fctx->mctx, fctx->info);
	if (fctx->nfails != NULL) {
		isc_counter_detach(&fctx->nfails);
	}
	if (fctx->nvalidations != NULL) {
		isc_counter_detach(&fctx->nvalidations);
	}
	isc_counter_detach(&fctx->qc);
	if (fctx->gqc != NULL) {
		isc_counter_detach(&fctx->gqc);
	}

	dns_resolver_detach(&fctx->res);
	isc_mem_putanddetach(&fctx->mctx, fctx, sizeof(*fctx));

	return result;
}

/*
 * Handle Responses
 */
static bool
is_lame(fetchctx_t *fctx, dns_message_t *message) {
	if (message->rcode != dns_rcode_noerror &&
	    message->rcode != dns_rcode_yxdomain &&
	    message->rcode != dns_rcode_nxdomain)
	{
		return false;
	}

	if (message->counts[DNS_SECTION_ANSWER] != 0) {
		return false;
	}

	if (message->counts[DNS_SECTION_AUTHORITY] == 0) {
		return false;
	}

	MSG_SECTION_FOREACH (message, DNS_SECTION_AUTHORITY, name) {
		ISC_LIST_FOREACH (name->list, rdataset, link) {
			dns_namereln_t namereln;
			int order;
			unsigned int labels;
			if (rdataset->type != dns_rdatatype_ns) {
				continue;
			}
			namereln = dns_name_fullcompare(name, fctx->domain,
							&order, &labels);
			if (namereln == dns_namereln_equal &&
			    (message->flags & DNS_MESSAGEFLAG_AA) != 0)
			{
				return false;
			}
			if (namereln == dns_namereln_subdomain) {
				return false;
			}
			return true;
		}
	}

	return false;
}

static void
log_lame(fetchctx_t *fctx, dns_adbaddrinfo_t *addrinfo) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char domainbuf[DNS_NAME_FORMATSIZE];
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];

	dns_name_format(fctx->name, namebuf, sizeof(namebuf));
	dns_name_format(fctx->domain, domainbuf, sizeof(domainbuf));
	isc_sockaddr_format(&addrinfo->sockaddr, addrbuf, sizeof(addrbuf));
	isc_log_write(DNS_LOGCATEGORY_LAME_SERVERS, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_INFO, "lame server resolving '%s' (in '%s'?): %s",
		      namebuf, domainbuf, addrbuf);
}

static void
log_formerr(fetchctx_t *fctx, const char *format, ...) {
	char nsbuf[ISC_SOCKADDR_FORMATSIZE];
	char msgbuf[2048];
	va_list args;

	va_start(args, format);
	vsnprintf(msgbuf, sizeof(msgbuf), format, args);
	va_end(args);

	isc_sockaddr_format(&fctx->addrinfo->sockaddr, nsbuf, sizeof(nsbuf));

	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_NOTICE,
		      "DNS format error from %s resolving %s for %s: %s", nsbuf,
		      fctx->info, fctx->clientstr, msgbuf);
}

static isc_result_t
same_question(fetchctx_t *fctx, dns_message_t *message) {
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset = NULL;

	/*
	 * Caller must be holding the fctx lock.
	 */

	/*
	 * XXXRTH  Currently we support only one question.
	 */
	if (message->counts[DNS_SECTION_QUESTION] == 0) {
		if ((message->flags & DNS_MESSAGEFLAG_TC) != 0) {
			/*
			 * If TC=1 and the question section is empty, we
			 * accept the reply message as a truncated
			 * answer, to be retried over TCP.
			 *
			 * It is really a FORMERR condition, but this is
			 * a workaround to accept replies from some
			 * implementations.
			 *
			 * Because the question section matching is not
			 * performed, the worst that could happen is
			 * that an attacker who gets past the ID and
			 * source port checks can force the use of
			 * TCP. This is considered an acceptable risk.
			 */
			log_formerr(fctx, "empty question section, "
					  "accepting it anyway as TC=1");
			return ISC_R_SUCCESS;
		} else {
			log_formerr(fctx, "empty question section");
			return DNS_R_FORMERR;
		}
	} else if (message->counts[DNS_SECTION_QUESTION] > 1) {
		log_formerr(fctx, "too many questions");
		return DNS_R_FORMERR;
	}

	if (ISC_LIST_EMPTY(message->sections[DNS_SECTION_QUESTION])) {
		return ISC_R_NOMORE;
	}
	name = ISC_LIST_HEAD(message->sections[DNS_SECTION_QUESTION]);
	rdataset = ISC_LIST_HEAD(name->list);
	INSIST(rdataset != NULL);
	INSIST(ISC_LIST_NEXT(rdataset, link) == NULL);

	if (fctx->type != rdataset->type ||
	    fctx->res->rdclass != rdataset->rdclass ||
	    !dns_name_equal(fctx->name, name))
	{
		char namebuf[DNS_NAME_FORMATSIZE];
		char classbuf[DNS_RDATACLASS_FORMATSIZE];
		char typebuf[DNS_RDATATYPE_FORMATSIZE];

		dns_name_format(name, namebuf, sizeof(namebuf));
		dns_rdataclass_format(rdataset->rdclass, classbuf,
				      sizeof(classbuf));
		dns_rdatatype_format(rdataset->type, typebuf, sizeof(typebuf));
		log_formerr(fctx, "question section mismatch: got %s/%s/%s",
			    namebuf, classbuf, typebuf);
		return DNS_R_FORMERR;
	}

	return ISC_R_SUCCESS;
}

static void
clone_results(fetchctx_t *fctx) {
	dns_fetchresponse_t *hresp = NULL;

	FCTXTRACE("clone_results");

	/*
	 * Set up any other resps to have the same data as the first.
	 *
	 * Caller must be holding the appropriate lock.
	 */

	fctx->cloned = true;

	ISC_LIST_FOREACH (fctx->resps, resp, link) {
		/* This is the head resp; keep a pointer and move on */
		if (hresp == NULL) {
			hresp = ISC_LIST_HEAD(fctx->resps);
			FCTXTRACEN("clone_results", hresp->foundname,
				   hresp->result);
			continue;
		}

		resp->result = hresp->result;
		dns_name_copy(hresp->foundname, resp->foundname);
		dns_db_attach(hresp->db, &resp->db);
		dns_db_attachnode(hresp->db, hresp->node, &resp->node);

		INSIST(hresp->rdataset != NULL);
		INSIST(resp->rdataset != NULL);
		if (dns_rdataset_isassociated(hresp->rdataset)) {
			dns_rdataset_clone(hresp->rdataset, resp->rdataset);
		}

		INSIST(!(hresp->sigrdataset == NULL &&
			 resp->sigrdataset != NULL));
		if (hresp->sigrdataset != NULL &&
		    dns_rdataset_isassociated(hresp->sigrdataset) &&
		    resp->sigrdataset != NULL)
		{
			dns_rdataset_clone(hresp->sigrdataset,
					   resp->sigrdataset);
		}
	}
}

#define CACHE(r)      (((r)->attributes.cache))
#define ANSWER(r)     (((r)->attributes.answer))
#define ANSWERSIG(r)  (((r)->attributes.answersig))
#define EXTERNAL(r)   (((r)->attributes.external))
#define CHAINING(r)   (((r)->attributes.chaining))
#define CHASE(r)      (((r)->attributes.chase))
#define CHECKNAMES(r) (((r)->attributes.checknames))

/*
 * Cancel validators associated with '*fctx' if it is ready to be
 * destroyed (i.e., no queries waiting for it and no pending ADB finds).
 * Caller must hold fctx bucket lock.
 *
 * Requires:
 *      '*fctx' is shutting down.
 */
static void
maybe_cancel_validators(fetchctx_t *fctx) {
	if (atomic_load_acquire(&fctx->pending) != 0 ||
	    atomic_load_acquire(&fctx->nqueries) != 0)
	{
		return;
	}

	REQUIRE(SHUTTINGDOWN(fctx));
	ISC_LIST_FOREACH (fctx->validators, validator, link) {
		dns_validator_cancel(validator);
	}
}

/*
 * typemap with just RRSIG(46) and NSEC(47) bits set.
 *
 * Bitmap calculation from dns_nsec_setbit:
 *
 *					46	47
 *	shift = 7 - (type % 8);		0	1
 *	mask = 1 << shift;		0x02	0x01
 *	array[type / 8] |= mask;
 *
 * Window (0), bitmap length (6), and bitmap.
 */
static const unsigned char minimal_typemap[] = { 0, 6, 0, 0, 0, 0, 0, 0x03 };

static bool
is_minimal_nsec(dns_rdataset_t *nsecset) {
	dns_rdataset_t rdataset = DNS_RDATASET_INIT;

	dns_rdataset_clone(nsecset, &rdataset);

	DNS_RDATASET_FOREACH (&rdataset) {
		isc_result_t result;
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_nsec_t nsec;

		dns_rdataset_current(&rdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &nsec, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);

		if (nsec.len == sizeof(minimal_typemap) &&
		    memcmp(nsec.typebits, minimal_typemap, nsec.len) == 0)
		{
			dns_rdataset_disassociate(&rdataset);
			return true;
		}
	}
	dns_rdataset_disassociate(&rdataset);
	return false;
}

/*
 * If there is a SOA record in the type map then there must be a DNSKEY.
 */
static bool
check_soa_and_dnskey(dns_rdataset_t *nsecset) {
	dns_rdataset_t rdataset = DNS_RDATASET_INIT;

	dns_rdataset_clone(nsecset, &rdataset);

	DNS_RDATASET_FOREACH (&rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(&rdataset, &rdata);
		if (dns_nsec_typepresent(&rdata, dns_rdatatype_soa) &&
		    (!dns_nsec_typepresent(&rdata, dns_rdatatype_dnskey) ||
		     !dns_nsec_typepresent(&rdata, dns_rdatatype_ns)))
		{
			dns_rdataset_disassociate(&rdataset);
			return false;
		}
	}
	dns_rdataset_disassociate(&rdataset);
	return true;
}

/*
 * Look for NSEC next name that starts with the label '\000'.
 */
static bool
has_000_label(dns_rdataset_t *nsecset) {
	dns_rdataset_t rdataset = DNS_RDATASET_INIT;

	dns_rdataset_clone(nsecset, &rdataset);

	DNS_RDATASET_FOREACH (&rdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(&rdataset, &rdata);
		if (rdata.length > 1 && rdata.data[0] == 1 &&
		    rdata.data[1] == 0)
		{
			dns_rdataset_disassociate(&rdataset);
			return true;
		}
	}
	dns_rdataset_disassociate(&rdataset);
	return false;
}

/*
 * The validator has finished.
 */
static void
validated(void *arg) {
	dns_validator_t *val = (dns_validator_t *)arg;
	dns_validator_t *nextval = NULL;
	dns_adbaddrinfo_t *addrinfo = NULL;
	dns_dbnode_t *node = NULL;
	dns_dbnode_t *nsnode = NULL;
	dns_fetchresponse_t *hresp = NULL;
	dns_rdataset_t *ardataset = NULL;
	dns_rdataset_t *asigrdataset = NULL;
	dns_resolver_t *res = NULL;
	dns_valarg_t *valarg = NULL;
	fetchctx_t *fctx = NULL;
	bool chaining;
	bool negative;
	bool sentresponse;
	isc_result_t eresult = ISC_R_SUCCESS;
	isc_result_t result = ISC_R_SUCCESS;
	isc_stdtime_t now;
	uint32_t ttl;
	unsigned int options;
	dns_fixedname_t fwild;
	dns_name_t *wild = NULL;
	dns_message_t *message = NULL;
	bool done = false;

	valarg = val->arg;

	REQUIRE(VALID_FCTX(valarg->fctx));
	REQUIRE(!ISC_LIST_EMPTY(valarg->fctx->validators));

	fctx = valarg->fctx;
	valarg->fctx = NULL;

	REQUIRE(fctx->tid == isc_tid());

	FCTXTRACE("received validation completion event");

	res = fctx->res;
	addrinfo = valarg->addrinfo;

	message = val->message;
	fctx->vresult = val->result;

	LOCK(&fctx->lock);
	ISC_LIST_UNLINK(fctx->validators, val, link);
	UNLOCK(&fctx->lock);

	/*
	 * Destroy the validator early so that we can
	 * destroy the fctx if necessary.  Save the wildcard name.
	 */
	if (val->proofs[DNS_VALIDATOR_NOQNAMEPROOF] != NULL) {
		wild = dns_fixedname_initname(&fwild);
		dns_name_copy(dns_fixedname_name(&val->wild), wild);
	}

	isc_mem_put(fctx->mctx, valarg, sizeof(*valarg));

	negative = (val->rdataset == NULL);

	LOCK(&fctx->lock);
	sentresponse = ((fctx->options & DNS_FETCHOPT_NOVALIDATE) != 0);

	/*
	 * If shutting down, ignore the results.  Check to see if we're
	 * done waiting for validator completions and ADB pending
	 * events; if so, destroy the fctx.
	 */
	if (SHUTTINGDOWN(fctx) && !sentresponse) {
		UNLOCK(&fctx->lock);
		goto cleanup_fetchctx;
	}

	now = isc_stdtime_now();

	/*
	 * If chaining, we need to make sure that the right result code
	 * is returned, and that the rdatasets are bound.
	 */
	if (val->result == ISC_R_SUCCESS && !negative &&
	    val->rdataset != NULL && CHAINING(val->rdataset))
	{
		if (val->rdataset->type == dns_rdatatype_cname) {
			eresult = DNS_R_CNAME;
		} else {
			INSIST(val->rdataset->type == dns_rdatatype_dname);
			eresult = DNS_R_DNAME;
		}
		chaining = true;
	} else {
		chaining = false;
	}

	/*
	 * Either we're not shutting down, or we are shutting down but
	 * want to cache the result anyway (if this was a validation
	 * started by a query with cd set)
	 */

	hresp = ISC_LIST_HEAD(fctx->resps);
	if (hresp != NULL) {
		if (!negative && !chaining && dns_rdatatype_ismulti(fctx->type))
		{
			/*
			 * Don't bind rdatasets; the caller
			 * will iterate the node.
			 */
		} else {
			ardataset = hresp->rdataset;
			asigrdataset = hresp->sigrdataset;
		}
	}

	if (val->result != ISC_R_SUCCESS) {
		FCTXTRACE("validation failed");
		inc_stats(res, dns_resstatscounter_valfail);
		fctx->valfail++;
		fctx->vresult = val->result;
		if (fctx->vresult != DNS_R_BROKENCHAIN) {
			result = ISC_R_NOTFOUND;
			if (val->rdataset != NULL) {
				result = dns_db_findnode(fctx->cache, val->name,
							 false, &node);
			}
			if (result == ISC_R_SUCCESS) {
				(void)dns_db_deleterdataset(fctx->cache, node,
							    NULL, val->type, 0);
			}
			if (result == ISC_R_SUCCESS && val->sigrdataset != NULL)
			{
				(void)dns_db_deleterdataset(
					fctx->cache, node, NULL,
					dns_rdatatype_rrsig, val->type);
			}
			if (result == ISC_R_SUCCESS) {
				dns_db_detachnode(fctx->cache, &node);
			}
		}
		if (fctx->vresult == DNS_R_BROKENCHAIN && !negative) {
			/*
			 * Cache the data as pending for later
			 * validation.
			 */
			result = ISC_R_NOTFOUND;
			if (val->rdataset != NULL) {
				result = dns_db_findnode(fctx->cache, val->name,
							 true, &node);
			}
			if (result == ISC_R_SUCCESS) {
				(void)dns_db_addrdataset(
					fctx->cache, node, NULL, now,
					val->rdataset, 0, NULL);
			}
			if (result == ISC_R_SUCCESS && val->sigrdataset != NULL)
			{
				(void)dns_db_addrdataset(
					fctx->cache, node, NULL, now,
					val->sigrdataset, 0, NULL);
			}
			if (result == ISC_R_SUCCESS) {
				dns_db_detachnode(fctx->cache, &node);
			}
		}
		result = fctx->vresult;
		add_bad(fctx, message, addrinfo, result, badns_validation);

		UNLOCK(&fctx->lock);

		nextval = ISC_LIST_HEAD(fctx->validators);
		if (nextval != NULL) {
			dns_validator_send(nextval);
			goto cleanup_fetchctx;
		} else if (sentresponse) {
			done = true;
			goto cleanup_fetchctx;
		} else if (result == DNS_R_BROKENCHAIN) {
			done = true;
			goto cleanup_fetchctx;
		} else {
			fctx_try(fctx, true);
			goto cleanup_fetchctx;
		}
		UNREACHABLE();
	}

	if (negative) {
		dns_rdatatype_t covers;
		FCTXTRACE("nonexistence validation OK");

		inc_stats(res, dns_resstatscounter_valnegsuccess);

		/*
		 * Cache DS NXDOMAIN separately to other types.
		 */
		if (message->rcode == dns_rcode_nxdomain &&
		    fctx->type != dns_rdatatype_ds)
		{
			covers = dns_rdatatype_any;
		} else {
			covers = fctx->type;
		}

		/*
		 * Don't report qname minimisation NXDOMAIN errors
		 * when the result is NXDOMAIN except we have already
		 * confirmed a higher error.
		 */
		if (!fctx->force_qmin_warning &&
		    message->rcode == dns_rcode_nxdomain &&
		    (fctx->qmin_warning == DNS_R_NXDOMAIN ||
		     fctx->qmin_warning == DNS_R_NCACHENXDOMAIN))
		{
			fctx->qmin_warning = ISC_R_SUCCESS;
		}

		result = dns_db_findnode(fctx->cache, val->name, true, &node);
		if (result != ISC_R_SUCCESS) {
			/* fctx->lock unlocked in noanswer_response */
			goto noanswer_response;
		}

		/*
		 * If we are asking for a SOA record set the cache time
		 * to zero to facilitate locating the containing zone of
		 * a arbitrary zone.
		 */
		ttl = res->view->maxncachettl;
		if (fctx->type == dns_rdatatype_soa &&
		    covers == dns_rdatatype_any && res->zero_no_soa_ttl)
		{
			ttl = 0;
		}

		result = ncache_adderesult(message, fctx->cache, node, covers,
					   now, fctx->res->view->minncachettl,
					   ttl, val->optout, val->secure,
					   ardataset, &eresult);
		if (result != ISC_R_SUCCESS) {
			goto noanswer_response;
		}
		goto answer_response;
	} else {
		inc_stats(res, dns_resstatscounter_valsuccess);
	}

	FCTXTRACE("validation OK");

	if (val->proofs[DNS_VALIDATOR_NOQNAMEPROOF] != NULL) {
		result = dns_rdataset_addnoqname(
			val->rdataset, val->proofs[DNS_VALIDATOR_NOQNAMEPROOF]);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		INSIST(val->sigrdataset != NULL);
		val->sigrdataset->ttl = val->rdataset->ttl;
		if (val->proofs[DNS_VALIDATOR_CLOSESTENCLOSER] != NULL) {
			result = dns_rdataset_addclosest(
				val->rdataset,
				val->proofs[DNS_VALIDATOR_CLOSESTENCLOSER]);
			RUNTIME_CHECK(result == ISC_R_SUCCESS);
		}
	} else if (val->rdataset->trust == dns_trust_answer &&
		   val->rdataset->type != dns_rdatatype_rrsig)
	{
		isc_result_t tresult;
		dns_name_t *noqname = NULL;
		tresult = findnoqname(fctx, message, val->name,
				      val->rdataset->type, &noqname);
		if (tresult == ISC_R_SUCCESS && noqname != NULL) {
			tresult = dns_rdataset_addnoqname(val->rdataset,
							  noqname);
			RUNTIME_CHECK(tresult == ISC_R_SUCCESS);
		}
	}

	/*
	 * The data was already cached as pending data.
	 * Re-cache it as secure and bind the cached
	 * rdatasets to the first event on the fetch
	 * event list.
	 */
	result = dns_db_findnode(fctx->cache, val->name, true, &node);
	if (result != ISC_R_SUCCESS) {
		goto noanswer_response;
	}

	options = 0;
	if ((fctx->options & DNS_FETCHOPT_PREFETCH) != 0) {
		options = DNS_DBADD_PREFETCH;
	}
	result = dns_db_addrdataset(fctx->cache, node, NULL, now, val->rdataset,
				    options, ardataset);
	if (result != ISC_R_SUCCESS && result != DNS_R_UNCHANGED) {
		goto noanswer_response;
	}
	if (ardataset != NULL && NEGATIVE(ardataset)) {
		if (NXDOMAIN(ardataset)) {
			eresult = DNS_R_NCACHENXDOMAIN;
		} else {
			eresult = DNS_R_NCACHENXRRSET;
		}
	} else if (val->sigrdataset != NULL) {
		result = dns_db_addrdataset(fctx->cache, node, NULL, now,
					    val->sigrdataset, options,
					    asigrdataset);
		if (result != ISC_R_SUCCESS && result != DNS_R_UNCHANGED) {
			goto noanswer_response;
		}
	}

	if (sentresponse) {
		/*
		 * If we only deferred the destroy because we wanted to
		 * cache the data, destroy now.
		 */
		dns_db_detachnode(fctx->cache, &node);
		if (SHUTTINGDOWN(fctx)) {
			maybe_cancel_validators(fctx);
		}
		UNLOCK(&fctx->lock);
		goto cleanup_fetchctx;
	}

	if (!ISC_LIST_EMPTY(fctx->validators)) {
		INSIST(!negative);
		INSIST(dns_rdatatype_ismulti(fctx->type));
		/*
		 * Don't send a response yet - we have
		 * more rdatasets that still need to
		 * be validated.
		 */
		dns_db_detachnode(fctx->cache, &node);
		UNLOCK(&fctx->lock);
		dns_validator_send(ISC_LIST_HEAD(fctx->validators));
		goto cleanup_fetchctx;
	}

answer_response:

	/*
	 * Cache any SOA/NS/NSEC records that happened to be validated.
	 */
	MSG_SECTION_FOREACH (message, DNS_SECTION_AUTHORITY, name) {
		ISC_LIST_FOREACH (name->list, rdataset, link) {
			dns_rdataset_t *sigrdataset = NULL;

			if ((rdataset->type != dns_rdatatype_ns &&
			     rdataset->type != dns_rdatatype_soa &&
			     rdataset->type != dns_rdatatype_nsec) ||
			    rdataset->trust != dns_trust_secure)
			{
				continue;
			}

			ISC_LIST_FOREACH (name->list, s, link) {
				if (s->type == dns_rdatatype_rrsig &&
				    s->covers == rdataset->type)
				{
					sigrdataset = s;
					break;
				}
			}
			if (sigrdataset == NULL ||
			    sigrdataset->trust != dns_trust_secure)
			{
				continue;
			}

			/*
			 * Don't cache NSEC if missing NSEC or RRSIG types.
			 */
			if (rdataset->type == dns_rdatatype_nsec &&
			    !dns_nsec_requiredtypespresent(rdataset))
			{
				continue;
			}

			/*
			 * Don't cache "white lies" but do cache
			 * "black lies".
			 */
			if (rdataset->type == dns_rdatatype_nsec &&
			    !dns_name_equal(fctx->name, name) &&
			    is_minimal_nsec(rdataset))
			{
				continue;
			}

			/*
			 * Check SOA and DNSKEY consistency.
			 */
			if (rdataset->type == dns_rdatatype_nsec &&
			    !check_soa_and_dnskey(rdataset))
			{
				continue;
			}

			/*
			 * Look for \000 label in next name.
			 */
			if (rdataset->type == dns_rdatatype_nsec &&
			    has_000_label(rdataset))
			{
				continue;
			}

			result = dns_db_findnode(fctx->cache, name, true,
						 &nsnode);
			if (result != ISC_R_SUCCESS) {
				continue;
			}

			result = dns_db_addrdataset(fctx->cache, nsnode, NULL,
						    now, rdataset, 0, NULL);
			if (result == ISC_R_SUCCESS) {
				result = dns_db_addrdataset(
					fctx->cache, nsnode, NULL, now,
					sigrdataset, 0, NULL);
			}
			dns_db_detachnode(fctx->cache, &nsnode);
			if (result != ISC_R_SUCCESS) {
				continue;
			}
		}
	}

	/*
	 * Add the wild card entry.
	 */
	if (val->proofs[DNS_VALIDATOR_NOQNAMEPROOF] != NULL &&
	    val->rdataset != NULL && dns_rdataset_isassociated(val->rdataset) &&
	    val->rdataset->trust == dns_trust_secure &&
	    val->sigrdataset != NULL &&
	    dns_rdataset_isassociated(val->sigrdataset) &&
	    val->sigrdataset->trust == dns_trust_secure && wild != NULL)
	{
		dns_dbnode_t *wnode = NULL;

		result = dns_db_findnode(fctx->cache, wild, true, &wnode);
		if (result == ISC_R_SUCCESS) {
			result = dns_db_addrdataset(fctx->cache, wnode, NULL,
						    now, val->rdataset, 0,
						    NULL);
		}
		if (result == ISC_R_SUCCESS) {
			(void)dns_db_addrdataset(fctx->cache, wnode, NULL, now,
						 val->sigrdataset, 0, NULL);
		}
		if (wnode != NULL) {
			dns_db_detachnode(fctx->cache, &wnode);
		}
	}

	result = ISC_R_SUCCESS;

	/*
	 * Respond with an answer, positive or negative,
	 * as opposed to an error.  'node' must be non-NULL.
	 */

	FCTX_ATTR_SET(fctx, FCTX_ATTR_HAVEANSWER);

	if (hresp != NULL) {
		/*
		 * Negative results must be indicated in val->result.
		 */
		INSIST(hresp->rdataset != NULL);
		if (dns_rdataset_isassociated(hresp->rdataset)) {
			if (NEGATIVE(hresp->rdataset)) {
				INSIST(eresult == DNS_R_NCACHENXDOMAIN ||
				       eresult == DNS_R_NCACHENXRRSET);
			} else if (eresult == ISC_R_SUCCESS &&
				   hresp->rdataset->type != fctx->type)
			{
				switch (hresp->rdataset->type) {
				case dns_rdatatype_cname:
					eresult = DNS_R_CNAME;
					break;
				case dns_rdatatype_dname:
					eresult = DNS_R_DNAME;
					break;
				default:
					break;
				}
			}
		}

		hresp->result = eresult;
		dns_name_copy(val->name, hresp->foundname);
		dns_db_attach(fctx->cache, &hresp->db);
		dns_db_transfernode(fctx->cache, &node, &hresp->node);
		clone_results(fctx);
	}

noanswer_response:
	if (node != NULL) {
		dns_db_detachnode(fctx->cache, &node);
	}

	UNLOCK(&fctx->lock);
	done = true;

cleanup_fetchctx:
	if (done) {
		fctx_done_unref(fctx, result);
	}

	/*
	 * val->name points to name on a message on one of the
	 * queries on the fetch context so the name has to be
	 * released first with a dns_validator_shutdown() call.
	 */
	dns_validator_shutdown(val);
	dns_validator_detach(&val);
	fetchctx_detach(&fctx);
	INSIST(node == NULL);
}

static void
fctx_log(void *arg, int level, const char *fmt, ...) {
	char msgbuf[2048];
	va_list args;
	fetchctx_t *fctx = arg;

	va_start(args, fmt);
	vsnprintf(msgbuf, sizeof(msgbuf), fmt, args);
	va_end(args);

	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, level,
		      "fctx %p(%s): %s", fctx, fctx->info, msgbuf);
}

static isc_result_t
findnoqname(fetchctx_t *fctx, dns_message_t *message, dns_name_t *name,
	    dns_rdatatype_t type, dns_name_t **noqnamep) {
	dns_rdataset_t *sigrdataset = NULL;
	dns_rdata_rrsig_t rrsig;
	isc_result_t result;
	unsigned int labels;
	dns_name_t *zonename = NULL;
	dns_fixedname_t fzonename;
	dns_name_t *closest = NULL;
	dns_fixedname_t fclosest;
	dns_name_t *nearest = NULL;
	dns_fixedname_t fnearest;
	dns_rdatatype_t found = dns_rdatatype_none;
	dns_name_t *noqname = NULL;

	FCTXTRACE("findnoqname");

	REQUIRE(noqnamep != NULL && *noqnamep == NULL);

	/*
	 * Find the SIG for this rdataset, if we have it.
	 */
	ISC_LIST_FOREACH (name->list, sig, link) {
		if (sig->type == dns_rdatatype_rrsig && sig->covers == type) {
			sigrdataset = sig;
			break;
		}
	}

	if (sigrdataset == NULL) {
		return ISC_R_NOTFOUND;
	}

	labels = dns_name_countlabels(name);

	result = ISC_R_NOTFOUND;
	DNS_RDATASET_FOREACH (sigrdataset) {
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdataset_current(sigrdataset, &rdata);
		result = dns_rdata_tostruct(&rdata, &rrsig, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		/* Wildcard has rrsig.labels < labels - 1. */
		if (rrsig.labels + 1U >= labels) {
			continue;
		}
		result = ISC_R_SUCCESS;
		break;
	}

	if (result != ISC_R_SUCCESS) {
		return result;
	}

	zonename = dns_fixedname_initname(&fzonename);
	closest = dns_fixedname_initname(&fclosest);
	nearest = dns_fixedname_initname(&fnearest);

#define NXND(x) ((x) == ISC_R_SUCCESS)

	MSG_SECTION_FOREACH (message, DNS_SECTION_AUTHORITY, nsec) {
		ISC_LIST_FOREACH (nsec->list, nrdataset, link) {
			bool data = false, exists = false;
			bool optout = false, unknown = false;
			bool setclosest = false;
			bool setnearest = false;

			if (nrdataset->type != dns_rdatatype_nsec &&
			    nrdataset->type != dns_rdatatype_nsec3)
			{
				continue;
			}

			if (nrdataset->type == dns_rdatatype_nsec &&
			    NXND(dns_nsec_noexistnodata(
				    type, name, nsec, nrdataset, &exists, &data,
				    NULL, fctx_log, fctx)))
			{
				if (!exists) {
					noqname = nsec;
					found = dns_rdatatype_nsec;
				}
			}

			if (nrdataset->type == dns_rdatatype_nsec3 &&
			    NXND(dns_nsec3_noexistnodata(
				    type, name, nsec, nrdataset, zonename,
				    &exists, &data, &optout, &unknown,
				    &setclosest, &setnearest, closest, nearest,
				    fctx_log, fctx)))
			{
				if (!exists && setnearest) {
					noqname = nsec;
					found = dns_rdatatype_nsec3;
				}
			}
		}
	}

	if (noqname != NULL) {
		ISC_LIST_FOREACH (noqname->list, sig, link) {
			if (sig->type == dns_rdatatype_rrsig &&
			    sig->covers == found)
			{
				*noqnamep = noqname;
				break;
			}
		}
	}

	return result;
}

static isc_result_t
cache_name(fetchctx_t *fctx, dns_name_t *name, dns_message_t *message,
	   dns_adbaddrinfo_t *addrinfo, isc_stdtime_t now) {
	dns_rdataset_t *addedrdataset = NULL;
	dns_rdataset_t *ardataset = NULL, *asigrdataset = NULL;
	dns_rdataset_t *valrdataset = NULL, *valsigrdataset = NULL;
	dns_dbnode_t *node = NULL, **anodep = NULL;
	dns_db_t **adbp = NULL;
	dns_resolver_t *res = fctx->res;
	bool need_validation = false;
	bool secure_domain = false;
	bool have_answer = false;
	isc_result_t result, eresult = ISC_R_SUCCESS;
	dns_fetchresponse_t *resp = NULL;
	unsigned int options;
	bool fail;
	unsigned int valoptions = 0;
	bool checknta = true;

	FCTXTRACE("cache_name");

	/*
	 * The appropriate bucket lock must be held.
	 */

	/*
	 * Is DNSSEC validation required for this name?
	 */
	if ((fctx->options & DNS_FETCHOPT_NONTA) != 0) {
		valoptions |= DNS_VALIDATOR_NONTA;
		checknta = false;
	}

	if (res->view->enablevalidation) {
		result = issecuredomain(res->view, name, fctx->type, now,
					checknta, NULL, &secure_domain);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	if ((fctx->options & DNS_FETCHOPT_NOCDFLAG) != 0) {
		valoptions |= DNS_VALIDATOR_NOCDFLAG;
	}

	if ((fctx->options & DNS_FETCHOPT_NOVALIDATE) != 0) {
		need_validation = false;
	} else {
		need_validation = secure_domain;
	}

	if (name->attributes.answer && !need_validation) {
		have_answer = true;
		resp = ISC_LIST_HEAD(fctx->resps);

		if (resp != NULL) {
			adbp = &resp->db;
			dns_name_copy(name, resp->foundname);
			anodep = &resp->node;

			/*
			 * If this is an ANY, SIG or RRSIG query, we're
			 * not going to return any rdatasets, unless we
			 * encountered a CNAME or DNAME as "the answer".
			 * In this case, we're going to return
			 * DNS_R_CNAME or DNS_R_DNAME and we must set up
			 * the rdatasets.
			 */
			if (!dns_rdatatype_ismulti(fctx->type) ||
			    name->attributes.chaining)
			{
				ardataset = resp->rdataset;
				asigrdataset = resp->sigrdataset;
			}
		}
	}

	/*
	 * Find or create the cache node.
	 */
	result = dns_db_findnode(fctx->cache, name, true, &node);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	/*
	 * Cache or validate each cacheable rdataset.
	 */
	fail = ((fctx->res->options & DNS_RESOLVER_CHECKNAMESFAIL) != 0);
	ISC_LIST_FOREACH (name->list, rdataset, link) {
		dns_rdataset_t *sigrdataset = NULL;

		if (!CACHE(rdataset)) {
			continue;
		}
		if (CHECKNAMES(rdataset)) {
			char namebuf[DNS_NAME_FORMATSIZE];
			char typebuf[DNS_RDATATYPE_FORMATSIZE];
			char classbuf[DNS_RDATATYPE_FORMATSIZE];

			dns_name_format(name, namebuf, sizeof(namebuf));
			dns_rdatatype_format(rdataset->type, typebuf,
					     sizeof(typebuf));
			dns_rdataclass_format(rdataset->rdclass, classbuf,
					      sizeof(classbuf));
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_NOTICE,
				      "check-names %s %s/%s/%s",
				      fail ? "failure" : "warning", namebuf,
				      typebuf, classbuf);
			if (fail) {
				if (ANSWER(rdataset)) {
					dns_db_detachnode(fctx->cache, &node);
					return DNS_R_BADNAME;
				}
				continue;
			}
		}

		/*
		 * Enforce the configure maximum cache TTL.
		 */
		if (rdataset->ttl > res->view->maxcachettl) {
			rdataset->ttl = res->view->maxcachettl;
		}

		/*
		 * Enforce configured minimum cache TTL.
		 */
		if (rdataset->ttl < res->view->mincachettl) {
			rdataset->ttl = res->view->mincachettl;
		}

		/*
		 * Mark the rdataset as being prefetch eligible.
		 */
		if (rdataset->ttl >= fctx->res->view->prefetch_eligible) {
			rdataset->attributes.prefetch = true;
		}

		/*
		 * Find the SIG for this rdataset, if we have it.
		 */
		ISC_LIST_FOREACH (name->list, sig, link) {
			if (sig->type == dns_rdatatype_rrsig &&
			    sig->covers == rdataset->type)
			{
				sigrdataset = sig;
				break;
			}
		}

		/*
		 * If this RRset is in a secure domain, is in bailiwick,
		 * and is not glue, attempt DNSSEC validation.	(We do
		 * not attempt to validate glue or out-of-bailiwick
		 * data--even though there might be some performance
		 * benefit to doing so--because it makes it simpler and
		 * safer to ensure that records from a secure domain are
		 * only cached if validated within the context of a
		 * query to the domain that owns them.)
		 */
		if (secure_domain && rdataset->trust != dns_trust_glue &&
		    !EXTERNAL(rdataset))
		{
			dns_trust_t trust;

			/*
			 * RRSIGs are validated as part of validating
			 * the type they cover.
			 */
			if (rdataset->type == dns_rdatatype_rrsig) {
				continue;
			}

			if (sigrdataset == NULL && need_validation &&
			    !ANSWER(rdataset))
			{
				/*
				 * Ignore unrelated non-answer
				 * rdatasets that are missing
				 * signatures.
				 */
				continue;
			}

			/*
			 * Normalize the rdataset and sigrdataset TTLs.
			 */
			if (sigrdataset != NULL) {
				rdataset->ttl = ISC_MIN(rdataset->ttl,
							sigrdataset->ttl);
				sigrdataset->ttl = rdataset->ttl;
			}

			/*
			 * Mark the rdataset as being prefetch eligible.
			 */
			if (rdataset->ttl >= fctx->res->view->prefetch_eligible)
			{
				rdataset->attributes.prefetch = true;
			}

			/*
			 * Cache this rdataset/sigrdataset pair as
			 * pending data.  Track whether it was
			 * additional or not. If this was a priming
			 * query, additional should be cached as glue.
			 */
			if (rdataset->trust == dns_trust_additional) {
				trust = dns_trust_pending_additional;
			} else {
				trust = dns_trust_pending_answer;
			}

			rdataset->trust = trust;
			if (sigrdataset != NULL) {
				sigrdataset->trust = trust;
			}
			if (!need_validation || !ANSWER(rdataset)) {
				options = 0;
				if (ANSWER(rdataset) &&
				    rdataset->type != dns_rdatatype_rrsig)
				{
					isc_result_t tresult;
					dns_name_t *noqname = NULL;
					tresult = findnoqname(
						fctx, message, name,
						rdataset->type, &noqname);
					if (tresult == ISC_R_SUCCESS &&
					    noqname != NULL)
					{
						(void)dns_rdataset_addnoqname(
							rdataset, noqname);
					}
				}
				if ((fctx->options & DNS_FETCHOPT_PREFETCH) !=
				    0)
				{
					options = DNS_DBADD_PREFETCH;
				}
				if ((fctx->options & DNS_FETCHOPT_NOCACHED) !=
				    0)
				{
					options |= DNS_DBADD_FORCE;
				}
				addedrdataset = ardataset;
				result = dns_db_addrdataset(
					fctx->cache, node, NULL, now, rdataset,
					options, addedrdataset);
				if (result == DNS_R_UNCHANGED) {
					result = ISC_R_SUCCESS;
					if (!need_validation &&
					    ardataset != NULL &&
					    NEGATIVE(ardataset))
					{
						/*
						 * The answer in the
						 * cache is better than
						 * the answer we found.
						 * If it's a negative
						 * cache entry, we
						 * must set eresult
						 * appropriately.
						 */
						if (NXDOMAIN(ardataset)) {
							eresult =
								DNS_R_NCACHENXDOMAIN;
						} else {
							eresult =
								DNS_R_NCACHENXRRSET;
						}
						continue;
					} else if (!need_validation &&
						   ardataset != NULL &&
						   sigrdataset != NULL &&
						   !dns_rdataset_equals(
							   rdataset, ardataset))
					{
						/*
						 * The cache wasn't updated
						 * because something was
						 * already there. If the
						 * data was the same as what
						 * we were trying to add,
						 * then sigrdataset might
						 * still be useful, and we
						 * should carry on caching
						 * it. Otherwise, move on.
						 */
						continue;
					}
				}
				if (result != ISC_R_SUCCESS) {
					break;
				}
				if (sigrdataset != NULL) {
					addedrdataset = asigrdataset;
					result = dns_db_addrdataset(
						fctx->cache, node, NULL, now,
						sigrdataset, options,
						addedrdataset);
					if (result == DNS_R_UNCHANGED) {
						result = ISC_R_SUCCESS;
					}
					if (result != ISC_R_SUCCESS) {
						break;
					}
				} else if (!ANSWER(rdataset)) {
					continue;
				}
			}

			if (ANSWER(rdataset) && need_validation) {
				if (!dns_rdatatype_ismulti(fctx->type)) {
					/*
					 * This is The Answer.  We will
					 * validate it, but first we
					 * cache the rest of the
					 * response - it may contain
					 * useful keys.
					 */
					INSIST(valrdataset == NULL &&
					       valsigrdataset == NULL);
					valrdataset = rdataset;
					valsigrdataset = sigrdataset;
				} else {
					/*
					 * This is one of (potentially)
					 * multiple answers to an ANY
					 * or SIG query.  To keep things
					 * simple, we just start the
					 * validator right away rather
					 * than caching first and
					 * having to remember which
					 * rdatasets needed validation.
					 */
					result = valcreate(
						fctx, message, addrinfo, name,
						rdataset->type, rdataset,
						sigrdataset, valoptions);
				}
			} else if (CHAINING(rdataset)) {
				if (rdataset->type == dns_rdatatype_cname) {
					eresult = DNS_R_CNAME;
				} else {
					INSIST(rdataset->type ==
					       dns_rdatatype_dname);
					eresult = DNS_R_DNAME;
				}
			}
		} else if (!EXTERNAL(rdataset)) {
			/*
			 * It's OK to cache this rdataset now.
			 */
			if (ANSWER(rdataset)) {
				addedrdataset = ardataset;
			} else if (ANSWERSIG(rdataset)) {
				addedrdataset = asigrdataset;
			} else {
				addedrdataset = NULL;
			}
			if (CHAINING(rdataset)) {
				if (rdataset->type == dns_rdatatype_cname) {
					eresult = DNS_R_CNAME;
				} else {
					INSIST(rdataset->type ==
					       dns_rdatatype_dname);
					eresult = DNS_R_DNAME;
				}
			}
			if (rdataset->trust == dns_trust_glue &&
			    (rdataset->type == dns_rdatatype_ns ||
			     (rdataset->type == dns_rdatatype_rrsig &&
			      rdataset->covers == dns_rdatatype_ns)))
			{
				/*
				 * If the trust level is
				 * 'dns_trust_glue' then we are adding
				 * data from a referral we got while
				 * executing the search algorithm. New
				 * referral data always takes precedence
				 * over the existing cache contents.
				 */
				options = DNS_DBADD_FORCE;
			} else if ((fctx->options & DNS_FETCHOPT_PREFETCH) != 0)
			{
				options = DNS_DBADD_PREFETCH;
			} else {
				options = 0;
			}

			if (ANSWER(rdataset) &&
			    rdataset->type != dns_rdatatype_rrsig)
			{
				isc_result_t tresult;
				dns_name_t *noqname = NULL;
				tresult = findnoqname(fctx, message, name,
						      rdataset->type, &noqname);
				if (tresult == ISC_R_SUCCESS && noqname != NULL)
				{
					(void)dns_rdataset_addnoqname(rdataset,
								      noqname);
				}
			}

			/*
			 * Now we can add the rdataset.
			 */
			result = dns_db_addrdataset(fctx->cache, node, NULL,
						    now, rdataset, options,
						    addedrdataset);

			if (result == DNS_R_UNCHANGED) {
				if (ANSWER(rdataset) && ardataset != NULL &&
				    NEGATIVE(ardataset))
				{
					/*
					 * The answer in the cache is
					 * better than the answer we
					 * found, and is a negative
					 * cache entry, so we must set
					 * eresult appropriately.
					 */
					if (NXDOMAIN(ardataset)) {
						eresult = DNS_R_NCACHENXDOMAIN;
					} else {
						eresult = DNS_R_NCACHENXRRSET;
					}
				}
				result = ISC_R_SUCCESS;
			} else if (result != ISC_R_SUCCESS) {
				break;
			}
		}
	}

	if (valrdataset != NULL) {
		dns_rdatatype_t vtype = fctx->type;
		if (CHAINING(valrdataset)) {
			if (valrdataset->type == dns_rdatatype_cname) {
				vtype = dns_rdatatype_cname;
			} else {
				vtype = dns_rdatatype_dname;
			}
		}

		result = valcreate(fctx, message, addrinfo, name, vtype,
				   valrdataset, valsigrdataset, valoptions);
	}

	if (result == ISC_R_SUCCESS && have_answer) {
		FCTX_ATTR_SET(fctx, FCTX_ATTR_HAVEANSWER);
		if (resp != NULL) {
			/*
			 * Negative results must be indicated in
			 * resp->result.
			 */
			if (dns_rdataset_isassociated(resp->rdataset)) {
				if (NEGATIVE(resp->rdataset)) {
					INSIST(eresult ==
						       DNS_R_NCACHENXDOMAIN ||
					       eresult == DNS_R_NCACHENXRRSET);
				} else if (eresult == ISC_R_SUCCESS &&
					   resp->rdataset->type != fctx->type)
				{
					switch (resp->rdataset->type) {
					case dns_rdatatype_cname:
						eresult = DNS_R_CNAME;
						break;
					case dns_rdatatype_dname:
						eresult = DNS_R_DNAME;
						break;
					default:
						break;
					}
				}
			}
			resp->result = eresult;
			if (adbp != NULL && *adbp != NULL) {
				if (anodep != NULL && *anodep != NULL) {
					dns_db_detachnode(*adbp, anodep);
				}
				dns_db_detach(adbp);
			}
			dns_db_attach(fctx->cache, adbp);
			dns_db_transfernode(fctx->cache, &node, anodep);
			clone_results(fctx);
		}
	}

	if (node != NULL) {
		dns_db_detachnode(fctx->cache, &node);
	}

	return result;
}

static isc_result_t
cache_message(fetchctx_t *fctx, dns_message_t *message,
	      dns_adbaddrinfo_t *addrinfo, isc_stdtime_t now) {
	FCTXTRACE("cache_message");

	FCTX_ATTR_CLR(fctx, FCTX_ATTR_WANTCACHE);

	LOCK(&fctx->lock);

	isc_result_t result = ISC_R_SUCCESS;
	for (dns_section_t section = DNS_SECTION_ANSWER;
	     section <= DNS_SECTION_ADDITIONAL; section++)
	{
		MSG_SECTION_FOREACH (message, section, name) {
			if (name->attributes.cache) {
				result = cache_name(fctx, name, message,
						    addrinfo, now);
				if (result != ISC_R_SUCCESS) {
					goto cleanup;
				}
			}
		}
	}

cleanup:
	UNLOCK(&fctx->lock);
	return result;
}

/*
 * Do what dns_ncache_addoptout() does, and then compute an appropriate
 * eresult.
 */
static isc_result_t
ncache_adderesult(dns_message_t *message, dns_db_t *cache, dns_dbnode_t *node,
		  dns_rdatatype_t covers, isc_stdtime_t now, dns_ttl_t minttl,
		  dns_ttl_t maxttl, bool optout, bool secure,
		  dns_rdataset_t *ardataset, isc_result_t *eresultp) {
	isc_result_t result;
	dns_rdataset_t rdataset;

	if (ardataset == NULL) {
		dns_rdataset_init(&rdataset);
		ardataset = &rdataset;
	}
	if (secure) {
		result = dns_ncache_addoptout(message, cache, node, covers, now,
					      minttl, maxttl, optout,
					      ardataset);
	} else {
		result = dns_ncache_add(message, cache, node, covers, now,
					minttl, maxttl, ardataset);
	}
	if (result == DNS_R_UNCHANGED || result == ISC_R_SUCCESS) {
		/*
		 * If the cache now contains a negative entry and we
		 * care about whether it is DNS_R_NCACHENXDOMAIN or
		 * DNS_R_NCACHENXRRSET then extract it.
		 */
		if (NEGATIVE(ardataset)) {
			/*
			 * The cache data is a negative cache entry.
			 */
			if (NXDOMAIN(ardataset)) {
				*eresultp = DNS_R_NCACHENXDOMAIN;
			} else {
				*eresultp = DNS_R_NCACHENXRRSET;
			}
		} else {
			/*
			 * The attempt to add a negative cache entry
			 * was rejected.  Set *eresultp to reflect
			 * the type of the dataset being returned.
			 */
			switch (ardataset->type) {
			case dns_rdatatype_cname:
				*eresultp = DNS_R_CNAME;
				break;
			case dns_rdatatype_dname:
				*eresultp = DNS_R_DNAME;
				break;
			default:
				*eresultp = ISC_R_SUCCESS;
				break;
			}
		}
		result = ISC_R_SUCCESS;
	}
	if (ardataset == &rdataset && dns_rdataset_isassociated(ardataset)) {
		dns_rdataset_disassociate(ardataset);
	}

	return result;
}

static isc_result_t
ncache_message(fetchctx_t *fctx, dns_message_t *message,
	       dns_adbaddrinfo_t *addrinfo, dns_rdatatype_t covers,
	       isc_stdtime_t now) {
	isc_result_t result, eresult = ISC_R_SUCCESS;
	dns_name_t *name = fctx->name;
	dns_resolver_t *res = fctx->res;
	dns_db_t **adbp = NULL;
	dns_dbnode_t *node = NULL, **anodep = NULL;
	dns_rdataset_t *ardataset = NULL;
	bool need_validation = false, secure_domain = false;
	dns_fetchresponse_t *resp = NULL;
	uint32_t ttl;
	unsigned int valoptions = 0;
	bool checknta = true;

	FCTXTRACE("ncache_message");

	FCTX_ATTR_CLR(fctx, FCTX_ATTR_WANTNCACHE);

	POST(need_validation);

	/*
	 * XXXMPA remove when we follow cnames and adjust the setting
	 * of FCTX_ATTR_WANTNCACHE in rctx_answer_none().
	 */
	INSIST(message->counts[DNS_SECTION_ANSWER] == 0);

	/*
	 * Is DNSSEC validation required for this name?
	 */
	if ((fctx->options & DNS_FETCHOPT_NONTA) != 0) {
		valoptions |= DNS_VALIDATOR_NONTA;
		checknta = false;
	}

	if (fctx->res->view->enablevalidation) {
		result = issecuredomain(res->view, name, fctx->type, now,
					checknta, NULL, &secure_domain);
		if (result != ISC_R_SUCCESS) {
			return result;
		}
	}

	if ((fctx->options & DNS_FETCHOPT_NOCDFLAG) != 0) {
		valoptions |= DNS_VALIDATOR_NOCDFLAG;
	}

	if ((fctx->options & DNS_FETCHOPT_NOVALIDATE) != 0) {
		need_validation = false;
	} else {
		need_validation = secure_domain;
	}

	if (secure_domain) {
		/*
		 * Mark all rdatasets as pending.
		 */
		MSG_SECTION_FOREACH (message, DNS_SECTION_AUTHORITY, tname) {
			ISC_LIST_FOREACH (tname->list, trdataset, link) {
				trdataset->trust = dns_trust_pending_answer;
			}
		}
	}

	if (need_validation) {
		/*
		 * Do negative response validation.
		 */
		result = valcreate(fctx, message, addrinfo, name, fctx->type,
				   NULL, NULL, valoptions);
		/*
		 * If validation is necessary, return now.  Otherwise
		 * continue to process the message, letting the
		 * validation complete in its own good time.
		 */
		return result;
	}

	LOCK(&fctx->lock);

	if (!HAVE_ANSWER(fctx)) {
		resp = ISC_LIST_HEAD(fctx->resps);
		if (resp != NULL) {
			adbp = &resp->db;
			dns_name_copy(name, resp->foundname);
			anodep = &resp->node;
			ardataset = resp->rdataset;
		}
	}

	result = dns_db_findnode(fctx->cache, name, true, &node);
	if (result != ISC_R_SUCCESS) {
		goto unlock;
	}

	/*
	 * Don't report qname minimisation NXDOMAIN errors
	 * when the result is NXDOMAIN except we have already
	 * confirmed a higher error.
	 */
	if (!fctx->force_qmin_warning && message->rcode == dns_rcode_nxdomain &&
	    (fctx->qmin_warning == DNS_R_NXDOMAIN ||
	     fctx->qmin_warning == DNS_R_NCACHENXDOMAIN))
	{
		fctx->qmin_warning = ISC_R_SUCCESS;
	}

	/*
	 * If we are asking for a SOA record set the cache time
	 * to zero to facilitate locating the containing zone of
	 * a arbitrary zone.
	 */
	ttl = fctx->res->view->maxncachettl;
	if (fctx->type == dns_rdatatype_soa && covers == dns_rdatatype_any &&
	    fctx->res->zero_no_soa_ttl)
	{
		ttl = 0;
	}

	result = ncache_adderesult(message, fctx->cache, node, covers, now,
				   fctx->res->view->minncachettl, ttl, false,
				   false, ardataset, &eresult);
	if (result != ISC_R_SUCCESS) {
		goto unlock;
	}

	if (!HAVE_ANSWER(fctx)) {
		FCTX_ATTR_SET(fctx, FCTX_ATTR_HAVEANSWER);
		if (resp != NULL) {
			resp->result = eresult;
			if (adbp != NULL && *adbp != NULL) {
				if (anodep != NULL && *anodep != NULL) {
					dns_db_detachnode(*adbp, anodep);
				}
				dns_db_detach(adbp);
			}
			dns_db_attach(fctx->cache, adbp);
			dns_db_transfernode(fctx->cache, &node, anodep);
			clone_results(fctx);
		}
	}

unlock:
	UNLOCK(&fctx->lock);

	if (node != NULL) {
		dns_db_detachnode(fctx->cache, &node);
	}

	return result;
}

static void
mark_related(dns_name_t *name, dns_rdataset_t *rdataset, bool external,
	     bool gluing) {
	name->attributes.cache = true;
	if (gluing) {
		rdataset->trust = dns_trust_glue;
		/*
		 * Glue with 0 TTL causes problems.  We force the TTL to
		 * 1 second to prevent this.
		 */
		if (rdataset->ttl == 0) {
			rdataset->ttl = 1;
		}
	} else {
		rdataset->trust = dns_trust_additional;
	}
	/*
	 * Avoid infinite loops by only marking new rdatasets.
	 */
	if (!CACHE(rdataset)) {
		name->attributes.chase = true;
		rdataset->attributes.chase = true;
	}
	rdataset->attributes.cache = true;
	if (external) {
		rdataset->attributes.external = true;
	}
}

/*
 * Returns true if 'name' is external to the namespace for which
 * the server being queried can answer, either because it's not a
 * subdomain or because it's below a forward declaration or a
 * locally served zone.
 */
static inline bool
name_external(const dns_name_t *name, dns_rdatatype_t type, fetchctx_t *fctx) {
	isc_result_t result;
	dns_forwarders_t *forwarders = NULL;
	dns_name_t *apex = NULL;
	dns_name_t suffix;
	dns_zone_t *zone = NULL;
	unsigned int labels;
	dns_namereln_t rel;

	apex = (ISDUALSTACK(fctx->addrinfo) || !ISFORWARDER(fctx->addrinfo))
		       ? fctx->domain
		       : fctx->fwdname;

	/*
	 * The name is outside the queried namespace.
	 */
	rel = dns_name_fullcompare(name, apex, &(int){ 0 },
				   &(unsigned int){ 0U });
	if (rel != dns_namereln_subdomain && rel != dns_namereln_equal) {
		return true;
	}

	/*
	 * If the record lives in the parent zone, adjust the name so we
	 * look for the correct zone or forward clause.
	 */
	labels = dns_name_countlabels(name);
	if (dns_rdatatype_atparent(type) && labels > 1U) {
		dns_name_init(&suffix);
		dns_name_getlabelsequence(name, 1, labels - 1, &suffix);
		name = &suffix;
	} else if (rel == dns_namereln_equal) {
		/* If 'name' is 'apex', no further checking is needed. */
		return false;
	}

	/*
	 * If there is a locally served zone between 'apex' and 'name'
	 * then don't cache.
	 */
	dns_ztfind_t options = DNS_ZTFIND_NOEXACT | DNS_ZTFIND_MIRROR;
	result = dns_view_findzone(fctx->res->view, name, options, &zone);
	if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		dns_name_t *zname = dns_zone_getorigin(zone);
		dns_namereln_t reln = dns_name_fullcompare(
			zname, apex, &(int){ 0 }, &(unsigned int){ 0U });
		dns_zone_detach(&zone);
		if (reln == dns_namereln_subdomain) {
			return true;
		}
	}

	/*
	 * Look for a forward declaration below 'name'.
	 */
	result = dns_fwdtable_find(fctx->res->view->fwdtable, name,
				   &forwarders);

	if (ISFORWARDER(fctx->addrinfo)) {
		/*
		 * See if the forwarder declaration is better.
		 */
		if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
			bool better = !dns_name_equal(&forwarders->name,
						      fctx->fwdname);
			dns_forwarders_detach(&forwarders);
			return better;
		}

		/*
		 * If the lookup failed, the configuration must have
		 * changed: play it safe and don't cache.
		 */
		return true;
	} else if (result == ISC_R_SUCCESS || result == DNS_R_PARTIALMATCH) {
		/*
		 * If 'name' is covered by a 'forward only' clause then we
		 * can't cache this response.
		 */
		bool nocache = (forwarders->fwdpolicy == dns_fwdpolicy_only &&
				!ISC_LIST_EMPTY(forwarders->fwdrs));
		dns_forwarders_detach(&forwarders);
		return nocache;
	}

	return false;
}

static isc_result_t
check_section(void *arg, const dns_name_t *addname, dns_rdatatype_t type,
	      dns_rdataset_t *found, dns_section_t section) {
	respctx_t *rctx = arg;
	fetchctx_t *fctx = rctx->fctx;
	isc_result_t result;
	dns_name_t *name = NULL;
	bool external;
	dns_rdatatype_t rtype;
	bool gluing;

	REQUIRE(VALID_FCTX(fctx));

#if CHECK_FOR_GLUE_IN_ANSWER
	if (section == DNS_SECTION_ANSWER && type != dns_rdatatype_a) {
		return ISC_R_SUCCESS;
	}
#endif /* if CHECK_FOR_GLUE_IN_ANSWER */

	gluing = (GLUING(fctx) || (fctx->type == dns_rdatatype_ns &&
				   dns_name_equal(fctx->name, dns_rootname)));

	result = dns_message_findname(rctx->query->rmessage, section, addname,
				      dns_rdatatype_any, 0, &name, NULL);
	if (result == ISC_R_SUCCESS) {
		external = name_external(name, type, fctx);
		if (type == dns_rdatatype_a) {
			ISC_LIST_FOREACH (name->list, rdataset, link) {
				if (dns_rdatatype_issig(rdataset->type)) {
					rtype = rdataset->covers;
				} else {
					rtype = rdataset->type;
				}
				if (dns_rdatatype_isaddr(rtype)) {
					mark_related(name, rdataset, external,
						     gluing);
				}
			}
		} else {
			dns_rdataset_t *rdataset = NULL;
			result = dns_message_findtype(name, type, 0, &rdataset);
			if (result == ISC_R_SUCCESS) {
				mark_related(name, rdataset, external, gluing);
				if (found != NULL) {
					dns_rdataset_clone(rdataset, found);
				}
				/*
				 * Do we have its SIG too?
				 */
				rdataset = NULL;
				result = dns_message_findtype(
					name, dns_rdatatype_rrsig, type,
					&rdataset);
				if (result == ISC_R_SUCCESS) {
					mark_related(name, rdataset, external,
						     gluing);
				}
			}
		}
	}

	return ISC_R_SUCCESS;
}

static isc_result_t
check_related(void *arg, const dns_name_t *addname, dns_rdatatype_t type,
	      dns_rdataset_t *found DNS__DB_FLARG) {
	return check_section(arg, addname, type, found, DNS_SECTION_ADDITIONAL);
}

#ifndef CHECK_FOR_GLUE_IN_ANSWER
#define CHECK_FOR_GLUE_IN_ANSWER 0
#endif /* ifndef CHECK_FOR_GLUE_IN_ANSWER */

#if CHECK_FOR_GLUE_IN_ANSWER
static isc_result_t
check_answer(void *arg, const dns_name_t *addname, dns_rdatatype_t type,
	     dns_rdataset_t *found) {
	return check_section(arg, addname, type, found, DNS_SECTION_ANSWER);
}
#endif /* if CHECK_FOR_GLUE_IN_ANSWER */

static bool
is_answeraddress_allowed(dns_view_t *view, dns_name_t *name,
			 dns_rdataset_t *rdataset) {
	isc_result_t result;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	struct in_addr ina;
	struct in6_addr in6a;
	isc_netaddr_t netaddr;
	char addrbuf[ISC_NETADDR_FORMATSIZE];
	char namebuf[DNS_NAME_FORMATSIZE];
	char classbuf[64];
	char typebuf[64];
	int match;

	/* By default, we allow any addresses. */
	if (view->denyansweracl == NULL) {
		return true;
	}

	/*
	 * If the owner name matches one in the exclusion list, either
	 * exactly or partially, allow it.
	 */
	if (dns_nametree_covered(view->answeracl_exclude, name, NULL, 0)) {
		return true;
	}

	/*
	 * Otherwise, search the filter list for a match for each
	 * address record.  If a match is found, the address should be
	 * filtered, so should the entire answer.
	 */
	DNS_RDATASET_FOREACH (rdataset) {
		dns_rdata_reset(&rdata);
		dns_rdataset_current(rdataset, &rdata);
		if (rdataset->type == dns_rdatatype_a) {
			INSIST(rdata.length == sizeof(ina.s_addr));
			memmove(&ina.s_addr, rdata.data, sizeof(ina.s_addr));
			isc_netaddr_fromin(&netaddr, &ina);
		} else {
			INSIST(rdata.length == sizeof(in6a.s6_addr));
			memmove(in6a.s6_addr, rdata.data, sizeof(in6a.s6_addr));
			isc_netaddr_fromin6(&netaddr, &in6a);
		}

		result = dns_acl_match(&netaddr, NULL, view->denyansweracl,
				       view->aclenv, &match, NULL);
		if (result == ISC_R_SUCCESS && match > 0) {
			isc_netaddr_format(&netaddr, addrbuf, sizeof(addrbuf));
			dns_name_format(name, namebuf, sizeof(namebuf));
			dns_rdatatype_format(rdataset->type, typebuf,
					     sizeof(typebuf));
			dns_rdataclass_format(rdataset->rdclass, classbuf,
					      sizeof(classbuf));
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_NOTICE,
				      "answer address %s denied for %s/%s/%s",
				      addrbuf, namebuf, typebuf, classbuf);
			return false;
		}
	}

	return true;
}

static bool
is_answertarget_allowed(fetchctx_t *fctx, dns_name_t *qname, dns_name_t *rname,
			dns_rdataset_t *rdataset, bool *chainingp) {
	isc_result_t result;
	dns_name_t *tname = NULL;
	dns_rdata_cname_t cname;
	dns_rdata_dname_t dname;
	dns_view_t *view = fctx->res->view;
	dns_rdata_t rdata = DNS_RDATA_INIT;
	unsigned int nlabels;
	dns_fixedname_t fixed;
	dns_name_t prefix;
	int order;

	REQUIRE(rdataset != NULL);
	REQUIRE(dns_rdatatype_isalias(rdataset->type));

	/*
	 * By default, we allow any target name.
	 * If newqname != NULL we also need to extract the newqname.
	 */
	if (chainingp == NULL && view->denyanswernames == NULL) {
		return true;
	}

	result = dns_rdataset_first(rdataset);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	dns_rdataset_current(rdataset, &rdata);
	switch (rdataset->type) {
	case dns_rdatatype_cname:
		result = dns_rdata_tostruct(&rdata, &cname, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		tname = &cname.cname;
		break;
	case dns_rdatatype_dname:
		if (dns_name_fullcompare(qname, rname, &order, &nlabels) !=
		    dns_namereln_subdomain)
		{
			return true;
		}
		result = dns_rdata_tostruct(&rdata, &dname, NULL);
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		dns_name_init(&prefix);
		tname = dns_fixedname_initname(&fixed);
		nlabels = dns_name_countlabels(rname);
		dns_name_split(qname, nlabels, &prefix, NULL);
		result = dns_name_concatenate(&prefix, &dname.dname, tname);
		if (result == DNS_R_NAMETOOLONG) {
			SET_IF_NOT_NULL(chainingp, true);
			return true;
		}
		RUNTIME_CHECK(result == ISC_R_SUCCESS);
		break;
	default:
		UNREACHABLE();
	}

	SET_IF_NOT_NULL(chainingp, true);

	if (view->denyanswernames == NULL) {
		return true;
	}

	/*
	 * If the owner name matches one in the exclusion list, either
	 * exactly or partially, allow it.
	 */
	if (dns_nametree_covered(view->answernames_exclude, qname, NULL, 0)) {
		return true;
	}

	/*
	 * If the target name is a subdomain of the search domain, allow
	 * it.
	 *
	 * Note that if BIND is configured as a forwarding DNS server,
	 * the search domain will always match the root domain ("."), so
	 * we must also check whether forwarding is enabled so that
	 * filters can be applied; see GL #1574.
	 */
	if (!fctx->forwarding && dns_name_issubdomain(tname, fctx->domain)) {
		return true;
	}

	/*
	 * Otherwise, apply filters.
	 */
	if (dns_nametree_covered(view->denyanswernames, tname, NULL, 0)) {
		char qnamebuf[DNS_NAME_FORMATSIZE];
		char tnamebuf[DNS_NAME_FORMATSIZE];
		char classbuf[64];
		char typebuf[64];
		dns_name_format(qname, qnamebuf, sizeof(qnamebuf));
		dns_name_format(tname, tnamebuf, sizeof(tnamebuf));
		dns_rdatatype_format(rdataset->type, typebuf, sizeof(typebuf));
		dns_rdataclass_format(view->rdclass, classbuf,
				      sizeof(classbuf));
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_NOTICE, "%s target %s denied for %s/%s",
			      typebuf, tnamebuf, qnamebuf, classbuf);
		return false;
	}

	return true;
}

static void
trim_ns_ttl(fetchctx_t *fctx, dns_name_t *name, dns_rdataset_t *rdataset) {
	if (fctx->ns_ttl_ok && rdataset->ttl > fctx->ns_ttl) {
		char ns_namebuf[DNS_NAME_FORMATSIZE];
		char namebuf[DNS_NAME_FORMATSIZE];
		char tbuf[DNS_RDATATYPE_FORMATSIZE];

		dns_name_format(name, ns_namebuf, sizeof(ns_namebuf));
		dns_name_format(fctx->name, namebuf, sizeof(namebuf));
		dns_rdatatype_format(fctx->type, tbuf, sizeof(tbuf));

		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_DEBUG(10),
			      "fctx %p: trimming ttl of %s/NS for %s/%s: "
			      "%u -> %u",
			      fctx, ns_namebuf, namebuf, tbuf, rdataset->ttl,
			      fctx->ns_ttl);
		rdataset->ttl = fctx->ns_ttl;
	}
}

static bool
validinanswer(dns_rdataset_t *rdataset, fetchctx_t *fctx) {
	if (rdataset->type == dns_rdatatype_nsec3) {
		/*
		 * NSEC3 records are not allowed to
		 * appear in the answer section.
		 */
		log_formerr(fctx, "NSEC3 in answer");
		return false;
	}
	if (rdataset->type == dns_rdatatype_tkey) {
		/*
		 * TKEY is not a valid record in a
		 * response to any query we can make.
		 */
		log_formerr(fctx, "TKEY in answer");
		return false;
	}
	if (rdataset->rdclass != fctx->res->rdclass) {
		log_formerr(fctx, "Mismatched class in answer");
		return false;
	}
	return true;
}

#if DNS_RESOLVER_TRACE
ISC_REFCOUNT_TRACE_IMPL(fetchctx, fctx_destroy);
#else
ISC_REFCOUNT_IMPL(fetchctx, fctx_destroy);
#endif

static void
resume_dslookup(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	fetchctx_t *fctx = resp->arg;
	isc_loop_t *loop = resp->loop;
	isc_result_t result;
	dns_resolver_t *res = NULL;
	dns_rdataset_t *frdataset = NULL, *nsrdataset = NULL;
	dns_rdataset_t nameservers;
	dns_fixedname_t fixed;
	dns_name_t *domain = NULL;
	unsigned int n;
	dns_fetch_t *fetch = NULL;

	REQUIRE(VALID_FCTX(fctx));

	res = fctx->res;

	REQUIRE(fctx->tid == isc_tid());

	FCTXTRACE("resume_dslookup");

	if (resp->node != NULL) {
		dns_db_detachnode(resp->db, &resp->node);
	}
	if (resp->db != NULL) {
		dns_db_detach(&resp->db);
	}

	/* Preserve data from resp before freeing it. */
	frdataset = resp->rdataset; /* a.k.a. fctx->nsrrset */
	result = resp->result;

	dns_resolver_freefresp(&resp);

	LOCK(&fctx->lock);
	if (SHUTTINGDOWN(fctx)) {
		result = ISC_R_SHUTTINGDOWN;
	}
	UNLOCK(&fctx->lock);

	fetch = fctx->nsfetch;
	fctx->nsfetch = NULL;

	FTRACE("resume_dslookup");

	switch (result) {
	case ISC_R_SUCCESS:
		FCTXTRACE("resuming DS lookup");

		if (dns_rdataset_isassociated(&fctx->nameservers)) {
			dns_rdataset_disassociate(&fctx->nameservers);
		}
		dns_rdataset_clone(frdataset, &fctx->nameservers);

		/*
		 * Disassociate now the NS's are saved.
		 */
		if (dns_rdataset_isassociated(frdataset)) {
			dns_rdataset_disassociate(frdataset);
		}

		fctx->ns_ttl = fctx->nameservers.ttl;
		fctx->ns_ttl_ok = true;
		log_ns_ttl(fctx, "resume_dslookup");

		fcount_decr(fctx);
		dns_name_copy(fctx->nsname, fctx->domain);
		result = fcount_incr(fctx, false);
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}

		/* Try again. */
		fctx_try(fctx, true);
		break;

	case ISC_R_SHUTTINGDOWN:
	case ISC_R_CANCELED:
		/* Don't try anymore. */
		/* Can't be done in cleanup. */
		if (dns_rdataset_isassociated(frdataset)) {
			dns_rdataset_disassociate(frdataset);
		}
		goto cleanup;

	default:
		/*
		 * Disassociate for the next dns_resolver_createfetch call.
		 */
		if (dns_rdataset_isassociated(frdataset)) {
			dns_rdataset_disassociate(frdataset);
		}

		/*
		 * If the chain of resume_dslookup() invocations managed to
		 * chop off enough labels from the original DS owner name to
		 * reach the top of the namespace, no further progress can be
		 * made.  Interrupt the DS chasing process, returning SERVFAIL.
		 */
		if (dns_name_equal(fctx->nsname, fetch->private->domain)) {
			result = DNS_R_SERVFAIL;
			goto cleanup;
		}

		/* Get nameservers from fetch before we destroy it. */
		dns_rdataset_init(&nameservers);
		if (dns_rdataset_isassociated(&fetch->private->nameservers)) {
			dns_rdataset_clone(&fetch->private->nameservers,
					   &nameservers);
			nsrdataset = &nameservers;

			/* Get domain from fetch before we destroy it. */
			domain = dns_fixedname_initname(&fixed);
			dns_name_copy(fetch->private->domain, domain);
		}

		n = dns_name_countlabels(fctx->nsname);
		dns_name_getlabelsequence(fctx->nsname, 1, n - 1, fctx->nsname);

		FCTXTRACE("continuing to look for parent's NS records");

		fetchctx_ref(fctx);
		result = dns_resolver_createfetch(
			res, fctx->nsname, dns_rdatatype_ns, domain, nsrdataset,
			NULL, NULL, 0, fctx->options, 0, fctx->qc, fctx->gqc,
			loop, resume_dslookup, fctx, &fctx->edectx,
			&fctx->nsrrset, NULL, &fctx->nsfetch);
		if (result != ISC_R_SUCCESS) {
			fetchctx_unref(fctx);
			if (result == DNS_R_DUPLICATE) {
				result = DNS_R_SERVFAIL;
			}
		}

		if (dns_rdataset_isassociated(&nameservers)) {
			dns_rdataset_disassociate(&nameservers);
		}
	}

cleanup:
	dns_resolver_destroyfetch(&fetch);

	if (result != ISC_R_SUCCESS) {
		/* An error occurred, tear down whole fctx */
		fctx_done_unref(fctx, result);
	}

	fetchctx_detach(&fctx);
}

static void
checknamessection(dns_message_t *message, dns_section_t section) {
	MSG_SECTION_FOREACH (message, section, name) {
		ISC_LIST_FOREACH (name->list, rdataset, link) {
			DNS_RDATASET_FOREACH (rdataset) {
				dns_rdata_t rdata = DNS_RDATA_INIT;
				dns_rdataset_current(rdataset, &rdata);
				if (!dns_rdata_checkowner(name, rdata.rdclass,
							  rdata.type, false) ||
				    !dns_rdata_checknames(&rdata, name, NULL))
				{
					rdataset->attributes.checknames = true;
				}
			}
		}
	}
}

static void
checknames(dns_message_t *message) {
	checknamessection(message, DNS_SECTION_ANSWER);
	checknamessection(message, DNS_SECTION_AUTHORITY);
	checknamessection(message, DNS_SECTION_ADDITIONAL);
}

static void
make_hex(unsigned char *src, size_t srclen, char *buf, size_t buflen) {
	isc_buffer_t b;
	isc_region_t r;
	isc_result_t result;

	r.base = src;
	r.length = srclen;
	isc_buffer_init(&b, buf, buflen);
	result = isc_hex_totext(&r, 0, "", &b);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	isc_buffer_putuint8(&b, '\0');
}

static void
make_printable(unsigned char *src, size_t srclen, char *buf, size_t buflen) {
	INSIST(buflen > srclen);
	while (srclen-- > 0) {
		unsigned char c = *src++;
		*buf++ = isprint(c) ? c : '.';
	}
	*buf = '\0';
}

/*
 * Log server NSID at log level 'level'
 */
static void
log_nsid(isc_buffer_t *opt, size_t nsid_len, resquery_t *query, int level,
	 isc_mem_t *mctx) {
	char addrbuf[ISC_SOCKADDR_FORMATSIZE], *buf = NULL, *pbuf = NULL;
	size_t buflen;

	REQUIRE(nsid_len <= UINT16_MAX);

	/* Allocate buffer for storing hex version of the NSID */
	buflen = nsid_len * 2 + 1;
	buf = isc_mem_get(mctx, buflen);
	pbuf = isc_mem_get(mctx, nsid_len + 1);

	/* Convert to hex */
	make_hex(isc_buffer_current(opt), nsid_len, buf, buflen);

	/* Make printable version */
	make_printable(isc_buffer_current(opt), nsid_len, pbuf, nsid_len + 1);

	isc_sockaddr_format(&query->addrinfo->sockaddr, addrbuf,
			    sizeof(addrbuf));
	isc_log_write(DNS_LOGCATEGORY_NSID, DNS_LOGMODULE_RESOLVER, level,
		      "received NSID %s (\"%s\") from %s", buf, pbuf, addrbuf);

	isc_mem_put(mctx, pbuf, nsid_len + 1);
	isc_mem_put(mctx, buf, buflen);
}

static void
log_zoneversion(unsigned char *version, size_t version_len, unsigned char *nsid,
		size_t nsid_len, resquery_t *query, int level,
		isc_mem_t *mctx) {
	char addrbuf[ISC_SOCKADDR_FORMATSIZE];
	char namebuf[DNS_NAME_FORMATSIZE];
	size_t nsid_buflen = 0;
	char *nsid_buf = NULL;
	char *nsid_pbuf = NULL;
	const char *nsid_hex = "";
	const char *nsid_print = "";
	const char *sep_1 = "";
	const char *sep_2 = "";
	const char *sep_3 = "";
	dns_name_t suffix = DNS_NAME_INITEMPTY;
	unsigned int labels;

	REQUIRE(version_len <= UINT16_MAX);

	/*
	 * Don't log reflected ZONEVERSION option.
	 */
	if (version_len == 0) {
		return;
	}

	/* Enforced by dns_rdata_fromwire. */
	INSIST(version_len >= 2);

	/*
	 * Sanity check on label count.
	 */
	labels = version[0] + 1;
	if (dns_name_countlabels(query->fctx->name) < labels) {
		return;
	}

	/*
	 * Get zone name.
	 */
	dns_name_split(query->fctx->name, labels, NULL, &suffix);
	dns_name_format(&suffix, namebuf, sizeof(namebuf));

	if (nsid != NULL) {
		nsid_buflen = nsid_len * 2 + 1;
		nsid_hex = nsid_buf = isc_mem_get(mctx, nsid_buflen);
		nsid_print = nsid_pbuf = isc_mem_get(mctx, nsid_len + 1);

		/* Convert to hex */
		make_hex(nsid, nsid_len, nsid_buf, nsid_buflen);

		/* Convert to printable */
		make_printable(nsid, nsid_len, nsid_pbuf, nsid_len + 1);

		sep_1 = " (NSID ";
		sep_2 = " (";
		sep_3 = "))";
	}

	isc_sockaddr_format(&query->addrinfo->sockaddr, addrbuf,
			    sizeof(addrbuf));
	if (version[1] == 0 && version_len == 6) {
		uint32_t serial = version[2] << 24 | version[3] << 2 |
				  version[4] << 8 | version[5];
		isc_log_write(DNS_LOGCATEGORY_ZONEVERSION,
			      DNS_LOGMODULE_RESOLVER, level,
			      "received ZONEVERSION serial %u from %s for %s "
			      "zone %s%s%s%s%s%s",
			      serial, addrbuf, query->fctx->info, namebuf,
			      sep_1, nsid_hex, sep_2, nsid_print, sep_3);
	} else {
		size_t version_buflen = version_len * 2 + 1;
		char *version_hex = isc_mem_get(mctx, version_buflen);
		char *version_pbuf = isc_mem_get(mctx, version_len - 1);

		/* Convert to hex */
		make_hex(version + 2, version_len - 2, version_hex,
			 version_buflen);

		/* Convert to printable */
		make_printable(version + 2, version_len - 2, version_pbuf,
			       version_len - 1);

		isc_log_write(DNS_LOGCATEGORY_ZONEVERSION,
			      DNS_LOGMODULE_RESOLVER, level,
			      "received ZONEVERSION type %u value %s (%s) from "
			      "%s for %s zone %s%s%s%s%s%s",
			      version[1], version_hex, version_pbuf, addrbuf,
			      query->fctx->info, namebuf, sep_1, nsid_hex,
			      sep_2, nsid_print, sep_3);
		isc_mem_put(mctx, version_hex, version_buflen);
		isc_mem_put(mctx, version_pbuf, version_len - 1);
	}

	if (nsid_pbuf != NULL) {
		isc_mem_put(mctx, nsid_pbuf, nsid_len + 1);
	}
	if (nsid_buf != NULL) {
		isc_mem_put(mctx, nsid_buf, nsid_buflen);
	}
}

static bool
betterreferral(respctx_t *rctx) {
	dns_message_t *msg = rctx->query->rmessage;

	MSG_SECTION_FOREACH (msg, DNS_SECTION_AUTHORITY, name) {
		if (!isstrictsubdomain(name, rctx->fctx->domain)) {
			continue;
		}

		ISC_LIST_FOREACH (name->list, rdataset, link) {
			if (rdataset->type == dns_rdatatype_ns) {
				return true;
			}
		}
	}
	return false;
}

/*
 * Handles responses received in response to iterative queries sent by
 * resquery_send(). Sets up a response context (respctx_t).
 */
static void
resquery_response(isc_result_t eresult, isc_region_t *region, void *arg) {
	isc_result_t result;
	resquery_t *query = (resquery_t *)arg;
	fetchctx_t *fctx = NULL;
	respctx_t *rctx = NULL;

	if (eresult == ISC_R_CANCELED) {
		return;
	}

	REQUIRE(VALID_QUERY(query));
	fctx = query->fctx;
	REQUIRE(VALID_FCTX(fctx));
	REQUIRE(fctx->tid == isc_tid());

	QTRACE("response");

	if (eresult == ISC_R_SUCCESS) {
		if (isc_sockaddr_pf(&query->addrinfo->sockaddr) == PF_INET) {
			inc_stats(fctx->res, dns_resstatscounter_responsev4);
		} else {
			inc_stats(fctx->res, dns_resstatscounter_responsev6);
		}
	}

	rctx = isc_mem_get(fctx->mctx, sizeof(*rctx));
	rctx_respinit(query, fctx, eresult, region, rctx);

	if (eresult == ISC_R_SHUTTINGDOWN ||
	    atomic_load_acquire(&fctx->res->exiting))
	{
		result = ISC_R_SHUTTINGDOWN;
		FCTXTRACE("resolver shutting down");
		rctx->finish = NULL;
		rctx_done(rctx, result);
		goto cleanup;
	}

	result = rctx_timedout(rctx);
	if (result == ISC_R_COMPLETE) {
		goto cleanup;
	}

	fctx->addrinfo = query->addrinfo;
	fctx->timeout = false;
	fctx->timeouts = 0;

	/*
	 * Check whether the dispatcher has failed; if so we're done
	 */
	result = rctx_dispfail(rctx);
	if (result == ISC_R_COMPLETE) {
		goto cleanup;
	}

	if (query->tsig != NULL) {
		dns_message_setquerytsig(query->rmessage, query->tsig);
	}

	if (query->tsigkey != NULL) {
		result = dns_message_settsigkey(query->rmessage,
						query->tsigkey);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE3("unable to set tsig key", result);
			rctx_done(rctx, result);
			goto cleanup;
		}
	}

	dns_message_setclass(query->rmessage, fctx->res->rdclass);

	if ((rctx->retryopts & DNS_FETCHOPT_TCP) == 0) {
		if ((rctx->retryopts & DNS_FETCHOPT_NOEDNS0) == 0) {
			dns_adb_setudpsize(
				fctx->adb, query->addrinfo,
				isc_buffer_usedlength(&rctx->buffer));
		} else {
			dns_adb_plainresponse(fctx->adb, query->addrinfo);
		}
	}

	/*
	 * Parse response message.
	 */
	result = rctx_parse(rctx);
	if (result == ISC_R_COMPLETE) {
		goto cleanup;
	}

	/*
	 * Log the incoming packet.
	 */
	rctx_logpacket(rctx);

	if (query->rmessage->rdclass != fctx->res->rdclass) {
		rctx->resend = true;
		FCTXTRACE("bad class");
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * Process receive opt record.
	 */
	rctx->opt = dns_message_getopt(query->rmessage);
	if (rctx->opt != NULL) {
		rctx_opt(rctx);
	}

	if (query->rmessage->cc_bad &&
	    (rctx->retryopts & DNS_FETCHOPT_TCP) == 0)
	{
		/*
		 * If the COOKIE is bad, assume it is an attack and
		 * keep listening for a good answer.
		 */
		rctx->nextitem = true;
		if (isc_log_wouldlog(ISC_LOG_INFO)) {
			char addrbuf[ISC_SOCKADDR_FORMATSIZE];
			isc_sockaddr_format(&query->addrinfo->sockaddr, addrbuf,
					    sizeof(addrbuf));
			isc_log_write(DNS_LOGCATEGORY_RESOLVER,
				      DNS_LOGMODULE_RESOLVER, ISC_LOG_INFO,
				      "bad cookie from %s", addrbuf);
		}
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * Is the question the same as the one we asked?
	 * NOERROR/NXDOMAIN/YXDOMAIN/REFUSED/SERVFAIL/BADCOOKIE must
	 * have the same question. FORMERR/NOTIMP if they have a
	 * question section then it must match.
	 */
	switch (query->rmessage->rcode) {
	case dns_rcode_notimp:
	case dns_rcode_formerr:
		if (query->rmessage->counts[DNS_SECTION_QUESTION] == 0) {
			break;
		}
		FALLTHROUGH;
	case dns_rcode_nxrrset: /* Not expected. */
	case dns_rcode_badcookie:
	case dns_rcode_noerror:
	case dns_rcode_nxdomain:
	case dns_rcode_yxdomain:
	case dns_rcode_refused:
	case dns_rcode_servfail:
	default:
		result = same_question(fctx, query->rmessage);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE3("question section invalid", result);
			rctx->nextitem = true;
			rctx_done(rctx, result);
			goto cleanup;
		}
		break;
	}

	if (query->rmessage->tsigkey == NULL && query->rmessage->tsig == NULL &&
	    query->rmessage->sig0 != NULL)
	{
		/*
		 * If the message is not TSIG-signed (which has priorty) and is
		 * SIG(0)-signed (which consumes more resources), then run an
		 * asynchronous check.
		 */
		result = dns_message_checksig_async(
			query->rmessage, fctx->res->view, fctx->loop,
			resquery_response_continue, rctx);
		INSIST(result == DNS_R_WAIT);
	} else {
		/*
		 * If the message is signed, check the signature.  If not, this
		 * returns success anyway.
		 */
		result = dns_message_checksig(query->rmessage, fctx->res->view);
		resquery_response_continue(rctx, result);
	}

	return;

cleanup:
	isc_mem_putanddetach(&rctx->mctx, rctx, sizeof(*rctx));
}

static void
resquery_response_continue(void *arg, isc_result_t result) {
	respctx_t *rctx = arg;
	fetchctx_t *fctx = rctx->fctx;
	resquery_t *query = rctx->query;

	QTRACE("response_continue");

	if (result != ISC_R_SUCCESS) {
		FCTXTRACE3("signature check failed", result);
		if (result == DNS_R_UNEXPECTEDTSIG ||
		    result == DNS_R_EXPECTEDTSIG)
		{
			rctx->nextitem = true;
		}
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * The dispatcher should ensure we only get responses with QR
	 * set.
	 */
	INSIST((query->rmessage->flags & DNS_MESSAGEFLAG_QR) != 0);

	/*
	 * If we have had a server cookie and don't get one retry over
	 * TCP. This may be a misconfigured anycast server or an attempt
	 * to send a spoofed response.  Additionally retry over TCP if
	 * require-cookie is true and we don't have a got client cookie.
	 * Skip if we have a valid TSIG.
	 */
	if (dns_message_gettsig(query->rmessage, NULL) == NULL &&
	    !query->rmessage->cc_ok && !query->rmessage->cc_bad &&
	    (rctx->retryopts & DNS_FETCHOPT_TCP) == 0)
	{
		if (dns_adb_getcookie(query->addrinfo, NULL, 0) >
		    CLIENT_COOKIE_SIZE)
		{
			if (isc_log_wouldlog(ISC_LOG_INFO)) {
				char addrbuf[ISC_SOCKADDR_FORMATSIZE];
				isc_sockaddr_format(&query->addrinfo->sockaddr,
						    addrbuf, sizeof(addrbuf));
				isc_log_write(DNS_LOGCATEGORY_RESOLVER,
					      DNS_LOGMODULE_RESOLVER,
					      ISC_LOG_INFO,
					      "missing expected cookie "
					      "from %s",
					      addrbuf);
			}
			rctx->retryopts |= DNS_FETCHOPT_TCP;
			rctx->resend = true;
			rctx_done(rctx, result);
			goto cleanup;
		} else if (fctx->res->view->peers != NULL) {
			dns_peer_t *peer = NULL;
			isc_netaddr_t netaddr;
			isc_netaddr_fromsockaddr(&netaddr,
						 &query->addrinfo->sockaddr);
			result = dns_peerlist_peerbyaddr(fctx->res->view->peers,
							 &netaddr, &peer);
			if (result == ISC_R_SUCCESS) {
				bool required = false;
				result = dns_peer_getrequirecookie(peer,
								   &required);
				if (result == ISC_R_SUCCESS && required) {
					if (isc_log_wouldlog(ISC_LOG_INFO)) {
						char addrbuf
							[ISC_SOCKADDR_FORMATSIZE];
						isc_sockaddr_format(
							&query->addrinfo
								 ->sockaddr,
							addrbuf,
							sizeof(addrbuf));
						isc_log_write(
							DNS_LOGCATEGORY_RESOLVER,
							DNS_LOGMODULE_RESOLVER,
							ISC_LOG_INFO,
							"missing required "
							"cookie "
							"from %s",
							addrbuf);
					}
					rctx->retryopts |= DNS_FETCHOPT_TCP;
					rctx->resend = true;
					rctx_done(rctx, result);
					goto cleanup;
				}
			}
		}
	}

	rctx_edns(rctx);

	/*
	 * Deal with truncated responses by retrying using TCP.
	 */
	if ((query->rmessage->flags & DNS_MESSAGEFLAG_TC) != 0) {
		rctx->truncated = true;
	}

	if (rctx->truncated) {
		inc_stats(fctx->res, dns_resstatscounter_truncated);
		if ((rctx->retryopts & DNS_FETCHOPT_TCP) != 0) {
			rctx->broken_server = DNS_R_TRUNCATEDTCP;
			rctx->next_server = true;
		} else {
			rctx->retryopts |= DNS_FETCHOPT_TCP;
			rctx->resend = true;
		}
		FCTXTRACE3("message truncated", result);
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * Is it a query response?
	 */
	if (query->rmessage->opcode != dns_opcode_query) {
		rctx->broken_server = DNS_R_UNEXPECTEDOPCODE;
		rctx->next_server = true;
		FCTXTRACE("invalid message opcode");
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * Update statistics about erroneous responses.
	 */
	switch (query->rmessage->rcode) {
	case dns_rcode_noerror:
		/* no error */
		break;
	case dns_rcode_nxdomain:
		inc_stats(fctx->res, dns_resstatscounter_nxdomain);
		break;
	case dns_rcode_servfail:
		inc_stats(fctx->res, dns_resstatscounter_servfail);
		break;
	case dns_rcode_formerr:
		inc_stats(fctx->res, dns_resstatscounter_formerr);
		break;
	case dns_rcode_refused:
		inc_stats(fctx->res, dns_resstatscounter_refused);
		break;
	case dns_rcode_badvers:
		inc_stats(fctx->res, dns_resstatscounter_badvers);
		break;
	case dns_rcode_badcookie:
		inc_stats(fctx->res, dns_resstatscounter_badcookie);
		break;
	default:
		inc_stats(fctx->res, dns_resstatscounter_othererror);
		break;
	}

	/*
	 * Bad server?
	 */
	result = rctx_badserver(rctx, result);
	if (result == ISC_R_COMPLETE) {
		goto cleanup;
	}

	/*
	 * Lame server?
	 */
	result = rctx_lameserver(rctx);
	if (result == ISC_R_COMPLETE) {
		goto cleanup;
	}

	/*
	 * Optionally call dns_rdata_checkowner() and
	 * dns_rdata_checknames() to validate the names in the response
	 * message.
	 */
	if ((fctx->res->options & DNS_RESOLVER_CHECKNAMES) != 0) {
		checknames(query->rmessage);
	}

	/*
	 * Clear cache bits.
	 */
	FCTX_ATTR_CLR(fctx, FCTX_ATTR_WANTNCACHE | FCTX_ATTR_WANTCACHE);

	/*
	 * Did we get any answers?
	 */
	if (query->rmessage->counts[DNS_SECTION_ANSWER] > 0 &&
	    (query->rmessage->rcode == dns_rcode_noerror ||
	     query->rmessage->rcode == dns_rcode_yxdomain ||
	     query->rmessage->rcode == dns_rcode_nxdomain))
	{
		result = rctx_answer(rctx);
		if (result == ISC_R_COMPLETE) {
			goto cleanup;
		}
	} else if (query->rmessage->counts[DNS_SECTION_AUTHORITY] > 0 ||
		   query->rmessage->rcode == dns_rcode_noerror ||
		   query->rmessage->rcode == dns_rcode_nxdomain)
	{
		/*
		 * This might be an NXDOMAIN, NXRRSET, or referral.
		 * Call rctx_answer_none() to determine which it is.
		 */
		result = rctx_answer_none(rctx);
		switch (result) {
		case ISC_R_SUCCESS:
		case DNS_R_CHASEDSSERVERS:
			break;
		case DNS_R_DELEGATION:
			/*
			 * With NOFOLLOW we want to pass return
			 * DNS_R_DELEGATION to resume_qmin.
			 */
			if ((fctx->options & DNS_FETCHOPT_NOFOLLOW) == 0) {
				result = ISC_R_SUCCESS;
			}
			break;
		default:
			/*
			 * Something has gone wrong.
			 */
			if (result == DNS_R_FORMERR) {
				rctx->next_server = true;
			}
			FCTXTRACE3("rctx_answer_none", result);
			rctx_done(rctx, result);
			goto cleanup;
		}
	} else {
		/*
		 * The server is insane.
		 */
		/* XXXRTH Log */
		rctx->broken_server = DNS_R_UNEXPECTEDRCODE;
		rctx->next_server = true;
		FCTXTRACE("broken server: unexpected rcode");
		rctx_done(rctx, result);
		goto cleanup;
	}

	/*
	 * Follow additional section data chains.
	 */
	rctx_additional(rctx);

	/*
	 * Cache the cacheable parts of the message.  This may also
	 * cause work to be queued to the DNSSEC validator.
	 */
	if (WANTCACHE(fctx)) {
		isc_result_t tresult;
		tresult = cache_message(fctx, query->rmessage, query->addrinfo,
					rctx->now);
		if (tresult != ISC_R_SUCCESS) {
			FCTXTRACE3("cache_message complete", tresult);
			rctx_done(rctx, tresult);
			goto cleanup;
		}
	}

	/*
	 * Negative caching
	 */
	rctx_ncache(rctx);

	FCTXTRACE("resquery_response done");
	rctx_done(rctx, result);

cleanup:
	isc_mem_putanddetach(&rctx->mctx, rctx, sizeof(*rctx));
}

/*
 * rctx_respinit():
 * Initialize the response context structure 'rctx' to all zeroes, then
 * set the loop, event, query and fctx information from
 * resquery_response().
 */
static void
rctx_respinit(resquery_t *query, fetchctx_t *fctx, isc_result_t result,
	      isc_region_t *region, respctx_t *rctx) {
	*rctx = (respctx_t){ .result = result,
			     .query = query,
			     .fctx = fctx,
			     .broken_type = badns_response,
			     .retryopts = query->options };
	if (result == ISC_R_SUCCESS) {
		REQUIRE(region != NULL);
		isc_buffer_init(&rctx->buffer, region->base, region->length);
		isc_buffer_add(&rctx->buffer, region->length);
	} else {
		isc_buffer_initnull(&rctx->buffer);
	}
	rctx->tnow = isc_time_now();
	rctx->finish = &rctx->tnow;
	rctx->now = (isc_stdtime_t)isc_time_seconds(&rctx->tnow);
	isc_mem_attach(fctx->mctx, &rctx->mctx);
}

/*
 * rctx_answer_init():
 * Clear and reinitialize those portions of 'rctx' that will be needed
 * when scanning the answer section of the response message. This can be
 * called more than once if scanning needs to be restarted (though
 * currently there are no cases in which this occurs).
 */
static void
rctx_answer_init(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	rctx->aa = ((rctx->query->rmessage->flags & DNS_MESSAGEFLAG_AA) != 0);
	if (rctx->aa) {
		rctx->trust = dns_trust_authanswer;
	} else {
		rctx->trust = dns_trust_answer;
	}

	/*
	 * There can be multiple RRSIG and SIG records at a name so
	 * we treat these types as a subset of ANY.
	 */
	rctx->type = fctx->type;
	if (dns_rdatatype_issig(fctx->type)) {
		rctx->type = dns_rdatatype_any;
	}

	/*
	 * Bigger than any valid DNAME label count.
	 */
	rctx->dname_labels = dns_name_countlabels(fctx->name);
	rctx->domain_labels = dns_name_countlabels(fctx->domain);

	rctx->found_type = dns_rdatatype_none;

	rctx->aname = NULL;
	rctx->ardataset = NULL;

	rctx->cname = NULL;
	rctx->crdataset = NULL;

	rctx->dname = NULL;
	rctx->drdataset = NULL;

	rctx->ns_name = NULL;
	rctx->ns_rdataset = NULL;

	rctx->soa_name = NULL;
	rctx->ds_name = NULL;
	rctx->found_name = NULL;
}

/*
 * rctx_dispfail():
 * Handle the case where the dispatcher failed
 */
static isc_result_t
rctx_dispfail(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	if (rctx->result == ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	/*
	 * There's no hope for this response.
	 */
	rctx->next_server = true;

	/*
	 * If this is a network failure, the operation is cancelled,
	 * or the network manager is being shut down, we mark the server
	 * as bad so that we won't try it for this fetch again. Also
	 * adjust finish and no_response so that we penalize this
	 * address in SRTT adjustments later.
	 */
	switch (rctx->result) {
	case ISC_R_EOF:
	case ISC_R_HOSTDOWN:
	case ISC_R_HOSTUNREACH:
	case ISC_R_NETDOWN:
	case ISC_R_NETUNREACH:
	case ISC_R_CONNREFUSED:
	case ISC_R_CONNECTIONRESET:
	case ISC_R_INVALIDPROTO:
	case ISC_R_CANCELED:
	case ISC_R_SHUTTINGDOWN:
		rctx->broken_server = rctx->result;
		rctx->broken_type = badns_unreachable;
		rctx->finish = NULL;
		rctx->no_response = true;
		break;
	default:
		break;
	}

	FCTXTRACE3("dispatcher failure", rctx->result);
	rctx_done(rctx, ISC_R_SUCCESS);
	return ISC_R_COMPLETE;
}

/*
 * rctx_timedout():
 * Handle the case where a dispatch read timed out.
 */
static isc_result_t
rctx_timedout(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	if (rctx->result == ISC_R_TIMEDOUT) {
		isc_time_t now;

		inc_stats(fctx->res, dns_resstatscounter_querytimeout);
		FCTX_ATTR_CLR(fctx, FCTX_ATTR_ADDRWAIT);
		fctx->timeout = true;
		fctx->timeouts++;

		rctx->no_response = true;
		rctx->finish = NULL;

		now = isc_time_now();
		/* netmgr timeouts are accurate to the millisecond */
		if (isc_time_microdiff(&fctx->expires, &now) < US_PER_MS) {
			FCTXTRACE("query timed out; stopped trying to make "
				  "fetch happen");
			dns_ede_add(&fctx->edectx, DNS_EDE_NOREACHABLEAUTH,
				    NULL);
		} else {
			FCTXTRACE("query timed out; trying next server");
			/* try next server */
			rctx->next_server = true;
		}

		rctx_done(rctx, rctx->result);
		return ISC_R_COMPLETE;
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_parse():
 * Parse the response message.
 */
static isc_result_t
rctx_parse(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;
	resquery_t *query = rctx->query;

	result = dns_message_parse(query->rmessage, &rctx->buffer, 0);
	if (result == ISC_R_SUCCESS) {
		return ISC_R_SUCCESS;
	}

	FCTXTRACE3("message failed to parse", result);

	switch (result) {
	case ISC_R_UNEXPECTEDEND:
		if (query->rmessage->question_ok &&
		    (query->rmessage->flags & DNS_MESSAGEFLAG_TC) != 0 &&
		    (rctx->retryopts & DNS_FETCHOPT_TCP) == 0)
		{
			/*
			 * We defer retrying via TCP for a bit so we can
			 * check out this message further.
			 */
			rctx->truncated = true;
			return ISC_R_SUCCESS;
		}

		/*
		 * Either the message ended prematurely,
		 * and/or wasn't marked as being truncated,
		 * and/or this is a response to a query we
		 * sent over TCP.  In all of these cases,
		 * something is wrong with the remote
		 * server and we don't want to retry using
		 * TCP.
		 */
		if ((rctx->retryopts & DNS_FETCHOPT_NOEDNS0) == 0) {
			/*
			 * The problem might be that they
			 * don't understand EDNS0.  Turn it
			 * off and try again.
			 */
			rctx->retryopts |= DNS_FETCHOPT_NOEDNS0;
			rctx->resend = true;
			inc_stats(fctx->res, dns_resstatscounter_edns0fail);
		} else {
			rctx->broken_server = result;
			rctx->next_server = true;
		}

		rctx_done(rctx, result);
		break;
	case DNS_R_FORMERR:
		if ((rctx->retryopts & DNS_FETCHOPT_NOEDNS0) == 0) {
			/*
			 * The problem might be that they
			 * don't understand EDNS0.  Turn it
			 * off and try again.
			 */
			rctx->retryopts |= DNS_FETCHOPT_NOEDNS0;
			rctx->resend = true;
			inc_stats(fctx->res, dns_resstatscounter_edns0fail);
		} else {
			rctx->broken_server = DNS_R_UNEXPECTEDRCODE;
			rctx->next_server = true;
		}

		rctx_done(rctx, result);
		break;
	default:
		/*
		 * Something bad has happened.
		 */
		rctx_done(rctx, result);
		break;
	}

	return ISC_R_COMPLETE;
}

/*
 * rctx_opt():
 * Process the OPT record in the response.
 */
static void
rctx_opt(respctx_t *rctx) {
	resquery_t *query = rctx->query;
	fetchctx_t *fctx = rctx->fctx;
	dns_rdata_t rdata;
	isc_buffer_t optbuf;
	isc_result_t result;
	bool seen_cookie = false;
	bool seen_nsid = false;
	bool seen_zoneversion = false;
	unsigned char *nsid = NULL;
	uint16_t nsidlen = 0;
	unsigned char *zoneversion = NULL;
	uint16_t zoneversionlen = 0;

	result = dns_rdataset_first(rctx->opt);
	if (result != ISC_R_SUCCESS) {
		return;
	}

	dns_rdata_init(&rdata);
	dns_rdataset_current(rctx->opt, &rdata);
	isc_buffer_init(&optbuf, rdata.data, rdata.length);
	isc_buffer_add(&optbuf, rdata.length);

	while (isc_buffer_remaininglength(&optbuf) >= 4) {
		uint16_t optcode;
		uint16_t optlen;
		unsigned char *optvalue;
		unsigned char cookie[CLIENT_COOKIE_SIZE];
		optcode = isc_buffer_getuint16(&optbuf);
		optlen = isc_buffer_getuint16(&optbuf);
		INSIST(optlen <= isc_buffer_remaininglength(&optbuf));
		switch (optcode) {
		case DNS_OPT_NSID:
			if (seen_nsid) {
				break;
			}
			seen_nsid = true;
			nsid = isc_buffer_current(&optbuf);
			nsidlen = optlen;
			if ((query->options & DNS_FETCHOPT_WANTNSID) != 0) {
				log_nsid(&optbuf, optlen, query, ISC_LOG_INFO,
					 fctx->mctx);
			}
			break;
		case DNS_OPT_COOKIE:
			/* Only process the first cookie option. */
			if (seen_cookie) {
				break;
			}
			seen_cookie = true;

			optvalue = isc_buffer_current(&optbuf);
			compute_cc(query, cookie, sizeof(cookie));
			INSIST(query->rmessage->cc_bad == 0 &&
			       query->rmessage->cc_ok == 0);

			inc_stats(fctx->res, dns_resstatscounter_cookiein);

			if (optlen < CLIENT_COOKIE_SIZE ||
			    memcmp(cookie, optvalue, CLIENT_COOKIE_SIZE) != 0)
			{
				query->rmessage->cc_bad = 1;
				break;
			}

			/* Cookie OK */
			if (optlen == CLIENT_COOKIE_SIZE) {
				query->rmessage->cc_echoed = 1;
			} else {
				query->rmessage->cc_ok = 1;
				inc_stats(fctx->res,
					  dns_resstatscounter_cookieok);
				dns_adb_setcookie(fctx->adb, query->addrinfo,
						  optvalue, optlen);
			}
			break;
		case DNS_OPT_ZONEVERSION:
			if (seen_zoneversion) {
				break;
			}
			seen_zoneversion = true;
			zoneversion = isc_buffer_current(&optbuf);
			zoneversionlen = optlen;
			break;
		default:
			break;
		}
		isc_buffer_forward(&optbuf, optlen);
	}
	INSIST(isc_buffer_remaininglength(&optbuf) == 0U);

	if ((query->options & DNS_FETCHOPT_WANTZONEVERSION) != 0 &&
	    zoneversion != NULL)
	{
		log_zoneversion(zoneversion, zoneversionlen, nsid, nsidlen,
				query, ISC_LOG_INFO, fctx->mctx);
	}
}

/*
 * rctx_edns():
 * Determine whether the remote server is using EDNS correctly or
 * incorrectly and record that information if needed.
 */
static void
rctx_edns(respctx_t *rctx) {
	resquery_t *query = rctx->query;
	fetchctx_t *fctx = rctx->fctx;

	/*
	 * If we get a non error EDNS response record the fact so we
	 * won't fallback to plain DNS in the future for this server.
	 */
	if (rctx->opt != NULL && !EDNSOK(query->addrinfo) &&
	    (rctx->retryopts & DNS_FETCHOPT_NOEDNS0) == 0 &&
	    (query->rmessage->rcode == dns_rcode_noerror ||
	     query->rmessage->rcode == dns_rcode_nxdomain ||
	     query->rmessage->rcode == dns_rcode_refused ||
	     query->rmessage->rcode == dns_rcode_yxdomain))
	{
		dns_adb_changeflags(fctx->adb, query->addrinfo,
				    FCTX_ADDRINFO_EDNSOK, FCTX_ADDRINFO_EDNSOK);
	}
}

/*
 * rctx_answer():
 * We might have answers, or we might have a malformed delegation with
 * records in the answer section. Call rctx_answer_positive() or
 * rctx_answer_none() as appropriate.
 */
static isc_result_t
rctx_answer(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;
	resquery_t *query = rctx->query;

	if ((query->rmessage->flags & DNS_MESSAGEFLAG_AA) != 0 ||
	    ISFORWARDER(query->addrinfo))
	{
		result = rctx_answer_positive(rctx);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE3("rctx_answer_positive (AA/fwd)", result);
		}
	} else if (fctx->type != dns_rdatatype_ns && !betterreferral(rctx)) {
		result = rctx_answer_positive(rctx);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE3("rctx_answer_positive (!NS)", result);
		}
	} else {
		/*
		 * This may be a delegation.
		 */

		result = rctx_answer_none(rctx);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE3("rctx_answer_none", result);
		}

		if (result == DNS_R_DELEGATION) {
			/*
			 * With NOFOLLOW we want to return DNS_R_DELEGATION to
			 * resume_qmin.
			 */
			if ((rctx->fctx->options & DNS_FETCHOPT_NOFOLLOW) != 0)
			{
				return result;
			}
			result = ISC_R_SUCCESS;
		} else {
			/*
			 * At this point, AA is not set, the response
			 * is not a referral, and the server is not a
			 * forwarder.  It is technically lame and it's
			 * easier to treat it as such than to figure out
			 * some more elaborate course of action.
			 */
			rctx->broken_server = DNS_R_LAME;
			rctx->next_server = true;
			FCTXTRACE3("rctx_answer lame", result);
			rctx_done(rctx, result);
			return ISC_R_COMPLETE;
		}
	}

	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_FORMERR) {
			rctx->next_server = true;
		}
		FCTXTRACE3("rctx_answer failed", result);
		rctx_done(rctx, result);
		return ISC_R_COMPLETE;
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_answer_positive():
 * Handles positive responses. Depending which type of answer this is
 * (matching QNAME/QTYPE, CNAME, DNAME, ANY) calls the proper routine
 * to handle it (rctx_answer_match(), rctx_answer_cname(),
 * rctx_answer_dname(), rctx_answer_any()).
 */
static isc_result_t
rctx_answer_positive(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;

	FCTXTRACE("rctx_answer_positive");

	rctx_answer_init(rctx);
	rctx_answer_scan(rctx);

	/*
	 * Determine which type of positive answer this is:
	 * type ANY, CNAME, DNAME, or an answer matching QNAME/QTYPE.
	 * Call the appropriate routine to handle the answer type.
	 */
	if (rctx->aname != NULL && rctx->type == dns_rdatatype_any) {
		result = rctx_answer_any(rctx);
		if (result == ISC_R_COMPLETE) {
			return rctx->result;
		}
	} else if (rctx->aname != NULL) {
		result = rctx_answer_match(rctx);
		if (result == ISC_R_COMPLETE) {
			return rctx->result;
		}
	} else if (rctx->cname != NULL) {
		result = rctx_answer_cname(rctx);
		if (result == ISC_R_COMPLETE) {
			return rctx->result;
		}
	} else if (rctx->dname != NULL) {
		result = rctx_answer_dname(rctx);
		if (result == ISC_R_COMPLETE) {
			return rctx->result;
		}
	} else {
		log_formerr(fctx, "reply has no answer");
		return DNS_R_FORMERR;
	}

	/*
	 * This response is now potentially cacheable.
	 */
	FCTX_ATTR_SET(fctx, FCTX_ATTR_WANTCACHE);

	/*
	 * Did chaining end before we got the final answer?
	 */
	if (rctx->chaining) {
		return ISC_R_SUCCESS;
	}

	/*
	 * We didn't end with an incomplete chain, so the rcode should
	 * be "no error".
	 */
	if (rctx->query->rmessage->rcode != dns_rcode_noerror) {
		log_formerr(fctx, "CNAME/DNAME chain complete, but RCODE "
				  "indicates error");
		return DNS_R_FORMERR;
	}

	/*
	 * Cache records in the authority section, if
	 * there are any suitable for caching.
	 */
	rctx_authority_positive(rctx);

	log_ns_ttl(fctx, "rctx_answer");

	if (rctx->ns_rdataset != NULL &&
	    dns_name_equal(fctx->domain, rctx->ns_name) &&
	    !dns_name_equal(rctx->ns_name, dns_rootname))
	{
		trim_ns_ttl(fctx, rctx->ns_name, rctx->ns_rdataset);
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_answer_scan():
 * Perform a single pass over the answer section of a response, looking
 * for an answer that matches QNAME/QTYPE, or a CNAME matching QNAME, or
 * a covering DNAME. If more than one rdataset is found matching these
 * criteria, then only one is kept. Order of preference is 1) the
 * shortest DNAME, 2) the first matching answer, or 3) the first CNAME.
 */
static void
rctx_answer_scan(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;
	dns_message_t *msg = rctx->query->rmessage;

	MSG_SECTION_FOREACH (msg, DNS_SECTION_ANSWER, name) {
		int order;
		unsigned int nlabels;
		dns_namereln_t namereln;

		namereln = dns_name_fullcompare(fctx->name, name, &order,
						&nlabels);
		switch (namereln) {
		case dns_namereln_equal:
			ISC_LIST_FOREACH (name->list, rdataset, link) {
				if (rdataset->type == rctx->type ||
				    rctx->type == dns_rdatatype_any)
				{
					rctx->aname = name;
					if (rctx->type != dns_rdatatype_any) {
						rctx->ardataset = rdataset;
					}
					break;
				}
				if (rdataset->type == dns_rdatatype_cname) {
					rctx->cname = name;
					rctx->crdataset = rdataset;
					break;
				}
			}
			break;

		case dns_namereln_subdomain:
			/*
			 * Don't accept DNAME from parent namespace.
			 */
			if (name_external(name, dns_rdatatype_dname, fctx)) {
				continue;
			}

			/*
			 * In-scope DNAME records must have at least
			 * as many labels as the domain being queried.
			 * They also must be less that qname's labels
			 * and any previously found dname.
			 */
			if (nlabels >= rctx->dname_labels ||
			    nlabels < rctx->domain_labels)
			{
				continue;
			}

			/*
			 * We are looking for the shortest DNAME if
			 * there are multiple ones (which there
			 * shouldn't be).
			 */
			ISC_LIST_FOREACH (name->list, rdataset, link) {
				if (rdataset->type != dns_rdatatype_dname) {
					continue;
				}
				rctx->dname = name;
				rctx->drdataset = rdataset;
				rctx->dname_labels = nlabels;
				break;
			}
			break;
		default:
			break;
		}
	}

	/*
	 * If a DNAME was found, then any CNAME or other answer matching
	 * QNAME that may also have been found must be ignored.
	 * Similarly, if a matching answer was found along with a CNAME,
	 * the CNAME must be ignored.
	 */
	if (rctx->dname != NULL) {
		rctx->aname = NULL;
		rctx->ardataset = NULL;
		rctx->cname = NULL;
		rctx->crdataset = NULL;
	} else if (rctx->aname != NULL) {
		rctx->cname = NULL;
		rctx->crdataset = NULL;
	}
}

/*
 * rctx_answer_any():
 * Handle responses to queries of type ANY. Scan the answer section,
 * and as long as each RRset is of a type that is valid in the answer
 * section, and the rdata isn't filtered, cache it.
 */
static isc_result_t
rctx_answer_any(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	ISC_LIST_FOREACH (rctx->aname->list, rdataset, link) {
		if (!validinanswer(rdataset, fctx)) {
			rctx->result = DNS_R_FORMERR;
			return ISC_R_COMPLETE;
		}

		if (dns_rdatatype_issig(fctx->type) &&
		    rdataset->type != fctx->type)
		{
			continue;
		}

		if (dns_rdatatype_isaddr(rdataset->type) &&
		    !is_answeraddress_allowed(fctx->res->view, rctx->aname,
					      rdataset))
		{
			rctx->result = DNS_R_SERVFAIL;
			return ISC_R_COMPLETE;
		}

		if (dns_rdatatype_isalias(rdataset->type) &&
		    !is_answertarget_allowed(fctx, fctx->name, rctx->aname,
					     rdataset, NULL))
		{
			rctx->result = DNS_R_SERVFAIL;
			return ISC_R_COMPLETE;
		}

		rctx->aname->attributes.cache = true;
		rctx->aname->attributes.answer = true;
		rdataset->attributes.answer = true;
		rdataset->attributes.cache = true;
		rdataset->trust = rctx->trust;
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_answer_match():
 * Handle responses that match the QNAME/QTYPE of the resolver query.
 * If QTYPE is valid in the answer section and the rdata isn't filtered,
 * the answer can be cached. If there is additional section data related
 * to the answer, it can be cached as well.
 */
static isc_result_t
rctx_answer_match(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	if (!validinanswer(rctx->ardataset, fctx)) {
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	if (dns_rdatatype_isaddr(rctx->ardataset->type) &&
	    !is_answeraddress_allowed(fctx->res->view, rctx->aname,
				      rctx->ardataset))
	{
		rctx->result = DNS_R_SERVFAIL;
		return ISC_R_COMPLETE;
	}
	if (dns_rdatatype_isalias(rctx->ardataset->type) &&
	    rctx->type != rctx->ardataset->type &&
	    rctx->type != dns_rdatatype_any &&
	    !is_answertarget_allowed(fctx, fctx->name, rctx->aname,
				     rctx->ardataset, NULL))
	{
		rctx->result = DNS_R_SERVFAIL;
		return ISC_R_COMPLETE;
	}

	rctx->aname->attributes.cache = true;
	rctx->aname->attributes.answer = true;
	rctx->ardataset->attributes.answer = true;
	rctx->ardataset->attributes.cache = true;
	rctx->ardataset->trust = rctx->trust;
	(void)dns_rdataset_additionaldata(rctx->ardataset, rctx->aname,
					  check_related, rctx,
					  DNS_RDATASET_MAXADDITIONAL);

	ISC_LIST_FOREACH (rctx->aname->list, sigrdataset, link) {
		if (!validinanswer(sigrdataset, fctx)) {
			rctx->result = DNS_R_FORMERR;
			return ISC_R_COMPLETE;
		}

		if (sigrdataset->type != dns_rdatatype_rrsig ||
		    sigrdataset->covers != rctx->type)
		{
			continue;
		}

		sigrdataset->attributes.answersig = true;
		sigrdataset->attributes.cache = true;
		sigrdataset->trust = rctx->trust;
		break;
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_answer_cname():
 * Handle answers containing a CNAME. Cache the CNAME, and flag that
 * there may be additional chain answers to find.
 */
static isc_result_t
rctx_answer_cname(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	if (!validinanswer(rctx->crdataset, fctx)) {
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	if (rctx->type == dns_rdatatype_rrsig ||
	    rctx->type == dns_rdatatype_key || rctx->type == dns_rdatatype_nsec)
	{
		char buf[DNS_RDATATYPE_FORMATSIZE];
		dns_rdatatype_format(rctx->type, buf, sizeof(buf));
		log_formerr(fctx, "CNAME response for %s RR", buf);
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	if (!is_answertarget_allowed(fctx, fctx->name, rctx->cname,
				     rctx->crdataset, NULL))
	{
		rctx->result = DNS_R_SERVFAIL;
		return ISC_R_COMPLETE;
	}

	rctx->cname->attributes.cache = true;
	rctx->cname->attributes.answer = true;
	rctx->cname->attributes.chaining = true;
	rctx->crdataset->attributes.answer = true;
	rctx->crdataset->attributes.cache = true;
	rctx->crdataset->attributes.chaining = true;
	rctx->crdataset->trust = rctx->trust;

	ISC_LIST_FOREACH (rctx->cname->list, sigrdataset, link) {
		if (!validinanswer(sigrdataset, fctx)) {
			rctx->result = DNS_R_FORMERR;
			return ISC_R_COMPLETE;
		}

		if (sigrdataset->type != dns_rdatatype_rrsig ||
		    sigrdataset->covers != dns_rdatatype_cname)
		{
			continue;
		}

		sigrdataset->attributes.answersig = true;
		sigrdataset->attributes.cache = true;
		sigrdataset->trust = rctx->trust;
		break;
	}

	rctx->chaining = true;
	return ISC_R_SUCCESS;
}

/*
 * rctx_answer_dname():
 * Handle responses with covering DNAME records.
 */
static isc_result_t
rctx_answer_dname(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	if (!validinanswer(rctx->drdataset, fctx)) {
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	if (!is_answertarget_allowed(fctx, fctx->name, rctx->dname,
				     rctx->drdataset, &rctx->chaining))
	{
		rctx->result = DNS_R_SERVFAIL;
		return ISC_R_COMPLETE;
	}

	rctx->dname->attributes.cache = true;
	rctx->dname->attributes.answer = true;
	rctx->dname->attributes.chaining = true;
	rctx->drdataset->attributes.answer = true;
	rctx->drdataset->attributes.cache = true;
	rctx->drdataset->attributes.chaining = true;
	rctx->drdataset->trust = rctx->trust;

	ISC_LIST_FOREACH (rctx->dname->list, sigrdataset, link) {
		if (!validinanswer(sigrdataset, fctx)) {
			rctx->result = DNS_R_FORMERR;
			return ISC_R_COMPLETE;
		}

		if (sigrdataset->type != dns_rdatatype_rrsig ||
		    sigrdataset->covers != dns_rdatatype_dname)
		{
			continue;
		}

		sigrdataset->attributes.answersig = true;
		sigrdataset->attributes.cache = true;
		sigrdataset->trust = rctx->trust;
		break;
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_authority_positive():
 * Examine the records in the authority section (if there are any) for a
 * positive answer.  We expect the names for all rdatasets in this
 * section to be subdomains of the domain being queried; any that are
 * not are skipped.  We expect to find only *one* owner name; any names
 * after the first one processed are ignored. We expect to find only
 * rdatasets of type NS, RRSIG, or SIG; all others are ignored. Whatever
 * remains can be cached at trust level authauthority or additional
 * (depending on whether the AA bit was set on the answer).
 */
static void
rctx_authority_positive(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;

	dns_message_t *msg = rctx->query->rmessage;
	MSG_SECTION_FOREACH (msg, DNS_SECTION_AUTHORITY, name) {
		if (!name_external(name, dns_rdatatype_ns, fctx)) {
			/*
			 * We expect to find NS or SIG NS rdatasets, and
			 * nothing else.
			 */
			ISC_LIST_FOREACH (name->list, rdataset, link) {
				if (rdataset->type == dns_rdatatype_ns ||
				    (rdataset->type == dns_rdatatype_rrsig &&
				     rdataset->covers == dns_rdatatype_ns))
				{
					name->attributes.cache = true;
					rdataset->attributes.cache = true;

					if (rctx->aa) {
						rdataset->trust =
							dns_trust_authauthority;
					} else {
						rdataset->trust =
							dns_trust_additional;
					}

					if (rdataset->type == dns_rdatatype_ns)
					{
						rctx->ns_name = name;
						rctx->ns_rdataset = rdataset;
					}
					/*
					 * Mark any additional data
					 * related to this rdataset.
					 */
					(void)dns_rdataset_additionaldata(
						rdataset, name, check_related,
						rctx,
						DNS_RDATASET_MAXADDITIONAL);
					return;
				}
			}
		}
	}
}

/*
 * rctx_answer_none():
 * Handles a response without an answer: this is either a negative
 * response (NXDOMAIN or NXRRSET) or a referral. Determine which it is,
 * then either scan the authority section for negative caching and
 * DNSSEC proof of nonexistence, or else call rctx_referral().
 */
static isc_result_t
rctx_answer_none(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;

	FCTXTRACE("rctx_answer_none");

	rctx_answer_init(rctx);

	/*
	 * Sometimes we can tell if its a negative response by looking
	 * at the message header.
	 */
	if (rctx->query->rmessage->rcode == dns_rcode_nxdomain ||
	    (rctx->query->rmessage->counts[DNS_SECTION_ANSWER] == 0 &&
	     rctx->query->rmessage->counts[DNS_SECTION_AUTHORITY] == 0))
	{
		rctx->negative = true;
	}

	/*
	 * Process the authority section
	 */
	result = rctx_authority_negative(rctx);
	if (result == ISC_R_COMPLETE) {
		return rctx->result;
	}

	log_ns_ttl(fctx, "rctx_answer_none");

	if (rctx->ns_rdataset != NULL &&
	    dns_name_equal(fctx->domain, rctx->ns_name) &&
	    !dns_name_equal(rctx->ns_name, dns_rootname))
	{
		trim_ns_ttl(fctx, rctx->ns_name, rctx->ns_rdataset);
	}

	/*
	 * A negative response has a SOA record (Type 2)
	 * and a optional NS RRset (Type 1) or it has neither
	 * a SOA or a NS RRset (Type 3, handled above) or
	 * rcode is NXDOMAIN (handled above) in which case
	 * the NS RRset is allowed (Type 4).
	 */
	if (rctx->soa_name != NULL) {
		rctx->negative = true;
	}

	/*
	 * Process DNSSEC records in the authority section.
	 */
	result = rctx_authority_dnssec(rctx);
	if (result == ISC_R_COMPLETE) {
		return rctx->result;
	}

	/*
	 * Trigger lookups for DNS nameservers.
	 */
	if (rctx->negative &&
	    rctx->query->rmessage->rcode == dns_rcode_noerror &&
	    fctx->type == dns_rdatatype_ds && rctx->soa_name != NULL &&
	    dns_name_equal(rctx->soa_name, fctx->name) &&
	    !dns_name_equal(fctx->name, dns_rootname))
	{
		return DNS_R_CHASEDSSERVERS;
	}

	/*
	 * Did we find anything?
	 */
	if (!rctx->negative && rctx->ns_name == NULL) {
		/*
		 * The responder is insane.
		 */
		if (rctx->found_name == NULL) {
			log_formerr(fctx, "invalid response");
			return DNS_R_FORMERR;
		}
		if (!dns_name_issubdomain(rctx->found_name, fctx->domain)) {
			char nbuf[DNS_NAME_FORMATSIZE];
			char dbuf[DNS_NAME_FORMATSIZE];
			char tbuf[DNS_RDATATYPE_FORMATSIZE];

			dns_rdatatype_format(rctx->found_type, tbuf,
					     sizeof(tbuf));
			dns_name_format(rctx->found_name, nbuf, sizeof(nbuf));
			dns_name_format(fctx->domain, dbuf, sizeof(dbuf));

			log_formerr(fctx,
				    "Name %s (%s) not subdomain"
				    " of zone %s -- invalid response",
				    nbuf, tbuf, dbuf);
		} else {
			log_formerr(fctx, "invalid response");
		}
		return DNS_R_FORMERR;
	}

	/*
	 * If we found both NS and SOA, they should be the same name.
	 */
	if (rctx->ns_name != NULL && rctx->soa_name != NULL &&
	    rctx->ns_name != rctx->soa_name)
	{
		log_formerr(fctx, "NS/SOA mismatch");
		return DNS_R_FORMERR;
	}

	/*
	 * Handle a referral.
	 */
	result = rctx_referral(rctx);
	if (result == ISC_R_COMPLETE) {
		return rctx->result;
	}

	/*
	 * Since we're not doing a referral, we don't want to cache any
	 * NS RRs we may have found.
	 */
	if (rctx->ns_name != NULL) {
		rctx->ns_name->attributes.cache = false;
	}

	if (rctx->negative) {
		FCTX_ATTR_SET(fctx, FCTX_ATTR_WANTNCACHE);
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_authority_negative():
 * Scan the authority section of a negative answer, handling
 * NS and SOA records. (Note that this function does *not* handle
 * DNSSEC records; those are addressed separately in
 * rctx_authority_dnssec() below.)
 */
static isc_result_t
rctx_authority_negative(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;
	dns_section_t section;

	section = DNS_SECTION_AUTHORITY;

	dns_message_t *msg = rctx->query->rmessage;
	MSG_SECTION_FOREACH (msg, section, name) {
		if (!dns_name_issubdomain(name, fctx->domain)) {
			continue;
		}

		ISC_LIST_FOREACH (name->list, rdataset, link) {
			dns_rdatatype_t type = rdataset->type;
			if (dns_rdatatype_issig(rdataset->type)) {
				type = rdataset->covers;
			}
			if ((type == dns_rdatatype_ns ||
			     type == dns_rdatatype_soa) &&
			    !dns_name_issubdomain(fctx->name, name))
			{
				char qbuf[DNS_NAME_FORMATSIZE];
				char nbuf[DNS_NAME_FORMATSIZE];
				char tbuf[DNS_RDATATYPE_FORMATSIZE];
				dns_rdatatype_format(type, tbuf, sizeof(tbuf));
				dns_name_format(name, nbuf, sizeof(nbuf));
				dns_name_format(fctx->name, qbuf, sizeof(qbuf));
				log_formerr(fctx,
					    "unrelated %s %s in "
					    "%s authority section",
					    tbuf, nbuf, qbuf);
				break;
			}

			switch (type) {
			case dns_rdatatype_ns:
				/*
				 * NS or RRSIG NS.
				 *
				 * Only one set of NS RRs is allowed.
				 */
				if (rdataset->type == dns_rdatatype_ns) {
					if (rctx->ns_name != NULL &&
					    name != rctx->ns_name)
					{
						log_formerr(fctx, "multiple NS "
								  "RRsets "
								  "in "
								  "authority "
								  "section");
						rctx->result = DNS_R_FORMERR;
						return ISC_R_COMPLETE;
					}
					rctx->ns_name = name;
					rctx->ns_rdataset = rdataset;
				}
				name->attributes.cache = true;
				rdataset->attributes.cache = true;
				rdataset->trust = dns_trust_glue;
				break;
			case dns_rdatatype_soa:
				/*
				 * SOA, or RRSIG SOA.
				 *
				 * Only one SOA is allowed.
				 */
				if (rdataset->type == dns_rdatatype_soa) {
					if (rctx->soa_name != NULL &&
					    name != rctx->soa_name)
					{
						log_formerr(fctx, "multiple "
								  "SOA RRs "
								  "in "
								  "authority "
								  "section");
						rctx->result = DNS_R_FORMERR;
						return ISC_R_COMPLETE;
					}
					rctx->soa_name = name;
				}
				name->attributes.ncache = true;
				rdataset->attributes.ncache = true;
				if (rctx->aa) {
					rdataset->trust =
						dns_trust_authauthority;
				} else if (ISFORWARDER(fctx->addrinfo)) {
					rdataset->trust = dns_trust_answer;
				} else {
					rdataset->trust = dns_trust_additional;
				}
				break;
			default:
				continue;
			}
		}
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_ncache():
 * Cache the negatively cacheable parts of the message.  This may
 * also cause work to be queued to the DNSSEC validator.
 */
static void
rctx_ncache(respctx_t *rctx) {
	isc_result_t result;
	dns_rdatatype_t covers;
	fetchctx_t *fctx = rctx->fctx;

	if (!WANTNCACHE(fctx)) {
		return;
	}

	/*
	 * Cache DS NXDOMAIN separately to other types.
	 */
	if (rctx->query->rmessage->rcode == dns_rcode_nxdomain &&
	    fctx->type != dns_rdatatype_ds)
	{
		covers = dns_rdatatype_any;
	} else {
		covers = fctx->type;
	}

	/*
	 * Cache any negative cache entries in the message.
	 */
	result = ncache_message(fctx, rctx->query->rmessage,
				rctx->query->addrinfo, covers, rctx->now);
	if (result != ISC_R_SUCCESS) {
		FCTXTRACE3("ncache_message complete", result);
	}
}

/*
 * rctx_authority_dnssec():
 *
 * Scan the authority section of a negative answer or referral,
 * handling DNSSEC records (i.e. NSEC, NSEC3, DS).
 */
static isc_result_t
rctx_authority_dnssec(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;

	dns_message_t *msg = rctx->query->rmessage;
	MSG_SECTION_FOREACH (msg, DNS_SECTION_AUTHORITY, name) {
		if (!dns_name_issubdomain(name, fctx->domain)) {
			/*
			 * Invalid name found; preserve it for logging
			 * later.
			 */
			rctx->found_name = name;
			rctx->found_type = ISC_LIST_HEAD(name->list)->type;
			continue;
		}

		ISC_LIST_FOREACH (name->list, rdataset, link) {
			bool checknta = true;
			bool secure_domain = false;
			dns_rdatatype_t type = rdataset->type;

			if (dns_rdatatype_issig(type)) {
				type = rdataset->covers;
			}

			switch (type) {
			case dns_rdatatype_nsec:
			case dns_rdatatype_nsec3:
				if (rctx->negative) {
					name->attributes.ncache = true;
					rdataset->attributes.ncache = true;
				} else if (type == dns_rdatatype_nsec) {
					name->attributes.cache = true;
					rdataset->attributes.cache = true;
				}

				if (rctx->aa) {
					rdataset->trust =
						dns_trust_authauthority;
				} else if (ISFORWARDER(fctx->addrinfo)) {
					rdataset->trust = dns_trust_answer;
				} else {
					rdataset->trust = dns_trust_additional;
				}
				/*
				 * No additional data needs to be
				 * marked.
				 */
				break;
			case dns_rdatatype_ds:
				/*
				 * DS or SIG DS.
				 *
				 * These should only be here if this is
				 * a referral, and there should only be
				 * one DS RRset.
				 */
				if (rctx->ns_name == NULL) {
					log_formerr(fctx, "DS with no "
							  "referral");
					rctx->result = DNS_R_FORMERR;
					return ISC_R_COMPLETE;
				}

				if (rdataset->type == dns_rdatatype_ds) {
					if (rctx->ds_name != NULL &&
					    name != rctx->ds_name)
					{
						log_formerr(fctx, "DS doesn't "
								  "match "
								  "referral "
								  "(NS)");
						rctx->result = DNS_R_FORMERR;
						return ISC_R_COMPLETE;
					}
					rctx->ds_name = name;
				}

				name->attributes.cache = true;
				rdataset->attributes.cache = true;

				if ((fctx->options & DNS_FETCHOPT_NONTA) != 0) {
					checknta = false;
				}
				if (fctx->res->view->enablevalidation) {
					result = issecuredomain(
						fctx->res->view, name,
						dns_rdatatype_ds, fctx->now,
						checknta, NULL, &secure_domain);
					if (result != ISC_R_SUCCESS) {
						return result;
					}
				}
				if (secure_domain) {
					rdataset->trust =
						dns_trust_pending_answer;
				} else if (rctx->aa) {
					rdataset->trust =
						dns_trust_authauthority;
				} else if (ISFORWARDER(fctx->addrinfo)) {
					rdataset->trust = dns_trust_answer;
				} else {
					rdataset->trust = dns_trust_additional;
				}
				break;
			default:
				continue;
			}
		}
	}

	return ISC_R_SUCCESS;
}

/*
 * rctx_referral():
 * Handles referral responses. Check for sanity, find glue as needed,
 * and update the fetch context to follow the delegation.
 */
static isc_result_t
rctx_referral(respctx_t *rctx) {
	isc_result_t result;
	fetchctx_t *fctx = rctx->fctx;

	if (rctx->negative || rctx->ns_name == NULL) {
		return ISC_R_SUCCESS;
	}

	/*
	 * We already know ns_name is a subdomain of fctx->domain.
	 * If ns_name is equal to fctx->domain, we're not making
	 * progress.  We return DNS_R_FORMERR so that we'll keep
	 * trying other servers.
	 */
	if (dns_name_equal(rctx->ns_name, fctx->domain)) {
		log_formerr(fctx, "non-improving referral");
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	/*
	 * If the referral name is not a parent of the query
	 * name, consider the responder insane.
	 */
	if (!dns_name_issubdomain(fctx->name, rctx->ns_name)) {
		/* Logged twice */
		log_formerr(fctx, "referral to non-parent");
		FCTXTRACE("referral to non-parent");
		rctx->result = DNS_R_FORMERR;
		return ISC_R_COMPLETE;
	}

	/*
	 * Mark any additional data related to this rdataset.
	 * It's important that we do this before we change the
	 * query domain.
	 */
	INSIST(rctx->ns_rdataset != NULL);
	FCTX_ATTR_SET(fctx, FCTX_ATTR_GLUING);
	/*
	 * We want to append **all** the GLUE records here.
	 */
	(void)dns_rdataset_additionaldata(rctx->ns_rdataset, rctx->ns_name,
					  check_related, rctx, 0);
#if CHECK_FOR_GLUE_IN_ANSWER
	/*
	 * Look in the answer section for "glue" that is incorrectly
	 * returned as a answer.  This is needed if the server also
	 * minimizes the response size by not adding records to the
	 * additional section that are in the answer section or if
	 * the record gets dropped due to message size constraints.
	 */
	if (rctx->glue_in_answer && dns_rdatatype_isaddr(fctx->type)) {
		(void)dns_rdataset_additionaldata(
			rctx->ns_rdataset, rctx->ns_name, check_answer, fctx);
	}
#endif /* if CHECK_FOR_GLUE_IN_ANSWER */
	FCTX_ATTR_CLR(fctx, FCTX_ATTR_GLUING);

	/*
	 * NS rdatasets with 0 TTL cause problems.
	 * dns_view_findzonecut() will not find them when we
	 * try to follow the referral, and we'll SERVFAIL
	 * because the best nameservers are now above QDOMAIN.
	 * We force the TTL to 1 second to prevent this.
	 */
	if (rctx->ns_rdataset->ttl == 0) {
		rctx->ns_rdataset->ttl = 1;
	}

	/*
	 * Set the current query domain to the referral name.
	 *
	 * XXXRTH  We should check if we're in forward-only mode, and
	 *		if so we should bail out.
	 */
	INSIST(dns_name_countlabels(fctx->domain) > 0);
	fcount_decr(fctx);

	if (dns_rdataset_isassociated(&fctx->nameservers)) {
		dns_rdataset_disassociate(&fctx->nameservers);
	}

	dns_name_copy(rctx->ns_name, fctx->domain);

	if ((fctx->options & DNS_FETCHOPT_QMINIMIZE) != 0) {
		dns_name_copy(rctx->ns_name, fctx->qmindcname);

		fctx_minimize_qname(fctx);
	}

	result = fcount_incr(fctx, false);
	if (result != ISC_R_SUCCESS) {
		rctx->result = result;
		return ISC_R_COMPLETE;
	}

	FCTX_ATTR_SET(fctx, FCTX_ATTR_WANTCACHE);
	fctx->ns_ttl_ok = false;
	log_ns_ttl(fctx, "DELEGATION");
	rctx->result = DNS_R_DELEGATION;

	/*
	 * Reinitialize 'rctx' to prepare for following the delegation:
	 * set the get_nameservers and next_server flags appropriately
	 * and reset the fetch context counters.
	 *
	 */
	if ((rctx->fctx->options & DNS_FETCHOPT_NOFOLLOW) == 0) {
		rctx->get_nameservers = true;
		rctx->next_server = true;
		rctx->fctx->restarts = 0;
		rctx->fctx->referrals++;
		rctx->fctx->querysent = 0;
		rctx->fctx->lamecount = 0;
		rctx->fctx->quotacount = 0;
		rctx->fctx->neterr = 0;
		rctx->fctx->badresp = 0;
		rctx->fctx->adberr = 0;
	}

	return ISC_R_COMPLETE;
}

/*
 * rctx_additional():
 * Scan the additional section of a response to find records related
 * to answers we were interested in.
 */
static void
rctx_additional(respctx_t *rctx) {
	bool rescan;
	dns_section_t section = DNS_SECTION_ADDITIONAL;

again:
	rescan = false;

	dns_message_t *msg = rctx->query->rmessage;
	MSG_SECTION_FOREACH (msg, section, name) {
		if (!name->attributes.chase) {
			continue;
		}
		name->attributes.chase = false;
		ISC_LIST_FOREACH (name->list, rdataset, link) {
			if (CHASE(rdataset)) {
				rdataset->attributes.chase = false;
				(void)dns_rdataset_additionaldata(
					rdataset, name, check_related, rctx,
					DNS_RDATASET_MAXADDITIONAL);
				rescan = true;
			}
		}
	}
	if (rescan) {
		goto again;
	}
}

/*
 * rctx_nextserver():
 * We found something wrong with the remote server, but it may be
 * useful to try another one.
 */
static void
rctx_nextserver(respctx_t *rctx, dns_message_t *message,
		dns_adbaddrinfo_t *addrinfo, isc_result_t result) {
	fetchctx_t *fctx = rctx->fctx;
	bool retrying = true;

	if (result == DNS_R_FORMERR) {
		rctx->broken_server = DNS_R_FORMERR;
	}
	if (rctx->broken_server != ISC_R_SUCCESS) {
		/*
		 * Add this server to the list of bad servers for
		 * this fctx.
		 */
		add_bad(fctx, message, addrinfo, rctx->broken_server,
			rctx->broken_type);
	}

	if (rctx->get_nameservers) {
		dns_fixedname_t foundname, founddc;
		dns_name_t *name, *fname, *dcname;
		unsigned int findoptions = 0;

		fname = dns_fixedname_initname(&foundname);
		dcname = dns_fixedname_initname(&founddc);

		if (result != ISC_R_SUCCESS) {
			fctx_done_detach(&rctx->fctx, DNS_R_SERVFAIL);
			return;
		}
		if (dns_rdatatype_atparent(fctx->type)) {
			findoptions |= DNS_DBFIND_NOEXACT;
		}
		/* FIXME: Why??? */
		if ((rctx->retryopts & DNS_FETCHOPT_UNSHARED) == 0) {
			name = fctx->name;
		} else {
			name = fctx->domain;
		}
		result = dns_view_findzonecut(
			fctx->res->view, name, fname, dcname, fctx->now,
			findoptions, true, true, &fctx->nameservers, NULL);
		if (result != ISC_R_SUCCESS) {
			FCTXTRACE("couldn't find a zonecut");
			fctx_done_detach(&rctx->fctx, DNS_R_SERVFAIL);
			return;
		}
		if (!dns_name_issubdomain(fname, fctx->domain)) {
			/*
			 * The best nameservers are now above our
			 * QDOMAIN.
			 */
			FCTXTRACE("nameservers now above QDOMAIN");
			fctx_done_detach(&rctx->fctx, DNS_R_SERVFAIL);
			return;
		}

		fcount_decr(fctx);

		dns_name_copy(fname, fctx->domain);
		dns_name_copy(dcname, fctx->qmindcname);

		result = fcount_incr(fctx, true);
		if (result != ISC_R_SUCCESS) {
			fctx_done_detach(&rctx->fctx, DNS_R_SERVFAIL);
			return;
		}
		fctx->ns_ttl = fctx->nameservers.ttl;
		fctx->ns_ttl_ok = true;
		fctx_cancelqueries(fctx, true, false);
		fctx_cleanup(fctx);
		retrying = false;
	}

	/*
	 * Try again.
	 */
	fctx_try(fctx, retrying);
}

/*
 * rctx_resend():
 *
 * Resend the query, probably with the options changed. Calls
 * fctx_query(), passing rctx->retryopts (which is based on
 * query->options, but may have been updated since the last time
 * fctx_query() was called).
 */
static void
rctx_resend(respctx_t *rctx, dns_adbaddrinfo_t *addrinfo) {
	fetchctx_t *fctx = rctx->fctx;
	isc_result_t result;

	FCTXTRACE("resend");
	inc_stats(fctx->res, dns_resstatscounter_retry);
	result = fctx_query(fctx, addrinfo, rctx->retryopts);
	if (result != ISC_R_SUCCESS) {
		fctx_done_detach(&rctx->fctx, result);
	}
}

/*
 * rctx_next():
 * We got what appeared to be a response but it didn't match the
 * question or the cookie; it may have been meant for someone else, or
 * it may be a spoofing attack. Drop it and continue listening for the
 * response we wanted.
 */
static isc_result_t
rctx_next(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;
	isc_result_t result;

	FCTXTRACE("nextitem");
	inc_stats(rctx->fctx->res, dns_resstatscounter_nextitem);
	INSIST(rctx->query->dispentry != NULL);
	dns_message_reset(rctx->query->rmessage, DNS_MESSAGE_INTENTPARSE);
	result = dns_dispatch_getnext(rctx->query->dispentry);
	return result;
}

/*
 * rctx_chaseds():
 * Look up the parent zone's NS records so that DS records can be
 * fetched.
 */
static void
rctx_chaseds(respctx_t *rctx, dns_message_t *message,
	     dns_adbaddrinfo_t *addrinfo, isc_result_t result) {
	fetchctx_t *fctx = rctx->fctx;
	unsigned int n;

	add_bad(fctx, message, addrinfo, result, rctx->broken_type);
	fctx_cancelqueries(fctx, true, false);
	fctx_cleanup(fctx);

	n = dns_name_countlabels(fctx->name);
	dns_name_getlabelsequence(fctx->name, 1, n - 1, fctx->nsname);

	FCTXTRACE("suspending DS lookup to find parent's NS records");

	fetchctx_ref(fctx);
	result = dns_resolver_createfetch(
		fctx->res, fctx->nsname, dns_rdatatype_ns, NULL, NULL, NULL,
		NULL, 0, fctx->options, 0, fctx->qc, fctx->gqc, fctx->loop,
		resume_dslookup, fctx, &fctx->edectx, &fctx->nsrrset, NULL,
		&fctx->nsfetch);
	if (result != ISC_R_SUCCESS) {
		if (result == DNS_R_DUPLICATE) {
			result = DNS_R_SERVFAIL;
		}
		fctx_done_detach(&rctx->fctx, result);
		fetchctx_detach(&fctx);
		return;
	}
}

/*
 * rctx_done():
 * This resolver query response is finished, either because we
 * encountered a problem or because we've gotten all the information
 * from it that we can.  We either wait for another response, resend the
 * query to the same server, resend to a new server, or clean up and
 * shut down the fetch.
 */
static void
rctx_done(respctx_t *rctx, isc_result_t result) {
	resquery_t *query = rctx->query;
	fetchctx_t *fctx = rctx->fctx;
	dns_adbaddrinfo_t *addrinfo = query->addrinfo;
	dns_message_t *message = NULL;

	/*
	 * Need to attach to the message until the scope
	 * of this function ends, since there are many places
	 * where the message is used and/or may be destroyed
	 * before this function ends.
	 */
	dns_message_attach(query->rmessage, &message);

	FCTXTRACE4("query canceled in rctx_done();",
		   rctx->no_response ? "no response" : "responding", result);

#ifdef ENABLE_AFL
	if (dns_fuzzing_resolver &&
	    (rctx->next_server || rctx->resend || rctx->nextitem))
	{
		fctx_cancelquery(&query, rctx->finish, rctx->no_response,
				 false);
		fctx_done_detach(&rctx->fctx, DNS_R_SERVFAIL);
		goto detach;
	}
#endif /* ifdef ENABLE_AFL */

	if (rctx->nextitem) {
		REQUIRE(!rctx->next_server);
		REQUIRE(!rctx->resend);

		result = rctx_next(rctx);
		if (result == ISC_R_SUCCESS) {
			goto detach;
		}
	}

	/* Cancel the query */
	fctx_cancelquery(&query, rctx->finish, rctx->no_response, false);

	/*
	 * If nobody's waiting for results, don't resend or try next server.
	 */
	LOCK(&fctx->lock);
	if (ISC_LIST_EMPTY(fctx->resps)) {
		rctx->next_server = false;
		rctx->resend = false;
	}
	UNLOCK(&fctx->lock);

	if (rctx->next_server) {
		rctx_nextserver(rctx, message, addrinfo, result);
	} else if (rctx->resend) {
		rctx_resend(rctx, addrinfo);
	} else if (result == DNS_R_CHASEDSSERVERS) {
		rctx_chaseds(rctx, message, addrinfo, result);
	} else if (result == ISC_R_SUCCESS && !HAVE_ANSWER(fctx)) {
		/*
		 * All has gone well so far, but we are waiting for the DNSSEC
		 * validator to validate the answer.
		 */
		FCTXTRACE("wait for validator");
		fctx_cancelqueries(fctx, true, false);
	} else {
		/*
		 * We're done.
		 */
		fctx_done_detach(&rctx->fctx, result);
	}

detach:
	dns_message_detach(&message);
}

/*
 * rctx_logpacket():
 * Log the incoming packet; also log to DNSTAP if configured.
 */
static void
rctx_logpacket(respctx_t *rctx) {
	fetchctx_t *fctx = rctx->fctx;
	isc_result_t result;
	isc_sockaddr_t localaddr, *la = NULL;
#ifdef HAVE_DNSTAP
	unsigned char zone[DNS_NAME_MAXWIRE];
	dns_transport_type_t transport_type;
	dns_dtmsgtype_t dtmsgtype;
	dns_compress_t cctx;
	isc_region_t zr;
	isc_buffer_t zb;
#endif /* HAVE_DNSTAP */

	result = dns_dispentry_getlocaladdress(rctx->query->dispentry,
					       &localaddr);
	if (result == ISC_R_SUCCESS) {
		la = &localaddr;
	}

	dns_message_logpacketfromto(
		rctx->query->rmessage, "received packet",
		&rctx->query->addrinfo->sockaddr, la, DNS_LOGCATEGORY_RESOLVER,
		DNS_LOGMODULE_PACKETS, ISC_LOG_DEBUG(10), fctx->mctx);

#ifdef HAVE_DNSTAP
	/*
	 * Log the response via dnstap.
	 */
	memset(&zr, 0, sizeof(zr));
	dns_compress_init(&cctx, fctx->mctx, 0);
	dns_compress_setpermitted(&cctx, false);
	isc_buffer_init(&zb, zone, sizeof(zone));
	result = dns_name_towire(fctx->domain, &cctx, &zb);
	if (result == ISC_R_SUCCESS) {
		isc_buffer_usedregion(&zb, &zr);
	}
	dns_compress_invalidate(&cctx);

	if ((fctx->qmessage->flags & DNS_MESSAGEFLAG_RD) != 0) {
		dtmsgtype = DNS_DTTYPE_FR;
	} else {
		dtmsgtype = DNS_DTTYPE_RR;
	}

	if (rctx->query->addrinfo->transport != NULL) {
		transport_type = dns_transport_get_type(
			rctx->query->addrinfo->transport);
	} else if ((rctx->query->options & DNS_FETCHOPT_TCP) != 0) {
		transport_type = DNS_TRANSPORT_TCP;
	} else {
		transport_type = DNS_TRANSPORT_UDP;
	}

	dns_dt_send(fctx->res->view, dtmsgtype, la,
		    &rctx->query->addrinfo->sockaddr, transport_type, &zr,
		    &rctx->query->start, NULL, &rctx->buffer);
#endif /* HAVE_DNSTAP */
}

/*
 * rctx_badserver():
 * Is the remote server broken, or does it dislike us?
 */
static isc_result_t
rctx_badserver(respctx_t *rctx, isc_result_t result) {
	fetchctx_t *fctx = rctx->fctx;
	resquery_t *query = rctx->query;
	isc_buffer_t b;
	char code[64];
	dns_rcode_t rcode = rctx->query->rmessage->rcode;

	QTRACE("rctx_badserver");

	if (rcode == dns_rcode_noerror || rcode == dns_rcode_yxdomain ||
	    rcode == dns_rcode_nxdomain)
	{
		return ISC_R_SUCCESS;
	}

	if ((rcode == dns_rcode_formerr) && rctx->opt == NULL &&
	    (rctx->retryopts & DNS_FETCHOPT_NOEDNS0) == 0)
	{
		/*
		 * It's very likely they don't like EDNS0.
		 */
		rctx->retryopts |= DNS_FETCHOPT_NOEDNS0;
		rctx->resend = true;
		/*
		 * Remember that they may not like EDNS0.
		 */
		inc_stats(fctx->res, dns_resstatscounter_edns0fail);
	} else if (rcode == dns_rcode_formerr) {
		if (query->rmessage->cc_echoed) {
			/*
			 * Retry without DNS COOKIE.
			 */
			query->addrinfo->flags |= FCTX_ADDRINFO_NOCOOKIE;
			rctx->resend = true;
			log_formerr(fctx, "server sent FORMERR with echoed DNS "
					  "COOKIE");
		} else {
			/*
			 * The server (or forwarder) doesn't understand us,
			 * but others might.
			 */
			rctx->next_server = true;
			rctx->broken_server = DNS_R_REMOTEFORMERR;
			log_formerr(fctx, "server sent FORMERR");
		}
	} else if (rcode == dns_rcode_badvers) {
		unsigned int version;
#if DNS_EDNS_VERSION > 0
		unsigned int flags, mask;
#endif /* if DNS_EDNS_VERSION > 0 */

		INSIST(rctx->opt != NULL);
		version = (rctx->opt->ttl >> 16) & 0xff;
#if DNS_EDNS_VERSION > 0
		flags = (version << DNS_FETCHOPT_EDNSVERSIONSHIFT) |
			DNS_FETCHOPT_EDNSVERSIONSET;
		mask = DNS_FETCHOPT_EDNSVERSIONMASK |
		       DNS_FETCHOPT_EDNSVERSIONSET;
#endif /* if DNS_EDNS_VERSION > 0 */

		/*
		 * Record that we got a good EDNS response.
		 */
		if (query->ednsversion > (int)version &&
		    !EDNSOK(query->addrinfo))
		{
			dns_adb_changeflags(fctx->adb, query->addrinfo,
					    FCTX_ADDRINFO_EDNSOK,
					    FCTX_ADDRINFO_EDNSOK);
		}

		/*
		 * RFC 2671 was not clear that unknown options should
		 * be ignored.  RFC 6891 is clear that that they
		 * should be ignored. If we are supporting the
		 * experimental EDNS > 0 then perform strict
		 * version checking of badvers responses.  We won't
		 * be sending COOKIE etc. in that case.
		 */
#if DNS_EDNS_VERSION > 0
		if ((int)version < query->ednsversion) {
			dns_adb_changeflags(fctx->adb, query->addrinfo, flags,
					    mask);
			rctx->resend = true;
		} else {
			rctx->broken_server = DNS_R_BADVERS;
			rctx->next_server = true;
		}
#else  /* if DNS_EDNS_VERSION > 0 */
		rctx->broken_server = DNS_R_BADVERS;
		rctx->next_server = true;
#endif /* if DNS_EDNS_VERSION > 0 */
	} else if (rcode == dns_rcode_badcookie && rctx->query->rmessage->cc_ok)
	{
		/*
		 * We have recorded the new cookie.
		 */
		if (BADCOOKIE(query->addrinfo)) {
			rctx->retryopts |= DNS_FETCHOPT_TCP;
		}
		query->addrinfo->flags |= FCTX_ADDRINFO_BADCOOKIE;
		rctx->resend = true;
	} else if (ISFORWARDER(query->addrinfo) &&
		   query->rmessage->rcode == dns_rcode_servfail &&
		   (query->options & DNS_FETCHOPT_TRYCD) != 0)
	{
		/*
		 * We got a SERVFAIL from a forwarder with
		 * CD=0; try again with CD=1.
		 */
		rctx->retryopts |= DNS_FETCHOPT_TRYCD;
		rctx->resend = true;
	} else {
		rctx->broken_server = DNS_R_UNEXPECTEDRCODE;
		rctx->next_server = true;
	}

	isc_buffer_init(&b, code, sizeof(code) - 1);
	dns_rcode_totext(rcode, &b);
	code[isc_buffer_usedlength(&b)] = '\0';
	FCTXTRACE2("remote server broken: returned ", code);
	rctx_done(rctx, result);

	return ISC_R_COMPLETE;
}

/*
 * rctx_lameserver():
 * Is the server lame?
 */
static isc_result_t
rctx_lameserver(respctx_t *rctx) {
	isc_result_t result = ISC_R_SUCCESS;
	fetchctx_t *fctx = rctx->fctx;
	resquery_t *query = rctx->query;

	if (ISFORWARDER(query->addrinfo) || !is_lame(fctx, query->rmessage)) {
		return ISC_R_SUCCESS;
	}

	inc_stats(fctx->res, dns_resstatscounter_lame);
	log_lame(fctx, query->addrinfo);
	rctx->broken_server = DNS_R_LAME;
	rctx->next_server = true;
	FCTXTRACE("lame server");
	rctx_done(rctx, result);

	return ISC_R_COMPLETE;
}

/***
 *** Resolver Methods
 ***/
static void
dns_resolver__destroy(dns_resolver_t *res) {
	alternate_t *a = NULL;

	REQUIRE(!atomic_load_acquire(&res->priming));
	REQUIRE(res->primefetch == NULL);

	RTRACE("destroy");

	res->magic = 0;

	dns_nametree_detach(&res->algorithms);
	dns_nametree_detach(&res->digests);

	if (res->querystats != NULL) {
		dns_stats_detach(&res->querystats);
	}
	if (res->stats != NULL) {
		isc_stats_detach(&res->stats);
	}

	isc_mutex_destroy(&res->primelock);
	isc_mutex_destroy(&res->lock);

	INSIST(isc_hashmap_count(res->fctxs) == 0);
	isc_hashmap_destroy(&res->fctxs);
	isc_rwlock_destroy(&res->fctxs_lock);

	INSIST(isc_hashmap_count(res->counters) == 0);
	isc_hashmap_destroy(&res->counters);
	isc_rwlock_destroy(&res->counters_lock);

	if (res->dispatches4 != NULL) {
		dns_dispatchset_destroy(&res->dispatches4);
	}
	if (res->dispatches6 != NULL) {
		dns_dispatchset_destroy(&res->dispatches6);
	}
	while ((a = ISC_LIST_HEAD(res->alternates)) != NULL) {
		ISC_LIST_UNLINK(res->alternates, a, link);
		if (!a->isaddress) {
			dns_name_free(&a->_u._n.name, res->mctx);
		}
		isc_mem_put(res->mctx, a, sizeof(*a));
	}

	dns_view_weakdetach(&res->view);

	for (size_t i = 0; i < res->nloops; i++) {
		dns_message_destroypools(&res->namepools[i], &res->rdspools[i]);
	}
	isc_mem_cput(res->mctx, res->rdspools, res->nloops,
		     sizeof(res->rdspools[0]));
	isc_mem_cput(res->mctx, res->namepools, res->nloops,
		     sizeof(res->namepools[0]));

	isc_mem_putanddetach(&res->mctx, res, sizeof(*res));
}

static void
spillattimer_countdown(void *arg) {
	dns_resolver_t *res = (dns_resolver_t *)arg;
	unsigned int spillat = 0;

	REQUIRE(VALID_RESOLVER(res));

	if (atomic_load(&res->exiting)) {
		isc_timer_destroy(&res->spillattimer);
		return;
	}

	LOCK(&res->lock);
	INSIST(!atomic_load_acquire(&res->exiting));
	if (res->spillat > res->spillatmin) {
		spillat = --res->spillat;
	}
	if (res->spillat <= res->spillatmin) {
		isc_timer_destroy(&res->spillattimer);
	}
	UNLOCK(&res->lock);
	if (spillat > 0) {
		isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
			      ISC_LOG_NOTICE,
			      "clients-per-query decreased to %u", spillat);
	}
}

isc_result_t
dns_resolver_create(dns_view_t *view, unsigned int options,
		    isc_tlsctx_cache_t *tlsctx_cache,
		    dns_dispatch_t *dispatchv4, dns_dispatch_t *dispatchv6,
		    dns_resolver_t **resp) {
	dns_resolver_t *res = NULL;

	/*
	 * Create a resolver.
	 */

	REQUIRE(DNS_VIEW_VALID(view));
	REQUIRE(resp != NULL && *resp == NULL);
	REQUIRE(tlsctx_cache != NULL);
	REQUIRE(dispatchv4 != NULL || dispatchv6 != NULL);

	res = isc_mem_get(view->mctx, sizeof(*res));
	*res = (dns_resolver_t){
		.rdclass = view->rdclass,
		.options = options,
		.tlsctx_cache = tlsctx_cache,
		.spillatmin = 10,
		.spillat = 10,
		.spillatmax = 100,
		.retryinterval = 800,
		.nonbackofftries = 3,
		.query_timeout = DEFAULT_QUERY_TIMEOUT,
		.maxdepth = DEFAULT_RECURSION_DEPTH,
		.maxqueries = DEFAULT_MAX_QUERIES,
		.alternates = ISC_LIST_INITIALIZER,
		.nloops = isc_loopmgr_nloops(),
		.maxvalidations = DEFAULT_MAX_VALIDATIONS,
		.maxvalidationfails = DEFAULT_MAX_VALIDATION_FAILURES,
	};

	RTRACE("create");

	dns_view_weakattach(view, &res->view);
	isc_mem_attach(view->mctx, &res->mctx);

	res->quotaresp[dns_quotatype_zone] = DNS_R_DROP;
	res->quotaresp[dns_quotatype_server] = DNS_R_SERVFAIL;

#if DNS_RESOLVER_TRACE
	fprintf(stderr, "dns_resolver__init:%s:%s:%d:%p->references = 1\n",
		__func__, __FILE__, __LINE__, res);
#endif
	isc_refcount_init(&res->references, 1);

	isc_hashmap_create(view->mctx, RES_DOMAIN_HASH_BITS, &res->fctxs);
	isc_rwlock_init(&res->fctxs_lock);

	isc_hashmap_create(view->mctx, RES_DOMAIN_HASH_BITS, &res->counters);
	isc_rwlock_init(&res->counters_lock);

	if (dispatchv4 != NULL) {
		dns_dispatchset_create(res->mctx, dispatchv4, &res->dispatches4,
				       res->nloops);
	}

	if (dispatchv6 != NULL) {
		dns_dispatchset_create(res->mctx, dispatchv6, &res->dispatches6,
				       res->nloops);
	}

	isc_mutex_init(&res->lock);
	isc_mutex_init(&res->primelock);

	dns_nametree_create(res->mctx, DNS_NAMETREE_BITS, "algorithms",
			    &res->algorithms);
	dns_nametree_create(res->mctx, DNS_NAMETREE_BITS, "ds-digests",
			    &res->digests);

	res->namepools = isc_mem_cget(res->mctx, res->nloops,
				      sizeof(res->namepools[0]));
	res->rdspools = isc_mem_cget(res->mctx, res->nloops,
				     sizeof(res->rdspools[0]));
	for (size_t i = 0; i < res->nloops; i++) {
		isc_loop_t *loop = isc_loop_get(i);
		isc_mem_t *pool_mctx = isc_loop_getmctx(loop);

		dns_message_createpools(pool_mctx, &res->namepools[i],
					&res->rdspools[i]);
	}

	res->magic = RES_MAGIC;

	*resp = res;

	return ISC_R_SUCCESS;
}

static void
prime_done(void *arg) {
	dns_fetchresponse_t *resp = (dns_fetchresponse_t *)arg;
	dns_resolver_t *res = resp->arg;
	dns_fetch_t *fetch = NULL;
	dns_db_t *db = NULL;

	REQUIRE(VALID_RESOLVER(res));

	int level = (resp->result == ISC_R_SUCCESS) ? ISC_LOG_DEBUG(1)
						    : ISC_LOG_NOTICE;
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, level,
		      "resolver priming query complete: %s",
		      isc_result_totext(resp->result));

	LOCK(&res->primelock);
	fetch = res->primefetch;
	res->primefetch = NULL;
	UNLOCK(&res->primelock);

	atomic_compare_exchange_enforced(&res->priming, &(bool){ true }, false);

	if (resp->result == ISC_R_SUCCESS && res->view->cache != NULL &&
	    res->view->hints != NULL)
	{
		dns_cache_attachdb(res->view->cache, &db);
		dns_root_checkhints(res->view, res->view->hints, db);
		dns_db_detach(&db);
	}

	if (resp->node != NULL) {
		dns_db_detachnode(resp->db, &resp->node);
	}
	if (resp->db != NULL) {
		dns_db_detach(&resp->db);
	}
	if (dns_rdataset_isassociated(resp->rdataset)) {
		dns_rdataset_disassociate(resp->rdataset);
	}
	INSIST(resp->sigrdataset == NULL);

	isc_mem_put(res->mctx, resp->rdataset, sizeof(*resp->rdataset));
	dns_resolver_freefresp(&resp);
	dns_resolver_destroyfetch(&fetch);
}

void
dns_resolver_prime(dns_resolver_t *res) {
	bool want_priming = false;
	isc_result_t result;

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(res->frozen);

	RTRACE("dns_resolver_prime");

	if (!atomic_load_acquire(&res->exiting)) {
		want_priming = atomic_compare_exchange_strong_acq_rel(
			&res->priming, &(bool){ false }, true);
	}

	if (want_priming) {
		/*
		 * To avoid any possible recursive locking problems, we
		 * start the priming fetch like any other fetch, and
		 * holding no resolver locks.  No one else will try to
		 * start it because we're the ones who set res->priming
		 * to true. Any other callers of dns_resolver_prime()
		 * while we're running will see that res->priming is
		 * already true and do nothing.
		 */
		RTRACE("priming");

		dns_rdataset_t *rdataset = isc_mem_get(res->mctx,
						       sizeof(*rdataset));
		dns_rdataset_init(rdataset);

		LOCK(&res->primelock);
		result = dns_resolver_createfetch(
			res, dns_rootname, dns_rdatatype_ns, NULL, NULL, NULL,
			NULL, 0, DNS_FETCHOPT_NOFORWARD, 0, NULL, NULL,
			isc_loop(), prime_done, res, NULL, rdataset, NULL,
			&res->primefetch);
		UNLOCK(&res->primelock);

		if (result != ISC_R_SUCCESS) {
			isc_mem_put(res->mctx, rdataset, sizeof(*rdataset));
			atomic_compare_exchange_enforced(
				&res->priming, &(bool){ true }, false);
		}
		inc_stats(res, dns_resstatscounter_priming);
	}
}

void
dns_resolver_freeze(dns_resolver_t *res) {
	/*
	 * Freeze resolver.
	 */

	REQUIRE(VALID_RESOLVER(res));

	res->frozen = true;
}

void
dns_resolver_shutdown(dns_resolver_t *res) {
	isc_result_t result;
	bool is_false = false;

	REQUIRE(VALID_RESOLVER(res));

	RTRACE("shutdown");

	if (atomic_compare_exchange_strong(&res->exiting, &is_false, true)) {
		isc_hashmap_iter_t *it = NULL;

		RTRACE("exiting");

		RWLOCK(&res->fctxs_lock, isc_rwlocktype_write);
		isc_hashmap_iter_create(res->fctxs, &it);
		for (result = isc_hashmap_iter_first(it);
		     result == ISC_R_SUCCESS;
		     result = isc_hashmap_iter_next(it))
		{
			fetchctx_t *fctx = NULL;

			isc_hashmap_iter_current(it, (void **)&fctx);
			INSIST(fctx != NULL);

			fetchctx_ref(fctx);
			isc_async_run(fctx->loop, fctx_shutdown, fctx);
		}
		isc_hashmap_iter_destroy(&it);
		RWUNLOCK(&res->fctxs_lock, isc_rwlocktype_write);

		LOCK(&res->lock);
		if (res->spillattimer != NULL) {
			isc_timer_async_destroy(&res->spillattimer);
		}
		UNLOCK(&res->lock);
	}
}

#if DNS_RESOLVER_TRACE
ISC_REFCOUNT_TRACE_IMPL(dns_resolver, dns_resolver__destroy);
#else
ISC_REFCOUNT_IMPL(dns_resolver, dns_resolver__destroy);
#endif

static void
log_fetch(const dns_name_t *name, dns_rdatatype_t type) {
	char namebuf[DNS_NAME_FORMATSIZE];
	char typebuf[DNS_RDATATYPE_FORMATSIZE];
	int level = ISC_LOG_DEBUG(1);

	/*
	 * If there's no chance of logging it, don't render (format) the
	 * name and RDATA type (further below), and return early.
	 */
	if (!isc_log_wouldlog(level)) {
		return;
	}

	dns_name_format(name, namebuf, sizeof(namebuf));
	dns_rdatatype_format(type, typebuf, sizeof(typebuf));

	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER, level,
		      "fetch: %s/%s", namebuf, typebuf);
}

static void
fctx_minimize_qname(fetchctx_t *fctx) {
	isc_result_t result;
	unsigned int dlabels, nlabels;
	dns_name_t name;

	REQUIRE(VALID_FCTX(fctx));

	dns_name_init(&name);

	dlabels = dns_name_countlabels(fctx->qmindcname);
	nlabels = dns_name_countlabels(fctx->name);

	if (dlabels > fctx->qmin_labels) {
		fctx->qmin_labels = dlabels + 1;
	} else {
		fctx->qmin_labels++;
	}

	if (fctx->ip6arpaskip) {
		/*
		 * For ip6.arpa we want to skip some of the labels, with
		 * boundaries at /16, /32, /48, /56, /64 and /128
		 * In 'label count' terms that's equal to
		 *    7    11   15   17   19      35
		 * We fix fctx->qmin_labels to point to the nearest
		 * boundary
		 */
		if (fctx->qmin_labels < 7) {
			fctx->qmin_labels = 7;
		} else if (fctx->qmin_labels < 11) {
			fctx->qmin_labels = 11;
		} else if (fctx->qmin_labels < 15) {
			fctx->qmin_labels = 15;
		} else if (fctx->qmin_labels < 17) {
			fctx->qmin_labels = 17;
		} else if (fctx->qmin_labels < 19) {
			fctx->qmin_labels = 19;
		} else if (fctx->qmin_labels < 35) {
			fctx->qmin_labels = 35;
		} else {
			fctx->qmin_labels = nlabels + 1;
		}
	} else if (fctx->qmin_labels > DNS_QMIN_MAXLABELS) {
		fctx->qmin_labels = DNS_NAME_MAXLABELS;
	}

	if (fctx->qmin_labels <= nlabels) {
		dns_rdataset_t rdataset;
		dns_fixedname_t fixed;
		dns_name_t *fname = dns_fixedname_initname(&fixed);
		dns_rdataset_init(&rdataset);
		do {
			/*
			 * We want to query for qmin_labels from fctx->name.
			 */
			dns_name_split(fctx->name, fctx->qmin_labels, NULL,
				       &name);
			/*
			 * Look to see if we have anything cached about NS
			 * RRsets at this name and if so skip this name and
			 * try with an additional label prepended.
			 */
			result = dns_db_find(fctx->cache, &name, NULL,
					     dns_rdatatype_ns, 0, 0, NULL,
					     fname, &rdataset, NULL);
			if (dns_rdataset_isassociated(&rdataset)) {
				dns_rdataset_disassociate(&rdataset);
			}
			switch (result) {
			case ISC_R_SUCCESS:
			case DNS_R_CNAME:
			case DNS_R_DNAME:
			case DNS_R_NCACHENXDOMAIN:
			case DNS_R_NCACHENXRRSET:
				fctx->qmin_labels++;
				continue;
			default:
				break;
			}
			break;
		} while (fctx->qmin_labels <= nlabels);
	}

	/*
	 * DS lookups come from the parent zone so we don't need to do a
	 * NS lookup at the QNAME.  If the QTYPE is NS we are not leaking
	 * the type if we just do the final NS lookup.
	 */
	if (fctx->qmin_labels < nlabels ||
	    (fctx->type != dns_rdatatype_ns && fctx->type != dns_rdatatype_ds &&
	     fctx->qmin_labels == nlabels))
	{
		dns_name_copy(&name, fctx->qminname);
		fctx->qmintype = dns_rdatatype_ns;
		fctx->minimized = true;
	} else {
		/* Minimization is done, we'll ask for whole qname */
		dns_name_copy(fctx->name, fctx->qminname);
		fctx->qmintype = fctx->type;
		fctx->minimized = false;
	}

	char domainbuf[DNS_NAME_FORMATSIZE];
	dns_name_format(fctx->qminname, domainbuf, sizeof(domainbuf));
	isc_log_write(DNS_LOGCATEGORY_RESOLVER, DNS_LOGMODULE_RESOLVER,
		      ISC_LOG_DEBUG(5),
		      "QNAME minimization - %s minimized, qmintype %d "
		      "qminname %s",
		      fctx->minimized ? "" : "not", fctx->qmintype, domainbuf);
}

static isc_result_t
get_attached_fctx(dns_resolver_t *res, isc_loop_t *loop, const dns_name_t *name,
		  dns_rdatatype_t type, const dns_name_t *domain,
		  dns_rdataset_t *nameservers, const isc_sockaddr_t *client,
		  unsigned int options, unsigned int depth, isc_counter_t *qc,
		  isc_counter_t *gqc, fetchctx_t **fctxp, bool *new_fctx) {
	isc_result_t result;
	fetchctx_t key = {
		.name = UNCONST(name),
		.options = options,
		.type = type,
	};
	fetchctx_t *fctx = NULL;
	isc_rwlocktype_t locktype = isc_rwlocktype_read;
	uint32_t hashval = fctx_hash(&key);

again:
	RWLOCK(&res->fctxs_lock, locktype);
	result = isc_hashmap_find(res->fctxs, hashval, fctx_match, &key,
				  (void **)&fctx);
	switch (result) {
	case ISC_R_SUCCESS:
		break;
	case ISC_R_NOTFOUND:
		result = fctx_create(res, loop, name, type, domain, nameservers,
				     client, options, depth, qc, gqc, &fctx);
		if (result != ISC_R_SUCCESS) {
			RWUNLOCK(&res->fctxs_lock, locktype);
			return result;
		}

		UPGRADELOCK(&res->fctxs_lock, locktype);

		void *found = NULL;
		result = isc_hashmap_add(res->fctxs, hashval, fctx_match, fctx,
					 fctx, &found);
		if (result == ISC_R_SUCCESS) {
			*new_fctx = true;
		} else {
			/*
			 * The fctx_done() tries to acquire the fctxs_lock.
			 * Destroy the newly created fetchctx directly.
			 */
			fctx->state = fetchstate_done;
			isc_timer_destroy(&fctx->timer);

			fetchctx_detach(&fctx);
			fctx = found;
			result = ISC_R_SUCCESS;
		}
		break;
	default:
		UNREACHABLE();
	}
	INSIST(result == ISC_R_SUCCESS);
	fetchctx_ref(fctx);

	/*
	 * We need to lock the fetch context before unlocking the hash table to
	 * prevent other threads from looking up this thread before it has been
	 * properly initialized and started.
	 */
	LOCK(&fctx->lock);
	RWUNLOCK(&res->fctxs_lock, locktype);

	if (SHUTTINGDOWN(fctx) || fctx->cloned) {
		/*
		 * This is the single place where fctx might get
		 * accesses from a different thread, so we need to
		 * double check whether fctxs is done (or cloned) and
		 * help with the release if the fctx has been cloned.
		 */
		UNLOCK(&fctx->lock);

		/* The fctx will get deleted either here or in fctx__done() */
		RWLOCK(&res->fctxs_lock, isc_rwlocktype_write);
		(void)isc_hashmap_delete(res->fctxs, fctx_hash(fctx), match_ptr,
					 fctx);
		RWUNLOCK(&res->fctxs_lock, isc_rwlocktype_write);

		fetchctx_detach(&fctx);
		goto again;
	}

	/*
	 * The function returns a locked fetch context,
	 */
	*fctxp = fctx;

	return result;
}

isc_result_t
dns_resolver_createfetch(dns_resolver_t *res, const dns_name_t *name,
			 dns_rdatatype_t type, const dns_name_t *domain,
			 dns_rdataset_t *nameservers,
			 dns_forwarders_t *forwarders,
			 const isc_sockaddr_t *client, dns_messageid_t id,
			 unsigned int options, unsigned int depth,
			 isc_counter_t *qc, isc_counter_t *gqc,
			 isc_loop_t *loop, isc_job_cb cb, void *arg,
			 dns_edectx_t *edectx, dns_rdataset_t *rdataset,
			 dns_rdataset_t *sigrdataset, dns_fetch_t **fetchp) {
	dns_fetch_t *fetch = NULL;
	fetchctx_t *fctx = NULL;
	isc_result_t result = ISC_R_SUCCESS;
	bool new_fctx = false;
	unsigned int count = 0;
	unsigned int spillat;
	unsigned int spillatmin;
	isc_mem_t *mctx = isc_loop_getmctx(loop);

	UNUSED(forwarders);

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(res->frozen);
	/* XXXRTH  Check for meta type */
	if (domain != NULL) {
		REQUIRE(DNS_RDATASET_VALID(nameservers));
		REQUIRE(nameservers->type == dns_rdatatype_ns);
	} else {
		REQUIRE(nameservers == NULL);
	}
	REQUIRE(forwarders == NULL);
	REQUIRE(!dns_rdataset_isassociated(rdataset));
	REQUIRE(sigrdataset == NULL || !dns_rdataset_isassociated(sigrdataset));
	REQUIRE(fetchp != NULL && *fetchp == NULL);

	if (atomic_load_acquire(&res->exiting)) {
		return ISC_R_SHUTTINGDOWN;
	}

	log_fetch(name, type);

	fetch = isc_mem_get(mctx, sizeof(*fetch));
	*fetch = (dns_fetch_t){ 0 };

	dns_resolver_attach(res, &fetch->res);
	isc_mem_attach(mctx, &fetch->mctx);

	if ((options & DNS_FETCHOPT_UNSHARED) == 0) {
		/*
		 * We don't save the unshared fetch context to a bucket because
		 * we also would never match it again.
		 */

		LOCK(&res->lock);
		spillat = res->spillat;
		spillatmin = res->spillatmin;
		UNLOCK(&res->lock);

		result = get_attached_fctx(res, loop, name, type, domain,
					   nameservers, client, options, depth,
					   qc, gqc, &fctx, &new_fctx);
		if (result != ISC_R_SUCCESS) {
			goto fail;
		}

		/* On success, the fctx is locked in get_attached_fctx() */
		INSIST(!SHUTTINGDOWN(fctx));

		/* Is this a duplicate? */
		if (client != NULL) {
			ISC_LIST_FOREACH (fctx->resps, resp, link) {
				if (resp->client != NULL && resp->id == id &&
				    isc_sockaddr_equal(resp->client, client))
				{
					result = DNS_R_DUPLICATE;
					goto unlock;
				}

				count++;
			}
		}
		if (count >= spillatmin && spillatmin != 0) {
			if (count >= spillat) {
				fctx->spilled = true;
			}
			if (fctx->spilled) {
				inc_stats(res, dns_resstatscounter_clientquota);
				fctx->dropped++;
				result = DNS_R_DROP;
				goto unlock;
			}
		}
	} else {
		result = fctx_create(res, loop, name, type, domain, nameservers,
				     client, options, depth, qc, gqc, &fctx);
		if (result != ISC_R_SUCCESS) {
			goto fail;
		}
		new_fctx = true;
	}

	RUNTIME_CHECK(fctx != NULL);

	if (fctx->depth > depth) {
		fctx->depth = depth;
	}

	fctx->allowed++;

	fctx_join(fctx, loop, client, id, cb, arg, edectx, rdataset,
		  sigrdataset, fetch);

	if (new_fctx) {
		fetchctx_ref(fctx);
		isc_async_run(fctx->loop, fctx_start, fctx);
	}

unlock:
	if ((options & DNS_FETCHOPT_UNSHARED) == 0) {
		UNLOCK(&fctx->lock);
		fetchctx_unref(fctx);
	}

fail:
	if (result != ISC_R_SUCCESS) {
		dns_resolver_detach(&fetch->res);
		isc_mem_putanddetach(&fetch->mctx, fetch, sizeof(*fetch));
		return result;
	}

	FTRACE("created");
	*fetchp = fetch;

	return ISC_R_SUCCESS;
}

void
dns_resolver_cancelfetch(dns_fetch_t *fetch) {
	fetchctx_t *fctx = NULL;
	bool last_fetch = false;

	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;
	REQUIRE(VALID_FCTX(fctx));

	FTRACE("cancelfetch");

	LOCK(&fctx->lock);

	/*
	 * Find the completion event associated with this fetch (as opposed
	 * to those for other fetches that have joined the same fctx) and run
	 * the callback asynchronously with a ISC_R_CANCELED result.
	 */
	if (fctx->state != fetchstate_done) {
		ISC_LIST_FOREACH (fctx->resps, resp, link) {
			if (resp->fetch == fetch) {
				resp->result = ISC_R_CANCELED;
				ISC_LIST_UNLINK(fctx->resps, resp, link);
				isc_async_run(resp->loop, resp->cb, resp);
				break;
			}
		}
	}

	if (ISC_LIST_EMPTY(fctx->resps)) {
		last_fetch = true;
	}
	UNLOCK(&fctx->lock);

	if (last_fetch) {
		fetchctx_ref(fctx);
		isc_async_run(fctx->loop, fctx_shutdown, fctx);
	}
}

void
dns_resolver_destroyfetch(dns_fetch_t **fetchp) {
	dns_fetch_t *fetch = NULL;
	dns_resolver_t *res = NULL;
	fetchctx_t *fctx = NULL;

	REQUIRE(fetchp != NULL);
	fetch = *fetchp;
	*fetchp = NULL;
	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;
	REQUIRE(VALID_FCTX(fctx));
	res = fetch->res;

	FTRACE("destroyfetch");

	fetch->magic = 0;

	LOCK(&fctx->lock);
	/*
	 * Sanity check: the caller should have gotten its event before
	 * trying to destroy the fetch.
	 */
	if (fctx->state != fetchstate_done) {
		ISC_LIST_FOREACH (fctx->resps, resp, link) {
			RUNTIME_CHECK(resp->fetch != fetch);
		}
	}
	UNLOCK(&fctx->lock);

	isc_mem_putanddetach(&fetch->mctx, fetch, sizeof(*fetch));

	fetchctx_detach(&fctx);
	dns_resolver_detach(&res);
}

void
dns_resolver_logfetch(dns_fetch_t *fetch, isc_logcategory_t category,
		      isc_logmodule_t module, int level, bool duplicateok) {
	fetchctx_t *fctx = NULL;

	REQUIRE(DNS_FETCH_VALID(fetch));
	fctx = fetch->private;
	REQUIRE(VALID_FCTX(fctx));

	LOCK(&fctx->lock);

	if (!fctx->logged || duplicateok) {
		char domainbuf[DNS_NAME_FORMATSIZE];
		dns_name_format(fctx->domain, domainbuf, sizeof(domainbuf));
		isc_log_write(category, module, level,
			      "fetch completed for %s in "
			      "%" PRIu64 "."
			      "%06" PRIu64 ": %s/%s "
			      "[domain:%s,referral:%u,restart:%u,qrysent:%u,"
			      "timeout:%u,lame:%u,quota:%u,neterr:%u,"
			      "badresp:%u,adberr:%u,findfail:%u,valfail:%u]",
			      fctx->info, fctx->duration / US_PER_SEC,
			      fctx->duration % US_PER_SEC,
			      isc_result_totext(fctx->result),
			      isc_result_totext(fctx->vresult), domainbuf,
			      fctx->referrals, fctx->restarts, fctx->querysent,
			      fctx->timeouts, fctx->lamecount, fctx->quotacount,
			      fctx->neterr, fctx->badresp, fctx->adberr,
			      fctx->findfail, fctx->valfail);
		fctx->logged = true;
	}

	UNLOCK(&fctx->lock);
}

dns_dispatch_t *
dns_resolver_dispatchv4(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));
	return dns_dispatchset_get(resolver->dispatches4);
}

dns_dispatch_t *
dns_resolver_dispatchv6(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));
	return dns_dispatchset_get(resolver->dispatches6);
}

void
dns_resolver_addalternate(dns_resolver_t *res, const isc_sockaddr_t *alt,
			  const dns_name_t *name, in_port_t port) {
	alternate_t *a;

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(!res->frozen);
	REQUIRE((alt == NULL) ^ (name == NULL));

	a = isc_mem_get(res->mctx, sizeof(*a));
	if (alt != NULL) {
		a->isaddress = true;
		a->_u.addr = *alt;
	} else {
		a->isaddress = false;
		a->_u._n.port = port;
		dns_name_init(&a->_u._n.name);
		dns_name_dup(name, res->mctx, &a->_u._n.name);
	}
	ISC_LINK_INIT(a, link);
	ISC_LIST_APPEND(res->alternates, a, link);
}

isc_result_t
dns_resolver_disable_algorithm(dns_resolver_t *resolver, const dns_name_t *name,
			       unsigned int alg) {
	REQUIRE(VALID_RESOLVER(resolver));

	if (alg >= DST_MAX_ALGS) {
		return ISC_R_RANGE;
	}

	return dns_nametree_add(resolver->algorithms, name, alg);
}

isc_result_t
dns_resolver_disable_ds_digest(dns_resolver_t *resolver, const dns_name_t *name,
			       unsigned int digest_type) {
	REQUIRE(VALID_RESOLVER(resolver));

	if (digest_type > 255) {
		return ISC_R_RANGE;
	}

	return dns_nametree_add(resolver->digests, name, digest_type);
}

bool
dns_resolver_algorithm_supported(dns_resolver_t *resolver,
				 const dns_name_t *name, unsigned int alg,
				 unsigned char *private, size_t len) {
	REQUIRE(VALID_RESOLVER(resolver));

	if ((alg == DST_ALG_DH) || (alg == DST_ALG_INDIRECT)) {
		return false;
	}

	/*
	 * Look up the DST algorithm identifier for private-OID
	 * and private-DNS keys.
	 */
	if (alg == DST_ALG_PRIVATEDNS && private != NULL) {
		isc_buffer_t b;
		isc_buffer_init(&b, private, len);
		isc_buffer_add(&b, len);
		alg = dst_algorithm_fromprivatedns(&b);
		if (alg == 0) {
			return false;
		}
	}

	if (alg == DST_ALG_PRIVATEOID && private != NULL) {
		isc_buffer_t b;
		isc_buffer_init(&b, private, len);
		isc_buffer_add(&b, len);
		alg = dst_algorithm_fromprivateoid(&b);
		if (alg == 0) {
			return false;
		}
	}
	if (dns_nametree_covered(resolver->algorithms, name, NULL, alg)) {
		return false;
	}

	return dst_algorithm_supported(alg);
}

bool
dns_resolver_ds_digest_supported(dns_resolver_t *resolver,
				 const dns_name_t *name,
				 unsigned int digest_type) {
	REQUIRE(VALID_RESOLVER(resolver));

	if (dns_nametree_covered(resolver->digests, name, NULL, digest_type)) {
		return false;
	}

	return dst_ds_digest_supported(digest_type);
}

void
dns_resolver_getclientsperquery(dns_resolver_t *resolver, uint32_t *cur,
				uint32_t *min, uint32_t *max) {
	REQUIRE(VALID_RESOLVER(resolver));

	LOCK(&resolver->lock);
	SET_IF_NOT_NULL(cur, resolver->spillat);
	SET_IF_NOT_NULL(min, resolver->spillatmin);
	SET_IF_NOT_NULL(max, resolver->spillatmax);
	UNLOCK(&resolver->lock);
}

void
dns_resolver_setclientsperquery(dns_resolver_t *resolver, uint32_t min,
				uint32_t max) {
	REQUIRE(VALID_RESOLVER(resolver));

	LOCK(&resolver->lock);
	resolver->spillatmin = resolver->spillat = min;
	resolver->spillatmax = max;
	UNLOCK(&resolver->lock);
}

void
dns_resolver_setfetchesperzone(dns_resolver_t *resolver, uint32_t clients) {
	REQUIRE(VALID_RESOLVER(resolver));

	atomic_store_release(&resolver->zspill, clients);
}

uint32_t
dns_resolver_getfetchesperzone(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));

	return atomic_load_relaxed(&resolver->zspill);
}

bool
dns_resolver_getzeronosoattl(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));

	return resolver->zero_no_soa_ttl;
}

void
dns_resolver_setzeronosoattl(dns_resolver_t *resolver, bool state) {
	REQUIRE(VALID_RESOLVER(resolver));

	resolver->zero_no_soa_ttl = state;
}

unsigned int
dns_resolver_getoptions(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));

	return resolver->options;
}

unsigned int
dns_resolver_gettimeout(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));

	return resolver->query_timeout;
}

void
dns_resolver_settimeout(dns_resolver_t *resolver, unsigned int timeout) {
	REQUIRE(VALID_RESOLVER(resolver));

	if (timeout < MINIMUM_QUERY_TIMEOUT) {
		timeout *= 1000;
	}

	if (timeout == 0) {
		timeout = DEFAULT_QUERY_TIMEOUT;
	}
	if (timeout > MAXIMUM_QUERY_TIMEOUT) {
		timeout = MAXIMUM_QUERY_TIMEOUT;
	}
	if (timeout < MINIMUM_QUERY_TIMEOUT) {
		timeout = MINIMUM_QUERY_TIMEOUT;
	}

	resolver->query_timeout = timeout;
}

void
dns_resolver_setmaxvalidations(dns_resolver_t *resolver, uint32_t max) {
	REQUIRE(VALID_RESOLVER(resolver));
	atomic_store(&resolver->maxvalidations, max);
}

void
dns_resolver_setmaxvalidationfails(dns_resolver_t *resolver, uint32_t max) {
	REQUIRE(VALID_RESOLVER(resolver));
	atomic_store(&resolver->maxvalidationfails, max);
}

void
dns_resolver_setmaxdepth(dns_resolver_t *resolver, unsigned int maxdepth) {
	REQUIRE(VALID_RESOLVER(resolver));
	resolver->maxdepth = maxdepth;
}

unsigned int
dns_resolver_getmaxdepth(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));
	return resolver->maxdepth;
}

void
dns_resolver_setmaxqueries(dns_resolver_t *resolver, unsigned int queries) {
	REQUIRE(VALID_RESOLVER(resolver));
	resolver->maxqueries = queries;
}

unsigned int
dns_resolver_getmaxqueries(dns_resolver_t *resolver) {
	REQUIRE(VALID_RESOLVER(resolver));
	return resolver->maxqueries;
}

void
dns_resolver_dumpfetches(dns_resolver_t *res, isc_statsformat_t format,
			 FILE *fp) {
	isc_result_t result;
	isc_hashmap_iter_t *it = NULL;

	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(fp != NULL);
	REQUIRE(format == isc_statsformat_file);

	LOCK(&res->lock);
	fprintf(fp, "clients-per-query: %u/%u/%u\n", res->spillatmin,
		res->spillat, res->spillatmax);
	UNLOCK(&res->lock);

	RWLOCK(&res->fctxs_lock, isc_rwlocktype_read);
	isc_hashmap_iter_create(res->fctxs, &it);
	for (result = isc_hashmap_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(it))
	{
		char typebuf[DNS_RDATATYPE_FORMATSIZE];
		char timebuf[1024];
		fetchctx_t *fctx = NULL;
		unsigned int resp_count = 0, query_count = 0;

		isc_hashmap_iter_current(it, (void **)&fctx);

		LOCK(&fctx->lock);
		dns_name_print(fctx->name, fp);

		isc_time_formatISO8601ms(&fctx->start, timebuf,
					 sizeof(timebuf));

		dns_rdatatype_format(fctx->type, typebuf, sizeof(typebuf));

		fprintf(fp, "/%s (%s): started %s, ", typebuf,
			fctx->state == fetchstate_active ? "active" : "done",
			timebuf);

		ISC_LIST_FOREACH (fctx->resps, resp, link) {
			resp_count++;
		}

		ISC_LIST_FOREACH (fctx->queries, query, link) {
			query_count++;
		}

		if (isc_timer_running(fctx->timer)) {
			strlcpy(timebuf, "expires ", sizeof(timebuf));
			isc_time_formatISO8601ms(&fctx->expires, timebuf + 8,
						 sizeof(timebuf) - 8);
		} else {
			strlcpy(timebuf, "not running", sizeof(timebuf));
		}

		fprintf(fp,
			"fetches: %u active (%" PRIuFAST32
			" allowed, %" PRIuFAST32
			" dropped%s), queries: %u, timer %s\n",
			resp_count, fctx->allowed, fctx->dropped,
			fctx->spilled ? ", spilled" : "", query_count, timebuf);

		UNLOCK(&fctx->lock);
	}
	isc_hashmap_iter_destroy(&it);
	RWUNLOCK(&res->fctxs_lock, isc_rwlocktype_read);
}

isc_result_t
dns_resolver_dumpquota(dns_resolver_t *res, isc_buffer_t **buf) {
	isc_result_t result;
	isc_hashmap_iter_t *it = NULL;
	uint_fast32_t spill;

	REQUIRE(VALID_RESOLVER(res));

	spill = atomic_load_acquire(&res->zspill);
	if (spill == 0) {
		return ISC_R_SUCCESS;
	}

	RWLOCK(&res->counters_lock, isc_rwlocktype_read);
	isc_hashmap_iter_create(res->counters, &it);
	for (result = isc_hashmap_iter_first(it); result == ISC_R_SUCCESS;
	     result = isc_hashmap_iter_next(it))
	{
		fctxcount_t *counter = NULL;
		uint_fast32_t count, dropped, allowed;
		char nb[DNS_NAME_FORMATSIZE];
		char text[DNS_NAME_FORMATSIZE + BUFSIZ];

		isc_hashmap_iter_current(it, (void **)&counter);

		LOCK(&counter->lock);
		count = counter->count;
		dropped = counter->dropped;
		allowed = counter->allowed;
		UNLOCK(&counter->lock);

		if (count < spill) {
			continue;
		}

		dns_name_format(counter->domain, nb, sizeof(nb));
		snprintf(text, sizeof(text),
			 "\n- %s: %" PRIuFAST32 " active (allowed %" PRIuFAST32
			 " spilled %" PRIuFAST32 ")",
			 nb, count, allowed, dropped);

		result = isc_buffer_reserve(*buf, strlen(text));
		if (result != ISC_R_SUCCESS) {
			goto cleanup;
		}
		isc_buffer_putstr(*buf, text);
	}
	if (result == ISC_R_NOMORE) {
		result = ISC_R_SUCCESS;
	}

cleanup:
	isc_hashmap_iter_destroy(&it);
	RWUNLOCK(&res->counters_lock, isc_rwlocktype_read);
	return result;
}

void
dns_resolver_setquotaresponse(dns_resolver_t *resolver, dns_quotatype_t which,
			      isc_result_t resp) {
	REQUIRE(VALID_RESOLVER(resolver));
	REQUIRE(which == dns_quotatype_zone || which == dns_quotatype_server);
	REQUIRE(resp == DNS_R_DROP || resp == DNS_R_SERVFAIL);

	resolver->quotaresp[which] = resp;
}

isc_result_t
dns_resolver_getquotaresponse(dns_resolver_t *resolver, dns_quotatype_t which) {
	REQUIRE(VALID_RESOLVER(resolver));
	REQUIRE(which == dns_quotatype_zone || which == dns_quotatype_server);

	return resolver->quotaresp[which];
}

void
dns_resolver_setstats(dns_resolver_t *res, isc_stats_t *stats) {
	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(res->stats == NULL);

	isc_stats_attach(stats, &res->stats);

	/* initialize the bucket "counter"; it's a static value */
	set_stats(res, dns_resstatscounter_buckets, isc_loopmgr_nloops());
}

void
dns_resolver_getstats(dns_resolver_t *res, isc_stats_t **statsp) {
	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(statsp != NULL && *statsp == NULL);

	if (res->stats != NULL) {
		isc_stats_attach(res->stats, statsp);
	}
}

void
dns_resolver_incstats(dns_resolver_t *res, isc_statscounter_t counter) {
	REQUIRE(VALID_RESOLVER(res));

	isc_stats_increment(res->stats, counter);
}

void
dns_resolver_setquerystats(dns_resolver_t *res, dns_stats_t *stats) {
	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(res->querystats == NULL);

	dns_stats_attach(stats, &res->querystats);
}

void
dns_resolver_getquerystats(dns_resolver_t *res, dns_stats_t **statsp) {
	REQUIRE(VALID_RESOLVER(res));
	REQUIRE(statsp != NULL && *statsp == NULL);

	if (res->querystats != NULL) {
		dns_stats_attach(res->querystats, statsp);
	}
}

void
dns_resolver_freefresp(dns_fetchresponse_t **frespp) {
	REQUIRE(frespp != NULL);

	if (*frespp == NULL) {
		return;
	}

	dns_fetchresponse_t *fresp = *frespp;

	*frespp = NULL;
	isc_mem_putanddetach(&fresp->mctx, fresp, sizeof(*fresp));
}
