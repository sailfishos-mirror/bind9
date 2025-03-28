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

/*****
***** Module Info
*****/

/*! \file dns/peer.h
 * \brief
 * Data structures for peers (e.g. a 'server' config file statement)
 */

/***
 *** Imports
 ***/

#include <inttypes.h>
#include <stdbool.h>

#include <isc/magic.h>
#include <isc/netaddr.h>
#include <isc/refcount.h>

#include <dns/types.h>

#define DNS_PEERLIST_MAGIC ISC_MAGIC('s', 'e', 'R', 'L')
#define DNS_PEER_MAGIC	   ISC_MAGIC('S', 'E', 'r', 'v')

#define DNS_PEERLIST_VALID(ptr) ISC_MAGIC_VALID(ptr, DNS_PEERLIST_MAGIC)
#define DNS_PEER_VALID(ptr)	ISC_MAGIC_VALID(ptr, DNS_PEER_MAGIC)

/***
 *** Functions
 ***/

void
dns_peerlist_new(isc_mem_t *mem, dns_peerlist_t **list);

void
dns_peerlist_attach(dns_peerlist_t *source, dns_peerlist_t **target);

void
dns_peerlist_detach(dns_peerlist_t **list);

/*
 * After return caller still holds a reference to peer.
 */
void
dns_peerlist_addpeer(dns_peerlist_t *peers, dns_peer_t *peer);

/*
 * Ditto. */
isc_result_t
dns_peerlist_peerbyaddr(dns_peerlist_t *peers, const isc_netaddr_t *addr,
			dns_peer_t **retval);

/*
 * What he said.
 */
isc_result_t
dns_peerlist_currpeer(dns_peerlist_t *peers, dns_peer_t **retval);

isc_result_t
dns_peer_new(isc_mem_t *mem, const isc_netaddr_t *ipaddr, dns_peer_t **peer);

isc_result_t
dns_peer_newprefix(isc_mem_t *mem, const isc_netaddr_t *ipaddr,
		   unsigned int prefixlen, dns_peer_t **peer);

void
dns_peer_attach(dns_peer_t *source, dns_peer_t **target);

void
dns_peer_detach(dns_peer_t **list);

isc_result_t
dns_peer_setbogus(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getbogus(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestixfr(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestixfr(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestixfrmaxdiffs(dns_peer_t *peer, uint32_t newval);

isc_result_t
dns_peer_getrequestixfrmaxdiffs(dns_peer_t *peer, uint32_t *retval);

isc_result_t
dns_peer_setprovideixfr(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getprovideixfr(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestnsid(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestnsid(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestzoneversion(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestzoneversion(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setsendcookie(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getsendcookie(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequirecookie(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequirecookie(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setrequestexpire(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getrequestexpire(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setsupportedns(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getforcetcp(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_setforcetcp(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_gettcpkeepalive(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_settcpkeepalive(dns_peer_t *peer, bool newval);

isc_result_t
dns_peer_getsupportedns(dns_peer_t *peer, bool *retval);

isc_result_t
dns_peer_settransfers(dns_peer_t *peer, uint32_t newval);

isc_result_t
dns_peer_gettransfers(dns_peer_t *peer, uint32_t *retval);

isc_result_t
dns_peer_settransferformat(dns_peer_t *peer, dns_transfer_format_t newval);

isc_result_t
dns_peer_gettransferformat(dns_peer_t *peer, dns_transfer_format_t *retval);

isc_result_t
dns_peer_setkeybycharp(dns_peer_t *peer, const char *keyval);

isc_result_t
dns_peer_getkey(dns_peer_t *peer, dns_name_t **retval);

isc_result_t
dns_peer_setkey(dns_peer_t *peer, dns_name_t **keyval);

isc_result_t
dns_peer_settransfersource(dns_peer_t		*peer,
			   const isc_sockaddr_t *transfer_source);

isc_result_t
dns_peer_gettransfersource(dns_peer_t *peer, isc_sockaddr_t *transfer_source);

isc_result_t
dns_peer_setudpsize(dns_peer_t *peer, uint16_t udpsize);

isc_result_t
dns_peer_getudpsize(dns_peer_t *peer, uint16_t *udpsize);

isc_result_t
dns_peer_setmaxudp(dns_peer_t *peer, uint16_t maxudp);

isc_result_t
dns_peer_getmaxudp(dns_peer_t *peer, uint16_t *maxudp);

isc_result_t
dns_peer_setpadding(dns_peer_t *peer, uint16_t padding);

isc_result_t
dns_peer_getpadding(dns_peer_t *peer, uint16_t *padding);

isc_result_t
dns_peer_setnotifysource(dns_peer_t *peer, const isc_sockaddr_t *notify_source);

isc_result_t
dns_peer_getnotifysource(dns_peer_t *peer, isc_sockaddr_t *notify_source);

isc_result_t
dns_peer_setquerysource(dns_peer_t *peer, const isc_sockaddr_t *query_source);

isc_result_t
dns_peer_getquerysource(dns_peer_t *peer, isc_sockaddr_t *query_source);

isc_result_t
dns_peer_setednsversion(dns_peer_t *peer, uint8_t ednsversion);

isc_result_t
dns_peer_getednsversion(dns_peer_t *peer, uint8_t *ednsversion);
