.. Copyright (C) Internet Systems Consortium, Inc. ("ISC")
..
.. SPDX-License-Identifier: MPL-2.0
..
.. This Source Code Form is subject to the terms of the Mozilla Public
.. License, v. 2.0.  If a copy of the MPL was not distributed with this
.. file, you can obtain one at https://mozilla.org/MPL/2.0/.
..
.. See the COPYRIGHT file distributed with this work for additional
.. information regarding copyright ownership.

BIND 9.21.19
------------

Security Fixes
~~~~~~~~~~~~~~

- Remove purged adb names and entries from SIEVE list immediately.
  ``22181ec1b8a``

  Both expire_name() and expire_entry() use isc_async mechanism to
  remove the names and entries from the SIEVE-LRU lists on the matching
  isc_loop.

  Under certain circumstances, this could lead to double counting the
  purged named/entries when purging the SIEVE-LRU lists under the
  overmem condition.  This would cause not enough memory to be cleaned
  up and the ADB would then never recover from the overmem condition
  leading to OOM crash of the named. :gl:`!11544`

Feature Changes
~~~~~~~~~~~~~~~

- Record query time for all dnstap responses. ``d3343c724d8``

  Not all DNS responses had the query time set in their corresponding
  dnstap messages. This has been fixed. :gl:`#3695` :gl:`!11527`

- Implement Fisher-Yates shuffle for nameserver selection.
  ``e7e96c7f1f2``

  Replace the two-pass "random start index and wrap around" logic in
  fctx_getaddresses_nameservers() with a statistically sound partial
  Fisher-Yates shuffle.

  The previous implementation picked a random starting node and did two
  passes over the linked list to find query candidates. The new logic
  introduces fctx_getaddresses_nsorder() to perform an in-place
  randomization of indices into a bounded, stack-allocated lookup array
  (nsorder) representing the "winning" fetch slots.

  The nameserver dataset is now traversed in exactly one sequential
  pass: 1. Every nameserver is evaluated for local cached data. 2. If
  the current nameserver's sequential index exists in the randomized
  nsorder array, it is permitted to launch an outgoing network fetch. 3.
  If not, it is restricted to local lookups via DNS_ADBFIND_NOFETCH.

  This guarantees a fair random distribution for outbound queries while
  maximizing local cache hits, entirely within O(1) memory and without
  the overhead of linked-list pointer shuffling or dynamic allocation.
  :gl:`#5695` :gl:`!11604`

- Invalid NSEC3 can cause OOB read of the isdelegation() stack.
  ``d8be931c491``

  When .next_length is longer than NSEC3_MAX_HASH_LENGTH, it causes a
  harmless out-of-bound read of the isdelegation() stack.  This has been
  fixed. :gl:`#5749` :gl:`!11553`

- Optimize the TCP source port selection on Linux. ``b3d13387f69``

  Enable a socket option on the outgoing TCP sockets to allow faster
  selection of the source <address,port> tuple for different destination
  <address,port> tuples when nearing over 70-80% of the source port
  utilization. :gl:`!11569`

- Remove unnecessary dns_name_copy copies in qpzone_lookup.
  ``db6fe7bd162``

  Followup on !11339, which removes further unnecessary copies in the
  lookups in qpzone.c. The performance impact seems minor though.
  :gl:`!11418`

- Resolver: refactoring of the dns_fetchresponse_t handling.
  ``a36853d7fda``

  Instead of cloning fetch responses immediately after inserting them at
  the head of the `fetch_response` list, defer cloning until the events
  are actually sent.

  This enables to: - Remove the `fctx->cloned` state; - Simplify the
  code by eliminating explicit calls to `clone_result()`; - Remove the
  logic that enforced having a fetch response with a `sigrdataset` at
  the head of the list; - Remove (just a bit of) locking in some places.

  The fetch result is stored directly in new `fctx` properties, but
  there is no memory increase as those are grouped in an anonymous
  struct used in a union besides another (bigger) anonymous struct
  wrapping properties used by qmin fetch only (and, in the case of qmin
  fetch, those fetch result properties are not needed). :gl:`!11458`

Bug Fixes
~~~~~~~~~

- Fix errors when retrying over TCP in notify_send_toaddr.
  ``d72b5fd5f68``

  If the source address is not available do not attempt to retry over
  TCP otherwise clear the TSIG key from the message prior to retrying.
  :gl:`#5457` :gl:`!10805`

- Fetch loop detection improvements. ``bc0e9f1ccbf``

  Fixes a case where an in-domain NS with an expired glue would fail to
  resolve.

  Let's consider the following parent-side delegation (both for
  `foo.example.` and `dnshost.example.`

  ``` foo.example.            3600    NS      ns.dnshost.example.
  dnshost.example.        3600    NS      ns.dnshost.example.
  ns.dnshost.example.     3600    A       1.2.3.4 ```      Then the
  child-side of `dnshost.example.`:

  ```     dnshost.example.        300     NS      ns.dnshost.example.
  ns.dnshost.example.     300     A       1.2.3.4 ```      And then the
  child-side of `foo.example.`:

  ``` foo.example             3600    NS      ns.dnshost.example.
  a.foo.example           300     A       5.6.7.8 ```

  While there is a zone misconfiguration (the TTL of the delegation and
  glue doesn't match in the parent and the child), it is possible to
  resolve `a.foo.example` on a cold-cache resolver. However, after the
  `ns.dnshost.example.` glue expires, the resolution would have failed
  with a "fetch loop detected" error. This is now fixed. :gl:`#5588`
  :gl:`!11535`

- Remove deterministic selection of nameserver. ``55e9b72e3ce``

  When selecting nameserver addresses to be looked up we where always
  selecting them in dnssec name order from the start of the nameserver
  rrset.  This could lead to resolution failure despite there being
  address that could be resolved for the other names.  Use a random
  starting point when selecting which names to lookup. :gl:`#5695`
  :gl:`#5745` :gl:`!11395`

- DNSTAP wasn't logging forwarded queries correctly. ``cc643cad175``

  :gl:`#5724` :gl:`!11509`

- Fix read UAF in BIND9 dns_client_resolve() via DNAME Response.
  ``254d41f733d``

  An attacker controlling a malicious DNS server returns a DNAME record,
  and the we stores a pointer to resp->foundname, frees the response
  structure, then uses the dangling pointer in dns_name_fullcompare()
  possibly causing invalid match.  Only the `delv`is affected.  This has
  been fixed. :gl:`#5728` :gl:`!11570`

- Wipe hmac keys correctly pre-3.0 libcrypto. ``3c8c95a50e0``

  A lingering `sizeof` from the prototype era of !11094 caused the
  key-wipe in `isc_hmac_key_destroy` to use `sizeof(key->len)` instead
  of `key->len` for the length argument of `isc_safe_memwipe`.

  This results in a buffer overflow of zero bytes in HMAC keys that are
  less than 4 bytes. As such, the overflow can only be visibile in keys
  that are less than 32-bits, which is beyond broken and creating such
  keys are only possible in testing.

  Therefore, this change is *not* a security fix since the conditions
  are never reachable in any imaginable deployment scenario.

  Builds that use OpenSSL >=3.0 are unaffected as the `sizeof` was only
  remaining in pre-3.0 builds. :gl:`#5732` :gl:`!11520`

- Fix NULL Pointer Dereference in QP-trie Cache add() ``1b80394e5a5``

  When RRSIG(rdtype) was independently cached before the RDATA for the
  rdtype itself, named would crash on the subsequent query for the RDATA
  itself.  This has been fixed.

  ISC would like to thank Vitaly Simonovich for bringing this
  vulnerability to our attention. :gl:`#5738` :gl:`!11539`

- Clear serve-stale flags when following the CNAME chains.
  ``2c67f8bbcad``

  A stale answer could have been served in case of multiple upstream
  failures when following the CNAME chains.  This has been fixed.
  :gl:`#5751` :gl:`!11558`

- Fail DNSKEY validation when supported but invalid DS is found.
  ``d4ec8ebee84``

  A regression was introduced when adding the EDE code for unsupported
  DNSKEY and DS algorithms.  When the parent has both supported and
  unsupported algorithm in the DS record, the validator would treat the
  supported DS algorithm as insecure when validating DNSKEY records
  instead of BOGUS.  This has not security impact as the rest of the
  child zone correctly ends with BOGUS status, but it is incorrect and
  thus the regression has been fixed. :gl:`#5757` :gl:`!11580`

- Importing invalid SKR file might corrupt stack memory. ``91286490c1f``

  If an BIND 9 administrator imports an invalid SKR file, local stack in
  the import function might overflow.  This could lead to a memory
  corruption on the stack and ultimately server crash. This has been
  fixed.

  ISC would like to thank mcsky23 for bringing this bug to our
  attention. :gl:`#5758` :gl:`!11578`

- Return FORMERR for ECS family 0. ``ce954f1ded0``

  RFC 7871 only defines family 1 (IPv4) and 2 (IPv6). Additionally it
  requires FORMERR to be returned for all unknown families. :gl:`!11563`


