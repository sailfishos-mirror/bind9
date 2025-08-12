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

Notes for BIND 9.20.12
----------------------

New Features
~~~~~~~~~~~~

- Support for parsing the DSYNC record has been added.

  :gl:`#5440`

Feature Changes
~~~~~~~~~~~~~~~

- Add deprecation warnings for RSASHA1, RSASHA1-NSEC3SHA1 and DS digest
  type 1.

  RSASHA1 and RSASHA1-NSEC-SHA1 DNSKEY algorithms have been deprecated
  by the IETF and should no longer be used for DNSSEC. DS digest type 1
  (SHA1) has also been deprecated. Validators are now expected to treat
  these algorithms and digest as unknown, resulting in some zones being
  treated as insecure when they were previously treated as secure.
  Warnings have been added to named and tools when these algorithms and
  this digest are being used for signing.

  Zones signed with RSASHA1 or RSASHA1-NSEC-SHA1 should be migrated to a
  different DNSKEY algorithm.

  Zones with DS or CDS records with digest type 1 (SHA1) should be
  updated to use a different digest type (e.g. SHA256) and the digest
  type 1 records should be removed.

  Related to #5358

Bug Fixes
~~~~~~~~~

- Stale RRsets in a CNAME chain were not always refreshed.

  With serve-stale enabled, a CNAME chain that contains a stale RRset,
  the refresh query doesn't always properly refresh the stale RRsets.
  This has been fixed. :gl:`#5243`

- Add RPZ extended DNS error for zones with a CNAME override policy
  configured.

  When the zone is configured with a CNAME override policy, or the
  response policy zone contains a wildcard CNAME, the extended DNS error
  code was not added. This has been fixed. :gl:`#5342`

- Fix dig issues.

  When used with the ``+keepopen`` option with a TCP connection,
  iscman:`dig` could terminate unexpectedly in rare situations.
  Additionally, iscman:`dig` could hang and fail to shutdown properly
  when interrupted during a query. These have been fixed. :gl:`#5381`

- Log dropped or slipped responses in the query-errors category.

  Responses which were dropped or slipped because of RRL (Response Rate
  Limiting) were logged in the ``rate-limit`` category instead of the
  ``query-errors`` category, as documented in ARM. This has been fixed.
  :gl:`#5388`

- Synth-from-dnssec was not working in some scenarios.

  Aggressive use of DNSSEC-Validated cache with NSEC was not working in
  scenarios when no parent NSEC was not in cache.  This has been fixed.
  :gl:`#5422`

- Clean enough memory when adding new ADB names/entries under memory
  pressure.

  The ADB memory cleaning is opportunistic even when we are under memory
  pressure (in the overmem condition).  Split the opportunistic LRU
  cleaning and overmem cleaning and make the overmem cleaning always
  cleanup double of the newly allocated adbname/adbentry to ensure we
  never allocate more memory than the assigned limit.

- Prevent spurious validation failures.

  Under rare circumstances, validation could fail if multiple clients
  simultaneously iterated the same set of signatures.

  References #3014


