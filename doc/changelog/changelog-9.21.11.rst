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

BIND 9.21.11
------------

New Features
~~~~~~~~~~~~

- Support for parsing the DSYNC record has been added. ``fdf7e2f773``

  :gl:`#5440` :gl:`!10776`

Removed Features
~~~~~~~~~~~~~~~~

- Remove obsolete scripts across the repo. ``32499447cb``

  All are unmaintained, dysfunctional, or both. :gl:`!10712`

Feature Changes
~~~~~~~~~~~~~~~

- Reword the 'shut down hung fetch while resolving' message.
  ``93431eb839``

  The log message 'shut down hung fetch while resolving' may be
  confusing because no detection of hung fetches actually takes place,
  but rather the timer on the fetch context expires and the resolver
  gives up.

  Change the log message to actually say that instead of the original
  cryptic message about hung fetch. :gl:`#3148` :gl:`!10759`

- Use native shared library extension. ``8420adf218``

  Use the native shared library extension when build loadable libaries.
  For most platforms this is ".so" but for Darwin it is ".dylib".
  :gl:`#5375` :gl:`!10588`

- Plugin extension in plugin path is now optional. ``13807cf853``

  Plugin configuration no longer requires the library file extension, so
  it is now possible to invoke a plugin using the syntax `plugin query
  "library"` instead of `plugin query "libary.so"`. :gl:`#5377`
  :gl:`!10753`

- Check meson.build formatting in CI. ``a91e362bb7``

  Add a new CI job that checks whether all meson.build files in the
  repository are formatted in the exact same way as "muon fmt" would
  format them.  This enforces formatting consistency across all
  meson.build files in the repository and enables updating their
  contents using dedicated tools, e.g. "meson rewrite". :gl:`#5379`
  :gl:`!10770`

- Add and use global memory context called isc_g_mctx. ``999d7a5558``

  Instead of having individual memory contexts scattered across
  different files and called different names, add a single memory
  context called isc_g_mctx that replaces named_g_mctx and various other
  global memory contexts in various utilities and tests. :gl:`!10737`

- Add deprecation warnings for RSASHA1, RSASHA1-NSEC3SHA1 and DS digest
  type 1. ``c407f3c12a``

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

  Related to #5358 :gl:`!10559`

- Change the loopmgr to be singleton. ``a1b8fe45b0``

  All the applications built on top of the loop manager were required to
  create a single instance of the loop manager.  Refactor the loop
  manager not to expose this instance to the callers, and keep the loop
  manager object internal to the `isc_loop` compilation unit.

  This significantly simplifies a number of data structures and calls to
  the `isc_loop` API. :gl:`!10733`

- Extract the resigning heap into a separate struct. ``512f1d3005``

  In the current implementation, the resigning heap is part of the zone
  database. This leads to a cycle, as the database has a reference to
  its nodes, but each node needs a reference to the database.

  This MR splits the resigning heap into its own separate struct, in
  order to help breaking the cycle. :gl:`!10706`

- Improve efficiency of ns_client_t reset. ``1d71e3b507``

  The ns_client_t struct is reset and zeroed out on every query, but
  some fields (query, message, manager) are preserved.

  We observe two things:  - The sendbuf field is going to be overwritten
  anyway, there's    no need to zero it out.  - The fields are copied
  out when the struct is zero-ed out, and    then copied back in. For
  the query field (which is 896 bytes)    this is very inefficient.

  This commit makes the reset more efficient by avoiding the unnecessary
  zeroing and copying. :gl:`!10463`

- Increase the scalability in the ADB. ``0c15da33e8``

  This MR reduces lock contention and increases scalability in the ADB
  by:  a) Using SIEVE algorithm instead of classical LRU;  b) Replacing
  rwlocked isc_hashmap with RCU cds_lfht table;  c) Replace the single
  LRU table per-object with per-loop LRU tables per-object. :gl:`!10645`

- Migrate rdataset attributes to struct of bools and enum.
  ``08814b10a1``

  :gl:`!10721`

- Prepend qpkey with namespace (normal vs denial of existence)
  ``15653c54a0``

  Merge the three qp tries (tree, nsec, nsec3) into one, add the
  namespace to the qpkey. :gl:`!10480`

- Refactor the network manager to be a singleton. ``bdf7a44442``

  Refactor the network manager to be a single object which is not
  exposed to the caller. :gl:`!10735`

- Replace per-zone lock buckets with global buckets. ``e0d1d936de``

  Qpzone employs a locking strategy where rwlocks are grouped into
  buckets, and each zone gets 17 buckets. This strategy is suboptimal in
  two ways:  - If named is serving a single zone or a zone is the
  majority of the    traffic, this strategy pretty much guarantees
  contention when using    more than a dozen threads.  - If named is
  serving many small zones, it causes substantial memory    usage.

  This commit switches the locking to a global table initialized at
  start time. This should have three effects:  - Performance should
  improve in the single zone case, since now we are    selecting from a
  bigger pool of locks.  - Memory consumption should go down
  significantly in the many zone    cases.  - Performance should not
  degrade substantially in the many zone cases.    The reason for this
  is that, while we could have substantially more    zones than locks,
  we can query/edit only O(num threads) at the same    time. So by
  making the global table much bigger than the expected    number of
  threads, we can limit contention. :gl:`!10446`

Bug Fixes
~~~~~~~~~

- Stale RRsets in a CNAME chain were not always refreshed.
  ``315e234f20``

  With serve-stale enabled, a CNAME chain that contains a stale RRset,
  the refresh query doesn't always properly refresh the stale RRsets.
  This has been fixed. :gl:`#5243` :gl:`!10720`

- Add RPZ extended DNS error for zones with a CNAME override policy
  configured. ``09efe6039c``

  When the zone is configured with a CNAME override policy, or the
  response policy zone contains a wildcard CNAME, the extended DNS error
  code was not added. This has been fixed. :gl:`#5342` :gl:`!10777`

- Fix a possible crash when adding a zone while recursing.
  ``720fa14670``

  A query for a zone that was not yet loaded may yield an unexpected
  result such as a CNAME or DNAME, triggering an assertion failure. This
  has been fixed. :gl:`#5357` :gl:`!10562`

- Fix cross builds. ``08df53858a``

  Cross-compilation did not work even when the ``-Ddoc=disabled`` build
  option was passed to Meson due to the build targets used for
  generating documentation depending on a non-native executable. This
  has been fixed. :gl:`#5379` :gl:`!10702`

- Fix named-makejournal man page installation. ``28226f979a``

  The man page for :iscman:`named-makejournal` was erroneously not
  installed when building from a source tarball. This has been fixed.
  :gl:`#5379` :gl:`!10709`

- Fix plugin loading. ``db8a6ee8bd``

  Loading plugins specified using just the shared library name (i.e.
  without using an absolute path or a relative path) did not work. This
  has been fixed. :gl:`#5379` :gl:`!10734`

- Fix dig issues. ``f5aeeb1f69``

  When used with the ``+keepopen`` option with a TCP connection,
  iscman:`dig` could terminate unexpectedly in rare situations.
  Additionally, iscman:`dig` could hang and fail to shutdown properly
  when interrupted during a query. These have been fixed. :gl:`#5381`
  :gl:`!10681`

- Log dropped or slipped responses in the query-errors category.
  ``338bd67a10``

  Responses which were dropped or slipped because of RRL (Response Rate
  Limiting) were logged in the ``rate-limit`` category instead of the
  ``query-errors`` category, as documented in ARM. This has been fixed.
  :gl:`#5388` :gl:`!10676`

- Silence "may be truncated" warnings. ``c613d87308``

  Use memccpy() instead of strncpy() for safe string manipulation.
  :gl:`#5395` :gl:`!10647`

- Separate out adbname type flags. ``571d318466``

  There are three adbname flags that are used to identify different
  types of adbname lookups when hashing rather than using multiple hash
  tables.  Separate these to their own structure element as these need
  to be able to be read without locking the adbname structure.
  :gl:`#5404` :gl:`!10677`

- Synth-from-dnssec was not working in some scenarios. ``0b19600bfe``

  Aggressive use of DNSSEC-Validated cache with NSEC was not working in
  scenarios when no parent NSEC was not in cache.  This has been fixed.
  :gl:`#5422` :gl:`!10736`

- Clean enough memory when adding new ADB names/entries under memory
  pressure. ``754d17590e``

  The ADB memory cleaning is opportunistic even when we are under memory
  pressure (in the overmem condition).  Split the opportunistic LRU
  cleaning and overmem cleaning and make the overmem cleaning always
  cleanup double of the newly allocated adbname/adbentry to ensure we
  never allocate more memory than the assigned limit. :gl:`!10637`

- Convert dnssec system tests to python. ``321aa313c4``

  Most of the shell-based tests in the `dnssec` system test have been
  converted to python.  The only exceptions are the test cases that
  exercised the `dnssec-*` command line tools, and did not interact with
  a name server; those have been relocated into a new `dnssectools`
  system test. :gl:`!10688`

- Fix one-definition-rule violation in the loop unit test.
  ``b48040e788``

  Rename isc__loopmgr when including the loop.c into loop_test.c to
  prevent odr-violation over isc__loopmgr. :gl:`!10772`

- Fix one-definition-rule violation in the tests/ns. ``30753f7723``

  Move the client_addrs and client_refs to libtest to prevent this.
  :gl:`!10771`

- Fix the DoH unit test for meson. ``59875ecbf1``

  The DoH unit test was omitted since meson migration due to a typo.
  This commit fixes that. :gl:`!10723`

- Prevent spurious validation failures. ``719bb9443a``

  Under rare circumstances, validation could fail if multiple clients
  simultaneously iterated the same set of signatures.

  References #3014 :gl:`!5578`

- Refactor resolver cache_name() and validated() functions.
  ``4a6835b51f``

  These functions were excessive in length and complexity, with McCabe
  complexity values of 110 and 105 respectively, and also included some
  dead code. They have been cleaned up and split into smaller functions,
  with a maximum complexity of 27.  A few minor coding errors were
  discovered and fixed along the way. :gl:`!10198`

- Reintroduce cross version tests. ``1563d71c1b``

  :gl:`!10792`

- Rename variable called 'free' to prevent the clash with free()
  ``fc17f3fe2a``

  :gl:`!10756`


