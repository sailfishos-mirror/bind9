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

BIND 9.21.12
------------

New Features
~~~~~~~~~~~~

- Add manual mode configuration option to dnsec-policy. ``888b5f55a8``

  Add a new option ``manual-mode`` to :any:`dnssec-policy`. The intended
  use is that if it is enabled, it will not automatically move to the
  next state transition, but instead the transition is logged. Only
  after manual confirmation with ``rndc dnssec -step`` the transition is
  made. :gl:`#4606` :gl:`!10774`

- Add a new 'servfail-until-ready' configuration option for RPZ.
  ``ec1e919389``

  By default, when :iscman:`named` is started it may start answering to
  queries before the response policy zones are completely loaded and
  processed. This new feature gives an option to the users to tell
  :iscman:`named` that incoming requests should result in SERVFAIL
  answer until all the response policy zones are processed and ready.
  Note that if one or more response policy zones fail to load,
  :iscman:`named` starts responding to queries according to those zones
  that did load. :gl:`#5222` :gl:`!10839`

- Support for parsing HHIT and BRID records has been added.
  ``bdcb90f43c``

  :gl:`#5444` :gl:`!10795`

- Add <isc/bit.h> ``87dfd96743``

  The `<isc/bit.h>` header is a GNU C11 compatible version of C23's
  `<stdbit.h>`.

  It currently uses either `<stdbit.h>` or the equivilent compiler
  builtins. However, the generic `__builtin_ctzg` and `__builtin_ctlz`
  builtins are not available in every compiler version and thus falls
  back to manually selecting from type.

  Furthermore, the ctz fallback has been removed since `__builtin_ctzll`
  has been used for a while directly without any compilation issues from
  users. Thus, we can also require `__builtin_ctz`. :gl:`!10282`

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate the "tkey-gssapi-credential" statement. ``c47e8edd09``

  The :any:`tkey-gssapi-keytab` statement allows GSS-TSIG to be set up
  in a simpler and more reliable way than using the
  :any:`tkey-gssapi-credential` statement and setting environment
  variables (e.g. ``KRB5_KTNAME``). Therefore, the
  :any:`tkey-gssapi-credential` statement has been deprecated;
  :any:`tkey-gssapi-keytab` should be used instead.

  For configurations currently using a combination of both
  :any:`tkey-gssapi-keytab` *and* :any:`tkey-gssapi-credential`, the
  latter should be dropped and the keytab pointed to by
  :any:`tkey-gssapi-keytab` should now only contain the credential
  previously specified by :any:`tkey-gssapi-credential`. :gl:`#4204`
  :gl:`!10782`

- Obsolete the "tkey-domain" statement. ``bed752f57f``

  Mark the ``tkey-domain`` statement as obsolete, since it has not had
  any effect on server behavior since support for TKEY Mode 2
  (Diffie-Hellman) was removed (in BIND 9.20.0). :gl:`#4204`
  :gl:`!10798`

Feature Changes
~~~~~~~~~~~~~~~

- Don't count failed additions into the cache. ``14d2bbbfdf``

  Previously, when the new header was NOT added into the cache, we would
  increment and then decrement stat counters immediately.  This has been
  fixed. :gl:`!10859`

- Improve C23 compatibility. ``bfbc58063a``

  Use C23 stdckdint.h when available and define ckd_{mul,add,sub} shims
  to __builtin_{mul,add,sub}_overflow(). Require all the __builtin
  functions to be supported to further simplify the non-C23
  implementation.  Rename the <stdbit.h>-shims in <isc/bit.h> to their
  C23 names. :gl:`!10818`

- Lazily allocate fetch counter. ``8e3e4a5c19``

  The counter in ns_client_t is used to track the maximum number of
  recursions in the resolver, but it is created unconditionally when
  starting the client and deallocated when resetting it.

  This commit defers the allocation of the counter till recursion needs
  to actually happen, speeding up authoritative workloads in perflab by
  1.5~2%. :gl:`!10917`

- Move handle to keystores from the view to zonemgr. ``bc5c9cf62b``

  This is a follow-up of !10895 where the keystore pointer was removed
  from the zone (as not specific to the zone) and moved to the view. But
  in order to avoid adding extra lifecycle dependencies from the zone to
  the view, the keystore pointer is now moved to the zonemgr, which also
  makes more sense as this is a global settings, and zonemgr wraps a
  bunch of other global settings to be accessibles from the zones.

  Because the zonemgr lifecycle is the same of the keystores (which are
  both depending on named_g_server) this should be a safe change.
  :gl:`!10901`

- Move keystores handle from the zone to the view. ``7e12c7de0b``

  The list of keystores is owned by the single server object
  (named_g_server), but dns_zone_t has a pointer into it in order to
  preserve encapsulation (lib/dns won't link to bin/named for good
  reasons).

  However, getting the keystores from the zone uses the zone lock
  whereas this is not needed (as the pointer value doesn't depends on
  the zone, and is initialized only with the same
  named_g_server->keystores value); also storing an extra pointer per
  zone is not needed; also, there was a logic based on the zone->secure
  property which was not needed (as there is only one keystore).

  The keystores pointer is now accessible and lock-free at view level,
  it also simplifies a bit the various zone configuration APIs
  (server.c, zoneconf.c). :gl:`!10895`

- Remove locking from rdataslab_getownercase() ``9fc10b60f7``

  Under normal circumstances, the case bitfield in the slabheader should
  be set only once.  By actually (soft-)enforcing this, the read locking
  can be completely removed from the rdataslab_getownercase() as we can
  check whether the case has been already set or not and making
  everything immutable once the case has been set. :gl:`!10843`

- Remove opportunistic node cleaning from qpzone. ``3a84604e23``

  Currently, when releasing a qpznode after a read operation, we will
  check if the node is dirty due to a previous write, upgrade the lock
  to a write lock and perform a cleanup.

  An unintended side effect of this is that protecting a node by
  increasing the reference count must also protect its parent database.
  For the very common case where only one zone is configured, this is a
  non-trivial source of contention, as the same refcount will be hit by
  all threads.

  This MR removes the opportunistic cleaning and the database refcount,
  reducing contention. Cleaning will be done only on closeversion.
  :gl:`!10814`

- Remove the negative type logic from qpcache. ``3f3993b493``

  Remove the extra representation of the negative type in the
  slabheaders and simply use the negative attribute on the slabheader.
  :gl:`!10840`

- Rewrite the bit rotate functions using __builtin or generic.
  ``af0594f482``

  In gcc 15, __builtin_stdc_rotate_{left,right} was added.  Use these
  builtins when available otherwise rewrite the ISC_ROTATE_LEFT and
  ISC_ROTATE_RIGHT using _Generic. :gl:`!10893`

- Split dbmethods into node and db vtable. ``b084f8387f``

  All databases in the codebase follow the same structure: a database is
  an associative container from DNS names to nodes, and each node is an
  associative container from RR types to RR data.

  Each database implementation (qpzone, qpcache, sdlz, builtin, dyndb)
  has its own corresponding node type (qpznode, qpcnode, etc). However,
  some code needs to work with nodes generically regardless of their
  specific type - for example, to acquire locks, manage references, or
  register/unregister slabs from the heap.

  Before this MR, these generic node operations were implemented as
  methods in a `dns_dbmethods_t` vtable. This created a coupling between
  the database and node lifetimes. If a node were to outlive its parent
  database, the node destructor would destroy all RR data, and each RR
  data destructor would try to unregister from heaps by calling a
  virtual function from the database vtable. Since the database was
  already freed, this would cause a crash.

  This MR breaks the coupling by standardizing the layout of all
  database nodes, adding a `dns_dbnode_methods_t` vtable for node
  operations, and moving node-specific methods from the database vtable
  to the node vtable. :gl:`!10728`

- Split the top level slabheader hierarchy and the individual
  slabheaders. ``68153104fa``

  :gl:`!10826`

- The nodefullname doesn't need a read lock to access .name.
  ``a1c00cbbe3``

  The qpznode->name is constant - assigned when the node is created and
  it is immutable, so there's no reason to have it locked at all.
  :gl:`!10686`

- Update clang-format style with options added in newer versions.
  ``0da10d8bbe``

  Add and apply InsertBraces statement to add missing curly braces
  around one-line statements and use
  ControlStatementsExceptControlMacros for SpaceBeforeParens to remove
  space between foreach macro and the brace, e.g. `FOREACH (x) {`
  becomes `FOREACH(x) {`. :gl:`!10863`

Bug Fixes
~~~~~~~~~

- Ensure file descriptors 0-2 are in use. ``40b7f5b7ba``

  libuv expect file descriptors <= STDERR_FILENO are in use. otherwise,
  it may abort when closing a file descriptor it opened. :gl:`#5226`
  :gl:`!10582`

- Prevent spurious SERVFAILs for certain 0-TTL resource records.
  ``72189af7bf``

  Under certain circumstances, BIND 9 can return SERVFAIL when updating
  existing entries in the cache with new NS, A, AAAA, or DS records with
  0-TTL. :gl:`#5294` :gl:`!10897`

- Batch minor meson fixes. ``e6478836e7``

  This MR fixes various meson issues that are found after the first
  meson release and are too small to have a MR on their own. :gl:`#5379`
  :gl:`!10780`

- Use DNS_RDATACOMMON_INIT to hide branch differences. ``144d8f4295``

  Initialization of the common members of rdata type structures varies
  across branches.  Standardize it by using the `DNS_RDATACOMMON_INIT`
  macro for all types, so that new types are more likely to use it, and
  hence backport more cleanly. :gl:`#5467` :gl:`!10831`

- Result could be set incorrectly in validated() ``13e3c6bfe6``

  During a recent refactoring of `validated()`, a line was removed,
  causing `result` to be left unchanged. This caused time to be wasted
  continuing to try to validate when a non-recoverable error had
  occurred, and also caused the wrong reason to be logged in
  `add_bad()`. :gl:`#5468` :gl:`!10851`

- Simplify the DNS_R_UNCHANGED handling in dns_resolver unit.
  ``5682469a5a``

  Instead of catching the DNS_R_UNCHANGED from dns_db_addrdataset() (via
  cache_rrset() and dns_ncache_add()) individually, mask it properly as
  soon as possible by moving the sigrdataset caching logic inside the
  cache_rrset() and returning ISC_R_SUCCESS from cache_rrset() and
  dns_ncache_add() when the database was unchanged. :gl:`#5473`
  :gl:`!10850`

- Allow negative RRSIGs in the qpcache again. ``11bbef0eec``

  The previous refactoring added an assertion failure when negative
  RRSIG would be added to the cache database.  As result, any query for
  RRSIG in any unsigned zone would trigger that assertion failure.

  Allow the negative RRSIG entries to be stored in the cache database
  again as not caching these would trigger new remote fetch every time
  such query would be received from a client. :gl:`#5489` :gl:`!10876`

- RPZ canonical warning displays zone entry incorrectly. ``70757a47e6``

  When an IPv6 rpz prefix entry is entered incorrectly the log message
  was just displaying the prefix rather than the full entry.  This has
  been corrected. :gl:`#5491` :gl:`!10890`

- Fix a catalog zone issue when having an unset 'default-primaries'
  configuration clause. ``bcca7a6834``

  A catalog zone with an unset ``default-primaries`` clause could cause
  an unexpected termination of the :iscman:`named` process after two
  reloading or reconfiguration commands. This has been fixed.
  :gl:`#5494` :gl:`!10896`

- Fix ISC_ROTATE_LEFTSIZE macro on MacOS" ``449245b059``

  :gl:`#5497` :gl:`!10892`

- Add and use __attribute__((nonnull)) in dnssec-signzone.c.
  ``53cfb29205``

  Clang 20 was spuriously warning about the possibility of passing a
  NULL file pointer to `fprintf()`, which uses the 'nonnull' attribute.
  To silence the warning, the functions calling `fprintf()` have been
  marked with the same attribute to assure that NULL can't be passed to
  them in the first place.

  Close #5487 :gl:`!10888`

- Disassociate added rdataset on error in cache_rrset() ``018ff7b294``

  When first dns_db_addrdataset() succeeds in cache_rrset(), but the
  second one fails with error, the added rdataset was kept associated.
  This caused assertion failure down the pipe in fctx_sendevents().
  :gl:`!10861`

- RPZ 'servfail-until-ready': skip updating SERVFAIL cache.
  ``d8b975735a``

  In order to not pollute the SERVFAIL cache with the configured
  SERVFAIL answers while RPZ is loading, set the NS_CLIENTATTR_NOSETFC
  attribute for the client. :gl:`!10904`

- Remove unused warning if DNS_TYPEPAIR_CHECK is off. ``6d8c0b2a8d``

  The compile-time DNS__TYPEPAIR_CHECK macro (wrapping an INSIST) is a
  no-op if DNS_TYPEPAIR_CHECK is off, making at least one unused
  variable in DNS_TYPEPAIR_TYPE and DNS_TYPEPAIR_COVERS scopes (as in
  such case, only one member of the pair is effectively needed).

  In such case, having an unused variable (the other member of the pair)
  is expected, this silence the warning by adding a (void) cast on the
  no-op version of DNS__TYPEPAIR_CHECK. :gl:`!10860`

- Switch bit rotation functions to statement expressions. ``160bc1a198``

  Using `static inline` functions in the headers break gcov as it cannot
  properly track the hits. To fix the issue, convert the expressions to
  statement macros. The added static assertions will ensure integer
  promotion cannot occur unlike its previous function counterpart.
  :gl:`!10878`

- Update fxhash constants. ``492fd02409``

  The fxhash implementation was missing a constant for 32-bit platforms.
  This has been fixed.  Constant for 64-bit platform was update to match
  the current Rust constants. :gl:`!10894`


