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

BIND 9.21.21
------------

Security Fixes
~~~~~~~~~~~~~~

- Fix crash when reconfiguring zone update policy during active updates.
  ``b3115825c8f``

  Fixed a crash that could occur when running rndc reconfig to change a
  zone's update policy (e.g., from allow-update to update-policy) while
  DNS UPDATE requests were being processed for that zone.

  ISC would like to thank Vitaly Simonovich for bringing this issue to
  our attention. :gl:`#5817` :gl:`!11707`

New Features
~~~~~~~~~~~~

- Add switch to disable cookie checking in delv. ``9911743d6ac``

  This adds the switch +[no]cookie to delv to control the sending of DNS
  COOKIE options when sending requests.  The default is to send DNS
  COOKIE options. :gl:`#5825` :gl:`!11733`

- Add MOVE_OWNERSHIP() macro for transferring pointer ownership.
  ``72ddd899ba0``

  A helper macro that returns the current value of a pointer and sets it
  to NULL in one expression, useful for transferring ownership in
  designated initializers. :gl:`!11724`

- Optionally use libngtcp2 in development builds. ``786cac3b46e``

  Unlike new transports with a new dependency DNS-over-QUIC support will
  be added incrementally due to the non-trivial amound of plumbing
  required by libngtcp2. This will require non-functional QUIC code in
  the main branch that won't be exposed for non-development builds.

  Therefore, libngtcp2 is linked as an optional dependency only on
  explicitly enabled development builds and cannot be required. This
  will be changed with a `doq` meson build option once the server-side
  functionality is complete for consumption. :gl:`!11557`

Removed Features
~~~~~~~~~~~~~~~~

- Remove -C option from dnssec-keygen and dnssec-keyfromlabel.
  ``864932a15ec``

  The -C option, introduced in BIND 9.7, caused a backward-compatible
  key to be generated, using private key format version 1.2, omitting
  the creation date and other timing metadata. This made it possible to
  generate keys that could be loaded by older versions of BIND.

  Those older versions having reached end of life many years ago, the
  option can now be removed, along with the `dnssec-settime -f` option,
  which caused old-style keys to be upgraded. :gl:`!11446`

- Remove NZF file support in favor of NZD (New Zone Database)
  ``929eccdfdc8``

  The NZF (New Zone File) backend for storing rndc addzone
  configurations has been removed; LMDB-based NZD is now the only
  storage backend and LMDB is now a required build dependency.

  Existing NZF files are automatically migrated to NZD on startup, so no
  manual intervention is required when upgrading. :gl:`!11688`

Feature Changes
~~~~~~~~~~~~~~~

- Parent-centric resolver. ``e3b60291aab``

  The `named` resolver now uses a separate "delegation database" to
  store zone referral data instead of the DNS cache. This new database
  holds the NS RRset on the parent side of a zone cut, as well as
  necessary glue records that were included in the referral. The NS
  RRset from the child side is cached in the DNS cache and is not used
  for name resolution.

  This will be a step toward simplifying resolver logic and also
  supporting DELEG referrals. :gl:`#3311` :gl:`!11621`

- Add low contention stats counter. ``1e295b60f64``

  In the current statistics counter implementation, the statistics are
  backed by an array of counters, which are updated via atomic
  operations. This leads to contention, especially on high core count
  machines.

  This commit introduces a new isc_statsmulti_t counter that keeps a
  separate array per thread. These counters are then aggregated only
  when statistics are queried, shifting work off the critical path.

  These changes lead to a ~2% improvement in perflab. :gl:`!11036`

- Exclude named.args.j2 and system test README files from license header
  checks. ``ac29faea164``

  Exclude named.args.j2 files from license header checks so named.args
  can be generated from Jinja templates. Also exclude system test README
  files from the license header checks. :gl:`!11690`

- Fix cache flush ordering on NTA expiry. ``0b0931a5b12``

  dns_view_flushnode() was called in the delete_expired() async
  callback, which runs after the query that detected the NTA expiry.
  This created a race: the query would proceed with stale cached data
  from the NTA period before the flush had a chance to run, resulting in
  transient SERVFAIL with EDE 22 (No Reachable Authority).

  Move dns_view_flushnode() into dns_ntatable_covered() so the cache is
  flushed synchronously when the expiry is detected, before the query
  continues.

  Also simplify the expiry comparison in delete_expired() to a direct
  pointer comparison (nta == pval) instead of comparing expiry
  timestamps. :gl:`!11729`

- Refactor NTA to use RCU instead of rwlock. ``fdb5eca9a9c``

  Replace the ntatable rwlock with RCU read-side critical sections.
  :gl:`!11689`

- Revert NTA flush on expire. ``a44bf5c5a40``

  Flushing the name when NTA expires causes problems for the ongoing
  resolving process. Do not flush the name from the cache. Instead, the
  resolver should do the flushing (this is planned to be implemented
  later). :gl:`!11765`

- Switch to LRU-only cache eviction, enforce minimum cache size.
  ``8721a89b643``

  Busy resolvers will now gradually fill the configured
  :any:max-cache-size before entries start being evicted. Previously,
  expired records were proactively removed based on their TTL, which
  kept memory usage below the configured limit but added overhead. Cache
  eviction now relies solely on the SIEVE-LRU mechanism, which has
  matured to the point where TTL-based cleaning is no longer necessary.

  Setting :any:max-cache-size to unlimited or 0 is no longer supported
  and falls back to the default (90% of physical memory). :gl:`!11459`

- Use underscore for system test names. ``38a1ed8c591``

  Change the convention for system test directory names to always use an
  underscore rather than a hyphen. Names using underscore are valid
  python package names and can be used with standard `import` facilities
  in python, which allows easier code reuse. :gl:`!11710`

Bug Fixes
~~~~~~~~~

- Fix intermittent named crashes during asynchronous zone operations.
  ``da6a85dc63b``

  Asynchronous zone loading and dumping operations occasionally
  dispatched tasks to the wrong internal event loop. This threading
  violation triggered internal safety assertions that abruptly
  terminated named. Strict loop affinity is now enforced for these
  tasks, ensuring they execute on their designated threads and
  preventing the crashes. :gl:`#4882` :gl:`!11655`

- Fix data race in glue cache RCU pointer publication. ``ea408e3c3db``

  The liburcu rcu_cmpxchg_pointer() uses relaxed ordering on the CAS
  failure path. When two threads race to publish a new pointer and one
  loses the CAS, the returned pointer has no acquire semantics - reading
  fields through it is a data race on weakly-ordered architectures.

  Override rcu_cmpxchg_pointer() and rcu_xchg_pointer() to use
  acquire/release ordering via standard __atomic builtins, which also
  makes the operations natively visible to ThreadSanitizer. :gl:`#5182`
  :gl:`!11719`

- Count temporal problems with DNSSEC validation as attempts.
  ``3b9ad92cddd``

  After KeyTrap, the temporal DNSSEC were originally hard errors that
  caused validation failures even if the records had another valid
  signature.  This has been changed and the RRSIGs outside of the
  inception and expiration time are not counted as hard errors.
  However, these errors are not even counted as validation attempts, so
  excessive number of expired RRSIGs would cause some non-cryptograhic
  extra work for the validator.  This has been fixed and the temporal
  errors are correctly counted as validation attempts. :gl:`#5760`
  :gl:`!11589`

- Clear errno correctly. ``106416eb38d``

  Zero errno before calling strtol. :gl:`#5773` :gl:`!11625`

- Fix a possible deadlock in RPZ processing. ``5c8d64499e0``

  The :iscman:`named` process could hang when processing a maliciously
  crafted update for a response policy zone (RPZ). This has been fixed.
  :gl:`#5775` :gl:`!11659`

- Fix use-after-free in xfrin_recv_done. ``3df0f7fb9c0``

  Move the LIBDNS_XFRIN_RECV_DONE probe execution before
  dns_xfrin_detach in xfrin_recv_done.

  Previously, dns_xfrin_detach was called before the trace probe, which
  could free the xfr object.  Because the accessed member xfr->info is
  an embedded array, the expression evaluates via pointer arithmetic
  rather than a direct memory dereference.  Although this prevents a
  reliable crash in practice, it technically remains a use-after-free
  issue. Reorder the statements to ensure the transfer context is fully
  valid when the probe executes. :gl:`#5786` :gl:`!11632`

- Fix update-policy per-type max quota bypass via crafted UPDATE
  messages. ``d18a3f61c98``

  An authenticated DDNS client could bypass update-policy per-type
  record limits (e.g. TXT(3)) by including padding records in the UPDATE
  message that are silently skipped during processing. Each skipped
  record shifted an internal counter, causing subsequent records to be
  checked against the wrong quota — potentially reading an unlimited (0)
  entry instead of the configured maximum.

  This allowed a client with valid TSIG credentials to add an arbitrary
  number of records beyond the configured limit across repeated UPDATE
  messages up to the `max-records-per-type` limit. :gl:`#5799`
  :gl:`!11708`

- Fix a crash triggered by rndc modzone on zone from configuration file.
  ``48de26538ca``

  Calling `rndc modzone` on a zone that was configured in the
  configuration file caused a crash. This has been fixed.

  ISC would like to thank Nathan Reilly for reporting this. :gl:`#5800`
  :gl:`!11683`

- Fix the processing of empty catalog zone ACLs. ``632a389e2c3``

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog zone ACL in an APL resource record that was
  completely empty. This has been fixed. :gl:`#5801` :gl:`!11740`

- Fix OpenSSL 4 compatibility issue when calling X509_get_subject_name()
  ``247a2df5720``

  Starting from OpenSSL 4 the the X509_get_subject_name() function
  returns a 'const' pointer to a name instead of a regular pointer.
  Duplicate the name before operating on it, then free it. :gl:`#5807`
  :gl:`!11676`

- Take dns_dtenv_t reference before an async function call.
  ``09fe432cb42``

  A 'dns_dtenv_t' pointer is passed to an async function without taking
  a reference first, which can potentially cause a use-after-free error.
  Take a reference, then detach in the async function. :gl:`#5820`
  :gl:`!11705`

- Fix couple of reference counting bugs. ``6a94864c623``

  Fix missing detach/free on error paths. :gl:`!11666`

- Fix data race in server round-trip time tracking. ``892f50712df``

  The SRTT (Smoothed Round-Trip Time) update for remote servers was not
  atomic — concurrent callers could each read the same value and one
  update would be silently lost. Additionally, the aging decay applied
  once per second could run multiple times if several threads entered
  the function simultaneously.

  Use compare-and-swap loops for the SRTT update and for the aging
  timestamp to ensure no updates are lost. :gl:`!11718`

- Fix data race on fctx->vresult in validated() ``73dcf9373a9``

  Move the write to fctx->vresult after LOCK(&fctx->lock).  The field
  was being set before acquiring the lock, but dns_resolver_logfetch()
  reads it under the same lock from another thread. :gl:`!11717`

- Fix isc_buffer_init capacity mismatch in DoH data chunk callback.
  ``42f458d33f0``

  isc_buffer_init() is given MAX_DNS_MESSAGE_SIZE (65535) as capacity
  but only h2->content_length bytes are allocated.  This makes the
  buffer believe it has more space than actually allocated.  A secondary
  bounds check (new_bufsize <= h2->content_length) prevents actual
  overflow, but the buffer invariant is violated.

  Pass h2->content_length as the capacity to match the allocation.
  :gl:`!11662`

- Fix memory leak in dns_catz_options_setdefault() for zonedir.
  ``29790af3353``

  When defaults->zonedir is set, opts->zonedir is unconditionally
  overwritten without freeing the previous value. This leaks memory on
  every catalog zone update when zonedir defaults are configured.

  Free the existing opts->zonedir before replacing it. :gl:`!11660`

- Fix port validation rejecting valid port 65535. ``38d0bbd0b87``

  Three port validation checks use >= UINT16_MAX instead of >
  UINT16_MAX, incorrectly rejecting port 65535 as out of range.  Port
  65535 is a valid TCP/UDP port number.  Other port checks in the same
  file already use the correct > comparison. :gl:`!11665`

- Fix potential resource during resolver error handling. ``97e78c6bf46``

  Under specific error conditions during query processing, resources
  were not being properly released, which could eventually lead to
  unnecessary memory consumption for the server.  The a potential
  resource leak in the resolver has been fixed. :gl:`!11658`

- Remove legacy NS processing limit check. ``7135105d710``

  Commit `604d8f0b967563b0ba9dcd4f09559fdd9e21dfbe` introduced during
  9.19 development cycle a check to ensure the resolver never attempts
  to lookup more than 20 NS names. This limit was introduced by
  `3a44097fd6c6c260765b628cd1d2c9cb7efb0b2a` as part of the
  CVE-2022-2795.

  However, this test relies on the fact that, at the time, the NS names
  were processed in a specific order in the nameserver.

  This is not true anymore, as the NS are in a random order. Moreover,
  commit `3c33e7d9370006b1599e3d99c0d5fa6a6dad7979` introduced the
  randomization of the selection of the NS names to lookup, which make
  the test potentially unreliable, as it now doesn't mean anything to
  check the nameserver does not query `ns21.fake.redirect.com.`, as it
  could be the first one, or in any position form the randomized list.

  Another test has been added in commit
  `c67b52684f11652b07afaa75a917f6f0355dbca6` which test both the
  randomization of the NS name to be looked up, as well as the upper
  bound limit of NS  name lookup to be done.

  For all those reasons, this specific legacy check is now removed.
  :gl:`!11745`

- Rpz_rrset_find() now recurses on ISC_R_NOTFOUND. ``b9aa862b77c``

  Previously, `rpz_rrset_find()` behaved differently depending on
  whether a cache lookup returned `DNS_R_DELEGATION` or
  `ISC_R_NOTFOUND`.  The former indicates the presence of a cached NS
  rrset, and the latter indicates that the cache is cold or that all NS
  rrsets above the query name have expired. Both results indicate that
  the caller should recurse, but `rpz_rrset_find()` only recursed in the
  case of `DNS_R_DELEGATION`. This has been fixed and the test updated
  to match. :gl:`!11741`


