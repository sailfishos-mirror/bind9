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

BIND 9.21.13
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-8677] DNSSEC validation fails if matching but invalid DNSKEY
  is found. ``1d851c23529``

  Previously, if a matching but cryptographically invalid key was
  encountered during DNSSEC validation, the key was skipped and not
  counted towards validation failures. :iscman:`named` now treats such
  DNSSEC keys as hard failures and the DNSSEC validation fails
  immediately, instead of continuing with the next DNSKEYs in the RRset.

  ISC would like to thank Zuyao Xu and Xiang Li from the All-in-One
  Security and Privacy Laboratory at Nankai University for bringing this
  vulnerability to our attention. :gl:`#5343`

- [CVE-2025-40778] Address various spoofing attacks. ``7b95c382dbd``

  Previously, several issues could be exploited to poison a DNS cache
  with spoofed records for zones which were not DNSSEC-signed or if the
  resolver was configured to not do DNSSEC validation. These issues were
  assigned CVE-2025-40778 and have now been fixed.

  As an additional layer of protection, :iscman:`named` no longer
  accepts DNAME records or extraneous NS records in the AUTHORITY
  section unless these are received via spoofing-resistant transport
  (TCP, UDP with DNS cookies, TSIG, or SIG(0)).

  ISC would like to thank Yuxiao Wu, Yunyi Zhang, Baojun Liu, and Haixin
  Duan from Tsinghua University for bringing this vulnerability to our
  attention. :gl:`#5414`

- [CVE-2025-40780] Cache-poisoning due to weak pseudo-random number
  generator. ``6876753c7cc``

  It was discovered during research for an upcoming academic paper that
  a xoshiro128\*\* internal state can be recovered by an external 3rd
  party, allowing the prediction of UDP ports and DNS IDs in outgoing
  queries. This could lead to an attacker spoofing the DNS answers with
  great efficiency and poisoning the DNS cache.

  The internal random generator has been changed to a cryptographically
  secure pseudo-random generator.

  ISC would like to thank Prof. Amit Klein and Omer Ben Simhon from
  Hebrew University of Jerusalem for bringing this vulnerability to our
  attention. :gl:`#5484`

New Features
~~~~~~~~~~~~

- Add extra tokens to the zone file name template. ``b449fa95005``

  Extend the `$name`, `$view` and `$type` tokens (expanding into the
  zone name, zone's view name and type); the new following tokens are
  now also accepted:

  - `$name` or `%s` is replaced with the zone name in lower case; -
  `$type` or `%t` is replaced with the zone type -- i.e., primary,
  secondary, etc); - `$view` or `%v` is replaced with the view name; -
  `$char1` or `%1` is replaced with the first character of the zone
  name; - `$char2` or `%2` is replaced with the second character of the
  zone name   (or a dot if there is no second character); - `$char3` or
  `%3` is replaced with the third character of the zone name (or   a dot
  if there is no third character); - `$label1` or `%z` is replaced with
  the toplevel domain of the zone (or a   dot if it is the root zone); -
  `$label2` or `%y` is replaced with the next label under the toplevel
  domain (or a dot if there is no next label); - `$label3` or `%x` is
  replaced with the next-next label under the toplevel   domain (or a
  dot if there is no next-next label). :gl:`#85` :gl:`!10779`

- Add support for synthetic records. ``cefed841046``

  Add a query plugin which, in "reverse" mode, enables the server to
  build a synthesized response to a PTR query when the PTR record
  requested is not found in the zone.      The dynamically-built name is
  constructed from a static prefix (passed as a plugin parameter), the
  IP address (extracted from the query name) and a suffix (also passed
  as a plugin parameter).  An `allow-synth` address-match list can be
  used to limit the network addresses for which the plugin may generate
  responses.      The plugin can also be used in "forward" mode, to
  build synthesized A/AAAA records from names using the same format as
  the dynamically-built PTR names. The same parameters are used: the
  plugin will react and answer a query if the name matches the
  configured prefix and origin, and encodes an IP address that is within
  `allow-synth`. :gl:`#1586` :gl:`!10348`

- Support for zone-specific plugins. ``65fa5693572``

  Query plugins can now be configured at the `zone` level, as well as
  globally or at the `view` level. A plugin's hooks are then called only
  while that specific zone's database is being used to answer a query.

  This simplifies the implementation of plugins that are only needed for
  specific namespaces for which the server is authoritative. It can also
  enable quicker responses, since plugins will only be called when they
  are needed. :gl:`#5356` :gl:`!10483`

- Add dnssec-policy keys configuration check to named-checkconf.
  ``23a79b42ea4``

  A new option `-k` is added to `named-checkconf` that allows checking
  the `dnssec-policy` `keys` configuration against the configured key
  stores. If the found key files are not in sync with the given
  `dnssec-policy`, the check will fail.

  This is useful to run before migrating to `dnssec-policy`. :gl:`#5486`
  :gl:`!10907`

Removed Features
~~~~~~~~~~~~~~~~

- Remove randomized RRset ordering. ``014a05a2781``

  The rrset-order random doesn't offer uniform distribution of all
  permutations and it isn't superior to cyclic order in any way.  Make
  the random ordering an alias to the cyclic ordering. :gl:`#5513`
  :gl:`!10912`

- Remove CHECK_FOR_GLUE_IN_ANSWER. ``7fa4cbedc50``

  Macro CHECK_FOR_GLUE_IN_ANSWER is defined in `lib/dns/resolver.c`
  only, documented nowhere and not exposed as build configuration. This
  is valid at least for 9.21+, 9.20 and 9.18. Furthermore, it doesn't
  compile anymore on 9.21+ with -DCHECK_FOR_GLUE_IN_ANSWER=1.

  Considering it is very unlikely that anyone build named with this,
  remove the code rather than fixing it. :gl:`#5538` :gl:`!11029`

- Remove orphan dns_loadmgr_t type. ``96855b5449f``

  dns_loadmgr_t typedef is declared but never defines as well as a
  pointer of this type in named_server_t. Removing it. :gl:`!10974`

Feature Changes
~~~~~~~~~~~~~~~

- Add a circular reference between slabtops for type and RRSIG(type)
  ``a20c8fe74b0``

  Previously, the slabtops for "type" and its signature was only loosely
  coupled and the headers could expire at different time (both TTL and
  LRU based expiry).  Add a .related member to the slabtop that allows
  us to expire the headers in both related headers and also optimize the
  lookups because now both slabtops are looked up at the same time.
  :gl:`#3396` :gl:`!10985`

- Refactor view creation/configuration loops in dedicated functions.
  ``cb0807be2be``

  Refactor a bit of `apply_configuration` by extracting (into respective
  dedicated function) the logic to build the keystores list, the KASP
  list as well as creating the view/zones and configuring those. This is
  the next step of MR !10895 and !10901

  While the code is extracted, some global variables has been changed
  into a function parameters which enable to have a clear view of the
  dependency of the function, typically, to know if it depends on local
  configuration object or runtime "production" object. The end goal (not
  in this MR, but later on) is to move as much as possible
  initialization logic outside of the exclusive mode.

  As a first step, latest commits move the keystores list, KASP list and
  view/zones creation outside of the exclusive mode. (The view/zone
  configuration remain in exclusive mode for now, because of a
  dependency to the runtime "cachelist". This is the target of a next
  MR.

  For the record; while moving the keystores list, KASP list and
  view/zone creation doesn't have a significant impact on the time the
  exclusive mode is taken (from my experiment on a 1M small zones
  instance); moving `configure_views` did have a _massive_ impact
  (basically, the time spend in the exclusive mode is then non
  calculable). Configuring views outside the exclusive mode needs more
  work, which will be done in future MRs. :gl:`#4673` :gl:`!10910`

- Add option to always build fuzz binaries. ``54c8252c6e2``

  Currently the fuzzer binaries are only built when someone requests a
  fuzzer. This might cause us to inadvertently break fuzzing when
  changing function signatures. It also deviates with the behaviour we
  had with autotools, where the fuzz binaries were built with make test.

  This commit splits the -Dfuzzing option into two: fuzzing, and
  fuzzing-backend. The fuzzing option controls whether the fuzzing
  binaries are built. The fuzzing-backend option controls which backend
  to use, and defaults to none. If the value none is used the binaries
  are built, but no backend is used or guaranteed, which means that the
  binaries might be non-functional. :gl:`#5526` :gl:`!10990`

- Rename cfg_aclconfctx_t variables to aclctx. ``0411142f826``

  ACL configuration context variables are inconsistently named as
  `actx`, `ac`, or `aclconfctx`, which caused confusion during code
  reviews. This commit renames all `cfg_aclconfctx_t` variables to
  `aclctx`, which is short, consistent, and unambiguous. :gl:`#5530`
  :gl:`!11003`

- Provide more context when registering plugins. ``ac4cf4cce8d``

  Add a new type, `ns_pluginregister_ctx_t`, which is passed to
  `plugin_register()` in place of the `source` parameter. The source
  value is now just part of the structure, which also holds a pointer to
  the zone origin if the plugin is loaded at a zone level.      This
  provides more contextual information, enabling the plugin to make
  specific configuration decisions based on the name of the zone for
  which it is loaded.      It's also flexible if more contextual data
  are needed in the future: add a new field to
  `ns_pluginregister_ctx_t`, and new plugins can use it without
  affecting compatibility with existing plugins. :gl:`#5533`
  :gl:`!11019`

- Add option to compile named with static linking and LTO.
  ``b6971fb7240``

  Statically linking lib{isc,dns,ns,cfg,isccc} and enabling LTO shows
  over 10% improvements on all almost measurements in perflab. That
  said, we can't use Meson's option for LTO since it would result in
  every binary being compiled with LTO and a great increase in compile
  time.

  To work around it, we add a configuration option that enables LTO and
  static linking only for the `named` binary. :gl:`!10761`

- Convert slabtop and slabheader to use the cds list. ``7443ff330cc``

  This is the first MR in series that aims to reduce the node locking by
  replacing the single-linked list of slabtop(s) and slabheader(s) with
  CDS linked list.  This commit doesn't do anything else beyond
  replacing .next and .down links with the cds_list_head.  The RCU
  semantics will be added later. :gl:`!10944`

- Make the database ownercase modifiable only via addrdataset()
  ``dbc47312925``

  Simplify the implementation around the database ownercase.  Remove the
  dns_rdataset_setownercase() implementation for the slabheaders and
  only allow setting ownercase on rdatalists and rdatasets.  The
  ownercase in the database can now be set only with
  dns_db_addrdataset() by passing rdataset with correctly set ownercase.
  :gl:`!10971`

- Minor refactor of dst code. ``f5af3e431b9``

  Convert the defines to enums. Initialize the tags more explicitly and
  less ugly. :gl:`!11000`

- Rename ns_pluginregister_ctx_t into ns_pluginctx_t. ``029a7152bba``

  The type `ns_pluginregister_ctx_t` was initially added to pass plugin
  contextual data when the plugin is registered, but this is also now
  passed into `plugin_check`. Furthermore, those various data are not
  specific to the registration in particular. Rename the type into
  `ns_pluginctx_t` for clarity. :gl:`!11035`

- Simplify nchildren count in isc_nm_listenudp. ``722ce92f107``

  Slight simplification of the logic to define .nchildren listening UDP
  socket. :gl:`!10978`

- Squash the qpcache tree and nsec tries. ``22803b93e3f``

  The dns_qpcache already had all the namespace changes needed to put
  the normal data and auxiliary NSEC data into a single tree.  Remove
  the extra nsec QP trie and use the single QP trie for all the cache
  data. :gl:`!10975`

- Use lock-free hashtable for storing resolver fetch contexts.
  ``0ac744ee4de``

  Replace the locked hashmap with the lock-free hashtable from the RCU
  library and protect the fetch contexts against reuse by replacing the
  libisc reference counting with urcu_ref that can soft-fail in
  situation where the reference count is already zero.  This allows us
  to easily skip re-using the fetch context if it is already in process
  of being destroyed. :gl:`!10653`

Bug Fixes
~~~~~~~~~

- Use signer name when disabling DNSSEC algorithms. ``7e0318df857``

  ``disable-algorithms`` could cause DNSSEC validation failures when the
  parent zone was signed with the algorithms that were being disabled
  for the child zone. This has been fixed; `disable-algorithms` now
  works on a whole-of-zone basis.

  If the zone's name is at or below the ``disable-algorithms`` name the
  algorithm is disabled for that zone, using deepest match when there
  are multiple ``disable-algorithms`` clauses.  :gl:`#5165` :gl:`!10837`

- Rndc sign during ZSK rollover will now replace signatures.
  ``6246f9d7cb1``

  When performing a ZSK rollover, if the new DNSKEY is omnipresent, the
  :option:`rndc sign` command now signs the zone completely with the
  successor key, replacing all zone signatures from the predecessor key
  with new ones. :gl:`#5483` :gl:`!10867`

- Missing DNSSEC information when CD bit is set in query.
  ``5fcc063ce9a``

  The RRSIGs for glue records were not being cached correctly for CD=1
  queries.  This has been fixed. :gl:`#5502` :gl:`!10938`

- Fix datarace between unlocking fctx lock and shuttingdown fctx.
  ``2924f59cb3e``

  There was a data race where new fetch response could be added to the
  fetch context after we unlock the fetch context and before we shut it
  down.  This could cause assertion failure when fctx__done() was called
  with ISC_R_SUCCESS because there was originally no fetch response, but
  new fetch response without associated dataset was added before we had
  a chance to shutdown the fetch context.  This manifested in the
  validated() callback, where cache_rrset() now returns ISC_R_SUCCESS
  instead of DNS_R_UNCHANGED when cache was not changed.  However the
  data race was wrong on a general level.

  Add new argument to fctx__done() that allows to call it with
  fctx->lock already acquired to prevent these data races. :gl:`#5507`
  :gl:`!10961`

- Add chroot check to meson.build. ``f2f2488bbe1``

  The meson build procedure was not checking for the existence of the
  chroot function.  This has been fixed. :gl:`#5519` :gl:`!10973`

- Preserve cache when reload fails and reload the server again.
  ``33bcff46d30``

  Fixes an issue where failing to reconfigure/reload the server would
  prevent to preserved the views caches on the subsequent server
  reconfiguration/reload. :gl:`#5523` :gl:`!10984`

- Apply_configuration: leave exclusive mode after viewlist cleanup.
  ``5c53695bf32``

  When a re-configuration fails, `apply_configuration` flows jump to a
  cleanup label and, at some point, leave the exclusive mode and cleanup
  the viewlist. It looks fine as the viewlist is at this point only
  locally known (if this is a configuration failure, this is the new
  view list, if this is a success, this is the old list which has been
  swapped out from the production list during the exclusive mode).

  However, the view and zone initialization code enqueues job callbacks,
  for instance from `dns_zone_setsigninginterval` (but there are others
  cases) which will be called for the new views and zones after the
  exclusive mode is over.

  Depending where the configuration fails, those views and zones can be
  half-configured, for instance a view might have an unfrozen resolver.
  Hence, leaving the exclusive mode before cleaning up those views ans
  zones will immediately called the previously enqueued callbacks and
  lead to this reconfiguration-failure crash stack:

  ``` isc_assertion_failed dns_resolver_createfetch do_keyfetch
  isc__async_cb ... uv_run loop_thread thread_body thread_run
  start_thread ... ```

  To avoid the problem, the views are now cleaned up before leaving the
  exclusive mode (which also clean up the zones and enqueued callbacks).

  As context, the bug was introduced by !10910 which moved the creation
  (not configuration) of the view outsides of the exclusive mode. This
  is a safe move (as at this point, the newly view are only known
  locally by `apply_configuration`) but the re-order was wrong regarding
  the point where the exclusive mode was ended (before the change, the
  exclusive mode as always ended before the new view are detached).
  :gl:`!11016`

- Check plugin config before registering. ``0e575d150fd``

  In `named_config_parsefile()`, when checking the validity of
  `named.conf`, the checking of plugin correctness was deliberately
  postponed until the plugin is loaded and registered. However, the
  checking was never actually done: the `plugin_register()`
  implementation was called, but `plugin_check()` was not.

  `ns_plugin_register()` (used by `named`) now calls the check function
  before the register function, and aborts if either one fails.
  `ns_plugin_check()` (used by `named-checkconf`) calls only the check
  function. :gl:`!11031`

- Clean up the dns_db API. ``29fc7850f1e``

  Some of the API calls in `dns_db` were obsolete, and have been
  removed. Others were more complicated than necessary, and have been
  refactored to simplify. :gl:`!10830`

- Do not inline dns_zone_gethooktable. ``e7156fe57ae``

  Since !10959 `dns_zone_gethooktable()` is only called once per query,
  and the suspicion (from perflab analysis) that this (simple, as just
  returning a pointer) call was slowing things down (perhaps because of
  code locality reasons?) doesn't matter anymore. So even if !10959
  inlined it, it shouldn't matter anymore. :gl:`!10962`

- Fix detection of whether node is active in find_wildcard()
  ``f717bad1086``

  The current code would fail during the write transaction.  The first
  header would not match the search->serial and the node might be
  incorrectly detected as inactive. :gl:`!10972`

- Hookasyncctx renaming. ``6ec65c3d1ad``

  The field `ns_hookasync_t` was initially named `hook_actx` and wrongly
  renamed `hook_aclctx` during a mass-renaming of various names for the
  config acl context into a consistent `aclctx` name (see !11003). Of
  course this is wrong as `ns_hookasync_t` has nothing to do with ACL
  but about _async_ context. This commit fixes the mistake by renaming
  this field `hookasyncctx` :gl:`!11021`

- Minimize zone hooktable lookups. ``89039e0d78e``

  Merging !10483 caused a performance regression because the zone
  hooktable had to be looked up every time a hook point was reached,
  even if no zone plugins were configured. We now look up the zone
  hooktable when a zone is attached to the query context, and keep a
  pointer to it until the qctx is destroyed. :gl:`!10959`


