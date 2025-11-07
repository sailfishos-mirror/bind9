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

BIND 9.21.15
------------

New Features
~~~~~~~~~~~~

- New "rndc showconf" command. ``dad960025c2``

  The new `rndc showconf` command prints the running server
  configuration. There are three options:

  - `rndc showconf -user` displays the user configuration (i.e., the
    contents of `named.conf`).
  - `rndc showconf -builtin` displays the default settings, similar to
    `named -C`.
  - `rndc showconf -effective` displays the effective
    configuration. This is the merged combination of the `-user` and
    `-builtin` configurations. :gl:`#1075` :gl:`!11123`

- "named-checkconf -b" dumps the built-in configuration. ``ac2b36c4bfc``

  `named-checkconf` now supports the command line switch `-b`,  which
  prints the default built-in configuration used by `named`.      When
  `-b` is in use, other options are ignored. :gl:`#1326` :gl:`!11177`

- Add support for Extended DNS Error 24 (Invalid Data) ``4941d33a8ae``

  Extended DNS Error 24 (Invalid Data) is returned when the server
  cannot answer data for a zone it is configured for. This occurs
  typically when an authoritative server does not have loaded the DB of
  a configured zone, or a secondary server zone is expired.

  See RFC 8914 section 4.25. :gl:`#1836` :gl:`!11169`

- Named-checkconf -e prints the effective configuration. ``05c2ef2f77e``

  The new `named-checkconf -e` option prints the effective server
  configuration, including all the default settings, that would result
  from loading the specified configuration file into `named`.
  :gl:`#2798` :gl:`!11122`

- Introduce cfg_obj_clone to clone a config tree. ``d951cedd021``

  Introduce `cfg_obj_clone` which takes a `cfg_obj_t` node and clones
  it. it allocates a new node, copies its scalar values and recursively
  allocates child nodes, copying their scalar values as well and so on.
  Internally, a new method `cfg_copyfunc_t` copy is added in
  `cfg_rep_t`, which enables implementing a copy function specific for
  each representation type a node can hold.

  This is pre-require work for MR :gl:`!11121` :gl:`!11122` :gl:`!11123`
  :gl:`!11124`

- Run individual spatch form check-cocci.sh. ``a27275d2464``

  Add util/check-cocci.sh support for a command-line argument which is a
  path to a spatch file. Running `util/check-cocci.sh` runs all the
  spatch in `cocci` folder. Running `util/check-cocci.sh
  cocci/foo.spatch` only run the spatch `cocci/foo.spatch`.

  Any command line parameters after `--` are forwarded to `spatch`
  command, for instance:

  `util/check-cocci.sh -- --debug`

  `util/check-cocci.sh cocci/foo.spatch -- --debug`

  Will (1) run all spatch files in cocci/ with --debug spatch option and
  (2) run only `cocci/foo.spatch` with --debug options. :gl:`!11096`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the "tkey-domain" statement. ``b964d051057``

  The previously deprecated ``tkey-domain`` statement has now been
  removed. :gl:`#4204` :gl:`!10801`

- Remove the "tkey-gssapi-credential" statement. ``45b19a0655d``

  The previously deprecated ``tkey-gssapi-credential`` statement and all
  code related to it have now been removed. :gl:`#4204` :gl:`!10800`

- Remove "bindkeys-file" option. ``5b645cb2004``

  The `bindkeys-file` option was only used for testing purposes, and has
  now been replaced with a `-T bindkeys=<filename>` option for `named`.
  :gl:`!11081`

- Remove dns_zone_dump. ``07506035692``

  Zone API `dns_zone_dump` is dead code in 9.21 (and was also dead code
  at least in 9.20), removing it. :gl:`!11060`

Feature Changes
~~~~~~~~~~~~~~~

- Stop prettifying JSON statistics. ``90408b813dd``

  Passing the JSON_C_TO_STRING_PRETTY flag to
  json_object_to_json_string_ext() makes the latter produce prettified
  JSON output.  This results in a huge amount of redundant whitespace
  being inserted into each HTTP response (whitespace amounts to about
  40% of the entire JSON payload).

  The bandwidth cost can be amortized by enabling HTTP compression on
  the client side ("Accept-Encoding: deflate"), but that does not affect
  the size of data at rest.

  Use the JSON_C_TO_STRING_PLAIN flag instead of JSON_C_TO_STRING_PRETTY
  to minimize the size of JSON responses sent via the statistics
  channel. External tools should be used for prettifying JSON data.
  :gl:`#3304` :gl:`!10786`

- Fix assertion failure from arc4random_uniform with invalid limit.
  ``08ccc8bea81``

  When the arc4random_uniform() is called on NetBSD with upper_bound
  that makes no sense statistically (0 or 1), the call crashes the
  calling program.  Fix this by returning 0 when upper bound is < 2 as
  does Linux, FreeBSD and NetBSD.  (Hint: System CSPRNG should never
  crash.) :gl:`#5596` :gl:`!11147`

- Change the CONTRIBUTING to use Developer's Certificate of Origin 1.1.
  ``e7362cb5016``

  :gl:`!11108`

- Don't retain the default configuration tree. ``af0583fc604``

  The built-in configuration is actually used in two cases: first, when
  the server is loaded (or reloaded), and second when `rndc showconf
  -builtin` is called.

  Considering the parsing of the builtin configuration is quick and does
  not occur during exclusive mode, but the configuration tree takes
  considerable memory space, the built-in configuration is no longer
  kept in memory once it has been used; instead it is re-parsed on
  demand. :gl:`!11187`

- Load the effective configuration. ``5ba7df7f0eb``

  The configuration mechanism for `named` has been changed: instead of
  loading the user configuration from `named.conf` and then,
  statement-by-statement, picking values from there or from the built-in
  default configuration, we now merge the user configuration and the
  default configuration together, then pass the resulting "effective
  configuration" to `apply_configuration()`.

  The new `cfg_effective_config()` function takes a user configuration
  tree and the built-in default configuration tree, and returns a new
  effective configuration tree. It works by cloning the user
  configuration (see !11124) into the effective tree, then walking
  through the clauses defined in it. If a clause is not in the user
  config but is present in the defaults, the default version is cloned
  and attached to the effective tree. If a clause is in both trees, then
  depending on the statement semantics, either the user configuration
  overrides the default, or the two are merged. Because these semantics
  are now handled before `apply_configuration()` runs, that function has
  been substantially simplified.

  Future MRs will enable the effective configuration to be printed,
  either by `rndc` (!11123) or `named-checkconf` (!11122). The default
  configuration has been moved to an include file which is accessible to
  both `named` and `named-checkconf`. :gl:`!11121`

- Mem: checkfree assertion after debug list dump. ``54d7198a1a7``

  When a memory context is destroyed, if the `checkfree` property is
  set, the program assert there is no remaining allocation. If there are
  and assertions are enabled, the program immediately stops.

  However, if memory trace/record debug is enabled, the dump of
  outstanding allocation won't be printed as it is done after the no
  remaining allocation assertion check.

  This moves the no remaining allocation assertion check after the dump
  of outstanding allocations, so it is still possible to figure out
  what's still allocated by this memory context. :gl:`!11110`

- Minimal Meson version required is 1.3.0. ``6badc6e9396``

  The minimal required Meson version is 1.3.0.

  Where distribution repositories don't provide Meson 1.3.0 or newer,
  Meson from PyPI may be used instead. :gl:`!10997`

- Refactor notify code. ``0dd1da79590``

  Move notify code in separate source files in preparation for support
  of generalized DNS notifications. :gl:`!11146`

- Refactoring in lib/isccfg. ``3d0ddb5f9ba``

  `cfg_obj_t` objects no longer depend on the `cfg_parser_t` life-cycle;
  they can now persist until the last reference is detached. The `file`
  field, which was previously a pointer to memory allocated in the
  parser, is now a pointer to a subsidiary `cfg_obj_t` of type string.
  The API calls for creating and detaching these objects have been
  simplified accordingly.

  Since `cfg_obj_t` is now long-lived, a zone can hold a reference to
  its own configuration data, making it possible to use `rndc showzone`
  even if `allow-new-zones` is disabled.

  Several API calls related to the parser have been removed or hidden.
  The `cfg_parse_file()` and `cfg_parse_buffer()` functions now
  internally create and destroy their own parsers, eliminating the need
  for the caller to do so.

  Most of these changes are intended to simplify dumping of running
  configuration data in a future commit. :gl:`!11132`

Bug Fixes
~~~~~~~~~

- Report when a zone reload is already in progress. ``0caba8e9ce8``

  If a zone reload was already in progress when `rndc reload <zone>` was
  run, the message returned was "zone reload queued", which was
  technically correct, but it was identical to the message returned when
  a reload was not in progress. Consequently, a user could issue two
  reload commands without realizing that only one reload had actually
  taken place. This has been addressed by changing the message returned
  to "zone reload was already queued". :gl:`#5140` :gl:`!10849`

- Fix dnssec-keygen key collision checking for KEY rrtype keys.
  ``8c2285fca63``

  The :iscman:`dnssec-keygen` utility program failed to detect possible
  Key ID collisions with the existing keys generated using the
  non-default ``-T KEY`` option (e.g. for ``SIG(0)``). This has been
  fixed. :gl:`#5506` :gl:`!11047`

- Fix shutdown INSIST in dns_dispatchmgr_getblackhole. ``8c009d31ae4``

  Previously, `named` could trigger an assertion in
  `dns_dispatchmgr_getblackhole` while shutting down. This has been
  fixed. :gl:`#5525` :gl:`!11131`

- Dnssec-verify now uses exit code 1 when failing due to illegal
  options. ``5bb48740571``

  Previously, dnssec-verify exited with code 0 if the options could not
  be parsed. This has been fixed. :gl:`#5574` :gl:`!11106`

- Ensure correct result from check_signer() ``bac5ef96820``

  It was possible for the result to be overwritten after a validation
  failure, causing `check_signer()` to return success when it should
  have returned an error. :gl:`#5575` :gl:`!11103`

- Make libcap mandatory on Linux again. ``fb2b56a8880``

  When refactoring the BIND 9.21 build system to Meson, libcap was
  unintentionally made optional on Linux. :gl:`#5590` :gl:`!11136`

- Only unlink from SIEVE LRU if it is still linked. ``28926f210e1``

  Under the overmem conditions, the header could get unlinked from the
  SIEVE LRU using a different path.  This could lead to double-unlink
  which causes assertion failure.  Add a guard to ISC_SIEVE_UNLINK() to
  unlink only still linked headers. :gl:`#5606` :gl:`!11166`

- Prevent assertion failures of dig when server is specified before the
  -b option. ``3ee98de6b65``

  Previously, :iscman:`dig` could exit with an assertion failure when
  the server was specified before the :option:`dig -b` option. This has
  been fixed. :gl:`#5609` :gl:`!11183`

- Skip unsupported algorithms when looking for signing key.
  ``7ca069e28fa``

  A mix of supported and unsupported DNSSEC algorithms in the same zone
  could have caused validation failures. Ignore the DNSSEC keys with
  unsupported algorithm when looking for the signing keys. :gl:`#5622`
  :gl:`!11208`

- Fix configuration bugs involving global defaults. ``539cda62a74``

  The configuration code for the `max-cache-size`, `dnssec-validation`,
  and `response-padding` options were unnecessarily complicated, and in
  the case of `max-cache-size`, buggy. These have been fixed. The
  `optionmaps` variable in `configure_view()` is no longer needed and
  has been removed. :gl:`!11165`

- Fix fuzzing builds. ``365f9f04d66``

  Previously fuzzing builds were broken due to some typos in the
  `meson.build`. :gl:`!11052`

- Fix parser test (missing string termination) ``6af8f8ba5e6``

  Compare only the dumped configuration as the `cfg_printx` does not
  NULL-terminate the configuration strings. :gl:`!11215`

- Reduce the size of cfg_obj_t. ``6451b08f470``

  Instead of having `isc_sockaddr`, `isc_netaddr`, and `isccfg_duration`
  members in the `cfg_obj->value` union, we now just keep pointers to
  them, and allocate memory when parsing these types. This reduces the
  size of `cfg_obj_t` from 112 bytes to 72. :gl:`!11186`

- Remove sun_path field from isc_netaddr. ``89df7068741``

  The `sun_path` field is not used anymore, and consumes over a hundred
  bytes for every `isc_netaddr_t` object. Remove it.

  As `isc_netaddr_t` is used in `cfg_obj_t`, in some huge configuration
  trees (e.g., a million zones), the gain is almost 1GB of resident
  memory. :gl:`!11184`

- Remove unused dns_zone_getnotifyacl() function. ``9215ae3c7ee``

  Deals with Coverity issues:

  - CID 638286: Concurrent data access violations (MISSING_LOCK).
  - CID 638287: Concurrent data access
    violations (MISSING_LOCK). :gl:`!11200`

- Restore reuseport to yes by default on supported platforms.
  ``056a32798c2``

  Changes introduced by 72862c2a moved the default configuration from
  within `bin/named` to a central place `bin/includes`.

  The default configuration is conditioned by several compile-time
  macro. While for most of them it's fine because they are defined in
  the global `config.h` file included by default to all binaries (by
  Meson), one specific is not defined here. `HAVE_SO_REUSEPORT_LB` was
  defined in `lib/isc/include/isc/netmgr.h` which is of course not
  included in `bin/includes/defaultconfig.h`.

  As a result, reuseport was disabled for all platform by default, even
  the supported ones. This fixes the problem by checking if reuseport is
  available on the platform from Meson `config.h` generation directly,
  which makes `HAVE_SO_REUSEPORT_LB` available everywhere. :gl:`!11180`

- Save userconfig as text instead of a cfg_obj tree. ``9521f231694``

  Once the user configuration has been merged into the effective
  configuration, it no longer needs to be accessed as a configuration
  tree, but we still want to be able to show it with `rndc showconf
  -user`.

  Because the recursive strucure of `cfg_obj` objects is fairly large,
  the canonical text form is a fraction of the size of the configuration
  tree, so we now save it in that form instead. :gl:`!11185`

- Skip buffer allocations if not logging. ``a8f0898d2dc``

  Currently, during IXFR we allocate a 2KB buffer for IXFR change
  logging regardless of the log level. This commit introduces an early
  check on the log level in dns_diff_print to avoid this.

  Results in a speedup from 28% in the test case from issue #5442.
  :gl:`!11178`


