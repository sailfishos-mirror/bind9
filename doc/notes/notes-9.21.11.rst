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

Notes for BIND 9.21.11
----------------------

New Features
~~~~~~~~~~~~

- Support for parsing DSYNC records has been added.

  These records are used for discovering the receiver endpoint for DNS
  notification messages. For more information, see
  `draft-ietf-dnsop-generalized-notify-09`_. :gl:`#5440`

.. _`draft-ietf-dnsop-generalized-notify-09`: https://datatracker.ietf.org/doc/draft-ietf-dnsop-generalized-notify/09/

Feature Changes
~~~~~~~~~~~~~~~

- Reword the ``shut down hung fetch while resolving`` message.

  The log message ``shut down hung fetch while resolving`` may be
  confusing,  because no detection of hung fetches actually takes place.
  Instead, the timer on the fetch context expires and the resolver
  gives up.

  The log message has been changed to actually indicate that, instead of the
  original cryptic message about hung fetch. :gl:`#3148`

- Plugin extension in plugin path is now optional.

  Plugin configuration no longer requires the library file extension, so
  it is now possible to invoke a plugin using the syntax ``plugin query
  "library"`` instead of ``plugin query "library.so"``. :gl:`#5377`

- Add deprecation warnings for RSASHA1, RSASHA1-NSEC3SHA1, and DS digest
  type 1.

  RSASHA1 and RSASHA1-NSEC-SHA1 DNSKEY algorithms have been deprecated
  by the IETF and should no longer be used for DNSSEC. DS digest type 1
  (SHA1) has also been deprecated in BIND 9. Validators are now expected to treat
  these algorithms and digest as unknown, resulting in some zones being
  treated as insecure when they were previously treated as secure.
  Warnings have been added to :iscman:`named` and tools when these algorithms and
  this digest are being used for signing.

  Zones signed with RSASHA1 or RSASHA1-NSEC-SHA1 should be migrated to a
  different DNSKEY algorithm.

  Zones with DS or CDS records with digest type 1 (SHA1) should be
  updated to use a different digest type (e.g. SHA256) and the digest
  type 1 records should be removed. :gl:`#5358`

Bug Fixes
~~~~~~~~~

- Stale RRsets in a CNAME chain were not always refreshed.

  Previously, with serve-stale enabled and a CNAME chain that contained a stale RRset,
  the refresh query didn't always properly refresh the stale RRsets.
  This has been fixed. :gl:`#5243`

- Add RPZ extended DNS error for zones with a CNAME override policy
  configured.

  Previously, when the zone was configured with a CNAME override policy, or the
  response policy zone contained a wildcard CNAME, the extended DNS error
  code was not added. This has been fixed. :gl:`#5342`

- Fix cross builds.

  Cross-compilation did not work even when the ``-Ddoc=disabled`` build
  option was passed to Meson, because the build targets used for
  generating documentation depended on a non-native executable. This
  has been fixed. :gl:`#5379`

- Fix :iscman:`named-makejournal` man page installation.

  The man page for :iscman:`named-makejournal` was erroneously not
  installed when building from a source tarball. This has been fixed.
  :gl:`#5379`

- Fix plugin loading.

  Loading plugins specified using just the shared library name (i.e.
  without using an absolute or relative path) did not work. This
  has been fixed. :gl:`#5379`

- Fix :iscman:`dig` issues.

  When used with the ``+keepopen`` option,
  :iscman:`dig` could terminate unexpectedly in rare situations.
  Additionally, :iscman:`dig` could hang and fail to shutdown properly
  when interrupted during a query. These have been fixed. :gl:`#5381`

- Log dropped or slipped responses in the ``query-errors`` category.

  Responses which were dropped or slipped because of Response Rate
  Limiting (RRL) were logged in the ``rate-limit`` category instead of the
  ``query-errors`` category, as documented in the ARM. This has been fixed.
  :gl:`#5388`

- :any:`synth-from-dnssec` was not working in some scenarios.

  Aggressive use of DNSSEC-Validated cache with NSEC was not working in
  scenarios when no parent NSEC was in cache.  This has been fixed.
  :gl:`#5422`

- Clean enough memory when adding new ADB names/entries under memory
  pressure.

  The ADB memory cleaning is opportunistic even when BIND is under memory
  pressure (in the overmem condition).  :iscman:`named` now ensures that the assigned memory
  limit is not exceeded by releasing twice the amount of memory
  allocated for each new ADB name/entry when under memory pressure.
  :gl:`!10637`

- Prevent spurious validation failures.

  Under rare circumstances, validation could fail if multiple clients
  simultaneously iterated the same set of DNSSEC signatures. This has
  been fixed. :gl:`#3014`


