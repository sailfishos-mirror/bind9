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

Notes for BIND 9.21.21
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix crash when reconfiguring zone update policy during active updates.

  We fixed a crash that could occur when running :option:`rndc reconfig`
  to change a zone's update policy (e.g., from :any:`allow-update` to
  :any:`update-policy`) while DNS UPDATE requests were being processed
  for that zone.

  ISC would like to thank Vitaly Simonovich for bringing this issue to
  our attention. :gl:`#5817`

New Features
~~~~~~~~~~~~

- Add switch to disable cookie checking in :iscman:`delv`.

  This adds the ``+[no]cookie`` switch to :iscman:`delv` to control
  whether DNS COOKIE options are included in requests. The default is to
  send DNS COOKIE options. :gl:`#5825`

Removed Features
~~~~~~~~~~~~~~~~

- Remove ``-C`` option from :iscman:`dnssec-keygen` and
  :iscman:`dnssec-keyfromlabel`.

  The ``-C`` option, introduced in BIND 9.7, caused a
  backward-compatible key to be generated, using private key format
  version 1.2, omitting the creation date and other timing metadata.
  This made it possible to generate keys that could be loaded by older
  versions of BIND 9.

  Those older versions having reached end-of-life many years ago, the
  option has now been removed, along with the :iscman:`dnssec-settime`
  ``-f`` option, which caused old-style keys to be upgraded.
  :gl:`!11446`

- Remove NZF file support in favor of NZD.

  The NZF (New Zone File) backend for storing :option:`rndc addzone`
  configurations has been removed; LMDB-based NZD (New Zone
  Database) is now the only storage backend and LMDB is now
  a required build dependency.

  Existing NZF files are automatically migrated to NZD on startup, so no
  manual intervention is required when upgrading. :gl:`!11688`

Feature Changes
~~~~~~~~~~~~~~~

- Parent-centric resolver.

  The :iscman:`named` resolver now uses a separate "delegation database"
  to store zone referral data, instead of the DNS cache. This new
  database holds the NS RRset on the parent side of a zone cut, as well
  as necessary glue records that were included in the referral.  The NS
  RRset from the child side is cached in the DNS cache and is not used
  for recursion. :gl:`#3311`

- Switch to LRU-only cache eviction, enforce minimum cache size.

  Busy resolvers now gradually fill to the configured
  :any:`max-cache-size` before entries start being evicted. Previously,
  expired records were proactively removed based on their TTL, which
  kept memory usage below the configured limit but added overhead.
  Cache eviction now relies solely on the SIEVE-LRU mechanism, which has
  matured to the point where TTL-based cleaning is no longer necessary.

  Setting :any:`max-cache-size` to ``unlimited`` or ``0`` is no longer
  supported and falls back to the default (90% of physical memory).
  :gl:`!11459`

Bug Fixes
~~~~~~~~~

- Fix intermittent :iscman:`named` crashes during asynchronous zone
  operations.

  Asynchronous zone loading and dumping operations occasionally
  dispatched tasks to the wrong internal event loop. This threading
  violation triggered internal safety assertions that abruptly
  terminated :iscman:`named`. Strict loop affinity is now enforced for
  these tasks, ensuring they execute on their designated threads and
  preventing the crashes. :gl:`#4882`

- Count temporal problems with DNSSEC validation as attempts.

  After the KeyTrap vulnerability :cve:`2023-50387`, any temporal
  DNSSEC errors were originally hard errors that caused validation
  failures, even if the records had another valid signature. This has
  been changed; RRSIGs outside of the inception and expiration time are
  not counted as hard errors.  However, these errors were not even
  counted as validation attempts, so an excessive number of expired
  RRSIGs would cause some non-cryptographic extra work for the
  validator. This has been fixed and the temporal errors are now
  correctly counted as validation attempts. :gl:`#5760`

- Fix a possible deadlock in RPZ processing.

  The :iscman:`named` process could hang when processing a maliciously
  crafted update for a response policy zone (RPZ). This has been fixed.
  :gl:`#5775`

- Fix :any:`update-policy` per-type max quota bypass via crafted
  UPDATE messages.

  An authenticated DDNS client could bypass :any:`update-policy`
  per-type record limits (e.g. ``TXT(3)``) by including padding records
  in the UPDATE message that were silently skipped during processing.
  Each skipped record shifted an internal counter, causing subsequent
  records to be checked against the wrong quota — potentially reading an
  unlimited (0) entry instead of the configured maximum.

  This allowed a client with valid TSIG credentials to add an arbitrary
  number of records beyond the configured limit across repeated UPDATE
  messages, up to the :any:`max-records-per-type` limit. :gl:`#5799`

- Fix a crash triggered by :option:`rndc modzone` on a zone from a
  configuration file.

  Calling :option:`rndc modzone` on a zone that was configured in the
  configuration file caused a crash. This has been fixed. :gl:`#5800`

- Fix the processing of empty catalog zone ACLs.

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog zone ACL in an APL resource record that was
  completely empty. This has been fixed. :gl:`#5801`

- Fix potential resource leak during resolver error handling.

  Under specific error conditions during query processing, resources
  were not being properly released, which could eventually lead to
  unnecessary memory consumption for the server. A potential resource
  leak in the resolver has been fixed. :gl:`!11658`
