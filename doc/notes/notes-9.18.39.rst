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

Notes for BIND 9.18.39
----------------------

New Features
~~~~~~~~~~~~

- Support for parsing the DSYNC record has been added.

  :gl:`#5440`

Feature Changes
~~~~~~~~~~~~~~~

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

- Clean enough memory when adding new ADB names/entries under memory
  pressure.

  The ADB memory cleaning is opportunistic even when BIND is under memory
  pressure (in the overmem condition).  The opportunistic LRU
  cleaning and overmem cleaning have been split, and the overmem cleaning always
  cleans up double of the newly allocated adbname/adbentry to ensure we
  never allocate more memory than the assigned limit.  :gl:`!10637`

- Rescan the interfaces again when reconfiguring the server.

  Previously on FreeBSD, the server did not listen on the configured ``localhost``
  interfaces immediately, but only after the ``interface-interval`` period
  had passed. After an earlier fix, the server would listen on the ``localhost`` after
  60 minutes.

  Now, the interfaces are rescanned immediately after configuring the
  ``interface-interval`` value and begin listening on the ``localhost``
  interface immediately. :gl:`!10758`


