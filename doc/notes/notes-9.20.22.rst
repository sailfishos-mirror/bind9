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

Notes for BIND 9.20.22
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix crash when reconfiguring zone update policy during active updates.

  Fixed a crash that could occur when running rndc reconfig to change a
  zone's update policy (e.g., from allow-update to update-policy) while
  DNS UPDATE requests were being processed for that zone.

  ISC would like to thank Vitaly Simonovich for bringing this issue to
  our attention. :gl:`#5817`

Bug Fixes
~~~~~~~~~

- Fix intermittent named crashes during asynchronous zone operations.

  Asynchronous zone loading and dumping operations occasionally
  dispatched tasks to the wrong internal event loop. This threading
  violation triggered internal safety assertions that abruptly
  terminated named. Strict loop affinity is now enforced for these
  tasks, ensuring they execute on their designated threads and
  preventing the crashes. :gl:`#4882`

- Fix NTA (Negative Trust Anchor) expiration issue.

  When a configured NTA for a name expired, any possibly cached data for
  the name (with "insecure" DNSSEC validation result) was not flushed
  from the resolver's cache. This has been fixed. :gl:`#5747`

- Count temporal problems with DNSSEC validation as attempts.

  After KeyTrap, the temporal DNSSEC were originally hard errors that
  caused validation failures even if the records had another valid
  signature.  This has been changed and the RRSIGs outside of the
  inception and expiration time are not counted as hard errors.
  However, these errors are not even counted as validation attempts, so
  excessive number of expired RRSIGs would cause some non-cryptograhic
  extra work for the validator.  This has been fixed and the temporal
  errors are correctly counted as validation attempts. :gl:`#5760`

- Fix a possible deadlock in RPZ processing.

  The :iscman:`named` process could hang when processing a maliciously
  crafted update for a response policy zone (RPZ). This has been fixed.
  :gl:`#5775`

- Fix a crash triggered by rndc modzone on zone from configuration file.

  Calling `rndc modzone` on a zone that was configured in the
  configuration file caused a crash. This has been fixed.

  ISC would like to thank Nathan Reilly for reporting this. :gl:`#5800`

- Fix the processing of empty catalog zone ACLs.

  The :iscman:`named` process could terminate unexpectedly when
  processing a catalog zone ACL in an APL resource record that was
  completely empty. This has been fixed. :gl:`#5801`

- Fix a crash triggered by rndc modzone on zone that already existed in
  NZF file.

  Calling `rndc modzone` didn't work properly for a zone hat was
  configured in  the configuration file. It could crash if BIND 9 was
  built without LMDB or if  there was already an NZF file for the zone.
  In addition, `rndc modzone` failed in subsequent attempts. These
  problems are now fixed. :gl:`#5826`

- Fix potential resource during resolver error handling.

  Under specific error conditions during query processing, resources
  were not being properly released, which could eventually lead to
  unnecessary memory consumption for the server.  The a potential
  resource leak in the resolver has been fixed.


