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

Notes for BIND 9.18.48
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

- Fix a crash triggered by rndc modzone on zone from configuration file.

  Calling `rndc modzone` on a zone that was configured in the
  configuration file caused a crash. This has been fixed.

  ISC would like to thank Nathan Reilly for reporting this. :gl:`#5800`

- Fix a crash triggered by rndc modzone on zone that already existed in
  NZF file.

  Calling `rndc modzone` didn't work properly for a zone hat was
  configured in  the configuration file. It could crash if BIND 9 was
  built without LMDB or if  there was already an NZF file for the zone.
  In addition, `rndc modzone` failed in subsequent attempts. These
  problems are now fixed. :gl:`#5826`


