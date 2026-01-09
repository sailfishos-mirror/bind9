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

Notes for BIND 9.20.18
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-13878] Fix incorrect length checks for BRID and HHIT
  records.

  Malformed BRID and HHIT records could trigger an assertion failure.
  This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

Feature Changes
~~~~~~~~~~~~~~~

- Add more information to the rndc recursing output about fetches.

  This adds more information about the active fetches for debugging and
  diagnostic purposes.

Bug Fixes
~~~~~~~~~

- Make key rollovers more robust.

  A manual rollover when the zone is in an invalid DNSSEC state causes
  predecessor keys to be removed too quickly. Additional safeguards to
  prevent this have been added. DNSSEC records will not be removed from
  the zone until the underlying state machine has moved back into a
  valid DNSSEC state. :gl:`#5458`

- Fix a catalog zones issue when a member zone could fail to load.

  A catalog zone's member zone could fail to load in some rare cases,
  when the internally generated zone configuration string was exceeding
  512 bytes. That condition only was not enough for the issue to arise,
  but it was a necessary condition. This could happen, for example, if
  the catalog zone's default primary servers list contained a large
  number of items. This has been fixed. :gl:`#5658`

- Allow glue in delegations with QTYPE=ANY.

  When a query for type ANY triggered a delegation response, all
  additional data was omitted from the response, including mandatory
  glue. This has been corrected. :gl:`#5659`

- Fix slow speed of NSEC3 optout large delegation zone signing.

  BIND 9.20 takes much more time signing a large delegation zone with
  NSEC3 optout compared to version 9.18. This has been restored.
  :gl:`#5672`

- Reconfigure NSEC3 opt-out zone to NSEC causes zone to be invalid.

  A zone that is signed with NSEC3, opt-out enabled, and then
  reconfigured to use NSEC, causes the zone to be published with missing
  NSEC records. This has been fixed. :gl:`#5679`

- Fix a possible catalog zone issue during reconfiguration.

  The :iscman:`named` process could terminate unexpectedly during
  reconfiguration when a catalog zone update was taking place at the
  same time. This has been fixed.

- Fix the charts in the statistics channel.

  The charts in the statistics channel could sometimes fail to render in
  the browser, and were completely disabled for Mozilla-based browsers
  for historical reasons. This has been fixed.


