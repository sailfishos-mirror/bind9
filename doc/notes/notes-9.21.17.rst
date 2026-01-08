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

Notes for BIND 9.21.17
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-13878] Fix incorrect length checks for BRID and HHIT
  records.

  Malformed BRID and HHIT records could trigger an assertion failure.
  This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

New Features
~~~~~~~~~~~~

- Add support for Extended DNS Error 9 (Missing DNSKEY)

  Extended DNS Error 9 (Missing DNSKEY) is now sent when a validating
  resolver attempts to validate a response but can't get the DNSKEY from
  the authoritative server of the zone, while the DS record is present
  in the parent zone. :gl:`#2715`

- Add support for Generalized DNS Notifications.

  A new configuration option, ``notify-cfg CDS``, is added to enable
  Generalized DNS Notifications for CDS and/or CDNSKEY RRset changes, as
  specified in RFC 9859. :gl:`#5611`

Feature Changes
~~~~~~~~~~~~~~~

- Add Extended DNS Error 13 (Cached Error) support.

  Extended DNS Error 13 (Cached Error) is now returned when the server
  answers a message from a cached SERVFAIL.

  See RFC 8914 section 4.14. :gl:`#1836`

- Add more information to the rndc recursing output about fetches.

  This adds more information about the active fetches for debugging and
  diagnostic purposes.

- Enforce bounds of multiple configuration options.

  The configuration options `edns-version`, `edns-udp-size`,
  `max-udp-size`, `no-cookie-udp-size` and `padding` now enforce
  boundaries. The configuration (including when using `named-checkconf`)
  now fails if those options are set out of range.

Bug Fixes
~~~~~~~~~

- Resolve "Inbound IXFR performance regression between 9.18.31 and
  9.20.9"

  This MR adds add some specialized logic to handle IXFR in qpzone,
  avoiding the need to have one qp transaction per rdataset.

  We do this in multiple steps:  - We extend dns_rdatacallbacks_t vtable
  to allow subtraction and resigning.  - We add a new set of api
  (begin|commit|abort)update to the dbmethods vtable. These API model an
  incremental update that can be aborted, and make diff apply use these
  functions instead of adding the rdatasets directly to the database.  -
  We add a specialization of dns_rdatacallbacks_t to qpzone that uses a
  single qp transaction for the entire IXFR.

  With this batch API, we see performance improvements over adding one
  rdataset at a time. :gl:`#5442`

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

- Adding NSEC3 opt-out records could leave invalid records in chain.

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671`

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


