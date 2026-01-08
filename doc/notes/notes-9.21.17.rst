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

- Fix incorrect length checks for BRID and HHIT records.
  :cve:`2025-13878`

  Malformed BRID and HHIT records could trigger an assertion
  failure. This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

New Features
~~~~~~~~~~~~

- Add support for Extended DNS Error 9 (Missing DNSKEY).

  If the DS record is present in the parent zone and a validating
  resolver attempts to validate a response, but is unable to get the
  DNSKEY from the authoritative server of the zone, Extended DNS
  Error 9 (Missing DNSKEY) is now sent. :gl:`#2715`

- Add support for Extended DNS Error 13 (Cached Error).

  Extended DNS Error 13 (Cached Error) is now returned when the server
  answers a message from a cached SERVFAIL.

  See :rfc:`8914` section 4.14. :gl:`#1836`

- Add support for Generalized DNS Notifications.

  A new configuration option, :any:`notify-cfg CDS <notify-cfg>`, is
  added to enable Generalized DNS Notifications for CDS and/or
  CDNSKEY RRset changes, as specified in :rfc:`9859`. :gl:`#5611`

Feature Changes
~~~~~~~~~~~~~~~

- Add more information to the :option:`rndc recursing` output about
  fetches.

  This adds more information about active fetches, for debugging and
  diagnostic purposes. :gl:`!11305`

- Enforce bounds of multiple configuration options.

  The configuration options :any:`edns-version`, :any:`edns-udp-size`,
  :any:`max-udp-size`, :any:`nocookie-udp-size`, and :any:`padding` now
  enforce boundaries. The configuration (including when using
  :iscman:`named-checkconf`) now fails if those options are set out of
  range. :gl:`!11248`

Bug Fixes
~~~~~~~~~

- Fix inbound IXFR performance regression.

  Very large inbound IXFR transfers were much slower than those in BIND
  9.18. The performance was improved by adding specialized logic to
  handle IXFR transfers. :gl:`#5442`

- Make DNSSEC key rollovers more robust.

  A manual rollover when the zone was in an invalid DNSSEC state caused
  predecessor keys to be removed too quickly. Additional safeguards to
  prevent this have been added: DNSSEC records are not removed from the
  zone until the underlying state machine has moved back into a valid
  DNSSEC state. :gl:`#5458`

- Fix a catalog zone issue, where member zones could fail to load.

  A catalog zone member zone could fail to load in some rare cases, when
  the internally generated zone configuration string exceeded 512 bytes.
  That condition by itself was not enough for the issue to arise, but it
  was necessary. This could happen if, for example, the catalog zone's
  default primary servers list contained a large number of items. This
  has been fixed. :gl:`#5658`

- Fix slow speed when signing a large delegation zone with NSEC3
  opt-out.

  BIND 9.20+ took much longer signing a large delegation zone with NSEC3
  opt-out compared to version 9.18. This has been fixed. :gl:`#5672`

- Reconfiguring an NSEC3 opt-out zone to NSEC caused the zone to be
  invalid.

  A zone that was signed with NSEC3, had opt-out enabled, and was then
  reconfigured to use NSEC, was published with missing NSEC records.
  This has been fixed. :gl:`#5679`

- Fix a possible catalog zone issue during reconfiguration.

  The :iscman:`named` process could terminate unexpectedly during
  reconfiguration when a catalog zone update was taking place at the
  same time. This has been fixed. :gl:`!11366`

- Fix the charts in the statistics channel.

  The charts in the statistics channel could sometimes fail to render in
  the browser and were completely disabled for Mozilla-based browsers,
  for historical reasons. This has been fixed. :gl:`!11018`


