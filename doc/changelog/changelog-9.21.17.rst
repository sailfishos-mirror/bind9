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

BIND 9.21.17
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-13878] Fix incorrect length checks for BRID and HHIT
  records. ``7bf83f69a8``

  Malformed BRID and HHIT records could trigger an assertion failure.
  This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

New Features
~~~~~~~~~~~~

- Add support for Extended DNS Error 9 (Missing DNSKEY) ``fe456b47f9``

  Extended DNS Error 9 (Missing DNSKEY) is now sent when a validating
  resolver attempts to validate a response but can't get the DNSKEY from
  the authoritative server of the zone, while the DS record is present
  in the parent zone. :gl:`#2715` :gl:`!10296`

- Add support for Generalized DNS Notifications. ``9696da5f24``

  A new configuration option, ``notify-cfg CDS``, is added to enable
  Generalized DNS Notifications for CDS and/or CDNSKEY RRset changes, as
  specified in RFC 9859. :gl:`#5611` :gl:`!11315`

Feature Changes
~~~~~~~~~~~~~~~

- Add Extended DNS Error 13 (Cached Error) support. ``8055747146``

  Extended DNS Error 13 (Cached Error) is now returned when the server
  answers a message from a cached SERVFAIL.

  See RFC 8914 section 4.14. :gl:`#1836` :gl:`!11322`

- Support compilation with cmocka 2.0.0+ ``c49ee7907d``

  The `assert_in_range()` function was deprecated in favor of
  `assert_int_in_range()` and `assert_uint_in_range()`. Add
  compatibility shims for cmocka<2.0.0 and use the new functions.
  :gl:`#5699` :gl:`!11412`

- Add more information to the rndc recursing output about fetches.
  ``a3c703ac1c``

  This adds more information about the active fetches for debugging and
  diagnostic purposes. :gl:`!11305`

- Compact rdataset implementation for authoritative. ``22d49db2b0``

  This MR introduces a specialized rdataset implementation for
  authoritative workloads, which leads to substantial memory savings in
  our perflab tests. :gl:`!11269`

- Create list of dirty headers that needs cleaning. ``95a94668fc``

  Instead of just flagging the qpcache node to be dirty, add the headers
  to be cleaned to the dirty list and when cleaning the node, only walk
  through the dirty node, not all the headers in the node. :gl:`!11164`

- Enforce bounds of multiple configuration options. ``57ee4d1e1c``

  The configuration options `edns-version`, `edns-udp-size`,
  `max-udp-size`, `no-cookie-udp-size` and `padding` now enforce
  boundaries. The configuration (including when using `named-checkconf`)
  now fails if those options are set out of range. :gl:`!11248`

- Remove memory context form `cfg_obj_t` ``b97991463e``

  Removes the `cfg_obj_t` memory context pointer, as the parser always
  uses `isc_g_mctx`. This simplifies the parser API/configuration tree
  API (no need to pass the memory context); and the `cfg_obj_t` size
  goes down from 80 bytes to 72 bytes.

  While not directly related to the changes, also remove the
  `cfg_parser_t` `references` field as it is not used anymore (since the
  `cfg_obj_t` types doesn't reference it anymore). :gl:`!11199`

- Remove unused foundname parameter. ``2d72b48e62``

  The `foundname` parameter in `qp.c:dns_qp_lookup` was effectively used
  only in unit tests, as in every case the name is needed, it can be
  retrieved directly from the node pointer. It also required an
  inefficient implementation that extracted the name by converting it
  into a key and then immediately converting it back.

  This MR refactors `qp.c:dns_qp_lookup` not to have a foundname
  parameter, resulting in a 5% speedup in the handling of NXDOMAIN
  responses in perflab. :gl:`!11339`

- Shrunk cfgobj down from 48 bytes to 40 bytes. ``ca0dc621e4``

  Follow-up of 38ce2906 as the size of the `cfg_obj_t` can actually goes
  down to 40 bytes "for free", by using bitfields to only use 31 bits
  for the `line` field, so the remaining bit can be use to hold the
  `cloned` state without paying the extra 8 bytes padding. :gl:`!11334`

- Shrunk cfgobj down from 72 bytes to 48 bytes. ``38ce29066b``

  Make all non-scalar properties of `cfg_obj_t` allocated values, which
  ensures the union size is the width of one pointer. Also reorder the
  fields inside `cfg_obj_t` to avoid alignment padding that would
  increase the size. As a result, a `cfg_obj_t` instance is now 48 bytes
  on a 64-bit platform.

  Add a static assertion to avoid increasing the size of the struct by
  mistake.

  The function `parse_sockaddrsub` was taking advantage of the fact that
  both sockaddr and sockaddrtls were in the same position, and used to
  initialize the sockaddr field independently if this was a -tls one or
  not. This doesn't work anymore now that all fields are allocated, so
  it has been slightly rewritten to take both cases into account
  separately. :gl:`!11239`

Bug Fixes
~~~~~~~~~

- Resolve "Inbound IXFR performance regression between 9.18.31 and
  9.20.9" ``c47239985b``

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
  rdataset at a time. :gl:`#5442` :gl:`!11077`

- Make key rollovers more robust. ``42b0046d1e``

  A manual rollover when the zone is in an invalid DNSSEC state causes
  predecessor keys to be removed too quickly. Additional safeguards to
  prevent this have been added. DNSSEC records will not be removed from
  the zone until the underlying state machine has moved back into a
  valid DNSSEC state. :gl:`#5458` :gl:`!10813`

- Copy only raw data when we are copying dns_slab{header,vec}
  ``f5d6fd051f``

  Fix the data race between reading source slabheader in `makeslab()`
  and the heap (write) operation on the same header in the QPcache.
  :gl:`#5627` :gl:`!11375`

- Fix a catalog zones issue when a member zone could fail to load.
  ``8b78847b81``

  A catalog zone's member zone could fail to load in some rare cases,
  when the internally generated zone configuration string was exceeding
  512 bytes. That condition only was not enough for the issue to arise,
  but it was a necessary condition. This could happen, for example, if
  the catalog zone's default primary servers list contained a large
  number of items. This has been fixed. :gl:`#5658` :gl:`!11281`

- Adding NSEC3 opt-out records could leave invalid records in chain.
  ``064deef4a7``

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671` :gl:`!11328`

- Fix slow speed of NSEC3 optout large delegation zone signing.
  ``d67dcac70e``

  BIND 9.20 takes much more time signing a large delegation zone with
  NSEC3 optout compared to version 9.18. This has been restored.
  :gl:`#5672` :gl:`!11354`

- Missing unlock. ``5e486a7c0a``

  'kasp->lock' was not released before returning.  This could result in
  named locking up if 'dns_keymgr_status' fails when 'rndc dnssec
  -status' is called. :gl:`#5675` :gl:`!11338`

- Reconfigure NSEC3 opt-out zone to NSEC causes zone to be invalid.
  ``65592874bd``

  A zone that is signed with NSEC3, opt-out enabled, and then
  reconfigured to use NSEC, causes the zone to be published with missing
  NSEC records. This has been fixed. :gl:`#5679` :gl:`!11359`

- Unpack struct vecheader. ``7cbf5f652a``

  The bitset packing of the resign_lsb and heap_index in struct
  vecheader was causing a race condition, since both bindrdataset and
  heap operations tried to access the same byte (even though they are
  accessing different fields).      While heap operations are protected
  by the node lock of the header being inserted, they aren't protected
  by the node locks of the headers being displaced, leading to the race
  condition.      This MR fixes the issue by reverting the struct
  packing optimization. :gl:`#5688` :gl:`!11378`

- Dns_name_totext() can now resize dynamic buffers. ``c39e93b527``

  When `dns_name_totext()` is called with a dynamically allocated target
  buffer which is too small for the name, it will now resize the buffer
  instead of returning `ISC_R_NOSPACE`. :gl:`!11289`

- Fix a possible catalog zone issue during reconfiguration.
  ``9e806bd81f``

  The :iscman:`named` process could terminate unexpectedly during
  reconfiguration when a catalog zone update was taking place at the
  same time. This has been fixed. :gl:`!11366`

- Fix the charts in the statistics channel. ``4b4051b09b``

  The charts in the statistics channel could sometimes fail to render in
  the browser, and were completely disabled for Mozilla-based browsers
  for historical reasons. This has been fixed. :gl:`!11018`


