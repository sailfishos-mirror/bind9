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

BIND 9.18.44
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-13878] Fix incorrect length checks for BRID and HHIT
  records. ``d556bde123``

  Malformed BRID and HHIT records could trigger an assertion failure.
  This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

Feature Changes
~~~~~~~~~~~~~~~

- Support compilation with cmocka 2.0.0+ ``184df12da4``

  The `assert_in_range()` function was deprecated in favor of
  `assert_int_in_range()` and `assert_uint_in_range()`. Add
  compatibility shims for cmocka<2.0.0 and use the new functions.
  :gl:`#5699` :gl:`!11438`

Bug Fixes
~~~~~~~~~

- Allow glue in delegations with QTYPE=ANY. ``21ad0222b7``

  When a query for type ANY triggered a delegation response, all
  additional data was omitted from the response, including mandatory
  glue. This has been corrected. :gl:`#5659` :gl:`!11368`

- Reconfigure NSEC3 opt-out zone to NSEC causes zone to be invalid.
  ``53cfe984e3``

  A zone that is signed with NSEC3, opt-out enabled, and then
  reconfigured to use NSEC, causes the zone to be published with missing
  NSEC records. This has been fixed. :gl:`#5679` :gl:`!11402`


