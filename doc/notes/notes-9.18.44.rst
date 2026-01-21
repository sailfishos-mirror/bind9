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

Notes for BIND 9.18.44
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix incorrect length checks for BRID and HHIT records.
  :cve:`2025-13878`

  Malformed BRID and HHIT records could trigger an assertion
  failure. This has been fixed.

  ISC would like to thank Vlatko Kosturjak from Marlink Cyber for
  bringing this vulnerability to our attention. :gl:`#5616`

Bug Fixes
~~~~~~~~~

- Allow glue in delegations with QTYPE=ANY.

  When a query for type ANY triggered a delegation response, all
  additional data was omitted from the response, including mandatory
  glue. This has been fixed. :gl:`#5659`

- Reconfiguring an NSEC3 opt-out zone to NSEC caused the zone to be
  invalid.

  A zone that was signed with NSEC3, had opt-out enabled, and was then
  reconfigured to use NSEC, was published with missing NSEC records.
  This has been fixed. :gl:`#5679`


