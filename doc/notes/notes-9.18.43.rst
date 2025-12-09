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

Notes for BIND 9.18.43
----------------------

Bug Fixes
~~~~~~~~~

- AMTRELAY type 0 presentation format handling was wrong.

  RFC 8777 specifies a placeholder value of "." for the gateway field
  when the gateway type is 0 (no gateway).  This was not being checked
  for nor emitted when displaying the record. This has been corrected.

  Instances of this record will need the placeholder period added to
  them when upgrading. :gl:`#5639`

- Adding NSEC3 opt-out records could leave invalid records in chain.

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671`


