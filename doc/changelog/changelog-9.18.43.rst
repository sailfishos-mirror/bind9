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

BIND 9.18.43
------------

New Features
~~~~~~~~~~~~

- Add spatch to detect implicit bool/int/result cast. ``cce6c2dd0c``

  Detection of implicit cast from a boolean into an int, or an
  isc_result_t into a boolean (either in an assignement or return
  position).

  If such pattern is found, a warning comment is added into the code
  (and the CI will fails) so the error can be spotted and manually
  fixed. :gl:`!11238`

Bug Fixes
~~~~~~~~~

- AMTRELAY type 0 presentation format handling was wrong. ``e5025baf93``

  RFC 8777 specifies a placeholder value of "." for the gateway field
  when the gateway type is 0 (no gateway).  This was not being checked
  for nor emitted when displaying the record. This has been corrected.

  Instances of this record will need the placeholder period added to
  them when upgrading. :gl:`#5639` :gl:`!11256`

- Adding NSEC3 opt-out records could leave invalid records in chain.
  ``335be0e079``

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671` :gl:`!11341`

- Standardize CHECK and RETERR macros. ``83163f39d5``

  previously, there were over 40 separate definitions of CHECK macros,
  of which most used "goto cleanup", and the rest "goto failure" or
  "goto out". there were another 10 definitions of RETERR, of which most
  were identical to CHECK, but some simply returned a result code
  instead of jumping to a cleanup label.

  this has now been standardized throughout the code base: RETERR is for
  returning an error code in the case of an error, and CHECK is for
  jumping to a cleanup tag, which is now always called "cleanup". both
  macros are defined in isc/util.h. :gl:`!11080`


