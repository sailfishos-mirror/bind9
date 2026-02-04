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

Notes for BIND 9.21.18
----------------------

Feature Changes
~~~~~~~~~~~~~~~

- Update requirements for system test suite.

  Python 3.10 or newer is now required for running the system test
  suite. The required python packages and their version requirements are
  now tracked in `bin/tests/system/requirements.txt`.

  Support for pytest 9.0.0 has been added its minimum supported version
  has been raised to 7.0.0. The minimum supported dnspython version has
  been raised to 2.3.0. :gl:`#5690`  :gl:`#5614`

- Lowercase the NSEC next owner name when signing.

  When building the NSEC rdata, lowercase the next owner name before
  storing it in the Next Domain Name Field.

  Note that this is not required according to RFC 6840, but since there
  is inconsistency in the documents over time, having uppercase next
  owner names in the NSEC records may cause validation failures if
  validators are not following RFC 6840. :gl:`#5702`

- Enable minimal ANY answers by default.

  ANY queries are widely abused by attackers doing reflection attacks as
  they return the largest answers.  Enable minimal ANY answers by
  default to reduce the attack surface of the DNS servers. :gl:`#5723`

Bug Fixes
~~~~~~~~~

- Make catalog zone names and member zones' entry names
  case-insensitive.

  Previously, the catalog zone names and their member zones' entry names
  were unintentionally case-sensitive. This has been fixed. :gl:`#5693`

- Fix brid and hhit implementation.

  Fix bugs in BRID and HHIT implementation and enable the unit tests.
  :gl:`#5710`

- DSYNC record incorrectly used two octets for the Scheme Field.

  When creating the `DSYNC` record from a structure, `uint16_tobuffer`
  was used instead of `uint8_tobuffer` when adding the scheme, causing a
  `DSYNC` record that was one octet too long. This has been fixed.
  :gl:`#5711`

- Fix a possible issue with reponse policy zones and catalog zones.

  If a response policy zone (RPZ) or a catalog zone contained an
  `$INCLUDE` directive, then manually reloading that zone could fail to
  process the changes in the response policy or in the catalog,
  respectively. This has been fixed. :gl:`#5714`


