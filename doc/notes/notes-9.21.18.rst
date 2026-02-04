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

- Enable minimal ANY answers by default.

  ANY queries are widely abused by attackers in reflection attacks, as
  they result in large answers. The :namedconf:ref:`minimal-any` feature
  is now enabled by default to reduce the attack surface. :gl:`#5723`

- Lowercase the NSEC Next Domain Name field.

  When building an NSEC record, the next owner name is now converted to lowercase
  before storing it in the Next Domain Name field.

  This is not required according to :rfc:`6840#section-5.1`, but since
  inconsistencies have been introduced to the specification over time, having
  "next owner" names in only lowercase in the NSEC records improves compatibility with
  software that does not follow the latest version of the DNSSEC
  specification. :gl:`#5702`

- Update requirements for system test suite.

  Python 3.10 or newer is now required for running the system test suite. The
  required Python packages and their version requirements are now tracked in the
  file `bin/tests/system/requirements.txt`. :gl:`#5690` :gl:`#5614`


Bug Fixes
~~~~~~~~~

- Make catalog zone names and member zones' entry names
  case-insensitive. :gl:`#5693`

- Fix implementation of BRID and HHIT record types. :gl:`#5710`

- Fix implementation of DSYNC record type. :gl:`#5711`

- Fix response policy and catalog zones to work with `$INCLUDE` directive.

  Reloading a RPZ or a catalog zone could have failed when `$INCLUDE` was in use. :gl:`#5714`
