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

Notes for BIND 9.18.42
----------------------

Bug Fixes
~~~~~~~~~

- Skip unsupported algorithms when looking for signing key.

  A mix of supported and unsupported DNSSEC algorithms in the same zone
  could have caused validation failures. Ignore the DNSSEC keys with
  unsupported algorithm when looking for the signing keys. :gl:`#5622`


