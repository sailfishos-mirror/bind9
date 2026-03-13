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

Notes for BIND 9.18.47
----------------------

Security Fixes
~~~~~~~~~~~~~~

- Fix unbounded NSEC3 iterations when validating referrals to unsigned
  delegations. :cve:`2026-1519`

  DNSSEC-signed zones may contain high iteration-count NSEC3 records,
  which prove that certain delegations are insecure. Previously, a
  validating resolver encountering such a delegation processed these
  iterations up to the number given, which could be a maximum of 65,535.
  This has been addressed by introducing a processing limit, set at 150.
  Now, if such an NSEC3 record is encountered, the delegation will be
  treated as insecure.

  ISC would like to thank Samy Medjahed/Ap4sh for bringing this
  vulnerability to our attention. :gl:`#5708`
