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

Notes for BIND 9.21.20
----------------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2026-1519] Fix unbounded NSEC3 iterations when validating
  referrals to unsigned delegations.

  DNSSEC-signed zones may contain high iteration-count NSEC3 records,
  which prove that certain delegations are insecure. Previously, a
  validating resolver encountering such a delegation processed these
  iterations up to the number given, which could be a maximum of 65,535.
  This has been addressed by introducing a processing limit, set at 50.
  Now, if such an NSEC3 record is encountered, the delegation will be
  treated as insecure.

  ISC would like to thank Samy Medjahed/Ap4sh for bringing this
  vulnerability to our attention. :gl:`#5708`

- [CVE-2026-3104] Fix memory leaks in code preparing DNSSEC proofs of
  non-existence.

  An attacker controlling a DNSSEC-signed zone could trigger a memory
  leak in the logic preparing DNSSEC proofs of non-existence, by
  creating more than :any:`max-records-per-type` RRSIGs for NSEC
  records. These memory leaks have been fixed.

  ISC would like to thank Vitaly Simonovich for bringing this
  vulnerability to our attention. :gl:`#5742`

- [CVE-2026-3119] Prevent a crash in code processing queries containing
  a TKEY record.

  The :iscman:`named` process could terminate unexpectedly when
  processing a correctly signed query containing a TKEY record. This has
  been fixed.

  ISC would like to thank Vitaly Simonovich for bringing this
  vulnerability to our attention. :gl:`#5748`

- [CVE-2026-3591] Fix a stack use-after-return flaw in SIG(0) handling
  code.

  A stack use-after-return flaw in SIG(0) handling code could enable ACL
  bypass and/or assertion failures in certain circumstances. This flaw
  has been fixed.

  ISC would like to thank Mcsky23 for bringing this vulnerability to our
  attention. :gl:`#5754`

New Features
~~~~~~~~~~~~

- Provide response round-trip time (RTT) counters via statistics
  channel.

  Previously, :iscman:`named` provided RTT counters for outgoing queries
  performed by itself during name resolutions. Now this has been
  improved to provide more granular counters (histogram), and to also
  provide RTT counters for the incoming queries. :gl:`#5279`

Feature Changes
~~~~~~~~~~~~~~~

- Introduce max-delegation-servers configuration option.

  Make the maximum number of processed delegation nameservers
  configurable via the new 'max-delegation-servers' option (default:
  13), replacing the hardcoded NS_PROCESSING_LIMIT (20).

  The default is reduced to 13 to precisely match the maximum number of
  root servers that can fit into a classic 512-byte UDP payload.  This
  provides a natural, historically sound cap that mitigates resource
  exhaustion and amplification attacks from artificially inflated or
  misconfigured delegations.

  The configuration option is strictly bounded between 1 and 100 to
  ensure resolver stability.

Bug Fixes
~~~~~~~~~

- Fix setting retire in dns_keymgr_key_init.

  A wrong-variable bug in `dns_keymgr_key_init()` causes the DNSSEC key
  inactive time to never be read. This means the key state is retracting
  zone signatures where it should have, delaying the key rollover.

  ISC would like to thank Naresh Kandula Parmar (Nottiboy) for reporting
  this. :gl:`#5774`

- Resolve "key defined in view is not found"

  A recent change in `2956e4fc45b3c2142a3351682d4200647448f193` hardened
  the `key` name check when used in `primaries` to immediately reject
  the configuration if the key was not defined (rather than only
  checking whether the key name was correctly formed). However, the
  change introduced a regression that prevented the use of a `key`
  defined in a view. This is now fixed.


