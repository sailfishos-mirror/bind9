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

Notes for BIND 9.21.13
----------------------

Security Fixes
~~~~~~~~~~~~~~

- DNSSEC validation fails if matching but invalid DNSKEY is found.
  :cve:`2025-8677`

  Previously, if a matching but cryptographically invalid key was
  encountered during DNSSEC validation, the key was skipped and not
  counted towards validation failures. :iscman:`named` now treats such
  DNSSEC keys as hard failures and the DNSSEC validation fails
  immediately, instead of continuing with the next DNSKEYs in the RRset.

  ISC would like to thank Zuyao Xu and Xiang Li from the All-in-One
  Security and Privacy Laboratory at Nankai University for bringing this
  vulnerability to our attention. :gl:`#5343`

- Address various spoofing attacks. :cve:`2025-40778`

  Previously, several issues could be exploited to poison a DNS cache
  with spoofed records for zones which were not DNSSEC-signed or if the
  resolver was configured to not do DNSSEC validation. These issues were
  assigned CVE-2025-40778 and have now been fixed.

  As an additional layer of protection, :iscman:`named` no longer
  accepts DNAME records or extraneous NS records in the AUTHORITY
  section unless these are received via spoofing-resistant transport
  (TCP, UDP with DNS cookies, TSIG, or SIG(0)).

  ISC would like to thank Yuxiao Wu, Yunyi Zhang, Baojun Liu, and Haixin
  Duan from Tsinghua University for bringing this vulnerability to our
  attention. :gl:`#5414`

- Cache-poisoning due to weak pseudo-random number generator.
  :cve:`2025-40780`

  It was discovered during research for an upcoming academic paper that
  a xoshiro128\*\* internal state can be recovered by an external 3rd
  party, allowing the prediction of UDP ports and DNS IDs in outgoing
  queries. This could lead to an attacker spoofing the DNS answers with
  great efficiency and poisoning the DNS cache.

  The internal random generator has been changed to a cryptographically
  secure pseudo-random generator.

  ISC would like to thank Prof. Amit Klein and Omer Ben Simhon from
  Hebrew University of Jerusalem for bringing this vulnerability to our
  attention. :gl:`#5484`

New Features
~~~~~~~~~~~~

- Support for additional tokens in the zone file name template.

  See :any:`file` for a complete list of currently supported tokens.
  :gl:`#85`

- Add support for synthetic records.

  Add :iscman:`synthrecord` query plugin which, in "reverse" mode,
  enables the server to build a synthesized response to a PTR query when
  the PTR record requested is not found in the zone.

  The dynamically built name is constructed from a static prefix (passed
  as a plugin parameter), the IP address (extracted from the query
  name), and a suffix (also passed as a plugin parameter). An
  ``allow-synth`` address-match list can be used to limit the network
  addresses for which the plugin may generate responses.

  The plugin can also be used in "forward" mode, to build synthesized
  A/AAAA records from names using the same format as the dynamically
  built PTR names. The same parameters are used: the plugin reacts and
  answers a query if the name matches the configured prefix and origin,
  and encodes an IP address that is within ``allow-synth``. :gl:`#1586`

- Support for zone-specific plugins.

  Query plugins can now be configured at the :any:`zone` level, as well
  as globally or at the :any:`view` level. A plugin's hooks are then
  called only while that specific zone's database is being used to
  answer a query.

  This simplifies the implementation of plugins that are only needed for
  specific namespaces for which the server is authoritative. It can also
  enable quicker responses, since plugins are only called when they are
  needed. :gl:`#5356`

- Add :any:`dnssec-policy` keys configuration check to
  :iscman:`named-checkconf`.

  A new option :option:`-k <named-checkconf -k>` was added to
  :iscman:`named-checkconf` that allows checking the
  :any:`dnssec-policy` :any:`keys` configuration against the configured
  key stores. If the found key files are not in sync with the given
  :any:`dnssec-policy`, the check will fail.

  This is useful to run before migrating to :any:`dnssec-policy`.
  :gl:`#5486`

Removed Features
~~~~~~~~~~~~~~~~

- Remove randomized RRset ordering.

  :any:`rrset-order` ``random`` did not offer uniform distribution of
  all permutations and it was not superior to the ``cyclic`` order in
  any way. ``random`` ordering is now an alias for ``cyclic`` ordering.
  :gl:`#5513`

Bug Fixes
~~~~~~~~~

- Use signer name when disabling DNSSEC algorithms.

  :any:`disable-algorithms` could cause DNSSEC validation failures when
  the parent zone was signed with the algorithms that were being
  disabled for the child zone. This has been fixed;
  :any:`disable-algorithms` now works on a whole-of-zone basis.

  If the zone's name is at or below the :any:`disable-algorithms` name
  the algorithm is disabled for that zone, using deepest match when
  there are multiple :any:`disable-algorithms` clauses. :gl:`#5165`

- :option:`rndc sign` during ZSK rollover will now replace signatures.

  When performing a ZSK rollover, if the new DNSKEY is omnipresent, the
  :option:`rndc sign` command now signs the zone completely with the
  successor key, replacing all zone signatures from the predecessor key
  with new ones. :gl:`#5483`

- Missing DNSSEC information when CD bit is set in query.

  The RRSIGs for glue records were not being cached correctly for CD=1
  queries. This has been fixed. :gl:`#5502`

- Add a check for ``chroot()`` to the build system.

  The Meson build procedure was not checking for the existence of the
  ``chroot()`` function. This has been fixed. :gl:`#5519`

- Preserve cache when reload fails and reload the server again.

  This fixes an issue where failing to reconfigure/reload the server
  would fail to preserve the views' caches for subsequent server
  reconfigurations/reloads. :gl:`#5523`
