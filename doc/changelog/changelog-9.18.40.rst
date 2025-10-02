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

BIND 9.18.40
------------

Security Fixes
~~~~~~~~~~~~~~

- [CVE-2025-8677] DNSSEC validation fails if matching but invalid DNSKEY
  is found. ``85d08e06831``

  Previously, if a matching but cryptographically invalid key was
  encountered during DNSSEC validation, the key was skipped and not
  counted towards validation failures. :iscman:`named` now treats such
  DNSSEC keys as hard failures and the DNSSEC validation fails
  immediately, instead of continuing with the next DNSKEYs in the RRset.

  ISC would like to thank Zuyao Xu and Xiang Li from the All-in-One
  Security and Privacy Laboratory at Nankai University for bringing this
  vulnerability to our attention. :gl:`#5343`

- [CVE-2025-40778] Address various spoofing attacks. ``4c99ba5a462``

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

- [CVE-2025-40780] Cache-poisoning due to weak pseudo-random number
  generator. ``f74fb05265b``

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

- Support for parsing HHIT and BRID records has been added.
  ``d7d4e94d085``

  :gl:`#5444` :gl:`!10933`

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate the "tkey-domain" statement. ``e28c95c1160``

  Mark the :any:`tkey-domain` statement as deprecated since it is only
  used by code implementing TKEY Mode 2 (Diffie-Hellman), which was
  removed from newer BIND 9 branches. :gl:`#4204` :gl:`!10783`

- Deprecate the "tkey-gssapi-credential" statement. ``2705307f818``

  The :any:`tkey-gssapi-keytab` statement allows GSS-TSIG to be set up
  in a simpler and more reliable way than using the
  :any:`tkey-gssapi-credential` statement and setting environment
  variables (e.g. ``KRB5_KTNAME``). Therefore, the
  :any:`tkey-gssapi-credential` statement has been deprecated;
  :any:`tkey-gssapi-keytab` should be used instead.

  For configurations currently using a combination of both
  :any:`tkey-gssapi-keytab` *and* :any:`tkey-gssapi-credential`, the
  latter should be dropped and the keytab pointed to by
  :any:`tkey-gssapi-keytab` should now only contain the credential
  previously specified by :any:`tkey-gssapi-credential`. :gl:`#4204`
  :gl:`!10925`

Feature Changes
~~~~~~~~~~~~~~~

- Update clang-format style with options added in newer versions.
  ``1bc0f245c79``

  Add and apply InsertBraces statement to add missing curly braces
  around one-line statements and use
  ControlStatementsExceptControlMacros for SpaceBeforeParens to remove
  space between foreach macro and the brace, e.g. `FOREACH (x) {`
  becomes `FOREACH(x) {`. :gl:`!10865`

Bug Fixes
~~~~~~~~~

- Prevent spurious SERVFAILs for certain 0-TTL resource records.
  ``f5a6a8be45f``

  Under certain circumstances, BIND 9 can return SERVFAIL when updating
  existing entries in the cache with new NS, A, AAAA, or DS records with
  0-TTL. :gl:`#5294` :gl:`!10899`

- Use DNS_RDATACOMMON_INIT to hide branch differences. ``aef4682e4aa``

  Initialization of the common members of rdata type structures varies
  across branches. Standardize it by using the `DNS_RDATACOMMON_INIT`
  macro for all types, so that new types are more likely to use it, and
  hence backport more cleanly. :gl:`#5467` :gl:`!10833`

- RPZ canonical warning displays zone entry incorrectly. ``3e787e98930``

  When an IPv6 rpz prefix entry is entered incorrectly the log message
  was just displaying the prefix rather than the full entry.  This has
  been corrected. :gl:`#5491` :gl:`!10931`

- Missing DNSSEC information when CD bit is set in query.
  ``990586f0496``

  The RRSIGs for glue records were not being cached correctly for CD=1
  queries.  This has been fixed. :gl:`#5502` :gl:`!10957`

- Add and use __attribute__((nonnull)) in dnssec-signzone.c.
  ``48c30cfcd08``

  Clang 20 was spuriously warning about the possibility of passing a
  NULL file pointer to `fprintf()`, which uses the 'nonnull' attribute.
  To silence the warning, the functions calling `fprintf()` have been
  marked with the same attribute to assure that NULL can't be passed to
  them in the first place.

  Close #5487 :gl:`!10914`


