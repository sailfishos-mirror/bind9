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

BIND 9.21.18
------------

Feature Changes
~~~~~~~~~~~~~~~

- Update requirements for system test suite. ``b0c2670cb8``

  Python 3.10 or newer is now required for running the system test
  suite. The required python packages and their version requirements are
  now tracked in `bin/tests/system/requirements.txt`.

  Support for pytest 9.0.0 has been added its minimum supported version
  has been raised to 7.0.0. The minimum supported dnspython version has
  been raised to 2.3.0. :gl:`#5690`  :gl:`#5614` :gl:`!11415`

- Split and refactor dns_view_findzonecut() ``263f54c9d1``

  The function `dns_view_findzonecut()` was previously a complex bit of
  code (multiple pages long with multiple gotos and mutating states)
  into a simpler main entry point making explicit the various steps and
  layers involved into the delegation lookup.

  Separate helper functions are added for specific sub-tasks (lookup
  from the zones, from the cache, deciding which result to use if there
  are valid candidates from the zone or cache, etc.)

  Finally, the range of result values returned by
  `dns_view_findzonecut()` is simplified and clearly specified. This
  simplifies a bit the callers code. :gl:`#5681` :gl:`!11377`

- Lowercase the NSEC next owner name when signing. ``dd8651ff36``

  When building the NSEC rdata, lowercase the next owner name before
  storing it in the Next Domain Name Field.

  Note that this is not required according to RFC 6840, but since there
  is inconsistency in the documents over time, having uppercase next
  owner names in the NSEC records may cause validation failures if
  validators are not following RFC 6840. :gl:`#5702` :gl:`!11442`

- Use enum rather than numbers for isc_base64_tobuffer and
  isc_hex_tobuffer. ``7e39596d57``

  Use isc_one_or_more and isc_zero_or_more rather than (-2) and (-1)
  when calling isc_base64_tobuffer. Similarly for isc_hex_tobuffer. This
  should help reduce the probability that the wrong number is used and
  it makes the intent clearer. :gl:`#5713` :gl:`!11479`

- Enable minimal ANY answers by default. ``40bffcc8a6``

  ANY queries are widely abused by attackers doing reflection attacks as
  they return the largest answers.  Enable minimal ANY answers by
  default to reduce the attack surface of the DNS servers. :gl:`#5723`
  :gl:`!11505`

- Dns_rdataset_clone() and dns_rdataset_isassociated() const parameters.
  ``8dfa96b91b``

  `dns_rdataset_clone()` takes now a const source rdataset. Also,
  `dns_rdataset_isassociated()` also takes a const rdataset.
  :gl:`!11462`

- Initial openssl version splitting. ``fe9fee63c6``

  Dealing with OpenSSL has been rapidly turning into an unwieldy
  situation as post-3.0 changes turn the library into a different beast.

  Start treating pre and post-3.0 versions differently for easier
  maintenance.

  To help with this Sisyphean task, this MR had to shift things around.

  `OPENSSL_NO_DEPRECATED` is now declared in BIND alongside an
  appropriate `OPENSSL_API_COMPAT` value. The former value will set to
  declare either OpenSSL 1.1.0 or 3.0 as the bare minimum version.

  Instead of splitting `md.c` and `hmac.c` into separate
  version-specific files, they now live inside `crypto/ossl1_1.c` and
  `crypto/ossl3.c`. This way, these functions will be able to utilize
  the same static `OSSL_PARAM` tables, removing redundant reconstruction
  for HMAC.

  For pre-3.0, `isc_hmac` has been reverted back to using the `HMAC_`
  interface. Using `EVP_MD_CTX`-based functions for HMAC will end up
  libcrypto calling the same `HMAC_` functions in the end, giving no
  advantage while confusingly using the digest functions.

  A new API, `isc_ossl_wrap` has been added. This family of functions
  aim to provide a common interface for libcrypto version specific code
  while not abstracting away OpenSSL's structures such as `EVP_PKEY`.

  Currently the main user of this API is the `dst` family of functions
  where some ECDSA and RSA opeations need to use the new `OSSL_PARAM`
  functionality by requirement or to avoid speed penalties.

  Furthermore OpenSSL based logging has been moved from `isc_tls` to
  `isc_ossl_wrap` as its a more appropriate place for such
  functionality. :gl:`!11094`

- Remove `sigrdataset` from `dns_view_findzonecut()` ``b40f92eb26``

  Since the `sigrdataset` "output" parameter of `dns_view_findzonecut()`
  is never used (always called with NULL), it is now removed. As the
  resolver is moving towards a parent-centric direction, there is no
  point having a signature for the NS record (which is not authoritative
  in the parent, so never signed) when `dns_view_findzonecut()` is
  called.

  Also, rename `dns_view_findzonecut()` as `dns_view_bestzonecut()` as
  it is used only in the context where the closest name servers for a
  name need to be queried and to avoid ambiguities with other code flows
  using `dns_db_findzonecut()`. :gl:`!11444`

- Remove rrset-order cyclic from the default config, with shim.
  ``d0cec705ab``

  Currently we add an rrset-order cyclic statement to the default
  config. Since the rrset-order allows matching a subset of all names,
  it must be implemented with a comparison against a wildcard, and since
  the statement applies per rrset, this can result in million of
  comparisons per second on a busy authoritative server.

  This commit removes rrset-order from the default config, but adds back
  a code shim in query_setorder to preserve the previous behaviour.
  :gl:`!11417`

Bug Fixes
~~~~~~~~~

- Fix a bug in qpzone.c:first_existing_header_indirect() ``0c1577b848``

  There is a bug in qpzone.c:first_existing_header_indirect() where it
  does not advance the pointer in the FOREACH type loop.

  Remove the static function altogether, as it was used only once and
  had some other problems too, and use simpler custom code instead in
  the place where it was used. :gl:`#5691` :gl:`!11460`

- Make catalog zone names and member zones' entry names
  case-insensitive. ``96160298bd``

  Previously, the catalog zone names and their member zones' entry names
  were unintentionally case-sensitive. This has been fixed. :gl:`#5693`
  :gl:`!11410`

- Use const pointer with strchr of const pointer. ``fbab0d546e``

  :gl:`#5694` :gl:`!11394`

- Fix brid and hhit implementation. ``4195821686``

  Fix bugs in BRID and HHIT implementation and enable the unit tests.
  :gl:`#5710` :gl:`!11491`

- DSYNC record incorrectly used two octets for the Scheme Field.
  ``a20bbb629a``

  When creating the `DSYNC` record from a structure, `uint16_tobuffer`
  was used instead of `uint8_tobuffer` when adding the scheme, causing a
  `DSYNC` record that was one octet too long. This has been fixed.
  :gl:`#5711` :gl:`!11477`

- Fix a possible issue with reponse policy zones and catalog zones.
  ``fd568032ac``

  If a response policy zone (RPZ) or a catalog zone contained an
  `$INCLUDE` directive, then manually reloading that zone could fail to
  process the changes in the response policy or in the catalog,
  respectively. This has been fixed. :gl:`#5714` :gl:`!11489`


