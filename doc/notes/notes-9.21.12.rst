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

Notes for BIND 9.21.12
----------------------

New Features
~~~~~~~~~~~~

- Add manual mode configuration option to dnsec-policy.

  Add a new option ``manual-mode`` to :any:`dnssec-policy`. The intended
  use is that if it is enabled, it will not automatically move to the
  next state transition, but instead the transition is logged. Only
  after manual confirmation with ``rndc dnssec -step`` the transition is
  made. :gl:`#4606`

- Add a new 'servfail-until-ready' configuration option for RPZ.

  By default, when :iscman:`named` is started it may start answering to
  queries before the response policy zones are completely loaded and
  processed. This new feature gives an option to the users to tell
  :iscman:`named` that incoming requests should result in SERVFAIL
  answer until all the response policy zones are processed and ready.
  Note that if one or more response policy zones fail to load,
  :iscman:`named` starts responding to queries according to those zones
  that did load. :gl:`#5222`

- Support for parsing HHIT and BRID records has been added.

  :gl:`#5444`

Removed Features
~~~~~~~~~~~~~~~~

- Deprecate the "tkey-gssapi-credential" statement.

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

- Obsolete the "tkey-domain" statement.

  Mark the ``tkey-domain`` statement as obsolete, since it has not had
  any effect on server behavior since support for TKEY Mode 2
  (Diffie-Hellman) was removed (in BIND 9.20.0). :gl:`#4204`

Bug Fixes
~~~~~~~~~

- Prevent spurious SERVFAILs for certain 0-TTL resource records.

  Under certain circumstances, BIND 9 can return SERVFAIL when updating
  existing entries in the cache with new NS, A, AAAA, or DS records with
  0-TTL. :gl:`#5294`

- Batch minor meson fixes.

  This MR fixes various meson issues that are found after the first
  meson release and are too small to have a MR on their own. :gl:`#5379`

- RPZ canonical warning displays zone entry incorrectly.

  When an IPv6 rpz prefix entry is entered incorrectly the log message
  was just displaying the prefix rather than the full entry.  This has
  been corrected. :gl:`#5491`

- Fix a catalog zone issue when having an unset 'default-primaries'
  configuration clause.

  A catalog zone with an unset ``default-primaries`` clause could cause
  an unexpected termination of the :iscman:`named` process after two
  reloading or reconfiguration commands. This has been fixed.
  :gl:`#5494`


