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

Notes for BIND 9.21.15
----------------------

New Features
~~~~~~~~~~~~

- New "rndc showconf" command.

  The new `rndc showconf` command prints the running server
  configuration. There are three options: - `rndc showconf -user`
  displays the user configuration (i.e., the contents of `named.conf`).
  - `rndc showconf -builtin` displays the default settings, similar to
  `named -H`. - `rndc showconf -effective` displays the effective
  configuration. This is the merged combination of the `-user` and
  `-builtin` configurations. :gl:`#1075`

- "named-checkconf -b" dumps the built-in configuration.

  `named-checkconf` now supports the command line switch `-b`,  which
  prints the default built-in configuration used by `named`.      When
  `-b` is in use, other options are ignored. :gl:`#1326`

- Add support for Extended DNS Error 24 (Invalid Data)

  Extended DNS Error 24 (Invalid Data) is returned when the server
  cannot answer data for a zone it is configured for. This occurs
  typically when an authoritative server does not have loaded the DB of
  a configured zone, or a secondary server zone is expired.

  See RFC 8914 section 4.25. :gl:`#1836`

- Named-checkconf -e prints the effective configuration.

  The new `named-checkconf -e` option prints the effective server
  configuration, including all the default settings, that would result
  from loading the specified configuration file into `named`.
  :gl:`#2798`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the "tkey-domain" statement.

  The previously deprecated ``tkey-domain`` statement has now been
  removed. :gl:`#4204`

- Remove the "tkey-gssapi-credential" statement.

  The previously deprecated ``tkey-gssapi-credential`` statement and all
  code related to it have now been removed. :gl:`#4204`

Feature Changes
~~~~~~~~~~~~~~~

- Minimal meson version required is 1.3.0.

  The minimal required meson version is 1.3.0.

  Where distribution repositories don't provide meson 1.3.0 or newer,
  meson from PyPI may be used instead.

Bug Fixes
~~~~~~~~~

- Report when a zone reload is already in progress.

  If a zone reload was already in progress when `rndc reload <zone>` was
  run, the message returned was "zone reload queued", which was
  technically correct, but it was identical to the message returned when
  a reload was not in progress. Consequently, a user could issue two
  reload commands without realizing that only one reload had actually
  taken place. This has been addressed by changing the message returned
  to "zone reload was already queued". :gl:`#5140`

- Fix dnssec-keygen key collision checking for KEY rrtype keys.

  The :iscman:`dnssec-keygen` utility program failed to detect possible
  Key ID collisions with the existing keys generated using the
  non-default ``-T KEY`` option (e.g. for ``SIG(0)``). This has been
  fixed. :gl:`#5506`

- Fix shutdown INSIST in dns_dispatchmgr_getblackhole.

  Previously, `named` could trigger an assertion in
  `dns_dispatchmgr_getblackhole` while shutting down. This has been
  fixed. :gl:`#5525`

- Dnssec-verify now uses exit code 1 when failing due to illegal
  options.

  Previously, dnssec-verify exited with code 0 if the options could not
  be parsed. This has been fixed. :gl:`#5574`

- Prevent assertion failures of dig when server is specified before the
  -b option.

  Previously, :iscman:`dig` could exit with an assertion failure when
  the server was specified before the :option:`dig -b` option. This has
  been fixed. :gl:`#5609`

- Skip unsupported algorithms when looking for signing key.

  A mix of supported and unsupported DNSSEC algorithms in the same zone
  could have caused validation failures. Ignore the DNSSEC keys with
  unsupported algorithm when looking for the signing keys. :gl:`#5622`

- Fix fuzzing builds.

  Previously fuzzing builds were broken due to some typos in the
  `meson.build`.

- Skip buffer allocations if not logging.

  Currently, during IXFR we allocate a 2KB buffer for IXFR change
  logging regardless of the log level. This commit introduces an early
  check on the log level in dns_diff_print to avoid this.

  Results in a speedup from 28% in the test case from issue #5442.


