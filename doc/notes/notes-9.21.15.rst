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

- New :option:`rndc showconf` command.

  The new :option:`rndc showconf` command prints the running server
  configuration. There are three options:

  - ``rndc showconf -user`` shows only settings explicitly declared in
    :iscman:`named.conf`.
  - ``rndc showconf -builtin`` shows the default settings, similar to
    :option:`named -C`.
  - ``rndc showconf -effective`` shows the result of applying user
    settings to defaults.

  :gl:`#1075`

- :option:`named-checkconf -b` dumps the built-in configuration.

  :iscman:`named-checkconf` now supports the option ``-b``, that prints
  the default built-in configuration used by :iscman:`named`. When
  the option is used, other options are ignored. :gl:`#1326`

- :option:`named-checkconf -e` prints the effective configuration.

  The new :option:`named-checkconf -e` option prints the effective
  server configuration. This is what would result from loading the
  specified configuration file into :iscman:`named`. The report
  includes all default settings, as modified by user values from the
  configuration file. :gl:`#2798`

- Add support for Extended DNS Error 24 (Invalid Data).

  See :rfc:`8914` section 4.25. :gl:`#1836`

Removed Features
~~~~~~~~~~~~~~~~

- Remove the ``tkey-domain`` statement.

  The previously deprecated ``tkey-domain`` statement has now been
  removed. :gl:`#4204`

- Remove the ``tkey-gssapi-credential`` statement.

  The previously deprecated ``tkey-gssapi-credential`` statement and all
  code related to it have now been removed. :gl:`#4204`

Feature Changes
~~~~~~~~~~~~~~~

- Minimal Meson version required is 1.3.0.

  Where distribution repositories don't provide Meson 1.3.0 or newer,
  the PyPI repository may be used instead.

Bug Fixes
~~~~~~~~~

- Skip unsupported algorithms when looking for a signing key.

  A mix of supported and unsupported DNSSEC algorithms in the same zone
  could cause validation failures. Unsupported algorithms are now
  ignored when looking for signing keys. :gl:`#5622`

- Report when a zone reload is already in progress.

  Previously, if a user attempted to manually reload a zone that was
  already being reloaded, the message returned was "zone reload queued".
  The message has been changed to "zone reload was already queued".
  :gl:`#5140`

- Fix :iscman:`dnssec-keygen` key collision checking for KEY RRtype
  keys.

  The :iscman:`dnssec-keygen` utility program failed to detect possible
  KEY ID collisions with existing keys generated using the non-default
  ``-T KEY`` option (e.g., for ``SIG(0)``). This has been fixed.
  :gl:`#5506`

- :iscman:`dnssec-verify` now uses exit code 1 when failing due to
  illegal options.

  Previously, :iscman:`dnssec-verify` exited with code 0 if the options
  could not be parsed. This has been fixed. :gl:`#5574`

- Prevent assertion failures of :iscman:`dig` when a server is specified
  before the ``-b`` option.

  Previously, :iscman:`dig` could exit with an assertion failure when
  a server was specified before the :option:`dig -b` option. This has
  been fixed. :gl:`#5609`

- Skip buffer allocations if not logging.

  Previously, we allocated a 2KB buffer for IXFR change logging,
  regardless of the log level.

  This results in a 28% speedup in some scenarios.


