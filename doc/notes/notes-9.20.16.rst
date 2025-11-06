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

Notes for BIND 9.20.16
----------------------

Bug Fixes
~~~~~~~~~

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

- Skip buffer allocations if not logging.

  Currently, during IXFR we allocate a 2KB buffer for IXFR change
  logging regardless of the log level. This commit introduces an early
  check on the log level in dns_diff_print to avoid this.

  Results in a speedup from 28% in the test case from issue #5442.


