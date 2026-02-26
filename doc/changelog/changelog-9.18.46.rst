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

BIND 9.18.46
------------

Feature Changes
~~~~~~~~~~~~~~~

- Invalid NSEC3 can cause OOB read of the isdelegation() stack.
  ``97fd0c56e48``

  When .next_length is longer than NSEC3_MAX_HASH_LENGTH, it causes a
  harmless out-of-bound read of the isdelegation() stack.  This has been
  fixed. :gl:`#5749` :gl:`!11595`

Bug Fixes
~~~~~~~~~

- Clear serve-stale flags when following the CNAME chains.
  ``7733cb4580e``

  A stale answer could have been served in case of multiple upstream
  failures when following the CNAME chains.  This has been fixed.
  :gl:`#5751` :gl:`!11584`


