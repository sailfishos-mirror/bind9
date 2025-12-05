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

Notes for BIND 9.21.16
----------------------

New Features
~~~~~~~~~~~~

- Add ``+[no]showtruncated`` and ``+[no]showallmessages`` to :iscman:`dig`.

  The option :option:`dig +showtruncated` adds the ability to display the
  truncated message before retrying the query over TCP.

  The option :option:`dig +showallmessages` adds a shortcut, which is the
  equivalent of ``dig +qr +showbadcookie +showbadversion +showtruncated``.
  :gl:`#5657`

Feature Changes
~~~~~~~~~~~~~~~

- Reduce the number of outgoing queries.

  Reduce the number of outgoing queries when resolving the nameservers
  for delegation points. This helps a DNS resolver with a cold cache
  resolve client queries with complex delegation chains and
  redirections. :gl:`!11148`

- Improve output of ``rndc dnssec -status``

  Add a new parameter ``-v`` to the ``rndc dnssec -status`` command for
  more verbose output. Previously, key states were printed, and keys
  that could be purged were listed. This made the output hard to read.
  This information is now only shown in the verbose output.

  Add more meaningful messages to the status output, making it clearer
  what the state of a rollover is.

  This makes the output more condensed, improving its readability.
  :gl:`#3938`

- Change the QNAME minimization algorithm to follow the standard.

  In :gl:`!9155`, QNAME minimization was changed to not leak the query
  type to the parent name server.  This violates :rfc:`9156` Section 3,
  step (3) and it is not necessary.  It also breaks some unusual
  authoritative DNS setups, especially when CNAMEs are involved.
  There is really no privacy leak with query type, so these changes
  were not beneficial. :gl:`#5661`

- Enforce bounds of :any:`prefetch` configuration option.

  The :any:`prefetch` configuration option now enforces boundaries. The
  configuration (including when using :iscman:`named-checkconf`) now fails if
  the trigger (first value) is above 10, and if the eligibility (second
  optional value) is not at least six seconds greater than the trigger
  value. :gl:`!11243`

- Enforce the fact that catalog zones cannot be used in non-IN views.

  Catalog zones cannot be used in a view which is not from the IN class.
  This is now enforced, as the server won't load (instead of loading
  without the catalog zone) if such a configuration is detected. This
  configuration error is now also caught by :iscman:`named-checkconf`.
  :gl:`!11245`

- Provide more information when memory allocation fails.

  BIND now provides more information about the failure when memory allocation
  fails. :gl:`!11272`

Bug Fixes
~~~~~~~~~

- Adding NSEC3 opt-out records could leave invalid records in chain.

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon. The previous NSEC3 would therefore not be found,
  resulting in invalid NSEC3 records being left in the zone. This has
  been fixed. :gl:`#5671`

- Fix spurious timeouts while resolving names.

  Sometimes, loops in the resolving process (e.g., to resolve or validate
  ``ns1.example.com``, we need to resolve ``ns1.example.com``) were not properly
  detected, leading to a spurious 10-second delay. This has been fixed,
  and such loops are properly detected. :gl:`#3033` :gl:`#5578`

- Fix bug where zone switches from NSEC3 to NSEC after retransfer.

  When a zone was re-transferred but the zone journal on an
  inline-signing secondary was out of sync, the zone could fall back to
  using NSEC records instead of NSEC3. This has been fixed. :gl:`#5527`

- Fix caching RRSIG covering cached NODATA record.

  If a cached NODATA record was already present for an RRSIG type
  due to a mismatch of records on the upstream nameservers, it could
  trigger an assertion failure. This has been fixed. :gl:`#5633`

- ``AMTRELAY`` type 0 presentation format handling was wrong.

  :rfc:`8777` specifies a placeholder value of ``.`` for the gateway field
  when the gateway type is 0 (no gateway). This was not being checked
  for, nor was it emitted when displaying the record. This has been corrected.

  Instances of this record will need the placeholder period added to
  them when upgrading. :gl:`#5639`

- Fix parsing bug in :any:`remote-servers` with key or TLS.

  The :any:`remote-servers` clause enables the following pattern using a
  named ``server-list``::

      remote-servers a { 1.2.3.4; ... };
      remote-servers b { a key foo; };

  However, such a configuration was wrongly rejected, with an ``unexpected
  token 'foo'`` error. This configuration is now accepted. :gl:`#5646`

- Fix :any:`allow-recursion`/:any:`allow-query-cache` inheritance.

  The merging of the user options and defaults into the effective
  configuration broke the mutual inheritance of the :any:`allow-recursion`,
  :any:`allow-query`, and :any:`allow-query-cache` ACLs, and of the
  :any:`allow-recursion-on` and :any:`allow-query-cache-on` ACLs. This has been
  fixed. :gl:`#5647`

- Fix DoT reconfigure/reload bug in the resolver.

  If client-side TLS transport was in use (for example, when
  forwarding queries to a DoT server), :iscman:`named` could
  terminate unexpectedly when reconfiguring or reloading. This
  has been fixed.
  :gl:`#5653`

