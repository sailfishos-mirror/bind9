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

- Add +[no]showtruncated and +[no]showallmessages to dig.

  The dig option +showtruncated adds the ability to display the
  truncated message before retrying the query over TCP.

  The dig option +showallmessages add a short cut which is the
  equivalent of "dig +qr +showbadcookie +showbadversion +showtruncated".
  :gl:`#5657`

Feature Changes
~~~~~~~~~~~~~~~

- Improve output of 'rndc dnssec -status'

  Add a new parameter ``-v`` to the ``rndc dnssec -status`` command for
  more verbose output. Previously, key states were printed, and keys
  that can be purged were listed. This made the output hard to read.
  This information is now only shown in the verbose output.

  Add more meaningful messages to the status output, making it clearer
  what the state of a rollover is.

  This makes the output more condense, improving its readability.
  :gl:`#3938`

- Change the QNAME minimization algorithm to follow the standard.

  In !9155, the QNAME minimization was changed to not leak the query
  type to the parent name server.  This violates RFC 9156 Section 3,
  step (3) and it is not necessary.  It also breaks some (weird)
  authoritative DNS setups, especially when CNAMEs are involved.  Also
  there is really no privacy leak with query type. :gl:`#5661`

- Enforce bounds of prefetch configuration option.

  The prefetch configuration option now enforces boundaries. The
  configuration (including when using `named-checkconf`) now fails if
  the trigger (first value) is above 10, and if the eligibility (second
  optional value) isn't at least six seconds greater than the trigger
  value.

- Enforces the fact that catalog-zone can not be used in non IN views.

  Catalog-zones can't be used in a view which is not from the IN class.
  This is now enforced as the server won't load (instead of loading
  without the catalog-zone) if such configuration is detected. This
  configuration error is now also caught by `named-checkconf`.

- Provide more information when the memory allocation fails.

  Provide more information about the failure when the memory allocation
  fails.

- Reduce the number of outgoing queries.

  Reduces the number of outgoing queries when resolving the nameservers
  for delegation points.  This helps the DNS resolver with cold cache
  resolve client queries with complex delegation chains and
  redirections.

Bug Fixes
~~~~~~~~~

- Fix the spurious timeouts while resolving names.

  Sometimes the loops in the resolving (e.g. to resolve or validate
  ns1.example.com we need to resolve ns1.example.com) were not properly
  detected leading to spurious 10 seconds delay.  This has been fixed
  and such loops are properly detected. :gl:`#3033`, #5578

- Fix bug where zone switches from NSEC3 to NSEC after retransfer.

  When a zone is re-transferred, but the zone journal on an
  inline-signing secondary is out of sync, the zone could fall back to
  using NSEC records instead of NSEC3. This has been fixed. :gl:`#5527`

- Fix caching RRSIG covering cache NODATA record.

  When a RRSIG for type that we already have cached NODATA record was
  cached due to mismatch of the records on the upstream nameservers, an
  assertion failure could trigger.  This has been fixed. :gl:`#5633`

- AMTRELAY type 0 presentation format handling was wrong.

  RFC 8777 specifies a placeholder value of "." for the gateway field
  when the gateway type is 0 (no gateway).  This was not being checked
  for nor emitted when displaying the record. This has been corrected.

  Instances of this record will need the placeholder period added to
  them when upgrading. :gl:`#5639`

- Fix parsing bug in remote-servers with key or tls.

  The :any:`remote-servers` clause enable the following pattern using a
  named ``server-list``:

  remote-servers a { 1.2.3.4; ... };         remote-servers b { a key
  foo; };

  However, such configuration was wrongly rejected, with an "unexpected
  token 'foo'" error. Such configuration is now accepted. :gl:`#5646`

- Fix allow-recursion/allow-query-cache inheritance.

  The merging of the user options and defaults into the effective
  configuration broke the mutual inheritance of the `allow-recursion`,
  `allow-query`, and `allow-query-cache` ACLs, and of the
  `allow-recursion-on` and `allow-query-cache-on` ACLs. This has been
  fixed. :gl:`#5647`

- Fix TLS contexts cache object usage bug in the resolver.

  :iscman:`named` could terminate unexpectedly when reconfiguring or
  reloading, and if client-side TLS transport was in use (for example,
  when forwarding queries to a DoT server). This has been fixed.
  :gl:`#5653`

- Adding NSEC3 opt-out records could leave invalid records in chain.

  When creating an NSEC3 opt-out chain, a node in the chain could be
  removed too soon, causing the previous NSEC3 being unable to be found,
  resulting in invalid NSEC3 records to be left in the zone. This has
  been fixed. :gl:`#5671`

