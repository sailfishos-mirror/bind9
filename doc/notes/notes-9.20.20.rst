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

Notes for BIND 9.20.20
----------------------

Feature Changes
~~~~~~~~~~~~~~~

- Record query time for all dnstap responses.

  Not all DNS responses had the query time set in their corresponding
  dnstap messages. This has been fixed. :gl:`#3695`

- Optimize the TCP source port selection on Linux.

  Enable a socket option on the outgoing TCP sockets to allow faster
  selection of the source <address,port> tuple for different destination
  <address,port> tuples when nearing over 70-80% of the source port
  utilization.

Bug Fixes
~~~~~~~~~

- Fix errors when retrying over TCP in notify_send_toaddr.

  If the source address is not available do not attempt to retry over
  TCP otherwise clear the TSIG key from the message prior to retrying.
  :gl:`#5457`

- Fetch loop detection improvements.

  Fixes a case where an in-domain NS with an expired glue would fail to
  resolve.

  Let's consider the following parent-side delegation (both for
  `foo.example.` and `dnshost.example.`

  ``` foo.example.            3600    NS      ns.dnshost.example.
  dnshost.example.        3600    NS      ns.dnshost.example.
  ns.dnshost.example.     3600    A       1.2.3.4 ```      Then the
  child-side of `dnshost.example.`:

  ```     dnshost.example.        300     NS      ns.dnshost.example.
  ns.dnshost.example.     300     A       1.2.3.4 ```      And then the
  child-side of `foo.example.`:

  ``` foo.example             3600    NS      ns.dnshost.example.
  a.foo.example           300     A       5.6.7.8 ```

  While there is a zone misconfiguration (the TTL of the delegation and
  glue doesn't match in the parent and the child), it is possible to
  resolve `a.foo.example` on a cold-cache resolver. However, after the
  `ns.dnshost.example.` glue expires, the resolution would have failed
  with a "fetch loop detected" error. This is now fixed. :gl:`#5588`

- Remove deterministic selection of nameserver.

  When selecting nameserver addresses to be looked up we where always
  selecting them in dnssec name order from the start of the nameserver
  rrset.  This could lead to resolution failure despite there being
  address that could be resolved for the other names.  Use a random
  starting point when selecting which names to lookup. :gl:`#5695`
  :gl:`#5745`

- DNSTAP wasn't logging forwarded queries correctly.

  :gl:`#5724`

- Fix read UAF in BIND9 dns_client_resolve() via DNAME Response.

  An attacker controlling a malicious DNS server returns a DNAME record,
  and the we stores a pointer to resp->foundname, frees the response
  structure, then uses the dangling pointer in dns_name_fullcompare()
  possibly causing invalid match.  Only the `delv`is affected.  This has
  been fixed. :gl:`#5728`

- Clear serve-stale flags when following the CNAME chains.

  A stale answer could have been served in case of multiple upstream
  failures when following the CNAME chains.  This has been fixed.
  :gl:`#5751`

- Fail DNSKEY validation when supported but invalid DS is found.

  A regression was introduced when adding the EDE code for unsupported
  DNSKEY and DS algorithms.  When the parent has both supported and
  unsupported algorithm in the DS record, the validator would treat the
  supported DS algorithm as insecure when validating DNSKEY records
  instead of BOGUS.  This has not security impact as the rest of the
  child zone correctly ends with BOGUS status, but it is incorrect and
  thus the regression has been fixed. :gl:`#5757`

- Importing invalid SKR file might corrupt stack memory.

  If an BIND 9 administrator imports an invalid SKR file, local stack in
  the import function might overflow.  This could lead to a memory
  corruption on the stack and ultimately server crash. This has been
  fixed.

  ISC would like to thank mcsky23 for bringing this bug to our
  attention. :gl:`#5758`

- Do not update the case on unchanged rdatasets.

  Fix assertion failure on unchanged rdataset during IXFR. :gl:`#5759`


