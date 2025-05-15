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

.. highlight: console

.. iscman:: synthrecord
.. _man_synthrecord:

synthrecord.so - dynamically synthesize PTR, A and AAAA records
---------------------------------------------------------------

Synopsis
~~~~~~~~

:program:`plugin query` "synthrecord.so" [{ parameters }];

Description
~~~~~~~~~~~

:program:`synthrecord.so` is a query plugin module for :iscman:`named`,
enabling :iscman:`named` to synthesize forward and reverse responses for
non-existent names in a zone.

This plugin can only configured inside a ``zone`` clause.

In ``reverse`` mode, the module intercepts queries of type PTR. If no
authoritative answer can be found in the zone database, and if the IP
address encoded in the query name matches one of the prefixes or addresses
specified in ``allow-synth``, then the module dynamically generates a
response, constructed by concatenating the configured ``prefix``, the IP
address encoded in the query reverse name, and the configured ``origin``.

In ``forward`` mode, the module intercepts queries of type A or AAAA.
If no authoritative answer can be found in the zone, the query
begins and ends with the configured ``prefix`` and ``origin``, and an
IP address can be parsed from the part in between, then that IP address
is returned to the client.

Note: these synthesized responses are not signed, so the use of this
module is incompatible with DNSSEC.

Example
~~~~~~~

::

   zone "1.168.192.in-addr.arpa." {
       type primary;
       file "1.168.192.in-addr.arpa.db";
       plugin query "synthrecord" {
           mode reverse;
           prefix "dynamic-";
           origin "example.";
       };
   };

   zone "e.f.a.c.ip6.arpa." {
       type primary;
       file "e.f.a.c.ip6.arpa.db";
       plugin query "synthrecord" {
           mode reverse;
           prefix "dynamic-";
           origin "example.";
       };
   };

   zone "example." {
       type primary;
       file "example.db";
       plugin query "synthrecord" {
           mode forward;
           prefix "dynamic-";
           origin "example.";
           allow-synth { 192.168.1/24; cafe::/16; };
           ttl 3600;
       };
   };


In the above configuration, a PTR query for the name
``5.1.168.192.in-addr.arpa`` (representing the IPv4 address ``192.168.1.5``)
receives the synthesized response ``dynamic-192-168-1-5.example.``. Hyphens
replace dots in this address representation.

Similarly, a PTR query for the name
``e.f.a.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.f.a.c.ip6.arpa``
(representing the IPv6 address ``cafe::cafe``) receives the synthesized
response "dynamic-cafe--cafe.example." In this format, hyphens replace
colons; two consecutive hyphens are the same as two consecutive colons.
Note, however, that a DNS label cannot begin or end with a hyphen;
therefore, an address like ``::1`` would be represented as ``0--1``, and
``2001:db8::`` would be ``2001-db8--0``.

Finally, an AAAA query for ``dynamic-cafe--cafe.example`` would
receive a synthesized response with the IPv6 address ``cafe::cafe``, and
and an A query for ``dynamic-192-168-1-5.example`` would receive
``192.168.1.5``.

Parameters
~~~~~~~~~~

The following parameters are mandatory:

``mode``
   If ``reverse``, the module will synthesize responses when answering PTR
   queries. If ``forward``, it will synthesize responses when answering
   A/AAAA queries.

``prefix``
   Specifies the prefix of the synthesized name. It must be a single-label
   name.

``origin``
   Specifies the origin of the synthesized name. This may be the same as
   the zone origin, or a descendent. It cannot be below a delegation point.

The following parameters are optional:

``allow-synth``
   This option is an address-match list, which can be used to restrict
   response synthesis to certain addresses.  The default is ``any``,
   meaning that in reverse mode, any address within the zone can receive
   a synthesized answer, and in forward mode, any name with a parseable
   address encoded in it will return that address in an A or AAAA answer.
   Note that in reverse mode, at least some of the addresses within the
   zone's namespace must be allowed; otherwise the plugin will be unable
   to synthesize any responses.

``ttl``
   Specifies the TTL of the synthesized resource record in the answer
   section. The default is ``300``.

See Also
~~~~~~~~

BIND 9 Administrator Reference Manual.
