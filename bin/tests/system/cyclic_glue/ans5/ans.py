"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from dns import name, rcode, rdataclass, rdatatype, rrset

from isctest.asyncserver import AsyncDnsServer, QnameHandler, StaticResponseHandler


def build_rrset(
    qname: name.Name | str,
    rtype: rdatatype.RdataType,
    rdata: str,
    ttl: int = 300,
) -> rrset.RRset:
    return rrset.from_text(qname, ttl, rdataclass.IN, rtype, rdata)


class BrokenFooHandler(QnameHandler, StaticResponseHandler):
    qnames = ["a.foo.test."]
    qtypes = [rdatatype.A]
    authority = [
        build_rrset("foo.test.", rdatatype.NS, "ns.foo.test."),
        build_rrset("foo.test.", rdatatype.NS, "ns.bar.test."),
        build_rrset("foo.test.", rdatatype.NS, "ns.test2."),
    ]
    additional = [
        build_rrset("ns.foo.test.", rdatatype.A, "10.53.0.3"),
        # These glues don't belong, as they're outside the
        # delegated domain. However, only the latest will be
        # ignored by the resolver (the former, being a sibling
        # glue, is still used.)
        build_rrset("ns.bar.test.", rdatatype.A, "10.53.0.3"),
        build_rrset("ns.test2.", rdatatype.A, "10.10.10.10"),
    ]


class BrokenBarHandler(QnameHandler, StaticResponseHandler):
    qnames = ["a.bar.test."]
    qtypes = [rdatatype.A]
    authority = [
        build_rrset("bar.test.", rdatatype.NS, "ns.bar.test."),
        # This NS is valid but outside the bar.test domain.
        build_rrset("bar.test.", rdatatype.NS, "ns2.foo.test."),
        # This NS is wrong, it's not the qname.
        # It will be ignored by the resolver.
        build_rrset("bar.test2.", rdatatype.NS, "ns.test2."),
    ]
    additional = [
        build_rrset("ns.bar.test.", rdatatype.A, "10.53.0.3"),
        build_rrset("ns2.foo.test.", rdatatype.A, "10.53.0.4"),
        # The glue is then ignored as well, is it doesn't match
        # any of the valid NS above.
        build_rrset("ns.test2.", rdatatype.A, "10.10.10.10"),
    ]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=rcode.NOERROR)
    server.install_response_handlers(BrokenFooHandler(), BrokenBarHandler())
    server.run()


if __name__ == "__main__":
    main()
