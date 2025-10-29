# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from typing import AsyncGenerator

import dns
import dns.tsigkeyring

from isctest.asyncserver import (
    AsyncDnsServer,
    ResponseHandler,
    DnsResponseSend,
    DnsProtocol,
    QueryContext,
)

from isctest.name import prepend_label
from isctest.vars.algorithms import ALG_VARS

KEYRING = dns.tsigkeyring.from_text(
    {
        "foo": (ALG_VARS["DEFAULT_HMAC"], "aaaaaaaaaaaa"),
        "fake": (ALG_VARS["DEFAULT_HMAC"], "aaaaaaaaaaaa"),
    }
)


def _reparse_with_keyring(qctx: QueryContext) -> None:
    """
    `isctest.asyncserver` doesn't support TSIG signing and validation properly
    and hacks around it. However, here we need to be able to sign responses with
    TSIG, so we reparse the query and recreate the response stub here.
    """
    qctx.query = dns.message.from_wire(qctx.query.to_wire(), keyring=KEYRING)
    qctx.response = dns.message.make_response(qctx.query)


def _first_label(qctx: QueryContext) -> str:
    return qctx.qname.labels[0].decode("ascii")


def _add_cookie(qctx: QueryContext) -> None:
    for o in qctx.query.options:
        if o.otype == dns.edns.OptionType.COOKIE:
            cookie = o
            try:
                if len(cookie.server) == 0:
                    cookie.server = cookie.client
            except AttributeError:  # dnspython<2.7.0 compat
                if len(o.data) == 8:
                    cookie.data *= 2

            qctx.response.use_edns(options=[cookie])
            return


def _tld(qctx: QueryContext) -> dns.name.Name:
    return dns.name.Name(qctx.qname.labels[-2:])


def _soa(qctx: QueryContext) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        _tld(qctx), 2, dns.rdataclass.IN, dns.rdatatype.SOA, ". . 0 0 0 0 2"
    )


def _ns_name(qctx: QueryContext) -> dns.name.Name:
    return prepend_label("ns", _tld(qctx))


def _ns(qctx: QueryContext) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        qctx.qname,
        1,
        dns.rdataclass.IN,
        dns.rdatatype.NS,
        _ns_name(qctx).to_text(),
    )


def _legit_a(qctx: QueryContext) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        qctx.qname, 1, dns.rdataclass.IN, dns.rdatatype.A, "10.53.0.9"
    )


def _spoofed_a(qctx: QueryContext) -> dns.rrset.RRset:
    return dns.rrset.from_text(
        qctx.qname, 1, dns.rdataclass.IN, dns.rdatatype.A, "10.53.0.10"
    )


class _SpoofableHandler(ResponseHandler):
    def __init__(self, evil_server: bool) -> None:
        self.evil_server = evil_server


class NsHandler(_SpoofableHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS and qctx.qname == _tld(qctx)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        _add_cookie(qctx)
        qctx.response.answer.append(_ns(qctx))
        if self.evil_server:
            qctx.response.authority.append(_spoofed_a(qctx))
        else:
            qctx.response.authority.append(_legit_a(qctx))
        yield DnsResponseSend(qctx.response, authoritative=True)


class GlueHandler(_SpoofableHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A and qctx.qname == _ns_name(qctx)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        _add_cookie(qctx)
        if self.evil_server:
            qctx.response.answer.append(_spoofed_a(qctx))
        else:
            qctx.response.answer.append(_legit_a(qctx))
        yield DnsResponseSend(qctx.response, authoritative=True)


class TcpAHandler(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A and qctx.protocol == DnsProtocol.TCP

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        if _first_label(qctx) != "nocookie":
            _add_cookie(qctx)
        qctx.response.answer.append(_legit_a(qctx))
        yield DnsResponseSend(qctx.response, authoritative=True)


class WithtsigUdpAHandler(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return (
            qctx.qtype == dns.rdatatype.A
            and qctx.protocol == DnsProtocol.UDP
            and _first_label(qctx) == "withtsig"
        )

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        qctx.response.answer.append(_legit_a(qctx))
        qctx.response.answer.append(_spoofed_a(qctx))
        qctx.response.use_tsig(keyring=KEYRING, keyname="fake")
        yield DnsResponseSend(qctx.response, authoritative=True)

        _reparse_with_keyring(qctx)
        _add_cookie(qctx)
        qctx.response.answer.append(_legit_a(qctx))
        yield DnsResponseSend(qctx.response, authoritative=True)


class UdpAHandler(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A and qctx.protocol == DnsProtocol.UDP

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        qctx.response.answer.append(_legit_a(qctx))
        if _first_label(qctx) not in ("nocookie", "tcponly"):
            _add_cookie(qctx)
        else:
            qctx.response.answer.append(_spoofed_a(qctx))

        yield DnsResponseSend(qctx.response, authoritative=True)


class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        _reparse_with_keyring(qctx)
        _add_cookie(qctx)
        if qctx.qtype == dns.rdatatype.SOA:
            qctx.response.answer.append(_soa(qctx))
        else:
            qctx.response.authority.append(_soa(qctx))
        yield DnsResponseSend(qctx.response, authoritative=True)


def cookie_server(evil: bool) -> AsyncDnsServer:
    server = AsyncDnsServer(acknowledge_tsig_dnspython_hacks=True)
    server.install_response_handler(NsHandler(evil))
    server.install_response_handler(GlueHandler(evil))
    server.install_response_handler(TcpAHandler())
    server.install_response_handler(WithtsigUdpAHandler())
    server.install_response_handler(UdpAHandler())
    server.install_response_handler(FallbackHandler())
    return server
