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

import os

from datetime import timedelta

import dns
import pytest

pytestmark = pytest.mark.extra_artifacts(
    [
        "*.axfr",
        "*.created",
        "dig.out.*",
        "rndc.reload.*",
        "rndc.signing.*",
        "update.out.*",
        "verify.out.*",
        "ns*/dsset-**",
        "ns*/K*",
        "ns*/settime.out.*",
        "ns*/*.db",
        "ns*/*.jbk",
        "ns*/*.jnl",
        "ns*/*.signed",
        "ns*/keygen.out.*",
        "ns3/named-common.conf",
        "ns3/named-fips.conf",
        "ns3/named-rsasha1.conf",
    ]
)

ALGORITHM = os.environ["DEFAULT_ALGORITHM_NUMBER"]
SIZE = os.environ["DEFAULT_BITS"]

default_config = {
    "dnskey-ttl": timedelta(hours=1),
    "ds-ttl": timedelta(days=1),
    "max-zone-ttl": timedelta(days=1),
    "parent-propagation-delay": timedelta(hours=1),
    "publish-safety": timedelta(hours=1),
    "retire-safety": timedelta(hours=1),
    "signatures-refresh": timedelta(days=5),
    "signatures-validity": timedelta(days=14),
    "zone-propagation-delay": timedelta(minutes=5),
}


def check_auth_nsec(response):
    rrs = []
    for rrset in response.authority:
        if rrset.match(dns.rdataclass.IN, dns.rdatatype.NSEC, dns.rdatatype.NONE):
            rrs.append(rrset)
        assert not rrset.match(
            dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE
        )
    assert len(rrs) != 0, "no NSEC records found in authority section"


def check_auth_nsec3(response, iterations=0, optout=0, saltlen=0):
    match = f"IN NSEC3 1 {optout} {iterations}"
    rrs = []

    for rrset in response.authority:
        if rrset.match(dns.rdataclass.IN, dns.rdatatype.NSEC3, dns.rdatatype.NONE):
            assert match in rrset.to_text()
            if saltlen == 0:
                assert f"{match} -" in rrset.to_text()
            else:
                assert not f"{match} -" in rrset.to_text()

            rrs.append(rrset)
        assert not rrset.match(
            dns.rdataclass.IN, dns.rdatatype.NSEC, dns.rdatatype.NONE
        )

    assert len(rrs) != 0, "no NSEC3 records found in authority section"


def check_nsec3param(response, match, saltlen):
    rrs = []

    for rrset in response.answer:
        if rrset.match(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, dns.rdatatype.NONE):
            assert match in rrset.to_text()
            if saltlen == 0:
                assert f"{match} -" in rrset.to_text()
            else:
                assert not f"{match} -" in rrset.to_text()

            rrs.append(rrset)
        else:
            assert rrset.match(
                dns.rdataclass.IN, dns.rdatatype.RRSIG, dns.rdatatype.NSEC3PARAM
            )

    assert len(rrs) != 0
