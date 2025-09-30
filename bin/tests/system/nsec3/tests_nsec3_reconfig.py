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

# pylint: disable=redefined-outer-name,unused-import

import os
import shutil
import time

import dns.update
import pytest

pytest.importorskip("dns", minversion="2.0.0")
import isctest
import isctest.mark
from isctest.vars.algorithms import RSASHA1
from nsec3.common import (
    ALGORITHM,
    SIZE,
    default_config,
    pytestmark,
    check_auth_nsec,
    check_auth_nsec3,
    check_nsec3param,
)


@pytest.fixture(scope="module", autouse=True)
def after_servers_start(ns3, templates):

    def wait_for_soa_update():
        match = "20 20 1814400 900"

        for _ in range(5):
            query = isctest.query.create(fqdn, dns.rdatatype.SOA)
            response = isctest.query.tcp(query, ns3.ip)
            rrset = response.get_rrset(
                response.answer,
                dns.name.from_text(fqdn),
                dns.rdataclass.IN,
                dns.rdatatype.SOA,
            )
            if match in str(rrset[0]):
                return True

        return False

    # Extra test for nsec3-change.kasp.
    zone = "nsec3-change.kasp"
    nsdir = ns3.identifier
    fqdn = f"{zone}."
    isctest.kasp.wait_keymgr_done(ns3, zone)
    shutil.copyfile(f"{nsdir}/template2.db.in", f"{nsdir}/{zone}.db")
    ns3.rndc(f"reload {zone}")

    isctest.run.retry_with_timeout(wait_for_soa_update, timeout=5)
    # After reconfig, the NSEC3PARAM TTL should match the new SOA MINIMUM.

    # Ensure rsasha1-to-nsec3-wait.kasp is fully signed prior to reconfig.
    with_rsasha1 = "RSASHA1_SUPPORTED"
    assert with_rsasha1 in os.environ, f"{with_rsasha1} env variable undefined"
    if os.getenv(with_rsasha1) == "1":
        zone = "rsasha1-to-nsec3-wait.kasp"
        isctest.kasp.check_dnssec_verify(ns3, zone)

    # Reconfigure.
    templates.render(f"{nsdir}/named-fips.conf", {"reconfiged": True})
    templates.render(f"{nsdir}/named-rsasha1.conf", {"reconfiged": True})
    ns3.reconfigure()


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3-wait.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="rsasha1-to-nsec3-wait.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:hidden dnskey:unretentive krrsig:unretentive zrrsig:unretentive ds:hidden",
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-rsasha1.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1-ds.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:hidden dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-rsasha1-ds.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3-to-nsec.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-nsec.kasp",
        ),
    ],
)
def test_nsec_case(ns3, params):
    # Get test parameters.
    zone = params["zone"]
    fqdn = f"{zone}."
    policy = params["policy"]
    keydir = ns3.identifier
    config = default_config
    ttl = int(config["dnskey-ttl"].total_seconds())
    expected = isctest.kasp.policy_to_properties(ttl=ttl, keys=params["key-properties"])

    # Test case.
    isctest.log.info(f"check nsec case zone {zone} policy {policy}")

    # First make sure the zone is properly signed.
    isctest.kasp.wait_keymgr_done(ns3, zone, reconfig=True)

    # Key files.
    keys = isctest.kasp.keydir_to_keylist(zone, keydir)

    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_dnssec_verify(ns3, zone)
    isctest.kasp.check_apex(ns3, zone, keys, [])

    query = isctest.query.create(fqdn, dns.rdatatype.NSEC3PARAM)
    response = isctest.query.tcp(query, ns3.ip)
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 0
    check_auth_nsec(response)

    query = isctest.query.create(f"nosuchname.{fqdn}", dns.rdatatype.A)
    response = isctest.query.tcp(query, ns3.ip)
    assert response.rcode() == dns.rcode.NXDOMAIN
    check_auth_nsec(response)


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "nsec-to-nsec3.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec-to-nsec3.kasp",
        ),
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:hidden dnskey:unretentive krrsig:unretentive zrrsig:unretentive ds:hidden",
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="rsasha1-to-nsec3.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-change.kasp",
                "policy": "nsec3",
                "soa-minimum": 900,
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 8,
                },
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-change.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-change.kasp",
                "policy": "nsec3-other",
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 8,
                },
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-change.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-to-inline.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-to-inline.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-inline-to-dynamic.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-inline-to-dynamic.kasp",
        ),
        # DISABLED:
        # There is a bug in the nsec3param building code that thinks when the
        # optout bit is changed, the chain already exists. [GL #2216]
        # pytest.param(
        #    {
        #        "zone": "nsec3-to-optout.kasp",
        #        "policy": "nsec3",
        #        "nsec3param": {
        #            "optout": 1,
        #            "salt-length": 0,
        #        },
        #        "key-properties": [
        #            f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
        #        ],
        #    },
        #    id="nsec3-to-optout.kasp",
        # ),
        # DISABLED:
        # There is a bug in the nsec3param building code that thinks when the
        # optout bit is changed, the chain already exists. [GL #2216]
        # pytest.param(
        #    {
        #        "zone": "nsec3-from-optout.kasp",
        #        "policy": "optout",
        #        "key-properties": [
        #            f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
        #        ],
        #    },
        #    id="nsec3-from-optout.kasp",
        # ),
        pytest.param(
            {
                "zone": "nsec3-other.kasp",
                "policy": "nsec3-other",
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 8,
                },
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-other.kasp",
        ),
    ],
)
def test_nsec3_case(ns3, params):
    # Get test parameters.
    zone = params["zone"]
    fqdn = f"{zone}."
    policy = params["policy"]
    keydir = ns3.identifier
    config = default_config
    ttl = int(config.get("dnskey-ttl", 3600).total_seconds())
    minimum = params.get("soa-minimum", 3600)
    expected = isctest.kasp.policy_to_properties(ttl=ttl, keys=params["key-properties"])

    iterations = 0
    optout = 0
    saltlen = 0
    if "nsec3param" in params:
        optout = params["nsec3param"].get("optout", 0)
        saltlen = params["nsec3param"].get("salt-length", 0)

    match = f"{fqdn} {minimum} IN NSEC3PARAM 1 0 {iterations}"

    # Test case.
    isctest.log.info(f"check nsec3 case zone {zone} policy {policy}")

    # First make sure the zone is properly signed.
    isctest.kasp.wait_keymgr_done(ns3, zone, reconfig=True)

    keys = isctest.kasp.keydir_to_keylist(zone, keydir)
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_dnssec_verify(ns3, zone)
    isctest.kasp.check_apex(ns3, zone, keys, [])

    query = isctest.query.create(fqdn, dns.rdatatype.NSEC3PARAM)
    response = isctest.query.tcp(query, ns3.ip)
    assert response.rcode() == dns.rcode.NOERROR

    salt = check_nsec3param(response, match, saltlen)

    query = isctest.query.create(f"nosuchname.{fqdn}", dns.rdatatype.A)
    response = isctest.query.tcp(query, ns3.ip)
    assert response.rcode() == dns.rcode.NXDOMAIN
    check_auth_nsec3(response, iterations, optout, salt)

    # Extra test for nsec3-change.kasp.
    if zone == "nsec3-change.kasp":
        # Using rndc signing -nsec3param (should fail)
        isctest.log.info(
            f"use rndc signing -nsec3param {zone} to change NSEC3 settings"
        )
        response = ns3.rndc(f"signing -nsec3param 1 1 12 ffff {zone}")
        assert "zone uses dnssec-policy, use rndc dnssec command instead" in response
