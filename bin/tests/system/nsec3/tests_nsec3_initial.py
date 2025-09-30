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

import shutil

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


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "nsec-to-nsec3.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec-to-nsec3.kasp",
        ),
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="rsasha1-to-nsec3.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "rsasha1-to-nsec3-wait.kasp",
                "policy": "rsasha1",
                "key-properties": [
                    f"csk 0 {RSASHA1.number} 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="rsasha1-to-nsec3-wait.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                # This is a secondary zone, where the primary is signed with
                # NSEC3 but the dnssec-policy dictates NSEC.
                "zone": "nsec3-xfr-inline.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
                "external-keys": [
                    f"csk 0 {ALGORITHM} {SIZE}",
                ],
                "external-keydir": "ns2",
            },
            id="nsec3-xfr-inline.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-update-inline.kasp",
                "policy": "nsec",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-dynamic-update-inline.kasp",
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
    isctest.kasp.wait_keymgr_done(ns3, zone)

    # Key files.
    keys = isctest.kasp.keydir_to_keylist(zone, keydir)
    if "external-keys" in params:
        expected2 = isctest.kasp.policy_to_properties(ttl, keys=params["external-keys"])
        for ek in expected2:
            ek.private = False  # noqa
            ek.legacy = True  # noqa
        expected = expected + expected2
        assert "external-keydir" in params
        extkeys = isctest.kasp.keydir_to_keylist(zone, params["external-keydir"])
        keys = keys + extkeys

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

    # Extra test for nsec3-dynamic-update-inline.kasp.
    if zone == "nsec3-dynamic-update-inline.kasp":
        isctest.log.info(f"dynamic update dnssec-policy zone {zone} with NSEC3")
        update_msg = dns.update.UpdateMessage(zone)
        update_msg.add(
            f"04O18462RI5903H8RDVL0QDT5B528DUJ.{zone}.",
            3600,
            "NSEC3",
            "0 0 0 408A4B2D412A4E95 1JMDDPMTFF8QQLIOINSIG4CR9OTICAOC A RRSIG",
        )

        with ns3.watch_log_from_here() as watcher:
            ns3.nsupdate(update_msg, expected_rcode=dns.rcode.REFUSED)
            watcher.wait_for_line(
                f"updating zone '{zone}/IN': update failed: explicit NSEC3 updates are not allowed in secure zones (REFUSED)"
            )


def wait_for_soa_update(server, fqdn):
    verified = False
    match = f"20 20 1814400 900"

    for _ in range(5):
        query = isctest.query.create(fqdn, dns.rdatatype.SOA)
        response = isctest.query.tcp(query, server.ip, server.ports.dns, timeout=3)
        for rrset in response.answer:
            if match in rrset.to_text():
                verified = True

        if verified:
            break

        time.sleep(1)

    return verified


@pytest.mark.parametrize(
    "params",
    [
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-rsasha1.kasp",
            marks=isctest.mark.with_algorithm("RSASHA1"),
        ),
        pytest.param(
            {
                "zone": "nsec3-to-rsasha1-ds.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:omnipresent krrsig:omnipresent zrrsig:omnipresent ds:omnipresent",
                ],
            },
            id="nsec3-to-rsasha1-ds.kasp",
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
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-change.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-dynamic-change.kasp",
                "policy": "nsec3",
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
        pytest.param(
            {
                "zone": "nsec3-to-nsec.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-nsec.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-to-optout.kasp",
                "policy": "nsec3",
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-to-optout.kasp",
        ),
        pytest.param(
            {
                "zone": "nsec3-from-optout.kasp",
                "policy": "optout",
                "nsec3param": {
                    "optout": 1,
                    "salt-length": 0,
                },
                "key-properties": [
                    f"csk 0 {ALGORITHM} {SIZE} goal:omnipresent dnskey:rumoured krrsig:rumoured zrrsig:rumoured ds:hidden",
                ],
            },
            id="nsec3-from-optout.kasp",
        ),
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
    ttl = int(config["dnskey-ttl"].total_seconds())
    expected = isctest.kasp.policy_to_properties(ttl=ttl, keys=params["key-properties"])

    iterations = 0
    optout = 0
    saltlen = 0
    if "nsec3param" in params:
        optout = params["nsec3param"].get("optout", 0)
        saltlen = params["nsec3param"].get("salt-length", 0)

    match = f"{fqdn} 3600 IN NSEC3PARAM 1 0 {iterations}"

    # Test case.
    isctest.log.info(f"check nsec3 case zone {zone} policy {policy}")

    # First make sure the zone is properly signed.
    isctest.kasp.wait_keymgr_done(ns3, zone)

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

        shutil.copyfile(
            f"{ns3.identifier}/template2.db.in", f"{ns3.identifier}/{zone}.db"
        )
        ns3.rndc(f"reload {zone}")

        wait_for_soa_update(ns3, fqdn)
        # After reconfig, the NSEC3PARAM TTL should match the new SOA MINIMUM.
