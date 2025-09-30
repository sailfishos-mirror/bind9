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

import dns.update
import pytest

pytest.importorskip("dns", minversion="2.0.0")
import isctest
import isctest.mark
from nsec3.common import (
    ALGORITHM,
    SIZE,
    default_config,
    pytestmark,
    check_auth_nsec3,
    check_nsec3param,
)


def perform_nsec3_tests(server, params):
    # Get test parameters.
    zone = params["zone"]
    fqdn = f"{zone}."
    policy = params["policy"]
    keydir = server.identifier
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
    isctest.kasp.wait_keymgr_done(server, zone)

    keys = isctest.kasp.keydir_to_keylist(zone, keydir)
    isctest.kasp.check_keys(zone, keys, expected)
    isctest.kasp.check_dnssec_verify(server, zone)
    isctest.kasp.check_apex(server, zone, keys, [])

    query = isctest.query.create(fqdn, dns.rdatatype.NSEC3PARAM)
    response = isctest.query.tcp(query, server.ip)
    assert response.rcode() == dns.rcode.NOERROR

    salt = check_nsec3param(response, match, saltlen)

    query = isctest.query.create(f"nosuchname.{fqdn}", dns.rdatatype.A)
    response = isctest.query.tcp(query, server.ip)
    assert response.rcode() == dns.rcode.NXDOMAIN
    check_auth_nsec3(response, iterations, optout, salt)

    return salt


@pytest.mark.parametrize(
    "params",
    [
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
    zone = params["zone"]
    salt = perform_nsec3_tests(ns3, params)

    # Test NSEC3 and NSEC3PARAM is the same after restart
    isctest.log.info(f"check zone {zone} after restart has salt {salt}")
    prevsalt = salt

    # Restart named, NSEC3 should stay the same.
    ns3.stop()
    ns3.start(["--noclean", "--restart", "--port", os.environ["PORT"]])

    salt = perform_nsec3_tests(ns3, params)
    assert prevsalt == salt
