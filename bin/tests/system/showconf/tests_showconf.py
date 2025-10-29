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

import dns
import isctest


def test_showconf(ns1):
    # Basic testing of rndc showconf
    msg = isctest.query.create("a.example.com", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.rcode(res, dns.rcode.NOERROR)

    effectiveconfig = ns1.rndc("showconf -effective", log=False)
    assert 'zone "example.com"' in effectiveconfig
    assert 'view "_bind" chaos {' in effectiveconfig

    # builtin-trust-anchors is non documented and internal clause only, it must
    # not be visible.
    assert "builtin-trust-anchors" not in effectiveconfig

    # Dynamically added zones are not visible from the effectiveconfig
    zonedata = '"added.example" { type primary; file "example.db"; };'
    ns1.rndc(f"addzone {zonedata}", log=False)

    msg = isctest.query.create("a.added.example", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.rcode(res, dns.rcode.NOERROR)

    effectiveconfig = ns1.rndc("showconf -effective", log=False)
    assert 'zone "added.example"' not in effectiveconfig

    userconfig = ns1.rndc("showconf -user", log=False)
    assert 'zone "example.com"' in userconfig
    assert 'view "_bind" chaos {' not in userconfig

    builtinconfig = ns1.rndc("showconf -builtin", log=False)
    assert len(userconfig.split()) < len(builtinconfig.split())
    assert len(builtinconfig.split()) < len(effectiveconfig.split())

    # Errors handling
    error_msg = ""

    try:
        ns1.rndc("showconf -idontexist", log=False)
    except isctest.rndc.RNDCException as e:
        error_msg = str(e)
    assert error_msg == "rndc: 'showconf' failed: syntax error\n"

    try:
        ns1.rndc("showconf", log=False)
    except isctest.rndc.RNDCException as e:
        error_msg = str(e)
    assert error_msg == "rndc: 'showconf' failed: unexpected end of input\n"
