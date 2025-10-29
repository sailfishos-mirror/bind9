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

import isctest


def check_soa_noerror():
    msg = isctest.query.create("foo.fr", "SOA")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.noerror(res)


def check_soa_servfail_ede24(edemsg):
    msg = isctest.query.create("foo.fr", "SOA")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.servfail(res)

    # Few CI machines uses old version of dnspython which doesn't supports
    # EDNS, so we effectively bypass the check for those one. (It's fine, a
    # bunch of other CI machines _does_ have recent version of dnspython).
    if hasattr(res, "extended_errors"):
        assert len(res.extended_errors()) == 1
        assert res.extended_errors()[0].to_text() == f"EDE 24 (Invalid Data): {edemsg}"


def test_ede24_noloaded(ns1, ns2):
    # Sanity check that everything works first
    check_soa_noerror()

    # Stop all servers, and we'll restart only ns2.
    ns1.stop()
    ns2.stop()
    with ns2.watch_log_from_here() as watcher:
        ns2.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line("failure trying primary 10.53.0.1")

    # ns2 attempts an XFR but ns1 since is off the zone DB can't be loaded.
    check_soa_servfail_ede24("zone not loaded")


def test_ede24_expired(ns1, ns2):
    # Restart ns1 then checks the server notify the zone in ns2 and ns2 serves
    # the zone again.
    with ns2.watch_log_from_here() as watcher:
        ns1.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line("Transfer status: success")
    check_soa_noerror()

    # Stop the primary and wait for expiration of the zone in the secondary.
    with ns2.watch_log_from_here() as watcher:
        ns1.stop()
        watcher.wait_for_line(" zone foo.fr/IN: expired")

    # ns2 can't answer anymore.
    check_soa_servfail_ede24("zone expired")

    # Restart the primary and wait for the zone to be back up again.
    with ns2.watch_log_from_here() as watcher:
        ns1.start(["--noclean", "--restart", "--port", os.environ["PORT"]])
        watcher.wait_for_line("Transfer status: success")
    check_soa_noerror()
