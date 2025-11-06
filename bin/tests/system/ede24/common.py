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


def check_ns2_ready(ns2):
    # Sanity check that everything works first, once we're sure the foo.fr zone
    # has transfered to ns2.
    with ns2.watch_log_from_start() as watcher:
        watcher.wait_for_line("Transfer status: success")
    check_soa_noerror()
