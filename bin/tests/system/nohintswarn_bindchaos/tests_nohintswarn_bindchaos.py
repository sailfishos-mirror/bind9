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


def test_nohintswarn_bindchaos(ns1):
    found = True
    try:
        with ns1.watch_log_from_start(timeout=1) as watcher:
            watcher.wait_for_line("no root hints for view '_bind'")
    except isctest.log.watchlog.WatchLogTimeout:
        found = False
    assert found is False

    with ns1.watch_log_from_start() as watcher:
        watcher.wait_for_line("no root hints for view 'bar'")
