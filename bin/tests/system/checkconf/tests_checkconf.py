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


def test_checkconf_effective():
    proc = isctest.run.cmd([os.environ["CHECKCONF"], "-e", "effective.conf"])
    checkconf_output = proc.stdout.decode()
    assert "listen-on port 5353 {\n\t\t127.1.2.3/32;\n\t};" in checkconf_output
    assert 'view "_bind" chaos {' in checkconf_output
    assert 'view "foo" {\n}' in checkconf_output

    # builtin-trust-anchors is non documented and internal clause only, it must
    # not be visible.
    assert "builtin-trust-anchors" not in checkconf_output
