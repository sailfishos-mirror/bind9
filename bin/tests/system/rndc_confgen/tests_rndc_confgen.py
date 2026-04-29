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
import subprocess

import pytest

import isctest

INJECTION = (
    'backdoor" { algorithm hmac-sha256; '
    'secret "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }; key "rndc-key'
)


def test_rndc_confgen_default():
    cmd = isctest.run.cmd([os.environ["RNDCCONFGEN"]])
    assert b'key "rndc-key" {' in cmd.proc.stdout


def test_rndc_confgen_keyname_with_dots():
    cmd = isctest.run.cmd([os.environ["RNDCCONFGEN"], "-k", "key.example.com"])
    assert b'key "key.example.com" {' in cmd.proc.stdout


def test_rndc_confgen_rejects_injection():
    with pytest.raises(subprocess.CalledProcessError):
        isctest.run.cmd([os.environ["RNDCCONFGEN"], "-k", INJECTION])


def test_tsig_keygen_default():
    cmd = isctest.run.cmd([os.environ["TSIGKEYGEN"]])
    assert b'key "tsig-key" {' in cmd.proc.stdout


def test_tsig_keygen_rejects_injection_positional():
    with pytest.raises(subprocess.CalledProcessError):
        isctest.run.cmd([os.environ["TSIGKEYGEN"], INJECTION])


DDNSCONFGEN = "./ddns-confgen"


def test_ddns_confgen_default():
    cmd = isctest.run.cmd([DDNSCONFGEN, "-q"])
    assert b'key "ddns-key" {' in cmd.proc.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["-k", INJECTION],
        ["-y", INJECTION],
        ["-z", INJECTION],
        ["-s", INJECTION],
    ],
)
def test_ddns_confgen_rejects_injection(args):
    with pytest.raises(subprocess.CalledProcessError):
        isctest.run.cmd([DDNSCONFGEN, "-q", *args])
