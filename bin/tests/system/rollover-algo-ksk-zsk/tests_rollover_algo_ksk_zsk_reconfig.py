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

import pytest

import isctest
from isctest.kasp import KeyTimingMetadata
from isctest.util import param
from rollover.common import (
    pytestmark,
    alg,
    size,
    CDSS,
    ALGOROLL_CONFIG,
    ALGOROLL_IPUB,
    ALGOROLL_IPUBC,
    ALGOROLL_IRET,
    ALGOROLL_IRETKSK,
    ALGOROLL_KEYTTLPROP,
    ALGOROLL_OFFSETS,
    ALGOROLL_OFFVAL,
    DURATION,
    TIMEDELTA,
)

CONFIG = ALGOROLL_CONFIG
POLICY = "ecdsa256"
TIME_PASSED = 0  # set in reconfigure() fixture


@pytest.fixture(scope="module", autouse=True)
def reconfigure(ns6, templates):
    global TIME_PASSED  # pylint: disable=global-statement

    isctest.kasp.wait_keymgr_done(ns6, "step1.algorithm-roll.kasp")

    templates.render("ns6/named.conf", {"alg_roll": True})
    start_time = KeyTimingMetadata.now()
    ns6.reconfigure()

    # Calculate time passed to correctly check for next key events.
    TIME_PASSED = KeyTimingMetadata.now().value - start_time.value


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step1(tld, ns6, alg, size):
    zone = f"step1.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    if tld == "manual":
        # Same as initial.
        step = {
            "zone": zone,
            "cdss": CDSS,
            "keyprops": [
                f"ksk 0 8 2048 goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{-DURATION['P7D']}",
                f"zsk 0 8 2048 goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{-DURATION['P7D']}",
            ],
            "manual-mode": True,
            "nextev": None,
        }
        keys = isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)

        # Check logs.
        ktag = keys[0].key.tag
        ztag = keys[1].key.tag
        msg1 = f"keymgr-manual-mode: block retire DNSKEY {zone}/RSASHA256/{ktag} (KSK)"
        msg2 = f"keymgr-manual-mode: block retire DNSKEY {zone}/RSASHA256/{ztag} (ZSK)"
        msg3 = f"keymgr-manual-mode: block new key generation for zone {zone} (policy {policy})"  # twice
        ns6.log.expect(msg1)
        ns6.log.expect(msg2)
        ns6.log.expect(msg3)

        # Force step.
        with ns6.watch_log_from_here() as watcher:
            ns6.rndc(f"dnssec -step {zone}")
            watcher.wait_for_line(f"keymgr: {zone} done")

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The RSASHA keys are outroducing.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            # The ECDSAP256SHA256 keys are introducing.
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:rumoured krrsig:rumoured ds:hidden",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:rumoured zrrsig:rumoured",
        ],
        # Next key event is when the ecdsa256 keys have been propagated.
        "nextev": ALGOROLL_IPUB,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step2(tld, ns6, alg, size):
    zone = f"step2.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    # manual-mode: Nothing changing in the zone, no 'dnssec -step' required.

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The RSASHA keys are outroducing, but need to stay present
            # until the new algorithm chain of trust has been established.
            # Thus the expected key states of these keys stay the same.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            # The ECDSAP256SHA256 keys are introducing. The DNSKEY RRset is
            # omnipresent, but the zone signatures are not.
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:hidden offset:{ALGOROLL_OFFSETS['step2']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:rumoured offset:{ALGOROLL_OFFSETS['step2']}",
        ],
        # Next key event is when all zone signatures are signed with the new
        # algorithm.  This is the max-zone-ttl plus zone propagation delay.  But
        # the publication interval has already passed. Also, prevent intermittent
        # false positives on slow platforms by subtracting the time passed between
        # key creation and invoking 'rndc reconfig'.
        "nextev": ALGOROLL_IPUBC - ALGOROLL_IPUB - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step3(tld, ns6, alg, size):
    zone = f"step3.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    if tld == "manual":
        # Same as step 2, but the zone signatures have become OMNIPRESENT.
        step = {
            "zone": zone,
            "cdss": CDSS,
            "keyprops": [
                f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFVAL}",
                f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
                f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:hidden offset:{ALGOROLL_OFFSETS['step3']}",
                f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step3']}",
            ],
            "manual-mode": True,
            "nextev": None,
        }
        keys = isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)

        # Check logs.
        tag = keys[2].key.tag
        msg = f"keymgr-manual-mode: block transition KSK {zone}/ECDSAP256SHA256/{tag} type DS state HIDDEN to state RUMOURED"
        ns6.log.expect(msg)

        # Force step.
        with ns6.watch_log_from_here() as watcher:
            ns6.rndc(f"dnssec -step {zone}")
            watcher.wait_for_line(f"keymgr: {zone} done")

        # Check logs.
        tag = keys[0].key.tag
        msg = f"keymgr-manual-mode: block transition KSK {zone}/RSASHA256/{tag} type DS state OMNIPRESENT to state UNRETENTIVE"
        if msg in ns6.log:
            # Force step.
            isctest.log.debug(
                f"keymgr-manual-mode blocking transition CSK {zone}/RSASHA256/{tag} type DS state OMNIPRESENT to state UNRETENTIVE, step again"
            )
            with ns6.watch_log_from_here() as watcher:
                ns6.rndc(f"dnssec -step {zone}")
                watcher.wait_for_line(f"keymgr: {zone} done")

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The DS can be swapped.
            f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:unretentive offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:rumoured offset:{ALGOROLL_OFFSETS['step3']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step3']}",
        ],
        # Next key event is when the DS becomes OMNIPRESENT. This happens
        # after the retire interval.
        "nextev": ALGOROLL_IRETKSK - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step4(tld, ns6, alg, size):
    zone = f"step4.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    if tld == "manual":
        # Same as step 3, but the DS has become HIDDEN/OMNIPRESENT.
        step = {
            "zone": zone,
            "cdss": CDSS,
            "keyprops": [
                f"ksk 0 8 2048 goal:hidden dnskey:omnipresent krrsig:omnipresent ds:hidden offset:{ALGOROLL_OFFVAL}",
                f"zsk 0 8 2048 goal:hidden dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFVAL}",
                f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
                f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
            ],
            "manual-mode": True,
            "nextev": None,
        }
        keys = isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)

        # Check logs.
        ktag = keys[0].key.tag
        ztag = keys[1].key.tag
        msg1 = f"keymgr-manual-mode: block transition KSK {zone}/RSASHA256/{ktag} type DNSKEY state OMNIPRESENT to state UNRETENTIVE"
        msg2 = f"keymgr-manual-mode: block transition ZSK {zone}/RSASHA256/{ztag} type DNSKEY state OMNIPRESENT to state UNRETENTIVE"
        ns6.log.expect(msg1)
        ns6.log.expect(msg2)

        # Force step.
        with ns6.watch_log_from_here() as watcher:
            ns6.rndc(f"dnssec -step {zone}")
            watcher.wait_for_line(f"keymgr: {zone} done")

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The old DS is HIDDEN, we can remove the old algorithm records.
            f"ksk 0 8 2048 goal:hidden dnskey:unretentive krrsig:unretentive ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:unretentive zrrsig:unretentive offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step4']}",
        ],
        # Next key event is when the old DNSKEY becomes HIDDEN.
        # This happens after the DNSKEY TTL plus zone propagation delay.
        "nextev": ALGOROLL_KEYTTLPROP,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step5(tld, ns6, alg, size):
    zone = f"step5.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    # manual-mode: Nothing changing in the zone, no 'dnssec -step' required.

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The DNSKEY becomes HIDDEN.
            f"ksk 0 8 2048 goal:hidden dnskey:hidden krrsig:hidden ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:hidden zrrsig:unretentive offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step5']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step5']}",
        ],
        # Next key event is when the RSASHA signatures become HIDDEN.
        # This happens after the max-zone-ttl plus zone propagation delay
        # minus the time already passed since the UNRETENTIVE state has
        # been reached. Prevent intermittent false positives on slow
        # platforms by subtracting the number of seconds which passed
        # between key creation and invoking 'rndc reconfig'.
        "nextev": ALGOROLL_IRET - ALGOROLL_IRETKSK - ALGOROLL_KEYTTLPROP - TIME_PASSED,
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)


@pytest.mark.parametrize(
    "tld",
    [
        param("kasp"),
        param("manual"),
    ],
)
def test_algoroll_ksk_zsk_reconfig_step6(tld, ns6, alg, size):
    zone = f"step6.algorithm-roll.{tld}"
    policy = f"{POLICY}-{tld}"

    isctest.kasp.wait_keymgr_done(ns6, zone, reconfig=True)

    # manual-mode: Nothing changing in the zone, no 'dnssec -step' required.

    step = {
        "zone": zone,
        "cdss": CDSS,
        "keyprops": [
            # The zone signatures are now HIDDEN.
            f"ksk 0 8 2048 goal:hidden dnskey:hidden krrsig:hidden ds:hidden offset:{ALGOROLL_OFFVAL}",
            f"zsk 0 8 2048 goal:hidden dnskey:hidden zrrsig:hidden offset:{ALGOROLL_OFFVAL}",
            f"ksk 0 {alg} {size} goal:omnipresent dnskey:omnipresent krrsig:omnipresent ds:omnipresent offset:{ALGOROLL_OFFSETS['step6']}",
            f"zsk 0 {alg} {size} goal:omnipresent dnskey:omnipresent zrrsig:omnipresent offset:{ALGOROLL_OFFSETS['step6']}",
        ],
        # Next key event is never since we established the policy and the
        # keys have an unlimited lifetime.  Fallback to the default
        # loadkeys interval.
        "nextev": TIMEDELTA["PT1H"],
    }
    isctest.kasp.check_rollover_step(ns6, CONFIG, policy, step)
