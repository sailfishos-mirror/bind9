#!/bin/sh

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

set -e

# shellcheck source=conf.sh
. ../conf.sh
# shellcheck source=kasp.sh
. ../kasp.sh

dig_with_opts() {
  $DIG +tcp +noadd +nosea +nostat +nocmd +dnssec -p $PORT "$@"
}

start_time="$(TZ=UTC date +%s)"
status=0
n=0

# Test to make sure no DNSSEC records end up in the raw journal.
no_dnssec_in_journal() {
  n=$((n + 1))
  ret=0
  echo_i "check zone ${ZONE} raw journal has no DNSSEC ($n)"
  $JOURNALPRINT "${DIR}/${ZONE}.db.jnl" >"${DIR}/${ZONE}.journal.out.test$n"
  rrset_exists NSEC "${DIR}/${ZONE}.journal.out.test$n" && ret=1
  rrset_exists NSEC3 "${DIR}/${ZONE}.journal.out.test$n" && ret=1
  rrset_exists NSEC3PARAM "${DIR}/${ZONE}.journal.out.test$n" && ret=1
  rrset_exists RRSIG "${DIR}/${ZONE}.journal.out.test$n" && ret= 1
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
}

# Check if a certain RRtype is present in the journal file.
rrset_exists() (
  rrtype=$1
  file=$2
  lines=$(awk -v rt="${rrtype}" '$5 == rt {print}' ${file} | wc -l)
  test "$lines" -gt 0
)

# Check that the CDNSKEY from both providers are published.
records_published() {
  _rrtype=$1
  _expect=$2

  dig_with_opts "$ZONE" "@${SERVER}" "${_rrtype}" >"dig.out.$DIR.test$n" || return 1
  lines=$(awk -v rt="${_rrtype}" '$4 == rt {print}' dig.out.$DIR.test$n | wc -l)
  test "$lines" -eq "$_expect" || return 1
}

#
# Check secondary server behaviour.
#
set_zone "model2.secondary"
set_policy "model2" "2" "3600"

set_server "ns3" "10.53.0.3"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_model2
check_keytimes
check_apex
dnssec_verify

set_server "ns4" "10.53.0.4"
check_keys
check_dnssecstatus "$SERVER" "$POLICY" "$ZONE"
set_keytimes_model2
check_keytimes
check_apex
dnssec_verify

#
# Update DNSKEY RRset.
#
n=$((n + 1))
echo_i "add dnskey record: update zone ${ZONE} at ns5 with ZSKs from providers ns3 and ns4 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update add $(cat "ns3/${ZONE}.zsk")
  echo update add $(cat "ns4/${ZONE}.zsk")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} DNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 zsks_are_published || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
grep "dns_zone_findkeys: error reading ./K${ZONE}.*\.private: file not found" "${DIR}/named.run" && ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} DNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 zsks_are_published || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
grep "dns_zone_findkeys: error reading ./K${ZONE}.*\.private: file not found" "${DIR}/named.run" && ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "remove dnskey record: remove ns3 and ns4 DNSKEY records from primary ns5 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update del $(cat "ns3/${ZONE}.zsk")
  echo update del $(cat "ns4/${ZONE}.zsk")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Now there should be one DNSKEY record again.
# While we did remove both DNSKEY records, the bump in the wire signer, i.e
# the secondary inline-signing zone, should add back the DNSKEY belonging to
# its own KSK when re-signing the zone.
#
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} DNSKEY RRset after update ($n)"
ret=0
check_keys
check_apex
dnssec_verify
no_dnssec_in_journal
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} DNSKEY RRset after update ($n)"
ret=0
check_keys
check_apex
dnssec_verify
no_dnssec_in_journal

#
# Update CDNSKEY RRset.
#

# Retrieve CDNSKEY records from the providers.
n=$((n + 1))
echo_i "check initial CDSNKEY response for zone ${ZONE} at ns3 and ns4 ($n)"
ret=0
dig_with_opts ${ZONE} @10.53.0.3 CDNSKEY >dig.out.ns3.secondary.cdnskey
awk '$4 == "CDNSKEY" {print}' dig.out.ns3.secondary.cdnskey >secondary.cdnskey.ns3
dig_with_opts ${ZONE} @10.53.0.4 CDNSKEY >dig.out.ns4.secondary.cdnskey
awk '$4 == "CDNSKEY" {print}' dig.out.ns4.secondary.cdnskey >secondary.cdnskey.ns4
# Initially there should be one CDNSKEY.
set_server "ns3" "10.53.0.3"
retry_quiet 10 records_published CDNSKEY 1 || ret=1
set_server "ns4" "10.53.0.4"
retry_quiet 10 records_published CDNSKEY 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "add cdnskey record: update zone ${ZONE} at ns5 with CDNSKEY records from providers ns3 and ns4 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update add $(cat "secondary.cdnskey.ns3")
  echo update add $(cat "secondary.cdnskey.ns4")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Now there should be two CDNSKEY records (we test that BIND does not
# skip it during DNSSEC maintenance).
#
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal

n=$((n + 1))
echo_i "remove cdnskey record: remove ns3 and ns4 CDNSKEY records from primary ns5 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update del $(cat "secondary.cdnskey.ns3")
  echo update del $(cat "secondary.cdnskey.ns4")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Now there should be one CDNSKEY record again.
# While we did remove both CDNSKEY records, the bump in the wire signer, i.e
# the secondary inline-signing zone, should add back the CDNSKEY belonging to
# its own KSK when re-signing the zone.
#
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} CDNSKEY RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDNSKEY 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal

#
# Update CDS RRset.
#

# Retrieve CDS records from the other provider.
n=$((n + 1))
echo_i "check initial CDS response for zone ${ZONE} at ns3 and ns4 ($n)"
ret=0
dig_with_opts ${ZONE} @10.53.0.3 CDS >dig.out.ns3.secondary.cds
awk '$4 == "CDS" {print}' dig.out.ns3.secondary.cds >secondary.cds.ns3
dig_with_opts ${ZONE} @10.53.0.4 CDS >dig.out.ns4.secondary.cds
awk '$4 == "CDS" {print}' dig.out.ns4.secondary.cds >secondary.cds.ns4
# Initially there should be one CDS.
set_server "ns3" "10.53.0.3"
retry_quiet 10 records_published CDS 1 || ret=1
set_server "ns4" "10.53.0.4"
retry_quiet 10 records_published CDS 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))

n=$((n + 1))
echo_i "add cds record: update zone ${ZONE} at ns5 with CDS from provider ns4 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update add $(cat "secondary.cds.ns3")
  echo update add $(cat "secondary.cds.ns4")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Now there should be two CDS records (we test that BIND does not
# skip it during DNSSEC maintenance).
#
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} CDS RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDS 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} CDS RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDS 2 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal

n=$((n + 1))
echo_i "remove cds record: remove ns3 and ns4 CDS records from primary ns5 ($n)"
ret=0
set_server "ns5" "10.53.0.5"
(
  echo zone "${ZONE}"
  echo server "${SERVER}" "${PORT}"
  echo update del $(cat "secondary.cds.ns3")
  echo update del $(cat "secondary.cds.ns4")
  echo send
) | $NSUPDATE || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
# Now there should be one CDS record again.
# While we did remove both CDS records, the bump in the wire signer, i.e
# the secondary inline-signing zone, should add back the CDS belonging to
# its own KSK when re-signing the zone.
#
# NS3
n=$((n + 1))
set_server "ns3" "10.53.0.3"
echo_i "check server ${DIR} zone ${ZONE} CDS RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDS 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal
# NS4
n=$((n + 1))
set_server "ns4" "10.53.0.4"
echo_i "check server ${DIR} zone ${ZONE} CDS RRset after update ($n)"
ret=0
retry_quiet 10 records_published CDS 1 || ret=1
test "$ret" -eq 0 || echo_i "failed"
status=$((status + ret))
dnssec_verify
no_dnssec_in_journal

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
