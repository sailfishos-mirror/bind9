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

# Log errors and increment $ret.
log_error() {
  echo_i "error: $1"
  ret=$((ret + 1))
}

# Call dig with default options.
dig_with_opts() {
  $DIG +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
}

# Call rndc.
rndccmd() {
  "$RNDC" -c ../_common/rndc.conf -p "$CONTROLPORT" -s "$@"
}

# Set zone name ($1) and policy ($2) for testing nsec3.
# Also set the expected number of keys ($3) and DNSKEY TTL ($4).
set_zone_policy() {
  ZONE=$1
  POLICY=$2
  NUM_KEYS=$3
  DNSKEY_TTL=$4
  KEYFILE_TTL=$4
  # The CDS digest type in these tests are all the default,
  # which is SHA-256 (2).
  CDS_SHA256="yes"
  CDS_SHA384="no"
}
# Set expected NSEC3 parameters: flags ($1) and salt length ($2).
set_nsec3param() {
  FLAGS=$1
  SALTLEN=$2
  # Reset salt.
  SALT=""
}

# Set expected default dnssec-policy keys values.
set_key_default_values() {
  key_clear $1

  set_keyrole $1 "csk"
  set_keylifetime $1 "0"
  set_keyalgorithm $1 "13" "ECDSAP256SHA256" "256"
  set_keysigning $1 "yes"
  set_zonesigning $1 "yes"

  set_keystate $1 "GOAL" "omnipresent"
  set_keystate $1 "STATE_DNSKEY" "rumoured"
  set_keystate $1 "STATE_KRRSIG" "rumoured"
  set_keystate $1 "STATE_ZRRSIG" "rumoured"
  set_keystate $1 "STATE_DS" "hidden"
}

# Set expected rsasha1 dnssec-policy keys values.
set_key_rsasha1_values() {
  key_clear $1

  set_keyrole $1 "csk"
  set_keylifetime $1 "0"
  set_keyalgorithm $1 "5" "RSASHA1" "2048"
  set_keysigning $1 "yes"
  set_zonesigning $1 "yes"

  set_keystate $1 "GOAL" "omnipresent"
  set_keystate $1 "STATE_DNSKEY" "rumoured"
  set_keystate $1 "STATE_KRRSIG" "rumoured"
  set_keystate $1 "STATE_ZRRSIG" "rumoured"
  set_keystate $1 "STATE_DS" "hidden"
}

# Update the key states.
set_key_states() {
  set_keystate $1 "GOAL" "$2"
  set_keystate $1 "STATE_DNSKEY" "$3"
  set_keystate $1 "STATE_KRRSIG" "$4"
  set_keystate $1 "STATE_ZRRSIG" "$5"
  set_keystate $1 "STATE_DS" "$6"
}

# The apex NSEC3PARAM record indicates that it is signed.
_wait_for_nsec3param() {
  dig_with_opts +noquestion "@${SERVER}" "$ZONE" NSEC3PARAM >"dig.out.test$n.wait" || return 1
  grep "${ZONE}\..*IN.*NSEC3PARAM 1 0 0.*${SALT}" "dig.out.test$n.wait" >/dev/null || return 1
  grep "${ZONE}\..*IN.*RRSIG" "dig.out.test$n.wait" >/dev/null || return 1
  return 0
}
# The apex NSEC record indicates that it is signed.
_wait_for_nsec() {
  dig_with_opts +noquestion "@${SERVER}" "$ZONE" NSEC >"dig.out.test$n.wait" || return 1
  grep "NS SOA" "dig.out.test$n.wait" >/dev/null || return 1
  grep "${ZONE}\..*IN.*RRSIG" "dig.out.test$n.wait" >/dev/null || return 1
  grep "${ZONE}\..*IN.*NSEC3PARAM" "dig.out.test$n.wait" >/dev/null && return 1
  return 0
}

# Wait for the zone to be signed.
wait_for_zone_is_signed() {
  n=$((n + 1))
  ret=0
  echo_i "wait for ${ZONE} to be signed with $1 ($n)"

  if [ "$1" = "nsec3" ]; then
    retry_quiet 10 _wait_for_nsec3param || log_error "wait for ${ZONE} to be signed failed"
  else
    retry_quiet 10 _wait_for_nsec || log_error "wait for ${ZONE} to be signed failed"
  fi

  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
}

# Test: check DNSSEC verify
_check_dnssec_verify() {
  dig_with_opts @$SERVER "${ZONE}" AXFR >"dig.out.test$n.axfr.$ZONE" || return 1
  $VERIFY -z -o "$ZONE" "dig.out.test$n.axfr.$ZONE" >"verify.out.test$n.$ZONE" 2>&1 || return 1
  return 0
}

# Test: check NSEC in answers
_check_nsec_nsec3param() {
  dig_with_opts +noquestion @$SERVER "${ZONE}" NSEC3PARAM >"dig.out.test$n.nsec3param.$ZONE" || return 1
  grep "NSEC3PARAM" "dig.out.test$n.nsec3param.$ZONE" >/dev/null && return 1
  return 0
}

_check_nsec_nxdomain() {
  dig_with_opts @$SERVER "nosuchname.${ZONE}" >"dig.out.test$n.nxdomain.$ZONE" || return 1
  grep "${ZONE}.*IN.*NSEC.*NS.*SOA.*RRSIG.*NSEC.*DNSKEY" "dig.out.test$n.nxdomain.$ZONE" >/dev/null || return 1
  grep "NSEC3" "dig.out.test$n.nxdomain.$ZONE" >/dev/null && return 1
  return 0
}

check_nsec() {
  wait_for_zone_is_signed "nsec"

  n=$((n + 1))
  echo_i "check DNSKEY rrset is signed correctly for zone ${ZONE} ($n)"
  ret=0
  check_keys
  retry_quiet 10 _check_apex_dnskey || log_error "bad DNSKEY RRset for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  n=$((n + 1))
  echo_i "verify DNSSEC for zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_dnssec_verify || log_error "DNSSEC verify failed for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check NSEC3PARAM response for zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_nsec_nsec3param || log_error "unexpected NSEC3PARAM in response for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check NXDOMAIN response for zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_nsec_nxdomain || log_error "bad NXDOMAIN response for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
}

# Test: check NSEC3 parameters in answers
_check_nsec3_nsec3param() {
  dig_with_opts +noquestion @$SERVER "${ZONE}" NSEC3PARAM >"dig.out.test$n.nsec3param.$ZONE" || return 1
  grep "${ZONE}.*0.*IN.*NSEC3PARAM.*1.*0.*0.*${SALT}" "dig.out.test$n.nsec3param.$ZONE" >/dev/null || return 1

  if [ -z "$SALT" ]; then
    SALT=$(awk '$4 == "NSEC3PARAM" { print $8 }' dig.out.test$n.nsec3param.$ZONE)
  fi
  return 0
}

_check_nsec3_nxdomain() {
  dig_with_opts @$SERVER "nosuchname.${ZONE}" >"dig.out.test$n.nxdomain.$ZONE" || return 1
  grep ".*\.${ZONE}.*IN.*NSEC3.*1.${FLAGS}.*0.*${SALT}" "dig.out.test$n.nxdomain.$ZONE" >/dev/null || return 1
  return 0
}

check_nsec3() {
  wait_for_zone_is_signed "nsec3"

  n=$((n + 1))
  echo_i "check that NSEC3PARAM 1 0 0 ${SALT} is published zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_nsec3_nsec3param || log_error "bad NSEC3PARAM response for ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  n=$((n + 1))
  echo_i "check NXDOMAIN response has correct NSEC3 1 ${FLAGS} 0 ${SALT} for zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_nsec3_nxdomain || log_error "bad NXDOMAIN response for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))

  n=$((n + 1))
  echo_i "verify DNSSEC for zone ${ZONE} ($n)"
  ret=0
  retry_quiet 10 _check_dnssec_verify || log_error "DNSSEC verify failed for zone ${ZONE}"
  test "$ret" -eq 0 || echo_i "failed"
  status=$((status + ret))
}

start_time="$(TZ=UTC date +%s)"
status=0
n=0

key_clear "KEY1"
key_clear "KEY2"
key_clear "KEY3"
key_clear "KEY4"

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
