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

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
