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

. ../conf.sh

status=0
n=0

for conf in conf/good*.conf; do
  n=$((n + 1))
  echo_i "checking that $conf is accepted ($n)"
  ret=0
  $CHECKCONF "$conf" || ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
done

for conf in conf/bad*.conf; do
  n=$((n + 1))
  echo_i "checking that $conf is rejected ($n)"
  ret=0
  $CHECKCONF "$conf" >/dev/null && ret=1
  if [ $ret != 0 ]; then echo_i "failed"; fi
  status=$((status + ret))
done

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
