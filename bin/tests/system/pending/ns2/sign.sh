#!/bin/sh -e

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

. ../../conf.sh

for domain in example example.com; do
  zone=${domain}.
  infile=${domain}.db.in
  zonefile=${domain}.db

  keyname1=$($KEYGEN -q -a ${DEFAULT_ALGORITHM} $zone)
  keyname2=$($KEYGEN -q -a ${DEFAULT_ALGORITHM} -f KSK $zone)

  cat $infile $keyname1.key $keyname2.key >$zonefile

  $SIGNER -3 bebe -o $zone $zonefile >/dev/null
done

# remove "removed" record from example.com, causing the server to
# send an apparently-invalid NXDOMAIN
sed '/^removed/d' example.com.db.signed >example.com.db.new
rm -f example.com.db.signed
mv example.com.db.new example.com.db.signed
