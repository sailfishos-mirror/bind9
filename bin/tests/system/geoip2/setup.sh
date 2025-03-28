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

. ../conf.sh

copy_setports ns2/named1.conf.in ns2/named.conf

for i in 1 2 3 4 5 6 7 other bogus; do
  cp ns2/example.db.in ns2/example${i}.db
  echo "@ IN TXT \"$i\"" >>ns2/example$i.db
done
