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

#
# Clean up after cache cleaner tests.
#

rm -f dig.out.ns2
rm -f dig.out.expire
rm -f rndc.out.*
rm -f sed.out.*
rm -f */named.memstats
rm -f */named.run
rm -f */named.conf
rm -f ns2/named_dump.db.*
rm -f ns*/managed-keys.bind*
