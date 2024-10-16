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
# Clean up after zone transfer tests.
#

rm -f ns3/example.bk
rm -f ns3/internal.bk
rm -f */named.conf
rm -f */named.memstats
rm -f */named.run
rm -f */ans.run
rm -f */named.stats
rm -f */named.stats-stage*
rm -f dig.out*
rm -f curl.out.*
rm -f stats*out
rm -f ns*/managed-keys.bind*
rm -f xsltproc.out.*
rm -f named.stats.* ns*/named.stats.* ns*/named.recursing
