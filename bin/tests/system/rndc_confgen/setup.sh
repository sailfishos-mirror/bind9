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

# tsig-keygen and ddns-confgen are the same binary; the install layout
# provides ddns-confgen as a symlink, but the build tree does not. Create
# one here so the test can exercise the ddns-confgen mode.
ln -sf "$TSIGKEYGEN" ddns-confgen
