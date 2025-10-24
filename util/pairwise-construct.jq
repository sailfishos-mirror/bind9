#!/usr/bin/env -S jq -rf

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

.[]
    | select((.section == "user") and (.name | IN("rcu-flavor", "fuzzing", "fuzzing-backend", "oss-fuzz-args", "fips", "trace-logging") | not))
    | ["\(.name):", "-D\(.name)=\(.choices[]),"]
    | join(" ")
    | .[:-1]
