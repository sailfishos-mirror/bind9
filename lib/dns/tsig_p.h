/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * SPDX-License-Identifier: MPL-2.0
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file */

#include <stdbool.h>

#include <isc/result.h>

#include <dns/types.h>

/*%
 *     These functions must not be used outside this module and
 *     its associated unit tests.
 */

bool
dns__tsig_algvalid(unsigned int alg);
dst_algorithm_t
dns__tsig_algfromname(const dns_name_t *algorithm);
