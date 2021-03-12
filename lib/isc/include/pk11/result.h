/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#ifndef PK11_RESULT_H
#define PK11_RESULT_H 1

/*! \file pk11/result.h */

#include <isc/resultclass.h>
#include <isc/types.h>

/*
 * Nothing in this file truly depends on <isc/result.h>, but the
 * PK11 result codes are considered to be publicly derived from
 * the ISC result codes, so including this file buys you the ISC_R_
 * namespace too.
 */
#include <isc/result.h> /* Contractual promise. */

#define pk11_result_totext isc_result_totext

#endif /* PK11_RESULT_H */
