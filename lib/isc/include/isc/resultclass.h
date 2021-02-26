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

#ifndef ISC_RESULTCLASS_H
#define ISC_RESULTCLASS_H 1

/*! \file isc/resultclass.h
 * \brief Registry of Predefined Result Type Classes
 *
 * Error codes are organized (divided) into classes, we use an uint32_t number
 * to store both the error class and the error code.
 *
 * The class number is stored into the low ISC_RESULTCLASS_BITS bits
 * of the number (see macro), thus 2^ISC_RESULTCLASS_BITS classes are available.
 *
 * Each class may contain up to 2^(32 - ISC_RESULTCLASS_BITS) error codes.
 *
 * A result code is formed by shifting right the error code (integer number)
 * by ISC_RESULTCLASS_BITS and oring the result with
 * (class_number & ISC_RESULTCLASS_MASK)
 *
 * Macros are provided to make this task easier.
 */

/* Bits reserved for the error class.  */
#define ISC_RESULTCLASS_BITS (uint32_t)4u

/* Mask used to extract the class bits within a number (using bitwise AND) */
#define ISC_RESULTCLASS_MASK (uint32_t)((1u << ISC_RESULTCLASS_BITS) - 1)

/* Macro used to extract the class value given a isc_result_t input */
#define ISC_RESULT_CLASS(result) ((result)&ISC_RESULTCLASS_MASK)

/* Macro used to extract the error value given a isc_result_t input */
#define ISC_RESULT_VALUE(result) ((result) >> ISC_RESULTCLASS_BITS)

/* Check whether result is in the same class as rclass */
#define ISC_RESULT_INCLASS(rclass, result) \
	((rclass) == ISC_RESULT_CLASS(result))

/*
 * Following are macros that define result classes (or error classes) in the
 * format ISC_RESULTCLASS_(CLASSNAME).
 * Following each result class are macros intended to be used to create
 * error codes for that class, in the format ISC_RESULTCODE_(CLASS_NAME).
 *
 * A library could have error codes defined like the example below:
 * #define ISC_R_EOF			ISC_RESULTCODE_ISC(14)
 * Another library could use the same number (14) to define an error code
 * without conflicting with another class, e.g:
 * #define DNS_R_TEXTTOOLONG		ISC_RESULTCODE_DNS(14)
 * ISC_R_EOF == DNS_R_TEXTTOOLONG (false, not in the same class)
 */

#define ISC_RESULTCLASS_ISC 0
#define ISC_RESULTCODE_ISC(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_ISC)
#define ISC_RESULTCLASS_DNS 1
#define ISC_RESULTCODE_DNS(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_DNS)
#define ISC_RESULTCLASS_DST 2
#define ISC_RESULTCODE_DST(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_DST)
#define ISC_RESULTCLASS_DNSRCODE 3
#define ISC_RESULTCODE_DNSRCODE(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_DNSRCODE)
#define ISC_RESULTCLASS_OMAPI 4
#define ISC_RESULTCODE_OMAPI(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_OMAPI)
#define ISC_RESULTCLASS_ISCCC 5
#define ISC_RESULTCODE_ISCCC(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_ISCCC)
#define ISC_RESULTCLASS_DHCP 6
#define ISC_RESULTCODE_DHCP(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_DHCP)
#define ISC_RESULTCLASS_PK11 7
#define ISC_RESULTCODE_PK11(code) \
	(((code) << ISC_RESULTCLASS_BITS) | ISC_RESULTCLASS_PK11)

#define ISC_RESULTCLASS_MAX 7

#endif /* ISC_RESULTCLASS_H */