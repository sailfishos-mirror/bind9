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

import os

# pylint: disable=import-error
from .build import BUILD_VARS, SYSTEM_TEST_DIR_GIT_PATH  # type: ignore

# pylint: enable=import-error


DIR_VARS = {
    "builddir": f"{BUILD_VARS['TOP_BUILDDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}",
    "srcdir": f"{BUILD_VARS['TOP_SRCDIR']}/{SYSTEM_TEST_DIR_GIT_PATH}",
    "SYSTESTDIR": None,
}


def set_system_test_name(name: str):
    DIR_VARS["SYSTESTDIR"] = name
    os.environ["SYSTESTDIR"] = name
