#!/usr/bin/python3

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

import abc
import re
from re import compile as Re
from typing import Iterator, Match, Optional, Pattern, TextIO, Union


FlexPattern = Union[str, Pattern]


def compile_pattern(string: FlexPattern) -> Pattern:
    if isinstance(string, Pattern):
        return string
    if isinstance(string, str):
        return Re(re.escape(string))
    raise TypeError("only string and re.Pattern allowed")


class LogFile:
    """
    Log file wrapper with a path and means to find a string in its contents.
    """

    def __init__(self, path: str):
        self.path = path

    @property
    def _lines(self) -> Iterator[str]:
        with open(self.path, encoding="utf-8") as f:
            yield from f

    def __contains__(self, substring: str) -> bool:
        """
        Return whether any of the lines in the log contains a given string.
        """
        for line in self._lines:
            if substring in line:
                return True
        return False

    def expect(self, msg: str):
        """Check the string is present anywhere in the log file."""
        if msg in self:
            return
        assert False, f"log message not found in log {self.path}: {msg}"

    def prohibit(self, msg: str):
        """Check the string is not present in the entire log file."""
        if msg in self:
            assert False, f"forbidden message appeared in log {self.path}: {msg}"


class LineReader:
    """
    >>> import io

    >>> file = io.StringIO("complete line\\n")
    >>> line_reader = LineReader(file)
    >>> for line in line_reader.readlines():
    ...     print(line.strip())
    complete line

    >>> file = io.StringIO("complete line\\nand then incomplete line")
    >>> line_reader = LineReader(file)
    >>> for line in line_reader.readlines():
    ...     print(line.strip())
    complete line

    >>> file = io.StringIO("complete line\\nand then another complete line\\n")
    >>> line_reader = LineReader(file)
    >>> for line in line_reader.readlines():
    ...     print(line.strip())
    complete line
    and then another complete line

    >>> file = io.StringIO()
    >>> line_reader = LineReader(file)
    >>> for chunk in (
    ...     "first line\\nsecond line\\nthi",
    ...     "rd ",
    ...     "line\\nfour",
    ...     "th line\\n\\nfifth line\\n"
    ... ):
    ...     print("=== OUTER ITERATION ===")
    ...     pos = file.tell()
    ...     print(chunk, end="", file=file)
    ...     _ = file.seek(pos)
    ...     for line in line_reader.readlines():
    ...         print("--- inner iteration ---")
    ...         print(line.strip() or "<blank>")
    === OUTER ITERATION ===
    --- inner iteration ---
    first line
    --- inner iteration ---
    second line
    === OUTER ITERATION ===
    === OUTER ITERATION ===
    --- inner iteration ---
    third line
    === OUTER ITERATION ===
    --- inner iteration ---
    fourth line
    --- inner iteration ---
    <blank>
    --- inner iteration ---
    fifth line
    """

    def __init__(self, stream: TextIO):
        self._stream = stream
        self._linebuf = ""

    def readline(self) -> Optional[str]:
        """
        Wrapper around io.readline() function to handle unfinished lines.

        If a line ends with newline character, it's returned immediately.
        If a line doesn't end with a newline character, the read contents are
        buffered until the next call of this function and None is returned
        instead.
        """
        read = self._stream.readline()
        if not read.endswith("\n"):
            self._linebuf += read
            return None
        read = self._linebuf + read
        self._linebuf = ""
        return read

    def readlines(self) -> Iterator[str]:
        """
        Wrapper around io.readline() which only returns finished lines.
        """
        while True:
            line = self.readline()
            if line is None:
                return
            yield line
