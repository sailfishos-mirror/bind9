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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define USAGE "usage: gencheck <filename>\n"

static int
check(const char *buf, ssize_t count, size_t *start) {
	const char chars[] = "abcdefghijklmnopqrstuvwxyz0123456789";
	ssize_t i;

	for (i = 0; i < count; i++, *start = (*start + 1) % (sizeof(chars) - 1))
	{
		/* Just ignore the trailing newline */
		if (buf[i] == '\n') {
			continue;
		}
		if (buf[i] != chars[*start]) {
			return 0;
		}
	}

	return 1;
}

int
main(int argc, char **argv) {
	int ret;
	int fd;
	ssize_t count;
	char buf[1024];
	size_t start;
	size_t length;

	ret = EXIT_FAILURE;
	fd = -1;
	length = 0;

	if (argc != 2) {
		fprintf(stderr, USAGE);
		goto out;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		goto out;
	}

	start = 0;
	while ((count = read(fd, buf, sizeof(buf))) != 0) {
		if (count < 0) {
			goto out;
		}

		if (!check(buf, count, &start)) {
			goto out;
		}

		length += count;
	}

	ret = EXIT_SUCCESS;

out:
	printf("%lu\n", (unsigned long)length);

	if (fd != -1) {
		close(fd);
	}

	return ret;
}
