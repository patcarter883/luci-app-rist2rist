/* librist. SPDX-License-Identifier: BSD-2-Clause */

/*
 * Regression test for issue #208 (rist/librist).
 *
 * On Windows 11 (and any caller that uses the remote-log socket path
 * before any rist_*_create), rist_logging_set with a non-NULL `address`
 * argument used to fail because WSAStartup had not been called yet.
 * The bug was specifically reachable when the public logging API ran
 * before rist_sender_create / rist_receiver_create.
 *
 * This test reproduces that exact call ordering with a `udp://` remote
 * address. On POSIX it serves as a baseline / smoke test; on Windows
 * (run under wine in CI, see .gitlab-ci.yml build-win64) it will fail
 * with WSANOTINITIALISED if winsock initialisation ever regresses.
 *
 * The test does NOT exercise any rist_*_create call and does NOT
 * require the remote log endpoint to actually exist - we only assert
 * that the UDP socket can be opened.
 */

#include "librist/librist.h"
#include "librist/logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	struct rist_logging_settings *settings = NULL;
	char address[] = "127.0.0.1:65530"; /* unprivileged + unlikely to clash */

	int ret = rist_logging_set(&settings, RIST_LOG_DEBUG,
	                           NULL, NULL, address, NULL);
	if (ret != 0) {
		fprintf(stderr,
		        "FAIL: rist_logging_set with remote address returned %d\n",
		        ret);
		return 1;
	}
	if (settings == NULL) {
		fprintf(stderr,
		        "FAIL: rist_logging_set returned 0 but settings is NULL\n");
		return 1;
	}

	rist_logging_settings_free2(&settings);
	printf("OK\n");
	return 0;
}
