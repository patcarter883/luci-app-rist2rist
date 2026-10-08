/* librist. SPDX-License-Identifier: BSD-2-Clause */

#include "librist/tun.h"

#include <stdio.h>
#include <string.h>

static int expect_ok(const char *cidr, const char *want_ip, int want_prefix)
{
	char ip[64];
	int prefix = -1;

	if (rist_tun_parse_cidr(cidr, ip, sizeof(ip), &prefix) != 0) {
		fprintf(stderr, "FAIL: expected success for %s\n", cidr);
		return 1;
	}
	if (strcmp(ip, want_ip) != 0 || prefix != want_prefix) {
		fprintf(stderr,
		        "FAIL: %s -> ip=%s prefix=%d (want ip=%s prefix=%d)\n",
		        cidr, ip, prefix, want_ip, want_prefix);
		return 1;
	}
	return 0;
}

static int expect_fail(const char *cidr)
{
	char ip[64];
	int prefix = 0;

	if (rist_tun_parse_cidr(cidr, ip, sizeof(ip), &prefix) == 0) {
		fprintf(stderr, "FAIL: expected error for %s\n", cidr);
		return 1;
	}
	return 0;
}

int main(void)
{
	int failures = 0;

	failures += expect_ok("10.0.0.1", "10.0.0.1", 32);
	failures += expect_ok("10.0.0.1/24", "10.0.0.1", 24);
	failures += expect_ok("fd00:0:ffff::1", "fd00:0:ffff::1", 128);
	failures += expect_ok("fd00:0:ffff::1/64", "fd00:0:ffff::1", 64);
	failures += expect_ok("2001:db8::2/48", "2001:db8::2", 48);

	failures += expect_fail("not-an-ip");
	failures += expect_fail("10.0.0.1/33");
	failures += expect_fail("fd00::1/129");
	failures += expect_fail("");

	return failures ? 1 : 0;
}
