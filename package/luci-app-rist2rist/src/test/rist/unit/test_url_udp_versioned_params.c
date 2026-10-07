/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?multiplex-mode= / ?rtp-ptype= URL parsing exercised through the public
 * rist_parse_udp_address2 API.  Both are guarded on RIST_UDP_CONFIG_VERSION,
 * so every case parses at whatever version the library was built with and a
 * bump cannot leave them unreachable.  Intentionally avoids cmocka so it runs
 * anywhere the public library does. */

#include "librist/librist.h"
#include "librist/headers.h"

#include <stdio.h>

/* A want of -1 leaves that field unchecked.  Returns the failure count. */
static int expect_url(const char *url, int want_mode, int want_ptype)
{
	struct rist_udp_config *cfg = NULL;
	int ret = rist_parse_udp_address2(url, &cfg);

	if (ret != 0 || cfg == NULL) {
		fprintf(stderr, "FAIL: %s rejected (ret=%d) at version %d\n",
		        url, ret, RIST_UDP_CONFIG_VERSION);
		if (cfg)
			rist_udp_config_free2(&cfg);
		return 1;
	}

	int bad = 0;
	if (want_mode >= 0 && (int)cfg->multiplex_mode != want_mode) {
		fprintf(stderr, "FAIL: %s -> multiplex_mode=%d (want %d)\n",
		        url, (int)cfg->multiplex_mode, want_mode);
		bad = 1;
	}
	if (want_ptype >= 0 && (int)cfg->rtp_ptype != want_ptype) {
		fprintf(stderr, "FAIL: %s -> rtp_ptype=%d (want %d)\n",
		        url, (int)cfg->rtp_ptype, want_ptype);
		bad = 1;
	}
	rist_udp_config_free2(&cfg);
	return bad;
}

int main(void)
{
	int failures = 0;

	/* The version the parser stamps on a fresh config has to be one the
	 * gates below accept, or every guarded parameter is unreachable. */
	if (RIST_UDP_CONFIG_VERSION < 1) {
		fprintf(stderr, "FAIL: RIST_UDP_CONFIG_VERSION=%d\n",
		        RIST_UDP_CONFIG_VERSION);
		return 1;
	}

	failures += expect_url("udp://127.0.0.1:1234?multiplex-mode=0", 0, -1);
	failures += expect_url("udp://127.0.0.1:1234?multiplex-mode=1", 1, -1);
	failures += expect_url("udp://127.0.0.1:1234?multiplex-mode=2", 2, -1);
	failures += expect_url("udp://127.0.0.1:1234?rtp-ptype=33", -1, 33);

	/* Alongside unguarded parameters, in either order. */
	failures += expect_url("udp://224.0.0.1:31001?stream-id=1968&multiplex-mode=1", 1, -1);
	failures += expect_url("udp://224.0.0.1:31001?multiplex-mode=1&stream-id=1968", 1, -1);
	failures += expect_url("udp://224.0.0.1:31001?stream-id=1968&multiplex-mode=1&rtp-ptype=33", 1, 33);

	/* Absent parameters leave the zeroed defaults. */
	failures += expect_url("udp://127.0.0.1:1234", 0, 0);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
