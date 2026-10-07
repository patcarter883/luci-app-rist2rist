/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Intentionally avoids cmocka so it runs anywhere the public library
 * does. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_legacy(const char *url, int want)
{
	struct rist_peer_config *cfg = NULL;
	int ret = rist_parse_address2(url, &cfg);
	if (ret != 0 || cfg == NULL) {
		fprintf(stderr,
		        "FAIL: rist_parse_address2(%s) ret=%d cfg=%p\n",
		        url, ret, (void *)cfg);
		if (cfg)
			rist_peer_config_free2(&cfg);
		return 1;
	}
	if (cfg->srp_compat_legacy != want) {
		fprintf(stderr,
		        "FAIL: %s -> srp_compat_legacy=%d (want %d)\n",
		        url, cfg->srp_compat_legacy, want);
		rist_peer_config_free2(&cfg);
		return 1;
	}
	rist_peer_config_free2(&cfg);
	return 0;
}

static int expect_parse_error(const char *url)
{
	struct rist_peer_config *cfg = NULL;
	int ret = rist_parse_address2(url, &cfg);
	if (ret == 0) {
		fprintf(stderr,
		        "FAIL: %s expected parse error, got success\n", url);
		if (cfg)
			rist_peer_config_free2(&cfg);
		return 1;
	}
	if (cfg)
		rist_peer_config_free2(&cfg);
	return 0;
}

int main(void)
{
	int failures = 0;

	failures += expect_legacy("rist://@127.0.0.1:1234", 0);
	failures += expect_legacy("rist://@127.0.0.1:1234?srp-compat=0", 0);
	failures += expect_legacy("rist://@127.0.0.1:1234?srp-compat=1", 1);

	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=legacy");
	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=auto");
	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=2");
	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=-1");
	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=1foo");
	failures += expect_parse_error("rist://@127.0.0.1:1234?srp-compat=garbage");

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
