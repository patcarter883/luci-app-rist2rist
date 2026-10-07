/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?recovery-depth= URL parsing exercised through the public
 * rist_parse_address2 API.  recovery-depth is a numeric exponent
 * (RIST_RECOVERY_DEPTH_MIN..MAX); the ring holds 65536 << depth packets.
 * Intentionally avoids cmocka so it runs anywhere the public library does. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_depth(const char *url, unsigned want)
{
	struct rist_peer_config *cfg = NULL;
	int ret = rist_parse_address2(url, &cfg);
	if (ret != 0 || cfg == NULL) {
		fprintf(stderr, "FAIL: rist_parse_address2(%s) ret=%d cfg=%p\n",
		        url, ret, (void *)cfg);
		if (cfg)
			rist_peer_config_free2(&cfg);
		return 1;
	}
	if (cfg->recovery_depth != want) {
		fprintf(stderr, "FAIL: %s -> recovery_depth=%u (want %u)\n",
		        url, (unsigned)cfg->recovery_depth, want);
		rist_peer_config_free2(&cfg);
		return 1;
	}
	rist_peer_config_free2(&cfg);
	return 0;
}

/* An out-of-range / non-numeric token must be flagged (non-zero return) per
 * the parse_url_options contract, and must not corrupt the default value. */
static int expect_parse_error(const char *url)
{
	struct rist_peer_config *cfg = NULL;
	int ret = rist_parse_address2(url, &cfg);
	int bad = 0;
	if (ret == 0) {
		fprintf(stderr, "FAIL: %s expected parse error, got success\n", url);
		bad = 1;
	} else if (cfg != NULL && cfg->recovery_depth != RIST_RECOVERY_DEPTH_DEFAULT) {
		fprintf(stderr, "FAIL: %s left recovery_depth=%u (want default %d)\n",
		        url, (unsigned)cfg->recovery_depth, RIST_RECOVERY_DEPTH_DEFAULT);
		bad = 1;
	}
	if (cfg)
		rist_peer_config_free2(&cfg);
	return bad;
}

int main(void)
{
	int failures = 0;

	/* Absent parameter leaves the library default. */
	failures += expect_depth("rist://@127.0.0.1:1234", RIST_RECOVERY_DEPTH_DEFAULT);

	/* Boundary and representative interior values. */
	failures += expect_depth("rist://@127.0.0.1:1234?recovery-depth=0", 0);
	failures += expect_depth("rist://@127.0.0.1:1234?recovery-depth=3", 3);
	failures += expect_depth("rist://@127.0.0.1:1234?recovery-depth=6", 6);
	failures += expect_depth("rist://@127.0.0.1:1234?recovery-depth=16", 16);

	/* Coexists with other parameters in either order. */
	failures += expect_depth("rist://@127.0.0.1:1234?buffer=100&recovery-depth=5", 5);
	failures += expect_depth("rist://@127.0.0.1:1234?recovery-depth=8&bandwidth=8000", 8);

	/* Out-of-range and non-numeric are rejected and leave the default. */
	failures += expect_parse_error("rist://@127.0.0.1:1234?recovery-depth=17");
	failures += expect_parse_error("rist://@127.0.0.1:1234?recovery-depth=-1");
	failures += expect_parse_error("rist://@127.0.0.1:1234?recovery-depth=large");

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
