/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?recovery-priority= URL parsing exercised through the public
 * rist_parse_address2 API.  Intentionally avoids cmocka so it runs
 * anywhere the public library does. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_priority(const char *url, uint32_t want)
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
	if (cfg->recovery_priority != want) {
		fprintf(stderr,
		        "FAIL: %s -> recovery_priority=%u (want %u)\n",
		        url, cfg->recovery_priority, want);
		rist_peer_config_free2(&cfg);
		return 1;
	}
	rist_peer_config_free2(&cfg);
	return 0;
}

int main(void)
{
	int failures = 0;

	/* Absent parameter keeps the default. */
	failures += expect_priority(
		"rist://@127.0.0.1:1234",
		RIST_DEFAULT_RECOVERY_PRIORITY);

	failures += expect_priority(
		"rist://@127.0.0.1:1234?recovery-priority=0", 0);
	failures += expect_priority(
		"rist://@127.0.0.1:1234?recovery-priority=1", 1);
	failures += expect_priority(
		"rist://@127.0.0.1:1234?recovery-priority=1000", 1000);

	/* Coexists with other parameters in either order. */
	failures += expect_priority(
		"rist://@127.0.0.1:1234?weight=1000&recovery-priority=5", 5);
	failures += expect_priority(
		"rist://@127.0.0.1:1234?recovery-priority=5&buffer=100", 5);

	/* Negative is rejected by the >=0 guard and leaves the default. */
	failures += expect_priority(
		"rist://@127.0.0.1:1234?recovery-priority=-1",
		RIST_DEFAULT_RECOVERY_PRIORITY);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
