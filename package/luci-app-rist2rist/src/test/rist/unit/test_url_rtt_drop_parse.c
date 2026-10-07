/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?rtt-drop= / ?rtt-restore= / ?rtt-drop-settle= / ?rtt-drop-trickle= URL
 * parsing exercised through the public rist_parse_address2 API.  Intentionally
 * avoids cmocka so it runs anywhere the public library does. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct want {
	uint32_t drop;
	uint32_t restore;
	uint32_t settle;
	uint32_t trickle;
};

static int expect_cfg(const char *url, struct want w)
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
	int bad = cfg->rtt_drop != w.drop || cfg->rtt_restore != w.restore
		|| cfg->rtt_drop_settle != w.settle || cfg->rtt_drop_trickle != w.trickle;
	if (bad) {
		fprintf(stderr,
		        "FAIL: %s -> drop=%u restore=%u settle=%u trickle=%u "
		        "(want %u/%u/%u/%u)\n",
		        url, cfg->rtt_drop, cfg->rtt_restore, cfg->rtt_drop_settle,
		        cfg->rtt_drop_trickle, w.drop, w.restore, w.settle, w.trickle);
	}
	rist_peer_config_free2(&cfg);
	return bad ? 1 : 0;
}

int main(void)
{
	int failures = 0;

	/* Absent parameters keep the versioned defaults (feature disabled). */
	failures += expect_cfg("rist://@127.0.0.1:1234",
		(struct want){ RIST_DEFAULT_RTT_DROP, RIST_DEFAULT_RTT_RESTORE,
		               RIST_DEFAULT_RTT_DROP_SETTLE, RIST_DEFAULT_RTT_DROP_TRICKLE });

	/* Each knob parses independently, leaving the rest at their defaults. */
	failures += expect_cfg("rist://@127.0.0.1:1234?rtt-drop=500",
		(struct want){ 500, RIST_DEFAULT_RTT_RESTORE,
		               RIST_DEFAULT_RTT_DROP_SETTLE, RIST_DEFAULT_RTT_DROP_TRICKLE });
	failures += expect_cfg("rist://@127.0.0.1:1234?rtt-restore=300",
		(struct want){ RIST_DEFAULT_RTT_DROP, 300,
		               RIST_DEFAULT_RTT_DROP_SETTLE, RIST_DEFAULT_RTT_DROP_TRICKLE });
	failures += expect_cfg("rist://@127.0.0.1:1234?rtt-drop-settle=5000",
		(struct want){ RIST_DEFAULT_RTT_DROP, RIST_DEFAULT_RTT_RESTORE,
		               5000, RIST_DEFAULT_RTT_DROP_TRICKLE });
	failures += expect_cfg("rist://@127.0.0.1:1234?rtt-drop-trickle=50",
		(struct want){ RIST_DEFAULT_RTT_DROP, RIST_DEFAULT_RTT_RESTORE,
		               RIST_DEFAULT_RTT_DROP_SETTLE, 50 });

	/* All four together, order-independent, coexisting with other params. */
	failures += expect_cfg(
		"rist://@127.0.0.1:1234?weight=5&rtt-drop=500&rtt-restore=350&rtt-drop-settle=2000&rtt-drop-trickle=40",
		(struct want){ 500, 350, 2000, 40 });

	/* Negative values are rejected by the >=0 guards and keep the defaults. */
	failures += expect_cfg("rist://@127.0.0.1:1234?rtt-drop=-1",
		(struct want){ RIST_DEFAULT_RTT_DROP, RIST_DEFAULT_RTT_RESTORE,
		               RIST_DEFAULT_RTT_DROP_SETTLE, RIST_DEFAULT_RTT_DROP_TRICKLE });

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
