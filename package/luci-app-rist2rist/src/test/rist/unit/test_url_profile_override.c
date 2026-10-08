/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Public-API tests for the ?profile= URL override in rist_peer_create. */

#include "librist/librist.h"
#include "librist/peer.h"
#include "librist/receiver.h"
#include "librist/logging.h"
#include "librist/urlparam.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int parse_cfg(const char *url, struct rist_peer_config **cfg)
{
	*cfg = NULL;
	int ret = rist_parse_address2(url, cfg);
	if (ret != 0 || *cfg == NULL) {
		fprintf(stderr, "parse_cfg(%s) ret=%d cfg=%p\n",
		        url, ret, (void *)*cfg);
		return -1;
	}
	return 0;
}

static int test_override_then_match(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "test1: rist_receiver_create failed\n");
		return 1;
	}

	struct rist_peer_config *cfg1 = NULL, *cfg2 = NULL;
	struct rist_peer *p1 = NULL, *p2 = NULL;
	int fails = 0;

	if (parse_cfg("rist://@127.0.0.1:30100?profile=2", &cfg1) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p1, cfg1) != 0) {
		fprintf(stderr,
		        "test1: first peer (?profile=2) rejected; override should have applied\n");
		fails++;
		goto cleanup;
	}

	if (parse_cfg("rist://@127.0.0.1:30102?profile=2", &cfg2) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p2, cfg2) != 0) {
		fprintf(stderr,
		        "test1: second peer with matching ?profile=2 rejected\n");
		fails++;
	}

cleanup:
	if (cfg1) rist_peer_config_free2(&cfg1);
	if (cfg2) rist_peer_config_free2(&cfg2);
	rist_destroy(ctx);
	return fails;
}

static int test_conflict_refused(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "test2: rist_receiver_create failed\n");
		return 1;
	}

	struct rist_peer_config *cfg1 = NULL, *cfg2 = NULL;
	struct rist_peer *p1 = NULL, *p2 = NULL;
	int fails = 0;

	if (parse_cfg("rist://@127.0.0.1:30110?profile=2", &cfg1) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p1, cfg1) != 0) {
		fprintf(stderr, "test2: first peer rejected\n");
		fails++;
		goto cleanup;
	}

	if (parse_cfg("rist://@127.0.0.1:30112?profile=1", &cfg2) < 0) {
		fails++;
		goto cleanup;
	}
	int ret = rist_peer_create(ctx, &p2, cfg2);
	if (ret != -1) {
		fprintf(stderr,
		        "test2: conflicting ?profile=1 peer returned %d; expected -1\n",
		        ret);
		fails++;
	}

cleanup:
	if (cfg1) rist_peer_config_free2(&cfg1);
	if (cfg2) rist_peer_config_free2(&cfg2);
	rist_destroy(ctx);
	return fails;
}

static int test_late_peer_refused(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "test3: rist_receiver_create failed\n");
		return 1;
	}

	struct rist_peer_config *cfg_pre = NULL, *cfg_late = NULL;
	struct rist_peer *p_pre = NULL, *p_late = NULL;
	int fails = 0;

	if (parse_cfg("rist://@127.0.0.1:30120", &cfg_pre) < 0) {
		fails++;
		goto cleanup;
	}
	if (rist_peer_create(ctx, &p_pre, cfg_pre) != 0) {
		fprintf(stderr, "test3: pre-start peer rejected\n");
		fails++;
		goto cleanup;
	}
	if (rist_start(ctx) != 0) {
		fprintf(stderr, "test3: rist_start failed\n");
		fails++;
		goto cleanup;
	}

	if (parse_cfg("rist://@127.0.0.1:30122?profile=2", &cfg_late) < 0) {
		fails++;
		goto cleanup;
	}
	int ret = rist_peer_create(ctx, &p_late, cfg_late);
	if (ret != -1) {
		fprintf(stderr,
		        "test3: late peer with ?profile=2 returned %d; expected -1\n",
		        ret);
		fails++;
	}

cleanup:
	if (cfg_pre) rist_peer_config_free2(&cfg_pre);
	if (cfg_late) rist_peer_config_free2(&cfg_late);
	rist_destroy(ctx);
	return fails;
}

int main(void)
{
	struct rist_logging_settings *logs = NULL;
	if (rist_logging_set(&logs, RIST_LOG_WARN, NULL, NULL, NULL,
	                     stderr) != 0) {
		fprintf(stderr, "rist_logging_set failed\n");
		return 1;
	}

	int fails = 0;
	fails += test_override_then_match(logs);
	fails += test_conflict_refused(logs);
	fails += test_late_peer_refused(logs);

	rist_logging_settings_free2(&logs);

	if (fails == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", fails);
	return 1;
}
