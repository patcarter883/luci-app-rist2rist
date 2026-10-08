/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * ?cbr-output= parsing on output URLs and rist_receiver_set_cbr_output().
 * Pacing happens in the flow's output loop ahead of the fan-out, so the setting
 * belongs to the context: whichever route claims it first wins, and a later
 * disagreement from either route is refused rather than resolved.
 * Intentionally avoids cmocka so it runs anywhere the public library does. */

#include "librist/librist.h"
#include "librist/urlparam.h"
#include "librist/receiver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_out_parsed(const char *url, int want_set, int want_val)
{
	struct rist_udp_config *cfg = NULL;
	int fails = 0;
	if (rist_parse_udp_address2(url, &cfg) != 0 || !cfg) {
		fprintf(stderr, "FAIL: could not parse output url %s\n", url);
		if (cfg) rist_udp_config_free2(&cfg);
		return 1;
	}
	if (cfg->cbr_output_set != want_set || cfg->cbr_output != want_val) {
		fprintf(stderr, "FAIL: %s -> set=%d val=%d (want %d/%d)\n",
		        url, cfg->cbr_output_set, cfg->cbr_output, want_set, want_val);
		fails++;
	}
	rist_udp_config_free2(&cfg);
	return fails;
}

/* The output URL is where the parameter belongs, since it governs output. */
static int test_output_url_parsing(void)
{
	int fails = 0;
	fails += expect_out_parsed("udp://127.0.0.1:31100", 0, 0);
	fails += expect_out_parsed("udp://127.0.0.1:31100?cbr-output=1", 1, 1);
	fails += expect_out_parsed("udp://127.0.0.1:31100?cbr-output=0", 1, 0);

	struct rist_udp_config *cfg = NULL;
	if (rist_parse_udp_address2("udp://127.0.0.1:31100?cbr-output=2", &cfg) == 0) {
		fprintf(stderr, "FAIL: output url cbr-output=2 accepted\n");
		fails++;
	}
	if (cfg) rist_udp_config_free2(&cfg);

	if (!fails)
		printf("  output urls: 0|1 accepted, absent stays unset, junk rejected\n");
	return fails;
}

/* What ristreceiver does with each -o url: parse it, and if it stated a value,
 * hand that to the API. Returns the API result, or -2 if the url did not ask. */
static int apply_out_url(struct rist_ctx *ctx, const char *url)
{
	struct rist_udp_config *cfg = NULL;
	if (rist_parse_udp_address2(url, &cfg) != 0 || !cfg) {
		fprintf(stderr, "could not parse output url %s\n", url);
		if (cfg) rist_udp_config_free2(&cfg);
		return -3;
	}
	int ret = -2;
	if (cfg->version >= 2 && cfg->cbr_output_set)
		ret = rist_receiver_set_cbr_output(ctx, cfg->cbr_output != 0);
	rist_udp_config_free2(&cfg);
	return ret;
}

/* Outputs agreeing is fine; the setting is context-wide. */
static int test_two_agreeing_output_urls(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "agreeing: rist_receiver_create failed\n");
		return 1;
	}
	int fails = 0;
	if (apply_out_url(ctx, "udp://127.0.0.1:31200?cbr-output=1") != 0 ||
	    apply_out_url(ctx, "udp://127.0.0.1:31201?cbr-output=1") != 0) {
		fprintf(stderr, "agreeing: two outputs asking for 1 were not accepted\n");
		fails++;
	} else {
		printf("  two outputs both asking for cbr-output=1 accepted\n");
	}
	rist_destroy(ctx);
	return fails;
}

/* first then second on one context: the second must be refused. */
static int test_conflicting_output_urls(struct rist_logging_settings *logs,
                                       int first, int second)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "conflict: rist_receiver_create failed\n");
		return 1;
	}
	char u1[96], u2[96];
	snprintf(u1, sizeof(u1), "udp://127.0.0.1:31210?cbr-output=%d", first);
	snprintf(u2, sizeof(u2), "udp://127.0.0.1:31211?cbr-output=%d", second);

	int fails = 0;
	if (apply_out_url(ctx, u1) != 0) {
		fprintf(stderr, "conflict: first output (%s) rejected\n", u1);
		fails++;
	} else if (apply_out_url(ctx, u2) == 0) {
		fprintf(stderr, "conflict: %s accepted after %s; expected refusal\n", u2, u1);
		fails++;
	} else {
		printf("  output cbr-output=%d after cbr-output=%d refused\n", second, first);
	}
	rist_destroy(ctx);
	return fails;
}

/* The API is the route a run script or provisioning layer uses, and it shares
 * the latch with the output-URL route. */
static int test_api_and_url_share_the_latch(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs) != 0) {
		fprintf(stderr, "api: rist_receiver_create failed\n");
		return 1;
	}
	int fails = 0;

	if (rist_receiver_set_cbr_output(ctx, true) != 0) {
		fprintf(stderr, "api: first call rejected\n");
		fails++;
	}
	if (rist_receiver_set_cbr_output(ctx, true) != 0) {
		fprintf(stderr, "api: agreeing repeat rejected\n");
		fails++;
	}
	if (rist_receiver_set_cbr_output(ctx, false) == 0) {
		fprintf(stderr, "api: disagreeing call accepted; expected refusal\n");
		fails++;
	}

	/* An output URL disagreeing with the API must lose too. */
	if (apply_out_url(ctx, "udp://127.0.0.1:31202?cbr-output=0") == 0) {
		fprintf(stderr, "api: output url disagreeing with the API accepted\n");
		fails++;
	}

	if (!fails)
		printf("  api latches, agrees with itself, and refuses a conflicting url\n");
	rist_destroy(ctx);
	return fails;
}

/* A sender context has no output loop to pace, so the call must not succeed. */
static int test_api_rejects_a_sender(struct rist_logging_settings *logs)
{
	struct rist_ctx *ctx = NULL;
	if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, logs) != 0) {
		fprintf(stderr, "sender: rist_sender_create failed\n");
		return 1;
	}
	int fails = 0;
	if (rist_receiver_set_cbr_output(ctx, true) == 0) {
		fprintf(stderr, "sender: accepted on a sender context\n");
		fails++;
	} else {
		printf("  api refused on a sender context\n");
	}
	rist_destroy(ctx);
	return fails;
}

int main(void)
{
	struct rist_logging_settings *logs = NULL;
	if (rist_logging_set(&logs, RIST_LOG_ERROR, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr, "rist_logging_set failed\n");
		return 1;
	}

	printf("?cbr-output= parsing and override semantics\n");
	int fails = 0;
	fails += test_output_url_parsing();
	fails += test_api_and_url_share_the_latch(logs);
	fails += test_api_rejects_a_sender(logs);
	fails += test_two_agreeing_output_urls(logs);
	fails += test_conflicting_output_urls(logs, 1, 0);
	/* 0 equals the default, so it must still claim the setting. */
	fails += test_conflicting_output_urls(logs, 0, 1);

	free(logs);
	if (fails) {
		fprintf(stderr, "%d failure(s)\n", fails);
		return 1;
	}
	printf("all cbr-output invariants held\n");
	return 0;
}
