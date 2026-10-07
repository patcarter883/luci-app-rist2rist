/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * A recovery_maxbitrate of 0 through the C API must be read as "unset" and
 * replaced with the default, not as "no ceiling" (#229). Driven through the
 * public API, asserting on the log. */

#include "librist/librist.h"
#include "librist/logging.h"
#include "librist/peer.h"
#include "librist/receiver.h"
#include "librist/sender.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* Room for every line a peer emits at INFO; overflow is dropped rather than
 * truncating mid-assertion. */
static char captured[16384];
static size_t captured_len;

static int capture(void *arg, enum rist_log_level level, const char *msg)
{
	(void)arg;
	(void)level;
	if (!msg)
		return 0;
	size_t len = strlen(msg);
	if (len < sizeof(captured) - captured_len) {
		memcpy(captured + captured_len, msg, len);
		captured_len += len;
		captured[captured_len] = '\0';
	}
	return 0;
}

static void capture_reset(void)
{
	captured[0] = '\0';
	captured_len = 0;
}

static int failures;

static void expect(const char *name, const char *needle, bool want)
{
	bool got = strstr(captured, needle) != NULL;
	if (got != want) {
		fprintf(stderr, "FAIL: %s: %s \"%s\"\n", name,
		        want ? "expected but did not find" : "unexpectedly found",
		        needle);
		failures++;
	}
}

/* Creates one peer from url on a fresh context of the given role, leaving the
 * log of that peer's creation in captured. maxbitrate is written into the
 * parsed config the way an application using the C API would. */
static int make_peer(struct rist_logging_settings *logs, bool receiver,
                     const char *url, uint32_t maxbitrate)
{
	struct rist_ctx *ctx = NULL;
	int ret = receiver ? rist_receiver_create(&ctx, RIST_PROFILE_MAIN, logs)
	                   : rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, logs);
	if (ret != 0) {
		fprintf(stderr, "rist_%s_create failed\n", receiver ? "receiver" : "sender");
		return -1;
	}

	struct rist_peer_config *cfg = NULL;
	struct rist_peer *peer = NULL;
	int fails = 0;

	if (rist_parse_address2(url, &cfg) != 0 || cfg == NULL) {
		fprintf(stderr, "rist_parse_address2(%s) failed\n", url);
		fails = -1;
		goto cleanup;
	}
	cfg->recovery_maxbitrate = maxbitrate;

	capture_reset();
	if (rist_peer_create(ctx, &peer, cfg) != 0) {
		fprintf(stderr, "rist_peer_create(%s, maxbitrate=%u) failed\n", url, maxbitrate);
		fails = -1;
	}

cleanup:
	if (cfg)
		rist_peer_config_free2(&cfg);
	rist_destroy(ctx);
	return fails;
}

int main(void)
{
	struct rist_logging_settings *logs = NULL;
	/* INFO, and no stream, so the receiver's config line is captured and the
	 * test stays quiet on success. */
	if (rist_logging_set(&logs, RIST_LOG_INFO, capture, NULL, NULL, NULL) != 0) {
		fprintf(stderr, "rist_logging_set failed\n");
		return 1;
	}

	/* A zero is corrected, and says so rather than silently. */
	if (make_peer(logs, false, "rist://127.0.0.1:30200", 0) < 0)
		failures++;
	else {
		expect("sender_zero", "recovery-maxbitrate of 0", true);
		expect("sender_zero", "100000 kbps default", true);
	}

	/* A real ceiling is left alone. */
	if (make_peer(logs, false, "rist://127.0.0.1:30202", 8000) < 0)
		failures++;
	else
		expect("sender_nonzero", "recovery-maxbitrate of 0", false);

	/* The correction lands before the derived settings are computed, not just
	 * in the warning: the receiver's own config line reports the default. */
	if (make_peer(logs, true, "rist://@127.0.0.1:30204", 0) < 0)
		failures++;
	else {
		expect("receiver_zero", "recovery-maxbitrate of 0", true);
		expect("receiver_zero", "maxrate=100000/", true);
	}

	rist_logging_settings_free2(&logs);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
