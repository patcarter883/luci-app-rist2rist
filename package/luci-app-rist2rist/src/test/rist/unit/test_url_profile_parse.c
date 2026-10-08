/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Intentionally avoids cmocka so it runs anywhere the public library
 * does. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int expect_profile(const char *url,
                          enum rist_profile want_profile,
                          int want_set)
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
	if ((int)cfg->profile != (int)want_profile ||
	    cfg->profile_set != want_set) {
		fprintf(stderr,
		        "FAIL: %s -> profile=%d profile_set=%d "
		        "(want profile=%d profile_set=%d)\n",
		        url, (int)cfg->profile, cfg->profile_set,
		        (int)want_profile, want_set);
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

	failures += expect_profile(
		"rist://@127.0.0.1:1234",
		RIST_DEFAULT_PROFILE, 0);

	failures += expect_profile(
		"rist://@127.0.0.1:1234?profile=0",
		RIST_PROFILE_SIMPLE, 1);
	failures += expect_profile(
		"rist://@127.0.0.1:1234?profile=1",
		RIST_PROFILE_MAIN, 1);
	failures += expect_profile(
		"rist://@127.0.0.1:1234?profile=2",
		RIST_PROFILE_ADVANCED, 1);

	failures += expect_profile(
		"rist://@127.0.0.1:1234?profile=2&buffer=100",
		RIST_PROFILE_ADVANCED, 1);
	failures += expect_profile(
		"rist://@127.0.0.1:1234?buffer=100&profile=2",
		RIST_PROFILE_ADVANCED, 1);

	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=3");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=garbage");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=simple");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=main");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=advanced");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=2foo");
	failures += expect_parse_error(
		"rist://@127.0.0.1:1234?profile=-1");

	/* Empty value: upstream parser yields val==NULL, treated as absent. */
	failures += expect_profile(
		"rist://@127.0.0.1:1234?profile=",
		RIST_DEFAULT_PROFILE, 0);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
