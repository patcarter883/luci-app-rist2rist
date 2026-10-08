/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * udp:// scheme-prefix parsing exercised through the public
 * rist_parse_udp_address2 API.  The prefix[] field is 16 bytes; the parser
 * must not underflow its copy length on a leading '/' nor write the NUL
 * terminator past the buffer on an over-long scheme.  Runs under ASan to
 * catch the out-of-bounds write directly.  No cmocka: links the public API
 * only, so it runs anywhere the library does. */

#include "librist/librist.h"

#include <stdio.h>
#include <string.h>

static int expect_prefix(const char *url, const char *want_prefix, int want_rtp)
{
	struct rist_udp_config *cfg = NULL;
	int ret = rist_parse_udp_address2(url, &cfg);
	if (ret != 0 || cfg == NULL) {
		fprintf(stderr, "FAIL: rist_parse_udp_address2(%s) ret=%d cfg=%p\n",
		        url, ret, (void *)cfg);
		if (cfg)
			rist_udp_config_free2(&cfg);
		return 1;
	}
	int bad = 0;
	if (strcmp(cfg->prefix, want_prefix) != 0) {
		fprintf(stderr, "FAIL: %s -> prefix=\"%s\" (want \"%s\")\n",
		        url, cfg->prefix, want_prefix);
		bad = 1;
	}
	if (cfg->rtp != want_rtp) {
		fprintf(stderr, "FAIL: %s -> rtp=%d (want %d)\n", url, cfg->rtp, want_rtp);
		bad = 1;
	}
	rist_udp_config_free2(&cfg);
	return bad;
}

/* Must not crash or corrupt memory; we don't assert on the exact prefix here,
 * only that the call returns without an out-of-bounds write (ASan gate). */
static int expect_no_crash(const char *url)
{
	struct rist_udp_config *cfg = NULL;
	int ret = rist_parse_udp_address2(url, &cfg);
	(void)ret;
	if (cfg)
		rist_udp_config_free2(&cfg);
	return 0;
}

int main(void)
{
	int failures = 0;

	/* Normal schemes. */
	failures += expect_prefix("udp://127.0.0.1:1234", "udp", 0);
	failures += expect_prefix("rtp://127.0.0.1:1234", "rtp", 1);

	/* Leading '/': prefix_len is 0. The old code passed prefix_len-1 (SIZE_MAX)
	   as the strncpy length and NUL-padded gigabytes over the 16-byte buffer. */
	failures += expect_no_crash("/127.0.0.1:1234");

	/* Scheme longer than the 16-byte prefix buffer: the old code wrote the NUL
	   terminator at prefix[prefix_len], out of bounds. */
	failures += expect_no_crash("averylongschemename://host:1234");
	failures += expect_no_crash("0123456789abcdef0123456789/host");

	if (failures) {
		fprintf(stderr, "%d failure(s)\n", failures);
		return 1;
	}
	printf("all udp prefix parse cases passed\n");
	return 0;
}
