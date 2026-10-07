/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Verifies rist_peer_config_defaults_set_versioned() writes only fields
 * that exist at or below the requested version, so a config struct from
 * an older RIST_PEER_CONFIG_VERSION is never written past its end.
 *
 * Field introduction versions (see include/librist/peer.h history):
 *   split_mode, merge_mode : version 1
 *   profile, profile_set   : version 4
 *   rtt_drop et al         : version 6
 *
 * Links against the public library only; no cmocka. */

#include "librist/librist.h"
#include "librist/peer.h"

#include <stdio.h>
#include <string.h>

#define SENTINEL 0x5a5a5a5a

static int check(int version, int expect_split_set, int expect_profile_set,
                 int expect_rtt_set)
{
	struct rist_peer_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	cfg.split_mode = SENTINEL;
	cfg.merge_mode = SENTINEL;
	cfg.profile = (enum rist_profile)SENTINEL;
	cfg.profile_set = SENTINEL;
	cfg.rtt_drop = SENTINEL;
	cfg.rtt_restore = SENTINEL;
	cfg.rtt_drop_settle = SENTINEL;
	cfg.rtt_drop_trickle = SENTINEL;

	if (rist_peer_config_defaults_set_versioned(&cfg, version) != 0) {
		fprintf(stderr, "FAIL: versioned(v=%d) returned error\n", version);
		return 1;
	}

	int failures = 0;
	if (cfg.version != version) {
		fprintf(stderr, "FAIL: v=%d recorded version=%d\n",
		        version, cfg.version);
		failures++;
	}

	int split_written = (cfg.split_mode != SENTINEL) ||
	                    (cfg.merge_mode != SENTINEL);
	if (split_written != expect_split_set) {
		fprintf(stderr, "FAIL: v=%d split/merge written=%d (want %d)\n",
		        version, split_written, expect_split_set);
		failures++;
	}

	int profile_written = ((int)cfg.profile != (int)(enum rist_profile)SENTINEL) ||
	                      (cfg.profile_set != SENTINEL);
	if (profile_written != expect_profile_set) {
		fprintf(stderr, "FAIL: v=%d profile written=%d (want %d)\n",
		        version, profile_written, expect_profile_set);
		failures++;
	}

	int rtt_written = (cfg.rtt_drop != SENTINEL) || (cfg.rtt_restore != SENTINEL) ||
	                  (cfg.rtt_drop_settle != SENTINEL) || (cfg.rtt_drop_trickle != SENTINEL);
	if (rtt_written != expect_rtt_set) {
		fprintf(stderr, "FAIL: v=%d rtt fields written=%d (want %d)\n",
		        version, rtt_written, expect_rtt_set);
		failures++;
	}
	return failures;
}

int main(void)
{
	int failures = 0;

	failures += check(0, 0, 0, 0);
	failures += check(1, 1, 0, 0);
	failures += check(3, 1, 0, 0);
	failures += check(4, 1, 1, 0);
	failures += check(5, 1, 1, 0);
	failures += check(6, 1, 1, 1);

	/* The public header maps rist_peer_config_defaults_set() to the
	 * caller's compiled RIST_PEER_CONFIG_VERSION. */
	struct rist_peer_config cfg;
	memset(&cfg, 0, sizeof(cfg));
	if (rist_peer_config_defaults_set(&cfg) != 0) {
		fprintf(stderr, "FAIL: defaults_set returned error\n");
		failures++;
	} else if (cfg.version != RIST_PEER_CONFIG_VERSION) {
		fprintf(stderr,
		        "FAIL: defaults_set recorded version=%d (want %d)\n",
		        cfg.version, RIST_PEER_CONFIG_VERSION);
		failures++;
	}

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
