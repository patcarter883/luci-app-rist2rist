/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the retransmission sequence-domain predicate
 * (rist_retx_use_rtp_domain).  Regression guard for the mixed-profile
 * ARQ defect: an Advanced head-end serving a peer that negotiated down
 * to Main must resolve/verify/frame that peer's retransmits in the
 * 16-bit RTP sequence domain, not the 32-bit advanced domain, or the
 * Main peer's NACKs never resolve and nothing is retransmitted
 * (recovered_packets_total stays 0).  No library link or threads. */

#include "../../../src/rist-retx-domain.h"

#include <stdio.h>

static int check(const char *name, enum rist_profile profile,
                 bool remote_adv, bool want)
{
	bool got = rist_retx_use_rtp_domain(profile, remote_adv);
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %d (want %d)\n", name, got, want);
		return 1;
	}
	return 0;
}

int main(void)
{
	int failures = 0;

	/* The bug case: Advanced context, peer has NOT advertised Advanced
	 * (negotiated down to Main) -> must use the 16-bit RTP domain. */
	failures += check("advanced_ctx_main_peer",
	                  RIST_PROFILE_ADVANCED, false, true);

	/* Production Advanced<->Advanced: peer advertised Advanced -> keep
	 * the 32-bit advanced domain (unchanged behaviour). */
	failures += check("advanced_ctx_advanced_peer",
	                  RIST_PROFILE_ADVANCED, true, false);

	/* Main context: its primary index is already the RTP domain, so the
	 * predicate must not divert (regardless of the peer flag). */
	failures += check("main_ctx_main_peer",
	                  RIST_PROFILE_MAIN, false, false);
	failures += check("main_ctx_adv_flag",
	                  RIST_PROFILE_MAIN, true, false);

	/* Simple context likewise. */
	failures += check("simple_ctx",
	                  RIST_PROFILE_SIMPLE, false, false);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
