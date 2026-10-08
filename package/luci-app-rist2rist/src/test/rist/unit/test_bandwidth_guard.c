/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the sender's retransmission-budget guard: whether a bandwidth
 * ceiling leaves any room for retransmissions, and how often to say so.
 * Pure, link-free. */

#include <stdio.h>

#include "../../../src/rist-bandwidth-guard.h"

static int failures;

static void check(const char *name, bool got, bool want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %d (want %d)\n", name, got, want);
		failures++;
	}
}

/* Bits per second throughout, as the caller passes. */
#define MBPS(x) ((size_t)((x) * 1000000))

int main(void)
{
	/* Comfortable headroom: the ceiling is well clear of the payload. The
	 * worst case measured in #227 wanted ~13.4 Mbps of payload plus
	 * retransmissions behind ~9.2 Mbps of payload, so a 20 Mbps ceiling is
	 * not close to starved. */
	check("ample_headroom",
	      rist_retransmit_budget_starved(MBPS(9.2), MBPS(20)), false);
	/* A thin budget is still a budget; this guard only catches the case
	 * where there is none at all. */
	check("thin_but_nonzero",
	      rist_retransmit_budget_starved(MBPS(9.2), MBPS(9.3)), false);

	/* The ceiling covers payload plus retransmissions, so a ceiling at or
	 * under the payload rate leaves nothing. 8.8 Mbps against that same
	 * 9.15 Mbps payload is the configuration that refused every NACK. */
	check("ceiling_below_payload",
	      rist_retransmit_budget_starved(MBPS(9.15), MBPS(8.8)), true);
	check("ceiling_equals_payload",
	      rist_retransmit_budget_starved(MBPS(9), MBPS(9)), true);
	check("ceiling_just_above_payload",
	      rist_retransmit_budget_starved(MBPS(9), MBPS(9) + 1), false);

	/* An unset ceiling has nothing to have exceeded; ?bandwidth=0 is
	 * ignored by the URL parser, so 0 means "left at the default". */
	check("no_ceiling", rist_retransmit_budget_starved(MBPS(100), 0), false);
	/* Nor does an idle stream warn. */
	check("idle_stream", rist_retransmit_budget_starved(0, MBPS(20)), false);

	/* The warning repeats on an interval rather than firing once, since a
	 * line at startup is long gone by the time anyone investigates. */
	check("first_time_always_due", rist_bandwidth_warn_due(0, 100, 0), true);
	check("not_due_yet", rist_bandwidth_warn_due(1000, 100, 1050), false);
	check("due_at_interval", rist_bandwidth_warn_due(1000, 100, 1100), true);
	check("due_past_interval", rist_bandwidth_warn_due(1000, 100, 5000), true);
	/* A clock that moved backwards must not stall the warning forever. */
	check("clock_went_backwards", rist_bandwidth_warn_due(1000, 100, 500), true);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
