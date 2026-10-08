/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_flow_reanchor_check() - the guard that decides whether a
 * packet may become the new baseline for a flow whose buffer was just emptied.
 * Pure, link-free. */

#include <inttypes.h>
#include <stdio.h>

#include "../../../src/rist-reanchor.h"

static int failures;

static const char *name_of(enum rist_reanchor_action a)
{
	switch (a) {
	case RIST_REANCHOR_OK:
		return "OK";
	case RIST_REANCHOR_WAIT:
		return "WAIT";
	case RIST_REANCHOR_FORCED:
		return "FORCED";
	}
	return "?";
}

static void check(const char *name, enum rist_reanchor_action got,
		  enum rist_reanchor_action want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %s (want %s)\n", name, name_of(got),
			name_of(want));
		failures++;
	}
}

/* One buffer window, and source times on the same scale. */
#define BUF 1800
#define MAX 100000

int main(void)
{
	/* No baseline yet: the first packet of a flow, and the tick right after
	 * a clock wrap zeroes the high-water mark. */
	check("no_baseline", rist_flow_reanchor_check(50000, 0, BUF, 0, 0),
	      RIST_REANCHOR_OK);
	/* No known buffer depth: nothing to measure staleness against. */
	check("no_buffer", rist_flow_reanchor_check(50000, MAX, 0, 0, 0),
	      RIST_REANCHOR_OK);

	/* A current packet anchors, whether it is ahead of the high-water mark
	 * or behind it by less than the buffer can absorb. */
	check("ahead", rist_flow_reanchor_check(MAX + 500, MAX, BUF, 0, 0),
	      RIST_REANCHOR_OK);
	check("behind_within_buffer",
	      rist_flow_reanchor_check(MAX - 1000, MAX, BUF, 0, 0), RIST_REANCHOR_OK);
	/* Exactly one buffer behind is still deliverable. */
	check("behind_exactly_buffer",
	      rist_flow_reanchor_check(MAX - BUF, MAX, BUF, 0, 0), RIST_REANCHOR_OK);

	/* Past that it cannot be output at all, so it is not a baseline. */
	check("behind_past_buffer",
	      rist_flow_reanchor_check(MAX - BUF - 1, MAX, BUF, 0, 0),
	      RIST_REANCHOR_WAIT);
	/* The 15 s lag that a collapsed bonded leg delivers. */
	check("behind_lagged_leg",
	      rist_flow_reanchor_check(MAX - 15000, MAX, BUF, 0, 0),
	      RIST_REANCHOR_WAIT);

	/* The wait is bounded: once a buffer window has passed with nothing
	 * better, the stale packet is taken rather than stalling the flow. */
	check("wait_still_short",
	      rist_flow_reanchor_check(MAX - 15000, MAX, BUF, 1000, 1000 + BUF - 1),
	      RIST_REANCHOR_WAIT);
	check("wait_expired",
	      rist_flow_reanchor_check(MAX - 15000, MAX, BUF, 1000, 1000 + BUF),
	      RIST_REANCHOR_FORCED);
	check("wait_long_expired",
	      rist_flow_reanchor_check(MAX - 15000, MAX, BUF, 1000, 1000 + 10 * BUF),
	      RIST_REANCHOR_FORCED);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
