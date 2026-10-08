/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_peer_may_send() - the grace period that keeps a peer in
 * the send rotation for one recovery buffer window after it is declared dead.
 * Pure, link-free. */

#include <stdio.h>

#include "../../../src/rist-send-grace.h"

static int failures;

static void check(const char *name, bool got, bool want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %s (want %s)\n", name,
			got ? "send" : "drop", want ? "send" : "drop");
		failures++;
	}
}

/* One buffer window, and a death well clear of zero so a backwards clock is
 * expressible. */
#define GRACE 4000
#define DIED 100000

int main(void)
{
	/* A live peer is always eligible, whatever the clock says. */
	check("alive", rist_peer_may_send(false, 0, GRACE, DIED), true);
	check("alive_no_grace", rist_peer_may_send(false, 0, 0, DIED), true);

	/* A dead peer keeps its place until the window runs out. This is the
	 * single-path case from #196: the return path went quiet but the
	 * receiver is still there, so cutting the stream strands it. */
	check("died_now", rist_peer_may_send(true, DIED, GRACE, DIED), true);
	check("inside_window",
	      rist_peer_may_send(true, DIED, GRACE, DIED + GRACE / 2), true);
	check("last_tick_of_window",
	      rist_peer_may_send(true, DIED, GRACE, DIED + GRACE), true);

	/* Past the window there is nothing left to wait for. */
	check("just_past_window",
	      rist_peer_may_send(true, DIED, GRACE, DIED + GRACE + 1), false);
	check("long_gone",
	      rist_peer_may_send(true, DIED, GRACE, DIED + 100 * GRACE), false);

	/* No configured window: a dead peer is dropped at once. */
	check("no_grace", rist_peer_may_send(true, DIED, 0, DIED), true);
	check("no_grace_next_tick", rist_peer_may_send(true, DIED, 0, DIED + 1),
	      false);

	/* A clock that moved backwards must not read as an expired window and
	 * cut a stream that is still fine. */
	check("clock_went_backwards",
	      rist_peer_may_send(true, DIED, GRACE, DIED - 10 * GRACE), true);
	check("clock_went_back_one_tick",
	      rist_peer_may_send(true, DIED, GRACE, DIED - 1), true);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
