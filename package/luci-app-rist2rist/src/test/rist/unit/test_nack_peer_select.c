/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the NACK routing peer-selection predicate
 * (rist_nack_peer_preferred).  Drives the same loop send_nack_group
 * runs, over small in-memory candidate tables, and asserts which peer
 * wins.  No library link or threads required. */

#include "../../../src/rist-nack-select.h"

#include <stdint.h>
#include <stdio.h>

struct cand {
	uint32_t priority;
	uint64_t rtt;
};

/* Mirror of the send_nack_group selection loop, returning the index of
 * the chosen candidate (-1 if none). */
static int select_index(const struct cand *c, int n)
{
	int chosen = -1;
	uint32_t best_priority = 0;
	uint64_t best_rtt = UINT64_MAX;
	for (int i = 0; i < n; i++) {
		if (rist_nack_peer_preferred(c[i].priority, c[i].rtt,
		                             best_priority, best_rtt)) {
			chosen = i;
			best_priority = c[i].priority;
			best_rtt = c[i].rtt;
		}
	}
	return chosen;
}

static int check(const char *name, const struct cand *c, int n, int want)
{
	int got = select_index(c, n);
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> index %d (want %d)\n",
		        name, got, want);
		return 1;
	}
	return 0;
}

int main(void)
{
	int failures = 0;

	/* Legacy behaviour: all default priority 0 -> lowest RTT wins. */
	struct cand all_zero[] = {
		{0, 50}, {0, 20}, {0, 80},
	};
	failures += check("all_zero_lowest_rtt", all_zero, 3, 1);

	/* A higher-priority peer wins even with a much larger RTT: a
	 * duplicate/relay feed has 0 RTT but no retransmit buffer, while
	 * the recovery peer has high RTT and holds the buffer. */
	struct cand prio_over_rtt[] = {
		{0, 1},        /* duplicate feed: tiny RTT, no buffer  */
		{1000, 9000},  /* recovery peer: big RTT, holds buffer */
	};
	failures += check("priority_beats_low_rtt", prio_over_rtt, 2, 1);

	/* Among equal (highest) priority, lowest RTT breaks the tie. */
	struct cand tie_break[] = {
		{5, 100}, {5, 40}, {5, 70}, {1, 1},
	};
	failures += check("tie_break_lowest_rtt", tie_break, 4, 1);

	/* Single candidate with a measured RTT is chosen. */
	struct cand single[] = { {0, 1000} };
	failures += check("single_candidate", single, 1, 0);

	/* Legacy parity: a default-priority peer whose RTT has never been
	 * measured (UINT64_MAX sentinel) is NOT selected, matching the
	 * historical send_nack_group behaviour. */
	struct cand unmeasured_zero[] = { {0, UINT64_MAX} };
	failures += check("unmeasured_rtt_priority_zero_skipped",
	                  unmeasured_zero, 1, -1);

	/* But a high-priority peer is selected even with an unmeasured RTT:
	 * priority short-circuits the RTT comparison.  This is what lets a
	 * recovery peer receive NACKs before its first RTT sample. */
	struct cand unmeasured_high[] = { {1000, UINT64_MAX} };
	failures += check("unmeasured_rtt_high_priority_selected",
	                  unmeasured_high, 1, 0);

	/* No candidates -> none chosen. */
	failures += check("empty", NULL, 0, -1);

	/* First-seen wins on a full priority+RTT tie (stable selection). */
	struct cand full_tie[] = { {3, 30}, {3, 30} };
	failures += check("full_tie_first_wins", full_tie, 2, 0);

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
