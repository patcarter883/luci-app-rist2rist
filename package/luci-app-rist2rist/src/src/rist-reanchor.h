/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Whether a packet may serve as the new baseline for a flow whose buffer has
 * just been emptied.  Kept in a small standalone header so the decision can be
 * unit-tested without a flow, a peer or a receiver thread.
 */

#ifndef RIST_REANCHOR_H
#define RIST_REANCHOR_H

#include <stdint.h>

enum rist_reanchor_action
{
	RIST_REANCHOR_OK = 0,     /* current enough; anchor the flow on it */
	RIST_REANCHOR_WAIT = 1,   /* too far behind; drop it and wait */
	RIST_REANCHOR_FORCED = 2, /* too far behind, but nothing better is coming */
};

/* Anchoring adopts a packet's sequence number and clock as the flow baseline,
 * so it has to come from a leg that is current. A bonded leg queued seconds
 * deep keeps delivering packets that old, and anchoring on one rewinds the
 * baseline by its lag: the next healthy packet then looks like a multi-second
 * jump, which empties the buffer again and can repeat until the stream dies.
 *
 * A packet more than buffer behind the highest source time the flow has seen
 * cannot be output anyway, so it is never a good baseline. Waiting for a better
 * one is bounded at one buffer window, after which there is no current leg left
 * to wait for -- or the source itself restarted on a lower clock -- and the
 * packet in hand is taken (FORCED).
 *
 * max_source_time or buffer of 0 means there is no baseline to compare against
 * yet (first packet of a flow, or just after a clock wrap): anchor freely.
 * waiting_since is when the flow first refused a candidate, 0 if it has not.
 * All times share one unit (RIST_CLOCK ticks). */
static inline enum rist_reanchor_action
rist_flow_reanchor_check(uint64_t source_time, uint64_t max_source_time,
                         uint64_t buffer, uint64_t waiting_since, uint64_t now)
{
	if (!max_source_time || !buffer)
		return RIST_REANCHOR_OK;
	if ((source_time + buffer) >= max_source_time)
		return RIST_REANCHOR_OK;
	if (waiting_since && (now - waiting_since) >= buffer)
		return RIST_REANCHOR_FORCED;
	return RIST_REANCHOR_WAIT;
}

#endif /* RIST_REANCHOR_H */
