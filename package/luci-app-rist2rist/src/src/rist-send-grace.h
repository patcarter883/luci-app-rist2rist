/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Whether a peer that has gone silent may still be sent payload.  Kept in a
 * small standalone header so the decision can be unit-tested without a peer,
 * a socket or a sender thread.
 */

#ifndef RIST_SEND_GRACE_H
#define RIST_SEND_GRACE_H

#include <stdbool.h>
#include <stdint.h>

/* Declaring a peer dead means its return path went quiet, which says nothing
 * about whether the forward path still works. Cutting a single-path stream the
 * moment an RTCP reply is late strands a receiver that is otherwise fine, so a
 * dead peer keeps its place in the send rotation for one recovery buffer window
 * and is only dropped once that runs out. A bonded leg never reaches this: the
 * stall check pulls it from the rotation far sooner.
 *
 * dead_since is when the peer was declared dead, grace is the window, and both
 * share one unit with now (RIST_CLOCK ticks). A grace of 0 drops the peer as
 * soon as it dies. A now behind dead_since keeps sending, which is the safe
 * reading of a clock that moved backwards. */
static inline bool
rist_peer_may_send(bool dead, uint64_t dead_since, uint64_t grace, uint64_t now)
{
	if (!dead)
		return true;
	if (now < dead_since)
		return true;
	return (now - dead_since) <= grace;
}

#endif /* RIST_SEND_GRACE_H */
