/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Whether a sender peer has any retransmission budget left to work with, and
 * whether it is time to say so again.  Kept in a small standalone header so
 * both can be unit-tested without a peer or a running sender.
 */

#ifndef RIST_BANDWIDTH_GUARD_H
#define RIST_BANDWIDTH_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Is the retransmission budget structurally exhausted?
 *
 * The bandwidth ceiling (?bandwidth=, recovery_maxbitrate) is not a limit on
 * payload: rist_retry_dequeue() refuses a retransmission whenever payload plus
 * retransmit bitrate would cross it, so what the ceiling really bounds is the
 * two together. Set it at or below the payload rate and the budget is nil --
 * every NACK is refused for as long as the stream runs, and the only trace is a
 * debug-level line nobody has enabled. What the operator sees is a link that
 * never recovers a lost packet, which reads as a bad network rather than a bad
 * ceiling, so it is worth saying out loud.
 *
 * payload and ceiling share one unit (bits per second). A ceiling of 0 means
 * "unset" everywhere it can still be seen -- init_peer_settings() replaces it
 * with the default before a peer runs -- so there is nothing to have exceeded. */
static inline bool
rist_retransmit_budget_starved(size_t payload_bps, size_t ceiling_bps)
{
	if (!ceiling_bps)
		return false;
	return payload_bps >= ceiling_bps;
}

/* Rate-limit for the warning above, which is evaluated once per stats interval
 * and would otherwise repeat every second for the life of a misconfigured
 * stream. Still repeats, because a single line at startup scrolls away long
 * before anyone goes looking for why nothing recovers.
 *
 * last is when it was last emitted (0 if never) and shares one unit with now.
 * A now behind last emits, which is the harmless reading of a clock that moved
 * backwards. */
static inline bool
rist_bandwidth_warn_due(uint64_t last, uint64_t interval, uint64_t now)
{
	if (!last || now < last)
		return true;
	return (now - last) >= interval;
}

#endif /* RIST_BANDWIDTH_GUARD_H */
