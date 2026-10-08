/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * NACK routing peer-selection predicate.  Kept in a small standalone
 * header so the comparison can be unit-tested in isolation, without
 * constructing full peer objects or starting receiver threads.
 */

#ifndef RIST_NACK_SELECT_H
#define RIST_NACK_SELECT_H

#include <stdbool.h>
#include <stdint.h>

/* Decide whether a candidate retransmission peer should replace the
 * current best choice for receiving a NACK group.
 *
 * Selection key, highest precedence first:
 *   1. higher recovery_priority wins;
 *   2. on equal priority, lower RTT wins.
 *
 * With the default recovery_priority of 0 on every peer this collapses
 * to "lowest RTT wins", matching the historical behaviour. */
static inline bool rist_nack_peer_preferred(uint32_t cand_priority,
                                            uint64_t cand_rtt,
                                            uint32_t best_priority,
                                            uint64_t best_rtt)
{
	return cand_priority > best_priority ||
	       (cand_priority == best_priority && cand_rtt < best_rtt);
}

#endif /* RIST_NACK_SELECT_H */
