/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Retransmission sequence-domain predicate.  An Advanced-context sender
 * indexes its retransmit buffer by the 32-bit advanced sequence, but a
 * peer that has negotiated down to Main (TR-06-3 §9: an Advanced device
 * starts each peer in Main and only frames Advanced once the peer
 * advertises I=1) requests retransmits with a 16-bit RTP sequence
 * (nack_seq_msb = 0).  Those two sequence spaces are independent
 * counters, so a Main peer's NACK never resolves against the 32-bit
 * index and its losses are never retransmitted.  This predicate decides,
 * per outgoing retransmission, whether to resolve/verify/frame it in the
 * 16-bit RTP domain instead.  Kept standalone so it can be unit-tested
 * without constructing peers or starting threads.
 */

#ifndef RIST_RETX_DOMAIN_H
#define RIST_RETX_DOMAIN_H

#include <stdbool.h>

#include "librist/headers.h" /* enum rist_profile */

/* True when a retransmission for a peer must be resolved in the 16-bit
 * RTP sequence domain rather than the 32-bit advanced domain: only an
 * Advanced-context sender serving a peer that has NOT negotiated up to
 * Advanced.  Every other case (Advanced<->Advanced, or a Main/Simple
 * context whose primary index is already the RTP domain) returns false,
 * so the established paths are unchanged. */
static inline bool rist_retx_use_rtp_domain(enum rist_profile ctx_profile,
                                            bool remote_supports_advanced)
{
	return ctx_profile == RIST_PROFILE_ADVANCED && !remote_supports_advanced;
}

#endif /* RIST_RETX_DOMAIN_H */
