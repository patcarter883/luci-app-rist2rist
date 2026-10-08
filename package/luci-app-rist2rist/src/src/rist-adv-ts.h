/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Advanced Profile (TR-06-3) receive-side source-clock reconstruction.
 *
 * The Advanced Profile carries a 32-bit RTP timestamp on a 1 MHz clock
 * (Section 5.2.1), i.e. microseconds that wrap every ~71.6 min. To dejitter
 * off the sender's timeline (instead of local arrival), the receiver rebuilds
 * a monotonic 64-bit NTP source clock from that field: accumulate wrap-safe
 * signed deltas (good for reorders/gaps up to +-35 min) scaled us -> NTP
 * ticks (x 2^32/1e6, exact as x2^26/15625, overflow-safe).
 *
 * By default the receiver assumes a conformant clock and dejitters off it
 * immediately, exactly like the Main profile. The catch is our own history:
 * librist releases before this one emitted this timestamp on a broken clock
 * (65536x too fast; see the sender fix), so a receiver may be fed by a sender
 * still running that code. There is no negotiated signal for it, so over the
 * first window the receiver also checks that the rebuilt clock advances at
 * real-time rate. A conformant clock matches arrival elapsed within jitter; a
 * broken one is off by orders of magnitude, and the peer then falls back to
 * arrival timing. The fallback is re-tried every window, not latched for the
 * session: a sender that recovers (or an attack burst that stops) costs one
 * window of dejitter, not the rest of the session. */

#ifndef RIST_ADV_TS_H
#define RIST_ADV_TS_H

#include <stdbool.h>
#include <stdint.h>

struct rist_adv_ts_state {
	bool seeded;         /* first live packet has anchored the clock */
	bool calibrating;    /* still verifying the source clock rate */
	bool use_source;     /* post-verdict: source clock kept, else arrival */
	uint32_t last;       /* last wire 1 MHz timestamp accumulated */
	uint64_t accum;      /* reconstructed source time, NTP ticks (1 s = 2^32) */
	uint64_t seed_now;   /* arrival at the window anchor */
	uint64_t deadline;   /* seed_now + window: when the verdict is (re)taken */
	uint64_t recon_anchor; /* accum at the window anchor (fallback re-verdict) */
};

/* Reconstruct the source time (NTP ticks) for one Advanced data packet.
 *   wire_ts   : the packet's 32-bit 1 MHz RTP timestamp
 *   now       : local arrival time (NTP ticks), also the fallback value
 *   window    : the source clock is used immediately; over this span its rate
 *               is verified and, if it fails, the peer falls back to arrival
 *               (re-verified every window thereafter)
 *   advance   : true for an in-order live packet (advances the clock);
 *               false for a retransmit (position only, no state change)
 * Returns the source time to stamp the packet with. */
static inline uint64_t
rist_adv_ts_reconstruct(struct rist_adv_ts_state *st, uint32_t wire_ts,
			uint64_t now, uint64_t window, bool advance)
{
	/* Only a live packet can anchor the clock; until then there is no
	 * reference, so stamp arrival. */
	if (!st->seeded) {
		if (!advance)
			return now;
		st->seeded = true;
		st->calibrating = true;
		st->last = wire_ts;
		st->accum = now;
		st->seed_now = now;
		st->deadline = now + window;
		st->recon_anchor = st->accum;
		return now;
	}

	/* Advance the rebuilt clock by the wire delta (wrap-safe signed 32-bit),
	 * scaled us -> NTP ticks. */
	int64_t d = (int32_t)(wire_ts - st->last);
	uint64_t recon = st->accum + (uint64_t)((d * 67108864LL) / 15625LL);

	if (st->calibrating) {
		/* Assume a conformant clock and dejitter off it from the start,
		 * like the Main profile. A retransmit only positions. Do not
		 * re-anchor here: a broken clock must be allowed to diverge so the
		 * verdict can see it. */
		if (!advance)
			return recon;
		st->accum = recon;
		st->last = wire_ts;
		if (now < st->deadline)
			return recon;
		/* Verdict: over a full window a conformant clock has advanced at
		 * real-time rate, so reconstructed elapsed matches arrival elapsed
		 * within jitter. A broken clock (the 65536x-fast one an older
		 * release emitted) misses by far more; fall back to arrival and
		 * keep re-trying the verdict every window. */
		st->calibrating = false;
		uint64_t src_elapsed = st->accum - st->seed_now;
		uint64_t arr_elapsed = now - st->seed_now;
		uint64_t drift = src_elapsed > arr_elapsed
				 ? src_elapsed - arr_elapsed
				 : arr_elapsed - src_elapsed;
		st->use_source = drift <= (arr_elapsed >> 1);
		st->recon_anchor = st->accum;
		st->seed_now = now;
		st->deadline = now + window;
		return st->use_source ? recon : now;
	}

	if (!st->use_source) {
		/* Arrival fallback. Keep tracking the wire clock and re-run the
		 * verdict each window; if the source clock advances at real-time
		 * rate again, resume dejittering off it. A retransmit only
		 * positions (stamped arrival anyway). */
		if (!advance)
			return now;
		st->accum = recon;
		st->last = wire_ts;
		if (now >= st->deadline) {
			uint64_t src_elapsed = st->accum - st->recon_anchor;
			uint64_t arr_elapsed = now - st->seed_now;
			uint64_t drift = src_elapsed > arr_elapsed
					 ? src_elapsed - arr_elapsed
					 : arr_elapsed - src_elapsed;
			st->use_source = drift <= (arr_elapsed >> 1);
			st->recon_anchor = st->accum;
			st->seed_now = now;
			st->deadline = now + window;
		}
		return now;
	}

	if (!advance)
		return recon; /* retransmit: position only, no state change */

	/* Verified: trust the source clock like the Main profile. A sender clock
	 * discontinuity is followed, not snapped to arrival (snapping would inject
	 * worse jitter than the jump itself). */
	st->accum = recon;
	st->last = wire_ts;
	return recon;
}

#endif /* RIST_ADV_TS_H */
