/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * RTT-based bonded-leg muting hysteresis state machine.  Kept in a small
 * standalone header so the transition logic can be unit-tested in isolation,
 * without constructing full peer objects or starting sender threads.
 */

#ifndef RIST_RTT_MUTE_H
#define RIST_RTT_MUTE_H

#include <stdbool.h>
#include <stdint.h>

enum rist_rtt_mute_action
{
	RIST_RTT_MUTE_NONE = 0,    /* no state change this step */
	RIST_RTT_MUTE_DROP = 1,    /* transition active -> muted */
	RIST_RTT_MUTE_RESTORE = 2, /* transition muted -> active */
};

struct rist_rtt_mute_state
{
	bool muted;             /* leg currently out of the unique-payload rotation */
	bool pending;           /* a transition condition is currently held */
	uint64_t pending_since; /* tick the pending condition first held */
};

/* Advance the hysteresis machine for one leg by one sample.
 *
 * All RTT/time arguments share one unit (RIST_CLOCK ticks):
 *   smoothed_rtt  : the leg's smoothed (EWMA) round-trip time
 *   drop          : ceiling; staying above it for drop_settle mutes the leg
 *   restore       : low-water; staying below it for restore_settle restores it
 *   drop_settle   : dwell required before muting (active -> muted)
 *   restore_settle: dwell required before rejoining (muted -> active)
 *   now           : monotonic tick
 *
 * The dwell is deliberately asymmetric (drop_settle short, restore_settle
 * longer) so a bad leg is pulled quickly but a still-marginal one does not flap
 * back in; the threshold split (restore < drop) is the spatial half of the
 * hysteresis. A drop of 0 disables muting. Returns the transition taken this
 * step (NONE if unchanged) and updates *st in place. */
static inline enum rist_rtt_mute_action
rist_rtt_mute_step(struct rist_rtt_mute_state *st, uint64_t smoothed_rtt,
                   uint64_t drop, uint64_t restore,
                   uint64_t drop_settle, uint64_t restore_settle, uint64_t now)
{
	if (drop == 0) {
		st->pending = false;
		if (st->muted) {
			st->muted = false;
			return RIST_RTT_MUTE_RESTORE;
		}
		return RIST_RTT_MUTE_NONE;
	}

	bool condition = st->muted ? (smoothed_rtt < restore)
	                           : (smoothed_rtt > drop);
	if (!condition) {
		st->pending = false;
		return RIST_RTT_MUTE_NONE;
	}
	if (!st->pending) {
		st->pending = true;
		st->pending_since = now;
		return RIST_RTT_MUTE_NONE;
	}
	uint64_t settle = st->muted ? restore_settle : drop_settle;
	if (now - st->pending_since < settle)
		return RIST_RTT_MUTE_NONE;

	st->pending = false;
	if (st->muted) {
		st->muted = false;
		return RIST_RTT_MUTE_RESTORE;
	}
	st->muted = true;
	return RIST_RTT_MUTE_DROP;
}

/* Should the sole-carrier role move from the incumbent to a challenger?
 *
 * When every leg wants muting, one has to keep carrying. Choosing the leg with
 * the lowest RTT each tick sounds right but ping-pongs the payload between two
 * equally bad legs, which is worse for the stream than committing to either, so
 * hand over only when the challenger measures margin times better and the
 * incumbent has served at least held_min. */
static inline bool
rist_rtt_sole_carrier_handover(uint64_t incumbent_rtt, uint64_t challenger_rtt,
                               uint64_t held_for, uint64_t held_min, unsigned margin)
{
	if (held_for < held_min)
		return false;
	return challenger_rtt * margin <= incumbent_rtt;
}

/* Is a trickle on a muted leg still worth sending?
 *
 * The trickle keeps a muted leg carrying a little payload so a restore starts
 * warm. Once the leg is queued deeper than the receiver's buffer, nothing sent
 * on it can arrive in time to be output, and the arrivals do harm: they are old
 * enough to be the only candidate the receiver has to rebuild its baseline on
 * after a reset, which then rewinds it. Judge by the one-way delay, half the
 * round trip. A buffer of 0 means unknown, so keep trickling. */
static inline bool
rist_rtt_trickle_useful(uint64_t smoothed_rtt, uint64_t buffer)
{
	if (!buffer)
		return true;
	return (smoothed_rtt / 2) <= buffer;
}

/* Share of the configured weight a rejoining leg should carry, ramped linearly
 * to full over ramp ticks since it was restored.
 *
 * A muted leg drains, so it measures well right up until it carries traffic
 * again; handing back the full share at once refloods the queue and mutes it
 * moments later. Ramping lets the leg reveal congestion under a rising load.
 * ramp_start of 0 (never muted) or an elapsed ramp both yield full weight, and
 * a ramping leg always keeps at least 1 so it never falls out entirely. */
static inline uint32_t
rist_rtt_ramped_weight(uint32_t weight, uint64_t ramp_start, uint64_t ramp, uint64_t now)
{
	if (!ramp_start || !ramp || weight <= 1)
		return weight;
	if (now <= ramp_start || (now - ramp_start) >= ramp)
		return weight;
	uint32_t scaled = (uint32_t)((uint64_t)weight * (now - ramp_start) / ramp);
	return scaled ? scaled : 1;
}

#endif /* RIST_RTT_MUTE_H */
