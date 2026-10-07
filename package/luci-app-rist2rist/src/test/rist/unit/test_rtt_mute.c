/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for the RTT-based bonded-leg muting hysteresis state machine
 * (rist_rtt_mute_step).  Drives sample sequences through the pure function
 * and asserts the drop/restore transitions and dwell behaviour.  No library
 * link or threads required. */

#include "../../../src/rist-rtt-mute.h"

#include <stdint.h>
#include <stdio.h>

/* Thresholds in abstract "tick" units; the production caller uses RIST_CLOCK
 * ticks but the machine is unit-agnostic. */
#define DROP     500
#define RESTORE  400
#define SETTLE   3

static int failures;

static void expect(const char *name, enum rist_rtt_mute_action got,
                   enum rist_rtt_mute_action want, bool muted, bool want_muted)
{
	if (got != want || muted != want_muted) {
		fprintf(stderr, "FAIL: %s -> action %d muted %d (want action %d muted %d)\n",
		        name, got, muted, want, want_muted);
		failures++;
	}
}

static void check(const char *name, bool got, bool want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %d (want %d)\n", name, got, want);
		failures++;
	}
}

static void check_weight(const char *name, uint32_t got, uint32_t want)
{
	if (got != want) {
		fprintf(stderr, "FAIL: %s -> %u (want %u)\n", name, got, want);
		failures++;
	}
}

int main(void)
{
	/* A leg that never crosses the ceiling stays active. */
	{
		struct rist_rtt_mute_state st = {0};
		enum rist_rtt_mute_action a = RIST_RTT_MUTE_NONE;
		for (uint64_t t = 0; t < 10; t++)
			a = rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, t);
		expect("stays_active_below_ceiling", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Over the ceiling but not long enough to satisfy the dwell: no drop. */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 0); /* arm pending */
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 1); /* dwell not met */
		expect("no_drop_before_settle", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Sustained over the ceiling past the dwell: drop. */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 0);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 1);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 2);
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 3); /* now-since == SETTLE */
		expect("drop_after_settle", a, RIST_RTT_MUTE_DROP, st.muted, true);
	}

	/* A transient dip back under the ceiling resets the dwell (anti-flap). */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 0);
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 1);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, 2); /* dip: clears pending */
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, SETTLE, SETTLE, 3); /* re-arm, no drop yet */
		expect("dip_resets_dwell", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Hysteresis: while muted, RTT between restore and drop does NOT restore. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		enum rist_rtt_mute_action a = RIST_RTT_MUTE_NONE;
		for (uint64_t t = 0; t < 10; t++)
			a = rist_rtt_mute_step(&st, 450, DROP, RESTORE, SETTLE, SETTLE, t); /* in the band */
		expect("no_restore_in_hysteresis_band", a, RIST_RTT_MUTE_NONE, st.muted, true);
	}

	/* Sustained below the restore low-water past the dwell: restore. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, 0);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, 1);
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, 2);
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 100, DROP, RESTORE, SETTLE, SETTLE, 3);
		expect("restore_after_settle", a, RIST_RTT_MUTE_RESTORE, st.muted, false);
	}

	/* drop == 0 disables the feature and force-restores a muted leg. */
	{
		struct rist_rtt_mute_state st = { .muted = true };
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 9999, 0, RESTORE, SETTLE, SETTLE, 0);
		expect("disabled_forces_restore", a, RIST_RTT_MUTE_RESTORE, st.muted, false);
	}

	/* drop == 0 on an already-active leg is a no-op. */
	{
		struct rist_rtt_mute_state st = {0};
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 9999, 0, RESTORE, SETTLE, SETTLE, 0);
		expect("disabled_active_noop", a, RIST_RTT_MUTE_NONE, st.muted, false);
	}

	/* Asymmetric dwell: a leg drops fast (drop_settle) but only rejoins after
	 * the longer restore_settle, so a marginal link cannot flap back in. With
	 * drop_settle 1 and restore_settle 5, muting engages quickly... */
	{
		struct rist_rtt_mute_state st = {0};
		rist_rtt_mute_step(&st, 900, DROP, RESTORE, 1, 5, 0); /* arm */
		enum rist_rtt_mute_action a =
			rist_rtt_mute_step(&st, 900, DROP, RESTORE, 1, 5, 1); /* fast drop */
		expect("asymmetric_fast_drop", a, RIST_RTT_MUTE_DROP, st.muted, true);

		/* ...but rejoining waits the full restore_settle: below the low-water
		 * for less than restore_settle does NOT restore yet. */
		rist_rtt_mute_step(&st, 100, DROP, RESTORE, 1, 5, 2); /* arm restore */
		a = rist_rtt_mute_step(&st, 100, DROP, RESTORE, 1, 5, 5); /* dwell 3 < 5 */
		expect("asymmetric_slow_restore_hold", a, RIST_RTT_MUTE_NONE, st.muted, true);

		/* Past the longer window it finally restores. */
		a = rist_rtt_mute_step(&st, 100, DROP, RESTORE, 1, 5, 7); /* dwell 5 == 5 */
		expect("asymmetric_slow_restore_fires", a, RIST_RTT_MUTE_RESTORE, st.muted, false);
	}

	/* Sole-carrier handover: when every leg wants muting one must keep
	 * carrying, and the role is sticky so the payload does not ping-pong. */
	{
		/* A marginally better challenger does not take the role, even
		 * once the incumbent has served its minimum. */
		check("handover_rejects_small_margin",
		      rist_rtt_sole_carrier_handover(126, 85, 10, 3, 2), false);
		/* Twice as good is enough. */
		check("handover_accepts_clear_margin",
		      rist_rtt_sole_carrier_handover(1162, 406, 10, 3, 2), true);
		/* ...but not before the incumbent has held for the minimum. */
		check("handover_holds_until_min",
		      rist_rtt_sole_carrier_handover(1162, 406, 2, 3, 2), false);
		/* Exactly at the margin and exactly at the minimum both count. */
		check("handover_boundaries",
		      rist_rtt_sole_carrier_handover(800, 400, 3, 3, 2), true);
	}

	/* Post-restore weight ramp. */
	{
		/* Never muted (no ramp start) or a finished ramp: full weight. */
		check_weight("ramp_absent", rist_rtt_ramped_weight(10, 0, 100, 50), 10);
		check_weight("ramp_complete", rist_rtt_ramped_weight(10, 0 + 1, 100, 201), 10);
		/* Linear across the window. */
		check_weight("ramp_quarter", rist_rtt_ramped_weight(10, 100, 100, 125), 2);
		check_weight("ramp_half", rist_rtt_ramped_weight(10, 100, 100, 150), 5);
		check_weight("ramp_end", rist_rtt_ramped_weight(10, 100, 100, 200), 10);
		/* A ramping leg never drops out of the rotation entirely. */
		check_weight("ramp_floor_is_one", rist_rtt_ramped_weight(10, 100, 100, 101), 1);
		/* Weight 1 and duplicate legs (0) are left alone. */
		check_weight("ramp_skips_weight_one", rist_rtt_ramped_weight(1, 100, 100, 150), 1);
		check_weight("ramp_skips_duplicate", rist_rtt_ramped_weight(0, 100, 100, 150), 0);
	}

	/* Trickle cutoff on a leg queued deeper than the buffer. */
	{
		/* One-way delay well inside the buffer: keep the leg warm. */
		check("trickle_within_buffer", rist_rtt_trickle_useful(400, 1800), true);
		/* One way is half the round trip, so the cutoff is twice the buffer. */
		check("trickle_at_cutoff", rist_rtt_trickle_useful(3600, 1800), true);
		check("trickle_past_cutoff", rist_rtt_trickle_useful(3602, 1800), false);
		/* The 33 s round trips seen on a collapsed leg. */
		check("trickle_collapsed_leg", rist_rtt_trickle_useful(33000, 1800), false);
		/* Unknown buffer: no basis to stop. */
		check("trickle_unknown_buffer", rist_rtt_trickle_useful(33000, 0), true);
	}

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
