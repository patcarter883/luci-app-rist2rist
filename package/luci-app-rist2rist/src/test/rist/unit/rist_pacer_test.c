/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Unit tests for the CBR pacing scheduler (rist_pacer).
 *
 * Every failure mode of this module still emits packets, at the wrong cadence or
 * the wrong rate, so the invariants are asserted rather than inspected. */

#include "rist_pacer.h"

#include <assert.h>
#include <stdio.h>

/* A representative CBR datagram: seven MPEG-TS packets at 71.25 Mbps. */
#define DGRAM_BYTES  (7 * 188)
#define RATE_BPS     71250000ULL

static void test_rate_converges(void)
{
	struct rist_pacer_rate r;
	uint64_t now_us = 1000000;

	rist_pacer_rate_init(&r, 0);
	assert(rist_pacer_rate_bps(&r) == 0);   /* nothing known yet: do not pace */

	/* Six seconds of exact-rate traffic, fed one datagram at a time. */
	uint64_t step_us = (uint64_t)DGRAM_BYTES * 8ULL * 1000000ULL / RATE_BPS;
	for (int i = 0; i < 6 * 1000000 / (int)step_us; i++) {
		now_us += step_us;
		rist_pacer_rate_add(&r, DGRAM_BYTES, now_us);
	}

	uint64_t bps = rist_pacer_rate_bps(&r);
	double err = ((double)bps - (double)RATE_BPS) / (double)RATE_BPS;
	if (err < 0)
		err = -err;
	assert(err < 0.01);
	printf("  rate converged to %llu bps (want %llu, err %.3f%%)\n",
	       (unsigned long long)bps, (unsigned long long)RATE_BPS, err * 100.0);
}

static void test_rate_freezes_across_outage(void)
{
	struct rist_pacer_rate r;
	uint64_t now_us = 1000000;

	rist_pacer_rate_init(&r, RATE_BPS);
	uint64_t before = rist_pacer_rate_bps(&r);
	assert(before == RATE_BPS);

	/* Data resuming 30 s later must not average in as a near-zero rate. */
	rist_pacer_rate_add(&r, DGRAM_BYTES, now_us);
	now_us += 30000000;
	rist_pacer_rate_add(&r, DGRAM_BYTES, now_us);

	assert(rist_pacer_rate_bps(&r) == before);
	printf("  rate held at %llu bps across a 30 s outage\n",
	       (unsigned long long)before);
}

static void test_interval_ignores_sleep_floor(void)
{
	struct rist_pacer p;

	/* Clamping a 148 us interval up to a 250 us floor would pace at 42 Mbps
	 * instead of 71: smooth-looking output, 40% too slow. */
	rist_pacer_init(&p, 0.0, 250000, 5000000);

	uint64_t interval = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES, 0);
	uint64_t want = (uint64_t)DGRAM_BYTES * 8ULL * 1000000000ULL / RATE_BPS;
	assert(interval == want);
	assert(interval < p.min_sleep_ns);

	assert(rist_pacer_interval_ns(&p, 0, DGRAM_BYTES, 0) == 0);
	printf("  interval stayed at %llu ns, below the %llu ns sleep floor\n",
	       (unsigned long long)interval, (unsigned long long)p.min_sleep_ns);
}

static void test_feedback_direction_and_clamp(void)
{
	struct rist_pacer p, raw;
	rist_pacer_init(&p, 40.0, 0, 5000000);
	rist_pacer_init(&raw, 0.0, 0, 5000000);

	/* Reference needs feedback off: occupancy 0 is itself a large fill trim. */
	uint64_t base = rist_pacer_interval_ns(&raw, RATE_BPS, DGRAM_BYTES, 0);

	/* Target fill is 40 ms at this rate, i.e. ~271 datagrams. */
	double target_dg = ((double)RATE_BPS / 8.0 * 0.040) / (double)DGRAM_BYTES;
	uint64_t at_target = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES,
	                                            (size_t)target_dg);
	uint64_t over = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES,
	                                       (size_t)(target_dg * 4));
	uint64_t under = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES, 0);

	/* At target the trim is a no-op; above it drains, below it fills. */
	double at_err = ((double)at_target - (double)base) / (double)base;
	if (at_err < 0)
		at_err = -at_err;
	assert(at_err < 0.01);
	assert(over < at_target);
	assert(under > at_target);

	/* Both directions clamped, so no queue excursion can slew the output rate
	 * more than 20% away from the measured one. */
	assert(over >= (uint64_t)((double)base * RIST_PACER_FEEDBACK_MIN) - 1);
	assert(under <= (uint64_t)((double)base * RIST_PACER_FEEDBACK_MAX) + 1);
	printf("  feedback: %llu ns at target (raw %llu), %llu when full, %llu when empty\n",
	       (unsigned long long)at_target, (unsigned long long)base,
	       (unsigned long long)over, (unsigned long long)under);
}

static void test_quota_averages_the_true_rate(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 0.0, 250000, 5000000);

	uint64_t interval = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES, 0);
	uint64_t now_ns = 1000000000ULL;
	uint64_t released = 0;
	const int wakes = 4000;   /* 1 s of wakes at the 250 us floor */

	for (int i = 0; i < wakes; i++) {
		released += rist_pacer_quota(&p, now_ns, interval, 64);
		now_ns += 250000;
	}

	/* A floor coarser than the interval must not throttle: the batch absorbs it. */
	double got_bps = (double)released * DGRAM_BYTES * 8.0;
	double err = (got_bps - (double)RATE_BPS) / (double)RATE_BPS;
	if (err < 0)
		err = -err;
	assert(err < 0.01);
	printf("  quota over %d wakes released %llu datagrams = %.2f Mbps (err %.3f%%)\n",
	       wakes, (unsigned long long)released, got_bps / 1e6, err * 100.0);
}

static void test_quota_ungated_without_an_estimate(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 0.0, 250000, 5000000);

	/* No rate means no authority to hold anything back. */
	assert(rist_pacer_quota(&p, 1000000000ULL, 0, 32) == 32);
	printf("  no estimate: quota passes everything through\n");
}

static void test_slip_resyncs_without_catching_up(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 0.0, 250000, 5000000);

	uint64_t interval = rist_pacer_interval_ns(&p, RATE_BPS, DGRAM_BYTES, 0);
	uint64_t now_ns = 1000000000ULL;

	rist_pacer_quota(&p, now_ns, interval, 64);
	assert(p.underruns == 0);

	/* Draining 2 s of arrears would be ~13500 datagrams in one wake. */
	now_ns += 2000000000ULL;
	unsigned n = rist_pacer_quota(&p, now_ns, interval, 64);
	assert(p.underruns == 1);
	assert(n <= 1);
	printf("  2 s stall: resynced with %u datagram(s), %llu underrun(s)\n",
	       n, (unsigned long long)p.underruns);

	/* Lateness inside the window is drift, to be corrected, not a resync. */
	uint64_t before = p.underruns;
	now_ns += RIST_PACER_MAX_SLIP_NS / 2;
	rist_pacer_quota(&p, now_ns, interval, 64);
	assert(p.underruns == before);
	printf("  lateness inside the slip window did not resync\n");
}

static void test_sleep_clamped_both_ends(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 0.0, 250000, 5000000);
	uint64_t now_ns = 1000000000ULL;

	/* Idle, nothing scheduled: wait the normal idle interval. */
	assert(rist_pacer_sleep_ns(&p, now_ns) == 5000000);

	/* Sooner than the floor: floored, bounding the wakeup rate. */
	rist_pacer_due_ns(&p, now_ns);
	rist_pacer_advance(&p, 148000);
	assert(rist_pacer_sleep_ns(&p, now_ns) == 250000);

	/* A far-future due time still respects the ceiling. */
	rist_pacer_reset(&p);
	rist_pacer_due_ns(&p, now_ns);
	rist_pacer_advance(&p, 900000000ULL);
	assert(rist_pacer_sleep_ns(&p, now_ns) == 5000000);

	/* Already due: wake as soon as the floor allows. */
	rist_pacer_reset(&p);
	rist_pacer_due_ns(&p, now_ns);
	assert(rist_pacer_sleep_ns(&p, now_ns + 1000) == 250000);

	printf("  sleep clamped to [250 us, 5 ms] in all four cases\n");
}

static void test_reset_keeps_configuration(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 40.0, 250000, 5000000);

	uint64_t now_ns = 1000000000ULL;
	rist_pacer_due_ns(&p, now_ns);
	rist_pacer_advance(&p, 148000);
	assert(p.next_due_ns != 0);

	rist_pacer_reset(&p);
	assert(p.next_due_ns == 0);
	assert(p.min_sleep_ns == 250000 && p.max_sleep_ns == 5000000);
	assert(p.target_latency_ms == 40.0);

	/* A known discontinuity must not be charged as an underrun. */
	uint64_t before = p.underruns;
	rist_pacer_due_ns(&p, now_ns + 10000000000ULL);
	assert(p.underruns == before);
	printf("  reset re-anchors the schedule without counting an underrun\n");
}

/* A replay of the receiver's output gate over a bursty source, where the whole of
 * a burst shares one release deadline. Modelled in the units the gate uses, so a
 * regression shows up as a batch - the symptom that matters - rather than as a
 * changed constant. */
#define GATE_WAKE_NS     107000ULL          /* measured output-loop wake gap */
#define GATE_HOLD_NS     10000000ULL        /* 2 x the 5 ms wake ceiling */
#define GATE_BURST       12
#define GATE_QUEUE       64                 /* undrained bursts; one is the observed depth */

static void gate_replay(uint64_t hold_ns, int reanchor_when_idle,
                        unsigned duty, unsigned *max_per_wake, double *out_bps)
{
	struct rist_pacer p;
	rist_pacer_init(&p, 0.0, 250000, 5000000);

	uint64_t interval = (uint64_t)DGRAM_BYTES * 8ULL * 1000000000ULL / RATE_BPS;
	uint64_t now = 1000000000ULL;
	uint64_t next_arrival = now;
	unsigned released = 0, worst = 0;
	const unsigned wakes = 200000;

	/* Deadlines rather than a count, because a burst carries one between all of
	 * it and a packet stays overdue against it across however many wakes it
	 * waits - which is what a tight ceiling eventually trips on. */
	uint64_t due[GATE_QUEUE];
	unsigned left[GATE_QUEUE];
	unsigned qh = 0, qt = 0;

	for (unsigned w = 0; w < wakes; w++, now += GATE_WAKE_NS) {
		while (next_arrival <= now) {
			assert(qt - qh < GATE_QUEUE);
			due[qt & (GATE_QUEUE - 1)] = next_arrival;
			left[qt & (GATE_QUEUE - 1)] = GATE_BURST;
			qt++;
			next_arrival += duty * GATE_BURST * interval;
		}

		unsigned this_wake = 0;
		int stopped_on_pacer = 0;
		while (qh != qt) {
			uint64_t head_due = due[qh & (GATE_QUEUE - 1)];
			uint64_t overdue = now > head_due ? now - head_due : 0;
			if (rist_pacer_due_ns(&p, now) > now) {
				if (overdue < hold_ns) {
					stopped_on_pacer = 1;
					break;
				}
				rist_pacer_reset(&p);
				rist_pacer_due_ns(&p, now);
			}
			rist_pacer_advance(&p, interval);
			if (--left[qh & (GATE_QUEUE - 1)] == 0)
				qh++;
			this_wake++;
			released++;
		}
		if (reanchor_when_idle && !stopped_on_pacer)
			rist_pacer_reset(&p);

		if (w > wakes / 10 && this_wake > worst)
			worst = this_wake;
	}

	*max_per_wake = worst;
	*out_bps = (double)released * DGRAM_BYTES * 8.0
	         / ((double)wakes * GATE_WAKE_NS / 1e9);
}

static void test_burst_spreads_at_the_paced_cadence(void)
{
	unsigned worst;
	double bps;

	/* Both rules in force: the burst leaves one datagram at a time, and the
	 * spreading costs nothing in throughput. */
	gate_replay(GATE_HOLD_NS, 1, 1, &worst, &bps);
	assert(worst == 1);
	double err = (bps - (double)RATE_BPS) / (double)RATE_BPS;
	if (err < 0)
		err = -err;
	assert(err < 0.01);
	printf("  burst of %d spread to %u datagram per wake at %.2f Mbps\n",
	       GATE_BURST, worst, bps / 1e6);

	/* A ceiling under the drain time re-anchors mid-burst, and the rest of the
	 * burst follows it out in the same wake. */
	gate_replay(1000000ULL, 1, 1, &worst, &bps);
	assert(worst > 1);
	printf("  ceiling below the drain released %u at once\n", worst);

	/* A source that pauses between bursts leaves the schedule behind the clock.
	 * Re-anchored it still spreads; left running it spends the gap at once. */
	gate_replay(GATE_HOLD_NS, 1, 2, &worst, &bps);
	assert(worst == 1);
	printf("  gapped source, re-anchored: still %u per wake\n", worst);

	gate_replay(GATE_HOLD_NS, 0, 2, &worst, &bps);
	assert(worst > 1);
	printf("  gapped source, schedule left running: %u at once\n", worst);
}

/* A second, independent implementation of the schedule, so the whole sequence of
 * send times can be compared rather than individual calls. Deliberately not
 * factored against the module: a shared helper would defeat the purpose. */
#define REF_TARGET_LATENCY_MS 40.0
#define REF_FEEDBACK_K        0.5
#define REF_MAX_SLIP_NS       50000000ULL

static uint64_t ref_feedback(uint64_t interval_ns, size_t occ, uint64_t rate, size_t len)
{
	double target_bytes = (double)rate / 8.0 * (REF_TARGET_LATENCY_MS / 1000.0);
	double target_dg = target_bytes / (double)(len ? len : 1);
	if (target_dg < 1.0)
		target_dg = 1.0;
	double err = ((double)occ - target_dg) / target_dg;
	double factor = 1.0 - REF_FEEDBACK_K * err;
	if (factor < 0.80)
		factor = 0.80;
	if (factor > 1.20)
		factor = 1.20;
	return (uint64_t)((double)interval_ns * factor);
}

static void test_matches_reference_implementation(void)
{
	struct rist_pacer p;
	rist_pacer_init(&p, REF_TARGET_LATENCY_MS, 0, 0);

	uint64_t ref_next = 0, ref_underruns = 0;
	uint64_t now_ns = 5000000000ULL;
	unsigned compared = 0;

	for (int i = 0; i < 20000; i++) {
		/* Sweeps both feedback clamps, a rate step, a no-estimate stretch and a
		 * gap past the slip threshold. */
		size_t occ = (size_t)((i * 37) % 600);
		size_t len = DGRAM_BYTES;
		uint64_t rate = (i > 500 && i < 700) ? 0
		              : (i < 9000 ? RATE_BPS : RATE_BPS + 250000);
		if (i == 12000)
			now_ns += 3 * RIST_PACER_MAX_SLIP_NS;

		/* --- reference --- */
		uint64_t ref_due = 0;
		int ref_paced = 0;
		if (rate == 0) {
			ref_next = 0;
		} else {
			uint64_t iv = ((uint64_t)len * 8ULL * 1000000000ULL) / rate;
			iv = ref_feedback(iv, occ, rate, len);
			if (ref_next == 0) {
				ref_next = now_ns;
			} else if (now_ns > ref_next + REF_MAX_SLIP_NS) {
				ref_next = now_ns;
				ref_underruns++;
			}
			ref_due = ref_next;
			ref_next += iv;
			ref_paced = 1;
		}

		/* --- module --- */
		uint64_t mod_due = 0;
		int mod_paced = 0;
		uint64_t iv = rist_pacer_interval_ns(&p, rate, len, occ);
		if (iv == 0) {
			rist_pacer_reset(&p);
		} else {
			mod_due = rist_pacer_due_ns(&p, now_ns);
			rist_pacer_advance(&p, iv);
			mod_paced = 1;
		}

		assert(mod_paced == ref_paced);
		if (ref_paced) {
			assert(mod_due == ref_due);
			compared++;
		}

		/* Advance as a real sender would: to the due time it just honoured. */
		now_ns = (ref_paced && ref_due > now_ns) ? ref_due + 1000 : now_ns + 148000;
	}

	assert(p.underruns == ref_underruns);
	assert(ref_underruns >= 1);
	printf("  reference cross-check: %u send times identical, "
	       "%llu underrun(s) both ways\n",
	       compared, (unsigned long long)ref_underruns);
}

int main(void)
{
	printf("shared CBR pacing scheduler\n");
	test_rate_converges();
	test_rate_freezes_across_outage();
	test_interval_ignores_sleep_floor();
	test_feedback_direction_and_clamp();
	test_quota_averages_the_true_rate();
	test_quota_ungated_without_an_estimate();
	test_slip_resyncs_without_catching_up();
	test_sleep_clamped_both_ends();
	test_reset_keeps_configuration();
	test_burst_spreads_at_the_paced_cadence();
	test_matches_reference_implementation();
	printf("all pacer invariants held\n");
	return 0;
}
