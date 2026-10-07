/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Constant-bitrate output pacing. See rist_pacer.h for the rationale. */

#include "rist_pacer.h"

#include <string.h>

void rist_pacer_rate_init(struct rist_pacer_rate *r, uint64_t seed_bps)
{
	memset(r, 0, sizeof(*r));
	if (seed_bps) {
		r->eight_times = seed_bps * 8ULL;
		r->bps = seed_bps;
	}
}

void rist_pacer_rate_add(struct rist_pacer_rate *r, size_t bytes, uint64_t now_us)
{
	if (!r->last_calc_us) {
		/* Anchor the first window; these bytes cannot be timed. */
		r->last_calc_us = now_us;
		r->bytes = 0;
		return;
	}

	r->bytes += bytes;

	uint64_t dt = now_us - r->last_calc_us;
	if (dt < RIST_PACER_RATE_WINDOW_US)
		return;

	if (dt <= RIST_PACER_RATE_WINDOW_US * RIST_PACER_RATE_STALL_FACTOR) {
		uint64_t bitrate = (8ULL * r->bytes * 1000000ULL) / dt;
		if (r->eight_times == 0)
			r->eight_times = bitrate * 8ULL;  /* prime, skip the 8-window ramp */
		else
			r->eight_times += bitrate - r->eight_times / 8;
		r->bps = r->eight_times / 8;
	}
	/* else: the window spans an outage; keep the last good rate. */

	r->last_calc_us = now_us;
	r->bytes = 0;
}

void rist_pacer_init(struct rist_pacer *p, double target_latency_ms,
                     uint64_t min_sleep_ns, uint64_t max_sleep_ns)
{
	memset(p, 0, sizeof(*p));
	p->target_latency_ms = target_latency_ms;
	p->min_sleep_ns = min_sleep_ns;
	p->max_sleep_ns = max_sleep_ns;
	p->max_slip_ns = RIST_PACER_MAX_SLIP_NS;
}

void rist_pacer_reset(struct rist_pacer *p)
{
	p->next_due_ns = 0;
}

uint64_t rist_pacer_interval_ns(const struct rist_pacer *p, uint64_t rate_bps,
                                size_t bytes, size_t occupancy)
{
	if (!rate_bps || !bytes)
		return 0;

	uint64_t interval_ns = ((uint64_t)bytes * 8ULL * 1000000000ULL) / rate_bps;

	if (p->target_latency_ms <= 0.0)
		return interval_ns;

	/* Above target shortens to drain, below lengthens to fill; clamped so a
	 * transient excursion cannot slew the rate far. */
	double target_bytes = (double)rate_bps / 8.0 * (p->target_latency_ms / 1000.0);
	double target_dg = target_bytes / (double)bytes;
	if (target_dg < 1.0)
		target_dg = 1.0;

	double err = ((double)occupancy - target_dg) / target_dg;
	double factor = 1.0 - RIST_PACER_FEEDBACK_K * err;
	if (factor < RIST_PACER_FEEDBACK_MIN)
		factor = RIST_PACER_FEEDBACK_MIN;
	if (factor > RIST_PACER_FEEDBACK_MAX)
		factor = RIST_PACER_FEEDBACK_MAX;

	return (uint64_t)((double)interval_ns * factor);
}

uint64_t rist_pacer_due_ns(struct rist_pacer *p, uint64_t now_ns)
{
	if (p->next_due_ns == 0) {
		p->next_due_ns = now_ns;
	} else if (now_ns > p->next_due_ns + p->max_slip_ns) {
		p->next_due_ns = now_ns;
		p->underruns++;
	}
	return p->next_due_ns;
}

void rist_pacer_advance(struct rist_pacer *p, uint64_t interval_ns)
{
	p->next_due_ns += interval_ns;
}

unsigned rist_pacer_quota(struct rist_pacer *p, uint64_t now_ns,
                          uint64_t interval_ns, unsigned max)
{
	/* No estimate: nothing to pace against, so do not gate. */
	if (interval_ns == 0)
		return max;

	/* Shared first-send and slip handling. */
	(void)rist_pacer_due_ns(p, now_ns);

	unsigned n = 0;
	while (n < max && p->next_due_ns <= now_ns) {
		p->next_due_ns += interval_ns;
		n++;
	}
	return n;
}

uint64_t rist_pacer_sleep_ns(const struct rist_pacer *p, uint64_t now_ns)
{
	uint64_t sleep_ns;

	if (p->next_due_ns == 0)
		sleep_ns = p->max_sleep_ns;   /* nothing scheduled: idle normally */
	else if (p->next_due_ns <= now_ns)
		sleep_ns = p->min_sleep_ns;   /* already due: wake as soon as allowed */
	else
		sleep_ns = p->next_due_ns - now_ns;

	if (sleep_ns < p->min_sleep_ns)
		sleep_ns = p->min_sleep_ns;
	if (p->max_sleep_ns && sleep_ns > p->max_sleep_ns)
		sleep_ns = p->max_sleep_ns;
	return sleep_ns;
}
