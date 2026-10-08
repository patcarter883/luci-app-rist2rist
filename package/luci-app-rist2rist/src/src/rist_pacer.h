/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* Constant-bitrate output pacing: a rate estimator and a schedule derived from
 * it, for spacing output that would otherwise be released in batches.
 *
 * Takes byte counts and returns times; it never inspects payload contents, so it
 * suits any CBR payload. Callers that can read a clock reference out of their
 * payload should use it to derive a rate and pass that in.
 *
 * Schedules but owns no thread, so a caller with its own wait keeps using it.
 * Not thread-safe; the estimator and the scheduler share no state, so a caller
 * may run them on separate threads and move the rate across itself.
 */

#ifndef RIST_PACER_H
#define RIST_PACER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rate estimator: 1 s windows, 8x EWMA, mirroring librist's
 * rist_calculate_bitrate so a stream measured here and there agrees. */
#define RIST_PACER_RATE_WINDOW_US   1000000ULL
/* A window this many times over-length means data resumed after an outage; it is
 * discarded so the rate freezes rather than decaying towards zero. */
#define RIST_PACER_RATE_STALL_FACTOR 3ULL

/* Behind by more than this is an outage, not drift: resynchronise to now rather
 * than catch up, which would emit the arrears as a burst. */
#define RIST_PACER_MAX_SLIP_NS      50000000ULL

/* Occupancy-trim gain, and the clamp on the resulting correction. */
#define RIST_PACER_FEEDBACK_K       0.5
#define RIST_PACER_FEEDBACK_MIN     0.80
#define RIST_PACER_FEEDBACK_MAX     1.20

/* ---------------------------------------------------------------- estimator */

struct rist_pacer_rate {
	uint64_t last_calc_us;
	uint64_t bytes;
	uint64_t eight_times;   /* 8x EWMA of the bitrate, as librist keeps it */
	uint64_t bps;           /* published estimate */
};

/* seed_bps 0 when nothing is known: reports 0 until the first full window, which
 * callers must treat as "do not pace" rather than guess a rate. */
void rist_pacer_rate_init(struct rist_pacer_rate *r, uint64_t seed_bps);

/* Feed one datagram. now_us must come from a monotonic clock. */
void rist_pacer_rate_add(struct rist_pacer_rate *r, size_t bytes, uint64_t now_us);

static inline uint64_t rist_pacer_rate_bps(const struct rist_pacer_rate *r)
{
	return r->bps;
}

/* ---------------------------------------------------------------- scheduler */

struct rist_pacer {
	uint64_t next_due_ns;      /* 0 until the first datagram establishes it */
	uint64_t max_slip_ns;
	double   target_latency_ms; /* occupancy feedback target; 0 disables it */

	/* Bound rist_pacer_sleep_ns() only, never the per-datagram interval. */
	uint64_t min_sleep_ns;
	uint64_t max_sleep_ns;

	uint64_t underruns;        /* schedule resyncs from slip */
};

/* min_sleep_ns 0 suits a dedicated pacing thread, where a floor would coarsen the
 * spacing it exists to hold; a shared event loop wants one to bound its wakeup
 * rate. target_latency_ms 0 disables the occupancy trim. */
void rist_pacer_init(struct rist_pacer *p, double target_latency_ms,
                     uint64_t min_sleep_ns, uint64_t max_sleep_ns);

/* Re-anchor on the next datagram, keeping the configuration. For a discontinuity
 * the caller already knows about, which slip would otherwise count as an
 * underrun. */
void rist_pacer_reset(struct rist_pacer *p);

/* Time a datagram of `bytes` occupies at `rate_bps`, trimmed towards
 * target_latency_ms by `occupancy` (the caller's queue depth in datagrams). The
 * trim corrects source-versus-local clock drift without a payload clock. Returns
 * 0 when rate_bps is 0, meaning do not pace.
 *
 * Never clamped to min_sleep_ns: raising the interval to a sleep floor would pace
 * the stream below its own rate. The floor belongs on the sleep. */
uint64_t rist_pacer_interval_ns(const struct rist_pacer *p, uint64_t rate_bps,
                                size_t bytes, size_t occupancy);

/* Absolute time the next datagram may be sent, establishing the schedule on the
 * first call and resynchronising past max_slip_ns. */
uint64_t rist_pacer_due_ns(struct rist_pacer *p, uint64_t now_ns);

/* Move the schedule on by one datagram. Call after sending. */
void rist_pacer_advance(struct rist_pacer *p, uint64_t interval_ns);

/* How many datagrams are due by now_ns, up to max, advancing past each; for a
 * caller that wakes on a timer and releases a batch. More than one per wake is
 * normal and is what keeps a sleep floor coarser than the interval honest. */
unsigned rist_pacer_quota(struct rist_pacer *p, uint64_t now_ns,
                          uint64_t interval_ns, unsigned max);

/* Time until the next datagram is due, clamped to [min_sleep_ns, max_sleep_ns],
 * or max_sleep_ns when nothing is scheduled yet. */
uint64_t rist_pacer_sleep_ns(const struct rist_pacer *p, uint64_t now_ns);

#ifdef __cplusplus
}
#endif

#endif /* RIST_PACER_H */
