/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_adv_ts_reconstruct() - the Advanced Profile receive-side
 * source-clock reconstruction (src/rist-adv-ts.h). Verifies: immediate
 * dejitter off the source clock (as the Main profile does), wrap-safe delta
 * accumulation, retransmit positioning without state change, following a
 * source discontinuity, and the first-window rate check that corrects a broken
 * clock (an older 65536x-fast sender) back to arrival. Pure, link-free:
 * exercises the header inline directly. */

#include "rist-adv-ts.h"

#include <inttypes.h>
#include <stdio.h>

static int failures = 0;

#define CHECK(cond, ...)                                                \
    do {                                                                \
        if (!(cond)) {                                                  \
            fprintf(stderr, "FAIL %s:%d: " #cond, __FILE__, __LINE__);  \
            fprintf(stderr, " - "); fprintf(stderr, __VA_ARGS__);       \
            fprintf(stderr, "\n");                                      \
            failures++;                                                 \
        }                                                               \
    } while (0)

/* NTP tick helpers (1 s = 2^32). All cast to uint64_t so printf args match
 * PRIu64 exactly on every ABI. us matches the helper's exact 2^26/15625. */
#define NTP_SEC(s)  ((uint64_t)((uint64_t)(s) << 32))
#define NTP_MS(ms)  ((uint64_t)(((uint64_t)(ms) << 32) / 1000))
#define NTP_US(us)  ((uint64_t)(((uint64_t)(us) * 67108864ULL) / 15625ULL))

static uint64_t absdiff(uint64_t a, uint64_t b) { return a > b ? a - b : b - a; }

static const uint64_t WINDOW = NTP_SEC(1);   /* rate-verification window */

/* Drive a conformant 1 MHz sender (wire us == elapsed us) through the window
 * so the clock is verified and kept. Returns the seed time t0; afterwards
 * last == 1000000 and accum ~= t0 + NTP_US(1000000). */
static uint64_t seed_and_verify(struct rist_adv_ts_state *st, uint64_t t0)
{
	uint64_t out = rist_adv_ts_reconstruct(st, 0, t0, WINDOW, true);
	CHECK(out == t0, "first packet stamps arrival(seed): got %" PRIu64, out);
	for (uint32_t ms = 200; ms < 1000; ms += 200) {
		uint64_t now = t0 + NTP_MS(ms);
		out = rist_adv_ts_reconstruct(st, ms * 1000u, now, WINDOW, true);
		CHECK(absdiff(out, t0 + NTP_US(ms * 1000)) <= 3,
		      "calibrating packet uses source clock at %ums", ms);
		CHECK(st->calibrating, "still calibrating before the window closes");
	}
	uint64_t now = t0 + NTP_SEC(1);
	out = rist_adv_ts_reconstruct(st, 1000000u, now, WINDOW, true);
	CHECK(!st->calibrating, "verdict taken at window close");
	CHECK(st->use_source, "conformant clock kept");
	CHECK(absdiff(out, t0 + NTP_SEC(1)) <= 3, "source ~= +1s: got %" PRIu64, out);
	return t0;
}

/* First live packet stamps arrival and anchors the clock. */
static void test_seed_is_arrival(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t now = NTP_SEC(1000);
	uint64_t out = rist_adv_ts_reconstruct(&st, 500000, now, WINDOW, true);
	CHECK(out == now, "first packet must stamp arrival: got %" PRIu64, out);
	CHECK(st.seeded && st.calibrating, "clock anchored after first live packet");
}

/* A retransmit arriving before any live packet has no reference: arrival. */
static void test_retry_before_seed(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t now = NTP_SEC(1000);
	uint64_t out = rist_adv_ts_reconstruct(&st, 12345, now, WINDOW, false);
	CHECK(out == now, "retry before seed -> arrival: got %" PRIu64, out);
	CHECK(!st.seeded, "retry must not anchor the clock");
}

/* From the very first packets - inside the verification window - output tracks
 * the source clock, not arrival jitter, just like the Main profile. */
static void test_source_used_immediately(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = NTP_SEC(1000);
	rist_adv_ts_reconstruct(&st, 0, t0, WINDOW, true); /* seed */

	/* Source +40 ms; arrival jittered to +55 ms. Still calibrating, but the
	 * output already follows the source clock. */
	uint64_t out = rist_adv_ts_reconstruct(&st, 40000, t0 + NTP_MS(55),
					       WINDOW, true);
	CHECK(absdiff(out, t0 + NTP_US(40000)) <= 3,
	      "source used immediately: got %" PRIu64 " want ~%" PRIu64,
	      out, t0 + NTP_US(40000));
	CHECK(st.calibrating, "still within the verification window");
}

/* Once verified, in-order packets keep tracking the source clock. */
static void test_verified_tracks_source(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = seed_and_verify(&st, NTP_SEC(1000));

	/* +40 ms of source; arrival jittered late to +55 ms. */
	uint64_t out = rist_adv_ts_reconstruct(&st, 1040000u, t0 + NTP_MS(1055),
					       WINDOW, true);
	CHECK(absdiff(out, t0 + NTP_US(1040000)) <= 4,
	      "tracks source not arrival: got %" PRIu64, out);

	/* +40 ms more; arrival jittered early to +30 ms. */
	out = rist_adv_ts_reconstruct(&st, 1080000u, t0 + NTP_MS(1085),
				      WINDOW, true);
	CHECK(absdiff(out, t0 + NTP_US(1080000)) <= 5,
	      "stays on source clock: got %" PRIu64, out);
}

/* A broken sender (pre-fix 65536x-fast timestamp) is used optimistically at
 * first, so early output races ahead of arrival; the first-window rate check
 * then rejects it and the peer corrects to arrival for the whole session. */
static void test_broken_sender_corrected(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = NTP_SEC(1000);
	rist_adv_ts_reconstruct(&st, 0, t0, WINDOW, true); /* seed */

	/* 20 ms spacing keeps each broken delta (20000*65536) under 2^31 so the
	 * signed delta stays positive; ~50 packets span the 1 s window. */
	uint32_t wire = 0;
	uint64_t now = t0;
	for (int i = 1; i <= 51; i++) {
		wire += 20000u * 65536u;
		now = t0 + NTP_MS(20 * i);
		uint64_t out = rist_adv_ts_reconstruct(&st, wire, now, WINDOW, true);
		if (i < 50) /* still calibrating: optimistic source races ahead */
			CHECK(out > now + NTP_SEC(1),
			      "broken clock used optimistically before verdict: got %" PRIu64,
			      out);
	}
	CHECK(!st.calibrating, "verdict taken");
	CHECK(!st.use_source, "broken clock rejected");

	/* Corrected for good: later packets and retries all use arrival. */
	uint64_t later = t0 + NTP_SEC(5);
	CHECK(rist_adv_ts_reconstruct(&st, wire + 50000u, later, WINDOW, true) == later,
	      "corrected: live packet uses arrival");
	CHECK(rist_adv_ts_reconstruct(&st, 12345, later, WINDOW, false) == later,
	      "corrected: retry uses arrival");
}

/* The 32-bit 1 MHz field wraps every ~71.6 min; a small forward delta across
 * the wrap boundary must stay small on the verified source clock. */
static void test_wrap(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = seed_and_verify(&st, NTP_SEC(1000));

	/* Place the verified clock just below the 32-bit wrap. */
	uint64_t src = t0 + NTP_SEC(10);
	st.last = UINT32_MAX - 500; /* 500 us before wrap */
	st.accum = src;

	/* 1000 us later the wire value wraps past 0 to 499. */
	uint64_t out = rist_adv_ts_reconstruct(&st, 499, src + NTP_US(1000),
					       WINDOW, true);
	CHECK(absdiff(out, src + NTP_US(1000)) <= 2,
	      "wrap yields +1000us, not a ~71min jump: got %" PRIu64, out);
}

/* A retransmit is positioned relative to the verified clock but must not move
 * it: the next live packet continues from where the live stream left off. */
static void test_retry_positions_without_advancing(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = seed_and_verify(&st, NTP_SEC(1000));
	rist_adv_ts_reconstruct(&st, 1100000u, t0 + NTP_MS(1100), WINDOW, true);
	uint32_t last_before = st.last;
	uint64_t accum_before = st.accum;

	/* An older packet (source +1020 ms from t0) is recovered late. */
	uint64_t r = rist_adv_ts_reconstruct(&st, 1020000u, t0 + NTP_MS(1250),
					     WINDOW, false);
	CHECK(absdiff(r, t0 + NTP_US(1020000)) <= 4,
	      "retry stamped at its own source time: got %" PRIu64, r);
	CHECK(st.last == last_before && st.accum == accum_before,
	      "retry must not mutate the clock");

	/* Next live packet continues from +1100 ms, not from the retry. */
	uint64_t out = rist_adv_ts_reconstruct(&st, 1140000u, t0 + NTP_MS(1300),
					       WINDOW, true);
	CHECK(absdiff(out, t0 + NTP_US(1140000)) <= 4,
	      "live stream resumes after retry: got %" PRIu64, out);
}

/* Once verified, the source clock is trusted like the Main profile: a sender
 * clock discontinuity is followed (reconstructed through), not snapped to
 * arrival, which would inject worse jitter than the jump itself. */
static void test_discontinuity_follows_source(void)
{
	struct rist_adv_ts_state st = {0};
	uint64_t t0 = seed_and_verify(&st, NTP_SEC(1000));

	/* A large forward step in the source timestamp (+500 s). */
	uint64_t now = t0 + NTP_MS(1080);
	uint64_t out = rist_adv_ts_reconstruct(&st, 1000000u + 500000000u, now, WINDOW, true);
	CHECK(out != now, "discontinuity is followed, not snapped to arrival: got %" PRIu64, out);
	CHECK(out > now + NTP_SEC(100),
	      "output jumps forward with the source clock: got %" PRIu64, out);
	CHECK(st.use_source, "source clock stays in use through a discontinuity");
}

int main(void)
{
	test_seed_is_arrival();
	test_retry_before_seed();
	test_source_used_immediately();
	test_verified_tracks_source();
	test_broken_sender_corrected();
	test_wrap();
	test_retry_positions_without_advancing();
	test_discontinuity_follows_source();

	if (failures) {
		fprintf(stderr, "adv_ts_reconstruct: %d check(s) failed\n", failures);
		return 1;
	}
	printf("adv_ts_reconstruct: all checks passed\n");
	return 0;
}
