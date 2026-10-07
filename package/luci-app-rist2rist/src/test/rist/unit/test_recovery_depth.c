/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_recovery_depth_set() (exponent-based API).
 *
 * recovery-depth N sizes the Advanced retransmission ring to
 * (UINT16_SIZE << N) packets. This test verifies the public setter's contract:
 *   - the default Advanced ring is RIST_SERVER_QUEUE_BUFFERS (== depth 3, 8x),
 *   - each depth maps to (UINT16_SIZE << depth) packets,
 *   - an Advanced sender's ring (sender_queue_max) is resized in place
 *     before rist_start(),
 *   - the Advanced receiver records the new capacity (recovery_queue_max),
 *   - Simple/Main store the request but never resize their 16-bit ring,
 *   - a NULL context is rejected.
 *
 * Test depths are kept modest (<= 6, i.e. <= 4M entries) to bound the
 * allocations performed here.
 *
 * Includes rist-private.h to inspect the internal ring sizes; links
 * against the public library for the symbols. */

#include "librist/librist.h"
#include "rist-private.h"

#include <stdatomic.h>
#include <inttypes.h>
#include <stdio.h>

#define DEPTH_PKTS(n) ((size_t)UINT16_SIZE << (n))
#define DEFAULT_PKTS  ((size_t)RIST_SERVER_QUEUE_BUFFERS) /* depth 3, 524288 */

static int failures;

#define CHECK(cond, ...)                                                   \
	do {                                                                   \
		if (!(cond)) {                                                     \
			fprintf(stderr, "FAIL (%s:%d): ", __func__, __LINE__);         \
			fprintf(stderr, __VA_ARGS__);                                  \
			fprintf(stderr, "\n");                                         \
			failures++;                                                    \
		}                                                                  \
	} while (0)

static size_t sender_ring(struct rist_ctx *ctx)
{
	return ctx->sender_ctx->sender_queue_max;
}

static size_t common_max(struct rist_ctx *ctx)
{
	return rist_struct_get_common(ctx)->recovery_queue_max;
}

static void test_default_is_depth_3(void)
{
	/* The compile-time default ring must equal depth RIST_RECOVERY_DEPTH_DEFAULT. */
	CHECK(DEFAULT_PKTS == DEPTH_PKTS(RIST_RECOVERY_DEPTH_DEFAULT),
		"RIST_SERVER_QUEUE_BUFFERS=%zu != depth %d (%zu)",
		DEFAULT_PKTS, RIST_RECOVERY_DEPTH_DEFAULT, DEPTH_PKTS(RIST_RECOVERY_DEPTH_DEFAULT));
	CHECK(RIST_RECOVERY_DEPTH_DEFAULT == 3, "default depth changed from 3");
}

static void test_advanced_sender(void)
{
	struct rist_ctx *ctx = NULL;
	if (rist_sender_create(&ctx, RIST_PROFILE_ADVANCED, 0, NULL) != 0 || !ctx) {
		fprintf(stderr, "FAIL: could not create advanced sender\n");
		failures++;
		return;
	}

	CHECK(common_max(ctx) == DEFAULT_PKTS,
		"default recovery_queue_max=%zu want %zu", common_max(ctx), DEFAULT_PKTS);
	CHECK(sender_ring(ctx) == DEFAULT_PKTS,
		"default sender_queue_max=%zu want %zu", sender_ring(ctx), DEFAULT_PKTS);

	static const int depths[] = { 0, 1, 4, 6, 3 };
	for (size_t i = 0; i < sizeof(depths) / sizeof(depths[0]); i++) {
		int d = depths[i];
		CHECK(rist_recovery_depth_set(ctx, (uint8_t)d) == 0, "set(%d) failed", d);
		CHECK(sender_ring(ctx) == DEPTH_PKTS(d),
			"depth %d sender_queue_max=%zu want %zu", d, sender_ring(ctx), DEPTH_PKTS(d));
		CHECK(common_max(ctx) == DEPTH_PKTS(d),
			"depth %d recovery_queue_max=%zu want %zu", d, common_max(ctx), DEPTH_PKTS(d));
	}

	rist_destroy(ctx);
}

static void test_advanced_receiver(void)
{
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_ADVANCED, NULL) != 0 || !ctx) {
		fprintf(stderr, "FAIL: could not create advanced receiver\n");
		failures++;
		return;
	}

	CHECK(common_max(ctx) == DEFAULT_PKTS,
		"default recovery_queue_max=%zu want %zu", common_max(ctx), DEFAULT_PKTS);

	/* Receiver rings are created per-flow at peer-add time, so the setter
	 * just records the capacity the next flow will use. */
	CHECK(rist_recovery_depth_set(ctx, 5) == 0, "set(5) failed");
	CHECK(common_max(ctx) == DEPTH_PKTS(5),
		"receiver recovery_queue_max=%zu want %zu", common_max(ctx), DEPTH_PKTS(5));

	rist_destroy(ctx);
}

static void test_main_profile_sender(void)
{
	struct rist_ctx *ctx = NULL;
	if (rist_sender_create(&ctx, RIST_PROFILE_MAIN, 0, NULL) != 0 || !ctx) {
		fprintf(stderr, "FAIL: could not create main sender\n");
		failures++;
		return;
	}

	size_t before = sender_ring(ctx);

	/* The setter accepts the call and records the request, but a 16-bit
	 * profile must never grow its ring. */
	CHECK(rist_recovery_depth_set(ctx, 6) == 0, "set on main failed");
	CHECK(sender_ring(ctx) == before,
		"main sender_queue_max changed: %zu -> %zu", before, sender_ring(ctx));

	rist_destroy(ctx);
}

static void test_out_of_range_clamps(void)
{
	/* Use a receiver: it records recovery_queue_max without allocating the
	 * (potentially huge) ring up front, so we can check the clamp of an
	 * over-range request without depending on the host's overcommit behavior. */
	struct rist_ctx *ctx = NULL;
	if (rist_receiver_create(&ctx, RIST_PROFILE_ADVANCED, NULL) != 0 || !ctx) {
		fprintf(stderr, "FAIL: could not create advanced receiver (clamp)\n");
		failures++;
		return;
	}
	/* expect the platform cap, computed with the same helper the library uses */
	int pmax = rist_recovery_depth_platform_max();
	CHECK(rist_recovery_depth_set(ctx, 200) == 0, "set(200) (clamped) failed");
	CHECK(common_max(ctx) == DEPTH_PKTS(pmax),
		"clamp: recovery_queue_max=%zu want %zu (depth %d)",
		common_max(ctx), DEPTH_PKTS(pmax), pmax);
	rist_destroy(ctx);
}

static void test_null_ctx(void)
{
	CHECK(rist_recovery_depth_set(NULL, 6) == -1, "NULL ctx should return -1");
}

int main(void)
{
	failures = 0;

	test_default_is_depth_3();
	test_advanced_sender();
	test_advanced_receiver();
	test_main_profile_sender();
	test_out_of_range_clamps();
	test_null_ctx();

	if (failures == 0) {
		printf("OK\n");
		return 0;
	}
	fprintf(stderr, "Total failures: %d\n", failures);
	return 1;
}
