/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_seq_next() - the "expected next sequence number" helper
 * used by the receiver out-of-order / late guard (receiver_enqueue). The
 * regression under test: the short_seq successor must wrap at 16 bits with
 * `& UINT16_MAX` (0xFFFF), not the historical `& (UINT16_MAX - 1)` (0xFFFE)
 * which forced the value even and mis-computed every odd successor.
 * Pure, link-free: mirrors the static-inline definition from rist-private.h. */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifndef UINT16_MAX
#define UINT16_MAX 0xFFFFu
#endif
static inline uint32_t rist_seq_next(uint32_t last, bool short_seq)
{
	uint32_t next = last + 1;
	return short_seq ? (next & UINT16_MAX) : next;
}

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

/* T1 - the regression: an odd successor must be returned exactly. Under the
 * old 0xFFFE mask, rist_seq_next(100, true) would have returned 100 (even). */
static void test_odd_successor(void)
{
    CHECK(rist_seq_next(100u, true) == 101u,
          "short odd successor: got %u want 101", rist_seq_next(100u, true));
    CHECK(rist_seq_next(101u, true) == 102u,
          "short even successor: got %u want 102", rist_seq_next(101u, true));
}

/* T2 - 16-bit wrap: short flows wrap modulo 65536. */
static void test_short_wrap(void)
{
    CHECK(rist_seq_next(65535u, true) == 0u,
          "short wrap: got %u want 0", rist_seq_next(65535u, true));
    CHECK(rist_seq_next(65534u, true) == 65535u,
          "short top: got %u want 65535", rist_seq_next(65534u, true));
}

/* T3 - 32-bit flows do not wrap at 16 bits and wrap correctly at 32. */
static void test_long(void)
{
    CHECK(rist_seq_next(65535u, false) == 65536u,
          "long no 16-bit wrap: got %u want 65536", rist_seq_next(65535u, false));
    CHECK(rist_seq_next(0xFFFFFFFFu, false) == 0u,
          "long 32-bit wrap: got %u want 0", rist_seq_next(0xFFFFFFFFu, false));
}

int main(void)
{
    test_odd_successor();
    test_short_wrap();
    test_long();

    if (failures > 0) {
        fprintf(stderr, "[test_seq_next] %d FAILURES\n", failures);
        return 1;
    }
    fprintf(stderr, "[test_seq_next] all tests passed\n");
    return 0;
}
