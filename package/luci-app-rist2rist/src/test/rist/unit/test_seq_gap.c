/* librist. SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit test for rist_seq_gap() - the forward sequence-number gap helper used
 * by the receiver gap detector (receiver_mark_missing). The key property under
 * test is that short-sequence (Simple/Main, 16-bit) flows wrap modulo 65536
 * while full 32-bit (Advanced) flows report the true gap, so a genuine >64k
 * gap on an Advanced flow is no longer silently truncated to a 16-bit value.
 * Pure, link-free: mirrors the static-inline definition from rist-private.h. */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* The helper is a static inline in rist-private.h, which drags in the entire
 * private header graph. Mirror just the definition here (kept byte-identical)
 * so the test stays a pure, link-free unit. A divergence between the two is a
 * deliberate review signal: update both. */
#ifndef UINT16_MAX
#define UINT16_MAX 0xFFFFu
#endif
static inline uint32_t rist_seq_gap(uint32_t current, uint32_t last,
                                    bool short_seq)
{
	uint32_t gap = current - last;
	return short_seq ? (gap & UINT16_MAX) : gap;
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

/* T1 - small in-order gap is identical for both framings. */
static void test_small_gap(void)
{
    CHECK(rist_seq_gap(105, 100, true) == 5, "short small gap");
    CHECK(rist_seq_gap(105, 100, false) == 5, "long small gap");
}

/* T2 - 16-bit wrap: short flows wrap modulo 65536. */
static void test_short_wrap(void)
{
    /* last=65530, current=4 -> 16-bit forward gap is 10. */
    CHECK(rist_seq_gap(4u, 65530u, true) == 10u,
          "short wrap gap: got %u want 10", rist_seq_gap(4u, 65530u, true));
}

/* T3 - the regression we are fixing: a real >64k gap on a 32-bit flow.
 * The old unconditional `& UINT16_MAX` truncated this to a tiny value and the
 * detector mis-counted the loss; the 32-bit path must report the true gap. */
static void test_long_gap_not_truncated(void)
{
    uint32_t gap = rist_seq_gap(70000u, 0u, false);
    CHECK(gap == 70000u, "long >64k gap must be exact: got %u want 70000", gap);

    /* Same numbers under short framing DO truncate (70000 & 0xFFFF = 4464),
     * documenting why the 16-bit path must stay separate. */
    CHECK(rist_seq_gap(70000u, 0u, true) == (70000u & UINT16_MAX),
          "short framing truncates to 16 bits by design");
}

/* T4 - 32-bit wrap is well-defined unsigned arithmetic. */
static void test_long_wrap(void)
{
    /* last near the top of the 32-bit space, current just past wrap. */
    CHECK(rist_seq_gap(5u, 0xFFFFFFFBu, false) == 10u,
          "long 32-bit wrap gap: got %u want 10",
          rist_seq_gap(5u, 0xFFFFFFFBu, false));
}

int main(void)
{
    test_small_gap();
    test_short_wrap();
    test_long_gap_not_truncated();
    test_long_wrap();

    if (failures > 0) {
        fprintf(stderr, "[test_seq_gap] %d FAILURES\n", failures);
        return 1;
    }
    fprintf(stderr, "[test_seq_gap] all tests passed\n");
    return 0;
}
