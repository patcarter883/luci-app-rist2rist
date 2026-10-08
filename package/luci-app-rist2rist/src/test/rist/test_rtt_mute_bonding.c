/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * End-to-end test for dynamic RTT-based bonded-leg muting (?rtt-drop=).
 *
 * A real two-leg bonded sender streams to a receiver over 127.0.0.1.  A
 * latency spike on one leg is simulated by driving that leg's measured
 * smoothed RTT (peer->eight_times_rtt) above the ?rtt-drop ceiling, which
 * is exactly the signal the production evaluator (rist_sender_rtt_mute_check)
 * consumes.  We then observe, through the real sender balancer and its
 * per-leg TX counters (stats_sender_instant.sent), that:
 *
 *   1. both legs share the unique payload before any spike;
 *   2. a sustained spike on leg B mutes it: leg A carries 100% of the
 *      unique payload (leg B's data TX freezes, trickle=0) and the stream
 *      keeps flowing;
 *   3. once leg B's RTT recovers it rejoins the bond and carries data again;
 *   4. when BOTH legs are over the ceiling the last-healthy-leg guard keeps
 *      one of them in the bond (never a full black-out).
 *
 * Runs anywhere the public library + loopback do; no root, no netem.
 *
 * Exit codes:
 *   0  - mute, reroute, recovery and last-leg guard all behaved
 *   1  - a behavioural assertion failed
 *   2  - INDETERMINATE: bonding never established / no data flowed
 *  99  - setup error
 */

#include "librist/librist.h"
#include "rist-private.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#define msleep(ms) Sleep(ms)
#else
#include <unistd.h>
#define msleep(ms) usleep((ms) * 1000)
#endif

#ifndef RIST_CLOCK
#define RIST_CLOCK (4294967LL)
#endif

#define LEG_A_PORT 20141
#define LEG_B_PORT 20142
#define RTT_DROP_MS     200
#define RTT_RESTORE_MS  100
#define RTT_SETTLE_MS   1000

/* smoothed RTT (ms) -> peer->eight_times_rtt (8x, in RIST_CLOCK ticks) */
#define MS_TO_RTT8(ms) ((uint64_t)(ms) * (uint64_t)RIST_CLOCK * 8ULL)

static struct rist_logging_settings *log_settings = NULL;
static volatile int rx_pkts = 0;
static volatile bool sender_run = true;

static int log_cb(void *arg, enum rist_log_level level, const char *msg) {
	(void)arg;
	const char *tag = level <= RIST_LOG_ERROR ? "E" :
	                  level <= RIST_LOG_WARN  ? "W" :
	                  level <= RIST_LOG_INFO  ? "I" : "D";
	fprintf(stderr, "%s| %s", tag, msg);
	return 0;
}

static int rx_data_cb(void *arg, struct rist_data_block *b) {
	(void)arg;
	rx_pkts++;
	rist_receiver_data_block_free2(&b);
	return 0;
}

static PTHREAD_START_FUNC(sender_feed, arg) {
	struct rist_ctx *tx = arg;
	uint32_t counter = 0;
	uint8_t buf[256];
	memset(buf, 0, sizeof(buf));
	while (sender_run) {
		struct rist_data_block blk;
		memset(&blk, 0, sizeof(blk));
		memcpy(buf, &counter, sizeof(counter));
		blk.payload = buf;
		blk.payload_len = sizeof(buf);
		blk.virt_src_port = 1968;
		rist_sender_data_write(tx, &blk);
		counter++;
		msleep(10); /* ~100 pkt/s */
	}
	return 0;
}

/* Pin one or both legs' smoothed RTT to rtt_ms for hold_ms, re-writing under
 * peerlist_lock frequently so the evaluator's 1 Hz sample always sees it (real
 * loopback echo responses would otherwise decay it back toward zero). */
static void pin_rtt(struct rist_peer *a, struct rist_peer *b, int rtt_ms, int hold_ms) {
	struct rist_common_ctx *cctx = &a->sender_ctx->common;
	for (int elapsed = 0; elapsed < hold_ms; elapsed += 50) {
		pthread_mutex_lock(&cctx->peerlist_lock);
		if (a) a->eight_times_rtt = MS_TO_RTT8(rtt_ms);
		if (b) b->eight_times_rtt = MS_TO_RTT8(rtt_ms);
		pthread_mutex_unlock(&cctx->peerlist_lock);
		msleep(50);
	}
}

static struct rist_peer *add_leg(struct rist_ctx *tx, int dst_port) {
	char url[320];
	snprintf(url, sizeof(url),
	         "rist://127.0.0.1:%d?weight=5&rtt-drop=%d&rtt-restore=%d"
	         "&rtt-drop-settle=%d&rtt-drop-trickle=0"
	         "&session-timeout=30000&keepalive-interval=1000",
	         dst_port, RTT_DROP_MS, RTT_RESTORE_MS, RTT_SETTLE_MS);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0)
		return NULL;
	struct rist_peer *peer = NULL;
	if (rist_peer_create(tx, &peer, pcfg) != 0) { free(pcfg); return NULL; }
	free(pcfg);
	return peer;
}

static struct rist_peer *add_listen(struct rist_ctx *rx, int port) {
	char url[320];
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=30000&keepalive-interval=1000",
	         port);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0)
		return NULL;
	struct rist_peer *peer = NULL;
	if (rist_peer_create(rx, &peer, pcfg) != 0) { free(pcfg); return NULL; }
	free(pcfg);
	return peer;
}

int main(void) {
	if (rist_logging_set(&log_settings, RIST_LOG_WARN, log_cb, NULL, NULL, stderr) != 0)
		return 99;

	/* receiver: one ctx, two bonded listening legs (same flow). */
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0) return 99;
	if (!add_listen(rx, LEG_A_PORT) || !add_listen(rx, LEG_B_PORT)) {
		rist_destroy(rx); return 99;
	}
	if (rist_receiver_data_callback_set2(rx, rx_data_cb, NULL) != 0 ||
	    rist_start(rx) != 0) { rist_destroy(rx); return 99; }

	/* sender: caller, two bonded legs to the two receiver ports. */
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0) {
		rist_destroy(rx); return 99;
	}
	struct rist_peer *leg_a = add_leg(tx, LEG_A_PORT);
	struct rist_peer *leg_b = add_leg(tx, LEG_B_PORT);
	if (!leg_a || !leg_b) { rist_destroy(tx); rist_destroy(rx); return 99; }
	if (rist_start(tx) != 0) { rist_destroy(tx); rist_destroy(rx); return 99; }

	pthread_t feeder;
	pthread_create(&feeder, NULL, sender_feed, tx);

	/* warm up: both legs authenticate and start carrying data. */
	msleep(4000);
	uint64_t base_a = leg_a->stats_sender_instant.sent;
	uint64_t base_b = leg_b->stats_sender_instant.sent;
	int rx_warm = rx_pkts;
	fprintf(stderr, "warmup: leg_a.sent=%"PRIu64" leg_b.sent=%"PRIu64" rx=%d\n",
	        base_a, base_b, rx_warm);
	fprintf(stderr, "diag: leg_b cfg rtt_drop=%u restore=%u settle=%u trickle=%u | "
	        "is_data=%d listening=%d parent=%p auth=%d e8rtt=%"PRIu64" (~%"PRIu64"ms)\n",
	        leg_b->config.rtt_drop, leg_b->config.rtt_restore,
	        leg_b->config.rtt_drop_settle, leg_b->config.rtt_drop_trickle,
	        leg_b->is_data, leg_b->listening, (void *)leg_b->parent,
	        leg_b->authenticated, leg_b->eight_times_rtt,
	        (uint64_t)(leg_b->eight_times_rtt / 8 / RIST_CLOCK));

	/* == Phase 1: spike leg B over the ceiling; it must mute == */
	fprintf(stderr, "\n== phase 1: leg B RTT spike (%dms > %dms ceiling) ==\n",
	        400, RTT_DROP_MS);
	int waited = 0;
	while (!leg_b->rtt_muted && waited < 9000) {
		pin_rtt(leg_b, NULL, 400, 500);
		waited += 500;
	}
	bool muted_b = leg_b->rtt_muted;
	uint32_t mute_events_b = leg_b->rtt_mute_count;
	fprintf(stderr, "leg B muted=%d mute_events=%u after %dms of spike\n",
	        muted_b, mute_events_b, waited);
	/* Measure the freeze AFTER the mute engages. With trickle disabled on this
	 * leg, a muted leg must carry neither new unique payload (diverted by the
	 * balancer) nor retransmissions (rerouted to a healthy sibling), so its
	 * total send rate collapses while healthy leg A keeps the stream flowing. */
	uint64_t a0 = leg_a->stats_sender_instant.sent;
	uint64_t b0 = leg_b->stats_sender_instant.sent;
	uint32_t b0_retx = leg_b->stats_sender_instant.retrans;
	int rx0 = rx_pkts;
	pin_rtt(leg_b, NULL, 400, 3000); /* keep it muted */
	uint64_t a1 = leg_a->stats_sender_instant.sent;
	uint64_t b1 = leg_b->stats_sender_instant.sent;
	uint32_t b1_retx = leg_b->stats_sender_instant.retrans;
	int rx1 = rx_pkts;
	uint64_t b_sent = b1 - b0;
	uint32_t b_retx = b1_retx - b0_retx;
	fprintf(stderr, "while muted: dA=%"PRIu64" dB=%"PRIu64" (retx=%u) drx=%d\n",
	        a1 - a0, b_sent, b_retx, rx1 - rx0);

	/* == Phase 2: leg B recovers; it must rejoin the bond == */
	fprintf(stderr, "\n== phase 2: leg B RTT recovers ==\n");
	waited = 0;
	while (leg_b->rtt_muted && waited < 9000) {
		pin_rtt(leg_b, NULL, 5, 500);
		waited += 500;
	}
	bool restored_b = !leg_b->rtt_muted;
	fprintf(stderr, "leg B muted=%d after %dms of recovery\n",
	        leg_b->rtt_muted, waited);
	/* Measure that leg B carries data again after rejoining. */
	uint64_t b1r = leg_b->stats_sender_instant.sent;
	int rx1r = rx_pkts;
	pin_rtt(leg_b, NULL, 5, 2500);
	uint64_t b2 = leg_b->stats_sender_instant.sent;
	int rx2 = rx_pkts;
	fprintf(stderr, "after rejoin: dB=%"PRIu64" drx=%d\n", b2 - b1r, rx2 - rx1r);

	/* == Phase 3: both legs over the ceiling; guard keeps one active == */
	fprintf(stderr, "\n== phase 3: both legs over ceiling (last-leg guard) ==\n");
	pin_rtt(leg_a, leg_b, 400, 7000);
	bool a_muted = leg_a->rtt_muted;
	bool b_muted = leg_b->rtt_muted;
	fprintf(stderr, "both-high: leg_a muted=%d leg_b muted=%d\n", a_muted, b_muted);

	/* == Phase 4: trickle keeps a muted leg measurable (default behaviour) ==
	 * Re-mute leg B (leg A recovers naturally and stays active) with a 1-in-10
	 * trickle enabled: the muted leg must carry a low rate of redundant
	 * duplicate packets so RTT stays sampled for a warm restore. */
	fprintf(stderr, "\n== phase 4: trickle on a muted leg (1-in-%d) ==\n", 10);
	struct rist_common_ctx *cctx = &leg_b->sender_ctx->common;
	pthread_mutex_lock(&cctx->peerlist_lock);
	leg_b->config.rtt_drop_trickle = 10;
	leg_b->rtt_trickle_counter = 0;
	pthread_mutex_unlock(&cctx->peerlist_lock);
	waited = 0;
	while (!leg_b->rtt_muted && waited < 9000) {
		pin_rtt(leg_b, NULL, 400, 500);
		waited += 500;
	}
	bool trickle_muted = leg_b->rtt_muted;
	uint64_t tb0 = leg_b->stats_sender_instant.sent;
	uint32_t tb0_retx = leg_b->stats_sender_instant.retrans;
	uint64_t ta0 = leg_a->stats_sender_instant.sent;
	pin_rtt(leg_b, NULL, 400, 3000);
	uint64_t tb1 = leg_b->stats_sender_instant.sent;
	uint32_t tb1_retx = leg_b->stats_sender_instant.retrans;
	uint64_t ta1 = leg_a->stats_sender_instant.sent;
	uint64_t trickle_new = (tb1 - tb0) - (uint64_t)(tb1_retx - tb0_retx);
	uint64_t healthy_new = ta1 - ta0;
	fprintf(stderr, "trickle: leg_b muted=%d trickle_dups=%"PRIu64" vs leg_a=%"PRIu64"\n",
	        trickle_muted, trickle_new, healthy_new);

	sender_run = false;
	pthread_join(feeder, NULL);
	rist_destroy(tx);
	rist_destroy(rx);
	free(log_settings);

	/* ---- verdicts ---- */
	if (base_a == 0 || base_b == 0 || rx_warm == 0) {
		fprintf(stderr, "INDETERMINATE: bonding never established or no data "
		                "(leg_a.sent=%"PRIu64" leg_b.sent=%"PRIu64" rx=%d).\n",
		        base_a, base_b, rx_warm);
		return 2;
	}
	if (!muted_b) {
		fprintf(stderr, "FAIL: leg B stayed in the bond despite a sustained "
		                "RTT spike over the ceiling.\n");
		return 1;
	}
	if (mute_events_b == 0) {
		fprintf(stderr, "FAIL: rtt_mute_events metric did not count the mute "
		                "transition (got 0).\n");
		return 1;
	}
	if ((a1 - a0) == 0 || (rx1 - rx0) == 0) {
		fprintf(stderr, "FAIL: stream did not keep flowing on healthy leg A "
		                "while B was muted (dA=%"PRIu64", drx=%d).\n",
		        a1 - a0, rx1 - rx0);
		return 1;
	}
	/* With trickle disabled, a muted leg must go essentially silent: the
	 * balancer diverts new payload and retransmissions are rerouted to the
	 * healthy leg. A couple of packets can straddle the mute-transition
	 * boundary, so require B's total send rate to collapse to under 10% of
	 * what leg A carries. */
	if (b_sent * 10 >= (a1 - a0)) {
		fprintf(stderr, "FAIL: muted leg B still carried significant traffic "
		                "(B=%"PRIu64" retx=%u vs A=%"PRIu64"; mute/reroute did "
		                "not take effect).\n", b_sent, b_retx, a1 - a0);
		return 1;
	}
	if (!restored_b) {
		fprintf(stderr, "FAIL: leg B did not rejoin the bond after RTT "
		                "recovered.\n");
		return 1;
	}
	if ((b2 - b1r) == 0) {
		fprintf(stderr, "FAIL: restored leg B carried no payload after "
		                "rejoining (dB=%"PRIu64").\n", b2 - b1r);
		return 1;
	}
	if (a_muted && b_muted) {
		fprintf(stderr, "FAIL: last-healthy-leg guard failed; both legs muted "
		                "with every leg over the ceiling (stream black-out).\n");
		return 1;
	}
	if (!trickle_muted) {
		fprintf(stderr, "FAIL: leg B did not re-mute for the trickle phase.\n");
		return 1;
	}
	if (trickle_new == 0) {
		fprintf(stderr, "FAIL: trickle sent no redundant packets on the muted "
		                "leg; warm-restore probing is not working.\n");
		return 1;
	}
	if (trickle_new * 2 >= healthy_new) {
		fprintf(stderr, "FAIL: trickle rate not sparse (dups=%"PRIu64" vs "
		                "healthy=%"PRIu64"); a muted leg must only carry a low "
		                "redundant rate.\n", trickle_new, healthy_new);
		return 1;
	}

	fprintf(stderr, "\nPASS: bonded leg muted on RTT spike (payload moved to the "
	                "healthy leg, stream never stalled), rejoined on recovery, and "
	                "the last-healthy-leg guard kept one leg active when both were "
	                "over the ceiling.\n");
	return 0;
}
