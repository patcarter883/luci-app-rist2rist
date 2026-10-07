/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Mid-stream rebind of ONE bonded leg while the other stays alive.
 *
 * This models a NAT source-port rebind on a single leg of a bonded
 * SRP receiver: from the listening sender's point of view, that leg's
 * source tuple goes silent and a new tuple (same cname, same SRP
 * credentials) appears, while the other leg keeps delivering the whole
 * time.  SRP is used because that is the only mode in which the
 * listener-side cname re-association is eligible to fire, so this
 * directly exercises the alive-duplicate guard.
 *
 * Sequence (all on 127.0.0.1, MAIN profile, SRP same user/pass):
 *   1. sender(listener) streams; receiver brings up legs A and B
 *      (one ctx, same cname, weight 5).  Both authenticate -> 2
 *      distinct callers, stream flows.
 *   2. leg A is destroyed (its tuple disappears) and left silent past
 *      the re-association window; leg B keeps delivering.
 *   3. leg A' is added on a fresh local port (same cname + creds),
 *      modelling A's rebound tuple.  While A is silent, B is still
 *      alive sharing the cname, so the re-association must REFUSE to
 *      migrate A' into A; A' rejoins as a fresh leg.
 *
 * Pass conditions:
 *   - The stream never stalls: data keeps arriving while leg A is down
 *     (B carries it) and after A' rejoins.
 *   - The surviving leg B is untouched: not dead, never rebound.
 *   - A' rejoins as a separate caller (3 distinct callers seen), i.e.
 *     the alive-duplicate guard refused the merge while B was alive.
 *
 * Exit codes:
 *   0  - stream stayed up, leg B undisturbed, A' rejoined separately
 *   1  - stream stalled, leg B disturbed, or A' wrongly merged
 *   2  - INDETERMINATE: both legs never established / no data
 *  99  - setup error
 */

#include "librist/librist.h"
#include "librist/librist_srp.h"
#include "rist-private.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define LISTEN_PORT 19956
#define LEG_A_PORT 20081
#define LEG_B_PORT 20082
#define LEG_APRIME_PORT 20083
#define CNAME "bonded-leg"
#define SRP_USER "leguser"
#define SRP_PASS "legpass-3344"

static struct rist_logging_settings *log_settings = NULL;

static pthread_mutex_t tracker_lock;
#define MAX_TRACKED_PEERS 16
static struct {
	struct rist_peer *seen[MAX_TRACKED_PEERS];
	int count;
} tracker;

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

static void sender_status_cb(void *arg, struct rist_peer *peer,
                             enum rist_connection_status status) {
	(void)arg;
	if (status == RIST_CONNECTION_ESTABLISHED ||
	    status == RIST_CLIENT_CONNECTED) {
		pthread_mutex_lock(&tracker_lock);
		bool seen = false;
		for (int i = 0; i < tracker.count; i++)
			if (tracker.seen[i] == peer) { seen = true; break; }
		if (!seen && tracker.count < MAX_TRACKED_PEERS) {
			tracker.seen[tracker.count++] = peer;
			fprintf(stderr, ">> sender CONNECTED (peer=%p, distinct_callers=%d)\n",
			        (void *)peer, tracker.count);
		}
		pthread_mutex_unlock(&tracker_lock);
	}
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
	while (sender_run) {
		struct rist_data_block blk;
		memset(&blk, 0, sizeof(blk));
		blk.payload = &counter;
		blk.payload_len = sizeof(counter);
		blk.virt_src_port = 1968;
		rist_sender_data_write(tx, &blk);
		counter++;
		usleep(20000); /* ~50 pkt/s */
	}
	return 0;
}

static struct rist_peer *add_srp_leg(struct rist_ctx *rx, int local_port) {
	char url[320];
	snprintf(url, sizeof(url),
	         "rist://127.0.0.1:%d?local-port=%d&cname=%s&weight=5"
	         "&session-timeout=30000&keepalive-interval=1000",
	         LISTEN_PORT, local_port, CNAME);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0)
		return NULL;
	struct rist_peer *peer = NULL;
	if (rist_peer_create(rx, &peer, pcfg) != 0) { free(pcfg); return NULL; }
	free(pcfg);
	if (rist_enable_eap_srp_2(peer, SRP_USER, SRP_PASS, NULL, NULL) != 0)
		return NULL;
	return peer;
}

int main(void) {
	char url[320];

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb, NULL, NULL, stderr) != 0)
		return 99;
	memset(&tracker, 0, sizeof(tracker));
	pthread_mutex_init(&tracker_lock, NULL);

	/* sender: listener, MAIN, single-user SRP authenticator, streams. */
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0) return 99;
	rist_connection_status_callback_set(tx, sender_status_cb, NULL);
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=30000&keepalive-interval=1000",
	         LISTEN_PORT);
	struct rist_peer_config *tx_pcfg = NULL;
	if (rist_parse_address2(url, (void *)&tx_pcfg) != 0) { rist_destroy(tx); return 99; }
	struct rist_peer *tx_peer = NULL;
	if (rist_peer_create(tx, &tx_peer, tx_pcfg) != 0) { free(tx_pcfg); rist_destroy(tx); return 99; }
	free(tx_pcfg);
	if (rist_enable_eap_srp_2(tx_peer, SRP_USER, SRP_PASS, NULL, NULL) != 0) {
		rist_destroy(tx); return 99;
	}
	if (rist_start(tx) != 0) { rist_destroy(tx); return 99; }

	pthread_t feeder;
	pthread_create(&feeder, NULL, sender_feed, tx);
	usleep(200000);

	/* receiver: one ctx, two bonded SRP legs, same cname + creds. */
	fprintf(stderr, "\n== receiver brings up bonded legs A and B (cname=%s) ==\n", CNAME);
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0) {
		sender_run = false; pthread_join(feeder, NULL); rist_destroy(tx); return 99;
	}
	struct rist_peer *leg_a = add_srp_leg(rx, LEG_A_PORT);
	struct rist_peer *leg_b = add_srp_leg(rx, LEG_B_PORT);
	if (!leg_a || !leg_b) {
		sender_run = false; pthread_join(feeder, NULL);
		rist_destroy(rx); rist_destroy(tx); return 99;
	}
	if (rist_receiver_data_callback_set2(rx, rx_data_cb, NULL) != 0 ||
	    rist_start(rx) != 0) {
		sender_run = false; pthread_join(feeder, NULL);
		rist_destroy(rx); rist_destroy(tx); return 99;
	}

	usleep(7000000); /* both SRP handshakes complete */

	pthread_mutex_lock(&tracker_lock);
	int distinct_setup = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	int rx_before = rx_pkts;
	fprintf(stderr, "after setup: distinct_callers=%d, rx_pkts=%d\n",
	        distinct_setup, rx_before);

	/* model leg A's NAT rebind: drop its tuple, let it go silent past
	 * the re-association window while leg B keeps delivering. */
	fprintf(stderr, "\n== leg A tuple drops (NAT rebind); leg B keeps streaming ==\n");
	rist_peer_destroy(rx, leg_a);
	usleep(3000000); /* > 2 * keepalive: A is now a silent candidate */
	int rx_mid = rx_pkts;
	fprintf(stderr, "while leg A down: rx_pkts=%d (was %d)\n", rx_mid, rx_before);

	/* leg A reappears on a fresh source tuple (same cname + creds). */
	fprintf(stderr, "\n== leg A' reappears on a new local port (same cname/creds) ==\n");
	struct rist_peer *leg_aprime = add_srp_leg(rx, LEG_APRIME_PORT);
	if (!leg_aprime) {
		sender_run = false; pthread_join(feeder, NULL);
		rist_destroy(rx); rist_destroy(tx); return 99;
	}
	usleep(7000000); /* A' handshake; re-association must refuse merge */

	pthread_mutex_lock(&tracker_lock);
	int distinct_rebind = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	int rx_after = rx_pkts;
	uint32_t reb_b = leg_b->rebind_attempts;
	int dead_b = leg_b->dead;
	fprintf(stderr, "\n== after A' rejoin: distinct_callers=%d, rx_pkts=%d, "
	                "leg_b rebind=%"PRIu32" dead=%d ==\n",
	        distinct_rebind, rx_after, reb_b, dead_b);

	sender_run = false;
	pthread_join(feeder, NULL);
	rist_destroy(rx);
	rist_destroy(tx);
	free(log_settings);

	if (distinct_setup < 2 || rx_before == 0) {
		fprintf(stderr, "INDETERMINATE: both legs never established or no data "
		                "(distinct_callers=%d, rx_pkts=%d).\n", distinct_setup, rx_before);
		return 2;
	}
	if (rx_mid <= rx_before) {
		fprintf(stderr, "FAIL: stream stalled while leg A was down; bonding did "
		                "not keep flowing on leg B (rx %d -> %d).\n", rx_before, rx_mid);
		return 1;
	}
	if (rx_after <= rx_mid) {
		fprintf(stderr, "FAIL: stream stalled after leg A' rejoined "
		                "(rx %d -> %d).\n", rx_mid, rx_after);
		return 1;
	}
	if (dead_b) {
		fprintf(stderr, "FAIL: surviving leg B died during the other leg's "
		                "rebind.\n");
		return 1;
	}
	if (reb_b != 0) {
		fprintf(stderr, "FAIL: surviving leg B rebound its own socket "
		                "(rebind_attempts=%"PRIu32"); it should have been "
		                "undisturbed.\n", reb_b);
		return 1;
	}
	if (distinct_rebind != 3) {
		fprintf(stderr, "FAIL: expected leg A' to rejoin as a separate caller "
		                "(3 distinct), got %d; the alive-duplicate guard did not "
		                "behave as expected while leg B was alive.\n", distinct_rebind);
		return 1;
	}

	fprintf(stderr, "\nPASS: one bonded SRP leg rebound mid-stream while the "
	                "other kept delivering (rx %d->%d->%d, no stall); surviving "
	                "leg B was undisturbed (not dead, no rebind) and the rebound "
	                "leg rejoined as a separate caller (distinct_callers=3, no "
	                "wrong merge while a same-cname leg was alive).\n",
	        rx_before, rx_mid, rx_after);
	return 0;
}
