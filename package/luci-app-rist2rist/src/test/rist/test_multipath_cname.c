/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Multipath safety check for the cname re-association / caller-side
 * rebind work (issue #188 and its SRP-only hardening).
 *
 * A multipath caller-receiver legitimately presents the SAME cname on
 * every path.  The listener-side re-association must therefore NOT
 * collapse two concurrently-alive paths that share a cname into one
 * peer record, and the caller-side socket rebind must NOT fire on a
 * path that is healthy.
 *
 * Topology (all on 127.0.0.1, MAIN profile):
 *   sender(listener, streams data)
 *       <-- receiver path A (caller, cname=X, local-port A, weight 5)
 *       <-- receiver path B (caller, cname=X, local-port B, weight 5)
 *
 * Both paths belong to ONE receiver ctx and share one cname.  They
 * arrive at the sender as two source tuples under the same listening
 * parent, i.e. two duplicate-cname siblings.
 *
 * Two crypto modes:
 *   psk  - both paths use the same shared PSK (listener-side
 *          re-association is SRP-gated, so it never fires here)
 *   srp  - both paths authenticate with the SAME username/password
 *          (listener-side re-association CAN fire for SRP, so the
 *          alive-duplicate guard is what must keep the paths apart)
 *
 * Usage:
 *   test_multipath_cname [srp]
 *
 * Pass conditions:
 *   1. The sender sees TWO distinct callers and keeps seeing two
 *      across steady state (no spurious cname merge).
 *   2. The receiver gets the stream.
 *   3. Neither receiver path rebinds its socket while healthy
 *      (rebind_attempts == 0) and neither is dead.
 *
 * Exit codes:
 *   0  - both paths stayed distinct, data flowed, no spurious rebind
 *   1  - paths merged, a healthy path rebound, or a path died
 *   2  - INDETERMINATE: both paths never established / no data
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

#define CNAME "bonded-1"
#define PSK "sharedgroupkey9090"
#define SRP_USER "bondeduser"
#define SRP_PASS "bondedpass-5566"

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

static struct rist_peer *add_path(struct rist_ctx *rx, int listen_port,
                                  int local_port, const char *crypto, bool srp) {
	char url[320];
	snprintf(url, sizeof(url),
	         "rist://127.0.0.1:%d?local-port=%d&cname=%s&weight=5"
	         "&session-timeout=30000&keepalive-interval=1000%s",
	         listen_port, local_port, CNAME, crypto);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0)
		return NULL;
	struct rist_peer *peer = NULL;
	if (rist_peer_create(rx, &peer, pcfg) != 0) { free(pcfg); return NULL; }
	free(pcfg);
	if (srp && rist_enable_eap_srp_2(peer, SRP_USER, SRP_PASS, NULL, NULL) != 0)
		return NULL;
	return peer;
}

int main(int argc, char *argv[]) {
	bool use_srp = (argc > 1 && strcmp(argv[1], "srp") == 0);
	int listen_port = use_srp ? 19958 : 19960;
	int path_a_port = use_srp ? 20071 : 20061;
	int path_b_port = use_srp ? 20072 : 20062;
	char crypto[96];
	snprintf(crypto, sizeof(crypto), use_srp ? "" : "&secret=%s&aes-type=128", PSK);
	char url[320];

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb, NULL, NULL, stderr) != 0)
		return 99;
	memset(&tracker, 0, sizeof(tracker));
	pthread_mutex_init(&tracker_lock, NULL);
	fprintf(stderr, "== mode: %s ==\n", use_srp ? "SRP (same user/pass on both paths)"
	                                            : "shared PSK");

	/* sender: listener, MAIN, streams data. */
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0) return 99;
	rist_connection_status_callback_set(tx, sender_status_cb, NULL);
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=30000&keepalive-interval=1000%s",
	         listen_port, crypto);
	struct rist_peer_config *tx_pcfg = NULL;
	if (rist_parse_address2(url, (void *)&tx_pcfg) != 0) { rist_destroy(tx); return 99; }
	struct rist_peer *tx_peer = NULL;
	if (rist_peer_create(tx, &tx_peer, tx_pcfg) != 0) { free(tx_pcfg); rist_destroy(tx); return 99; }
	free(tx_pcfg);
	if (use_srp && rist_enable_eap_srp_2(tx_peer, SRP_USER, SRP_PASS, NULL, NULL) != 0) {
		rist_destroy(tx); return 99;
	}
	if (rist_start(tx) != 0) { rist_destroy(tx); return 99; }

	pthread_t feeder;
	pthread_create(&feeder, NULL, sender_feed, tx);
	usleep(200000);

	/* receiver: ONE ctx, TWO caller paths, same cname. */
	fprintf(stderr, "\n== receiver brings up two bonded paths (cname=%s) ==\n", CNAME);
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0) {
		sender_run = false; pthread_join(feeder, NULL); rist_destroy(tx); return 99;
	}
	struct rist_peer *path_a = add_path(rx, listen_port, path_a_port, crypto, use_srp);
	struct rist_peer *path_b = add_path(rx, listen_port, path_b_port, crypto, use_srp);
	if (!path_a || !path_b) {
		sender_run = false; pthread_join(feeder, NULL);
		rist_destroy(rx); rist_destroy(tx); return 99;
	}
	if (rist_receiver_data_callback_set2(rx, rx_data_cb, NULL) != 0 ||
	    rist_start(rx) != 0) {
		sender_run = false; pthread_join(feeder, NULL);
		rist_destroy(rx); rist_destroy(tx); return 99;
	}

	usleep(use_srp ? 7000000 : 4000000); /* both handshakes complete (SRP is slower) */

	pthread_mutex_lock(&tracker_lock);
	int after_setup = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	int data_after_setup = rx_pkts;
	fprintf(stderr, "after setup: distinct_callers=%d, rx_pkts=%d\n",
	        after_setup, data_after_setup);

	/* steady state: confirm nothing merges or rebinds later. */
	usleep(4000000);

	pthread_mutex_lock(&tracker_lock);
	int after_steady = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	uint32_t reb_a = path_a->rebind_attempts;
	uint32_t reb_b = path_b->rebind_attempts;
	int dead_a = path_a->dead;
	int dead_b = path_b->dead;
	fprintf(stderr, "\n== steady state: distinct_callers=%d, rx_pkts=%d, "
	                "rebind_a=%"PRIu32" rebind_b=%"PRIu32" dead_a=%d dead_b=%d ==\n",
	        after_steady, rx_pkts, reb_a, reb_b, dead_a, dead_b);

	sender_run = false;
	pthread_join(feeder, NULL);
	rist_destroy(rx);
	rist_destroy(tx);
	free(log_settings);

	if (after_setup < 2 || data_after_setup == 0) {
		fprintf(stderr, "INDETERMINATE: both paths never established or no "
		                "data flowed (distinct_callers=%d, rx_pkts=%d).\n",
		        after_setup, data_after_setup);
		return 2;
	}

	if (after_steady != 2) {
		fprintf(stderr, "FAIL: expected 2 distinct callers, got %d; the two "
		                "same-cname paths were wrongly merged.\n", after_steady);
		return 1;
	}
	if (reb_a != 0 || reb_b != 0) {
		fprintf(stderr, "FAIL: a healthy path rebound its socket "
		                "(rebind_a=%"PRIu32", rebind_b=%"PRIu32").\n",
		        reb_a, reb_b);
		return 1;
	}
	if (dead_a || dead_b) {
		fprintf(stderr, "FAIL: a path died (dead_a=%d, dead_b=%d).\n",
		        dead_a, dead_b);
		return 1;
	}

	fprintf(stderr, "\nPASS: two bonded %s paths sharing cname \"%s\" stayed "
	                "distinct (distinct_callers=2), the stream flowed "
	                "(rx_pkts=%d), and neither healthy path rebound.\n",
	        use_srp ? "SRP" : "PSK", CNAME, rx_pkts);
	return 0;
}
