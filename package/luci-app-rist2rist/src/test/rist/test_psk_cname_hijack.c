/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Security regression guard: shared-PSK cname identity takeover.
 *
 * The original defect: listener-side cname re-association
 * (try_listener_reassociate_by_cname) authenticated the migrating
 * source using only the cname.  Under a shared PSK the cname is not a
 * per-peer secret, so an independent endpoint that held the group PSK
 * and knew the victim's cname could be absorbed into the victim's peer
 * record once the victim fell silent -- an identity takeover.
 *
 * The fix restricts the migration to peers with an authenticated
 * per-peer SRP session (eap_is_authenticated()).  Under a shared PSK
 * the gate must now refuse migration, so the attacker must remain a
 * SEPARATE caller and must never be absorbed into the victim's record.
 *
 * Topology (all on 127.0.0.1, MAIN profile, shared PSK):
 *   sender(listener, PSK, streams data)
 *       <-- victim  (caller, cname=X, src port A)   round 1
 *       <-- attacker(caller, cname=X, src port B)   round 2
 *
 * The attacker is a SEPARATE rist_ctx with its own socket and its own
 * receiver thread.  It shares ONLY the PSK and the cname with the
 * victim -- it never touches the victim's socket, keys, or peer object.
 *
 * Regression signal: with the fix in place the attacker is NOT
 * absorbed, so the sender sees it as a new distinct caller
 * (distinct_callers increments).  If the attacker is ever absorbed
 * (distinct_callers stays at the post-victim count) the PSK identity
 * takeover has been reintroduced.
 *
 * Note: a listener-sender under a shared PSK broadcasts to every
 * authenticated PSK caller, so the attacker receiving media is NOT by
 * itself the defect -- absorption into the victim's record is.
 *
 * Exit codes:
 *   0  - FIX HOLDS: PSK attacker was NOT absorbed (stayed a separate
 *        caller); the SRP-only gate refused the migration
 *   1  - REGRESSION: PSK attacker was absorbed into the victim's peer
 *        record (PSK cname identity takeover reintroduced)
 *   2  - INDETERMINATE: victim never established / never got data
 *  99  - setup error
 */

#include "librist/librist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "pthread-shim.h"

#ifdef _WIN32
#include <windows.h>
#define usleep(x) Sleep((x)/1000)
#else
#include <unistd.h>
#endif

#define LISTEN_PORT 19900
#define VICTIM_PORT 20011
#define ATTACKER_PORT 20012
#define CNAME "stream-1"
#define PSK "sharedgroupkey4321"

static struct rist_logging_settings *log_settings = NULL;

static pthread_mutex_t tracker_lock;
#define MAX_TRACKED_PEERS 16
static struct {
	struct rist_peer *seen[MAX_TRACKED_PEERS];
	int count;
} tracker;

static volatile int victim_pkts = 0;
static volatile int attacker_pkts = 0;
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

static int victim_data_cb(void *arg, struct rist_data_block *b) {
	(void)arg;
	victim_pkts++;
	rist_receiver_data_block_free2(&b);
	return 0;
}
static int attacker_data_cb(void *arg, struct rist_data_block *b) {
	(void)arg;
	attacker_pkts++;
	rist_receiver_data_block_free2(&b);
	return 0;
}

static struct rist_ctx *start_receiver(const char *url, receiver_data_callback2_t cb) {
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0)
		return NULL;
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0) { rist_destroy(rx); return NULL; }
	struct rist_peer *peer = NULL;
	if (rist_peer_create(rx, &peer, pcfg) != 0) { free(pcfg); rist_destroy(rx); return NULL; }
	free(pcfg);
	if (rist_receiver_data_callback_set2(rx, cb, NULL) != 0) { rist_destroy(rx); return NULL; }
	if (rist_start(rx) != 0) { rist_destroy(rx); return NULL; }
	return rx;
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

int main(int argc, char *argv[]) {
	char url[320];
	/* Negative control: attacker presents a DIFFERENT cname.  Expect no
	 * absorption (the cname is what drives the takeover). */
	bool control = (argc > 1 && strcmp(argv[1], "control") == 0);
	const char *attacker_cname = control ? "other-stream" : CNAME;

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb, NULL, NULL, stderr) != 0)
		return 99;

	memset(&tracker, 0, sizeof(tracker));
	pthread_mutex_init(&tracker_lock, NULL);

	/* sender: listener, MAIN, shared PSK, streams data. */
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0) return 99;
	rist_connection_status_callback_set(tx, sender_status_cb, NULL);
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=30000&keepalive-interval=1000"
	         "&secret=%s&aes-type=128", LISTEN_PORT, PSK);
	struct rist_peer_config *tx_pcfg = NULL;
	if (rist_parse_address2(url, (void *)&tx_pcfg) != 0) { rist_destroy(tx); return 99; }
	struct rist_peer *tx_peer = NULL;
	if (rist_peer_create(tx, &tx_peer, tx_pcfg) != 0) { free(tx_pcfg); rist_destroy(tx); return 99; }
	free(tx_pcfg);
	if (rist_start(tx) != 0) { rist_destroy(tx); return 99; }

	pthread_t feeder;
	pthread_create(&feeder, NULL, sender_feed, tx);
	usleep(200000);

	/* round 1: victim caller. */
	fprintf(stderr, "\n== round 1: VICTIM connects (port %d, cname %s) ==\n",
	        VICTIM_PORT, CNAME);
	snprintf(url, sizeof(url),
	         "rist://127.0.0.1:%d?local-port=%d&cname=%s"
	         "&session-timeout=30000&keepalive-interval=1000&secret=%s&aes-type=128",
	         LISTEN_PORT, VICTIM_PORT, CNAME, PSK);
	struct rist_ctx *victim = start_receiver(url, victim_data_cb);
	if (!victim) { sender_run = false; pthread_join(feeder, NULL); rist_destroy(tx); return 99; }
	usleep(3000000);

	pthread_mutex_lock(&tracker_lock);
	int callers_after_victim = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	int victim_before = victim_pkts;
	fprintf(stderr, "after victim: distinct_callers=%d, victim_pkts=%d\n",
	        callers_after_victim, victim_before);

	/* victim falls silent (modelled by teardown), past 2*keepalive. */
	fprintf(stderr, "\n== victim goes silent ==\n");
	rist_destroy(victim);
	usleep(3000000);

	/* round 2: independent ATTACKER, shares ONLY PSK + cname. */
	fprintf(stderr, "\n== round 2: ATTACKER connects (port %d, cname=%s, same PSK)%s ==\n",
	        ATTACKER_PORT, attacker_cname, control ? " [CONTROL: different cname]" : "");
	snprintf(url, sizeof(url),
	         "rist://127.0.0.1:%d?local-port=%d&cname=%s"
	         "&session-timeout=30000&keepalive-interval=1000&secret=%s&aes-type=128",
	         LISTEN_PORT, ATTACKER_PORT, attacker_cname, PSK);
	int attacker_start = attacker_pkts;
	struct rist_ctx *attacker = start_receiver(url, attacker_data_cb);
	if (!attacker) { sender_run = false; pthread_join(feeder, NULL); rist_destroy(tx); return 99; }
	usleep(4000000);

	pthread_mutex_lock(&tracker_lock);
	int callers_after_attacker = tracker.count;
	pthread_mutex_unlock(&tracker_lock);
	int attacker_got = attacker_pkts - attacker_start;
	fprintf(stderr, "\n== after attacker: distinct_callers=%d, attacker_pkts=%d ==\n",
	        callers_after_attacker, attacker_got);

	sender_run = false;
	pthread_join(feeder, NULL);
	rist_destroy(attacker);
	rist_destroy(tx);
	free(log_settings);

	if (victim_before == 0) {
		fprintf(stderr, "INDETERMINATE: victim never received the stream.\n");
		return 2;
	}

	bool absorbed = (callers_after_attacker == callers_after_victim); /* no new distinct caller */
	bool attacker_received = (attacker_got > 0);

	if (control) {
		/* Control: a different cname is never a migration candidate.
		 * With the SRP-only fix neither cname is absorbed under PSK, so
		 * this just confirms the different-cname caller stays separate. */
		fprintf(stderr, "\nCONTROL (different cname): absorbed=%d "
		                "(distinct_callers %d->%d), attacker_pkts=%d\n",
		        absorbed, callers_after_victim, callers_after_attacker, attacker_got);
		if (!absorbed) {
			fprintf(stderr, "CONTROL OK: different-cname caller stayed "
			                "separate.\n");
			return 0;
		}
		fprintf(stderr, "CONTROL UNEXPECTED: different cname was absorbed.\n");
		return 1;
	}

	if (absorbed) {
		fprintf(stderr, "\nREGRESSION: independent attacker holding only the "
		                "shared PSK + cname \"%s\" was ABSORBED into the "
		                "victim's peer record (distinct_callers stayed %d). "
		                "Finding 1 (PSK cname identity takeover) has been "
		                "reintroduced.\n",
		        CNAME, callers_after_attacker);
		return 1;
	}
	fprintf(stderr, "\nFIX HOLDS: PSK attacker was NOT absorbed; it became a "
	                "separate caller (distinct_callers %d->%d). The SRP-only "
	                "gate refused the cname migration. (attacker_received=%d is "
	                "expected PSK broadcast behaviour, not the defect.)\n",
	        callers_after_victim, callers_after_attacker, attacker_received);
	return 0;
}
