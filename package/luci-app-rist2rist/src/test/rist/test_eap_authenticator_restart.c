/* librist. Copyright © 2026 SipRadius LLC.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Regression for the EAP-SRP re-authentication lockout after an
 * *authenticator* (listener/hub) restart.
 *
 * process_eap_request_identity() refused every EAP_REQUEST_IDENTITY once the
 * authenticatee reached EAP_AUTH_STATE_SUCCESS (hardening against a forged
 * single-packet reset). That is correct for a lone forged
 * packet, but it also permanently locks out the *legitimate* case: when the
 * authenticator restarts it loses all session state, treats the caller as a
 * brand-new peer and drives a fresh handshake by re-sending IDENTITY. A caller
 * still parked in SUCCESS refused those forever, so the hub sat in "Waiting for
 * EAP authentication to happen" and the data plane carried 0 packets until an
 * operator restarted the caller.
 *
 * This is distinct from the caller *socket* rebind (test_caller_socket_rebind):
 * that recovers only from listener *silence* (NAT rebind / dead socket). Here
 * the restarted authenticator is NOT silent -- it actively re-challenges -- so
 * the silence rebind never fires. We prove that by pinning a long
 * session_timeout so the rebind path is disabled for the whole test; recovery
 * can therefore only come from the identity-request re-auth path under test.
 *
 * Topology (single hop, in-process):
 *   sender(listener/authenticator, 127.0.0.1:PORT) <-- receiver(caller/authenticatee)
 *
 * Sequence:
 *   1. Spin up authenticator + authenticatee, wait for the SRP handshake.
 *   2. Push a data burst and confirm the caller decodes it.
 *   3. Destroy the authenticator and immediately recreate it on the same port
 *      (a firmware upgrade / service restart). The caller never goes silent.
 *   4. Wait for the fresh authenticator to re-challenge and the caller to
 *      re-authenticate on its own.
 *   5. Push another burst and confirm it flows.
 *
 * PASS when post-restart payload flows AND rebind_attempts == 0 (recovery came
 * from the identity re-auth path, not the silence rebind). Before the fix the
 * caller stays locked in SUCCESS, no data flows, and the test fails.
 *
 * Exit codes:
 *   0  - caller re-authenticated against the restarted authenticator, data flowed
 *   1  - caller never recovered (locked out) / no data after restart
 *   2  - setup never reached an initial handshake / data path
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

#define SRP_USER "restartuser"
#define SRP_PASS "restartpass-9137"

/* Long enough that try_caller_socket_rebind (needs silence beyond
 * max(session_timeout, 4*keepalive)) cannot fire during this test, so recovery
 * is attributable solely to the identity-request re-auth path. */
#define SESSION_TIMEOUT_MS 30000
#define KEEPALIVE_MS       500

static struct rist_logging_settings *log_settings = NULL;
static pthread_mutex_t cb_lock;
static unsigned rx_data_count;

static int rx_data_cb(void *arg, struct rist_data_block *b) {
	(void)arg;
	pthread_mutex_lock(&cb_lock);
	rx_data_count++;
	pthread_mutex_unlock(&cb_lock);
	rist_receiver_data_block_free2(&b);
	return 0;
}

static unsigned rx_data_snapshot(void) {
	pthread_mutex_lock(&cb_lock);
	unsigned v = rx_data_count;
	pthread_mutex_unlock(&cb_lock);
	return v;
}

static void send_burst(struct rist_ctx *tx, uint32_t start, int count) {
	for (int i = 0; i < count; i++) {
		uint32_t v = start + (uint32_t)i;
		struct rist_data_block blk;
		memset(&blk, 0, sizeof(blk));
		blk.payload = &v;
		blk.payload_len = sizeof(v);
		blk.virt_src_port = 1968;
		rist_sender_data_write(tx, &blk);
		usleep(20000); /* ~50 pkt/s */
	}
}

static int log_cb(void *arg, enum rist_log_level level, const char *msg) {
	(void)arg;
	const char *tag = level <= RIST_LOG_ERROR ? "E" :
	                  level <= RIST_LOG_WARN  ? "W" :
	                  level <= RIST_LOG_INFO  ? "I" : "D";
	fprintf(stderr, "%s| %s", tag, msg);
	return 0;
}

/* Listener == SRP authenticator. */
static struct rist_ctx *spawn_authenticator(int port) {
	struct rist_ctx *tx = NULL;
	if (rist_sender_create(&tx, RIST_PROFILE_MAIN, 0, log_settings) != 0)
		return NULL;
	char url[256];
	snprintf(url, sizeof(url),
	         "rist://@127.0.0.1:%d?session-timeout=%d&keepalive-interval=%d",
	         port, SESSION_TIMEOUT_MS, KEEPALIVE_MS);
	struct rist_peer_config *pcfg = NULL;
	if (rist_parse_address2(url, (void *)&pcfg) != 0) { rist_destroy(tx); return NULL; }
	struct rist_peer *peer = NULL;
	if (rist_peer_create(tx, &peer, pcfg) != 0) { free(pcfg); rist_destroy(tx); return NULL; }
	free(pcfg);
	if (rist_enable_eap_srp_2(peer, SRP_USER, SRP_PASS, NULL, NULL) != 0) { rist_destroy(tx); return NULL; }
	if (rist_start(tx) != 0) { rist_destroy(tx); return NULL; }
	return tx;
}

int main(void) {
	const int listen_port = 22012;
	memset(&rx_data_count, 0, sizeof(rx_data_count));
	pthread_mutex_init(&cb_lock, NULL);

	if (rist_logging_set(&log_settings, RIST_LOG_INFO, log_cb, NULL, NULL, stderr) != 0) {
		fprintf(stderr, "logging setup failed\n");
		return 99;
	}

	fprintf(stderr, "== spawning first authenticator (listener) on :%d ==\n", listen_port);
	struct rist_ctx *tx1 = spawn_authenticator(listen_port);
	if (!tx1) { fprintf(stderr, "authenticator create failed\n"); return 99; }
	usleep(200000);

	fprintf(stderr, "== spawning caller (authenticatee) ==\n");
	struct rist_ctx *rx = NULL;
	if (rist_receiver_create(&rx, RIST_PROFILE_MAIN, log_settings) != 0) {
		fprintf(stderr, "rx ctx create failed\n"); rist_destroy(tx1); return 99;
	}
	char rx_url[256];
	snprintf(rx_url, sizeof(rx_url),
	         "rist://127.0.0.1:%d?session-timeout=%d&keepalive-interval=%d"
	         "&buffer=200&cname=restart-test",
	         listen_port, SESSION_TIMEOUT_MS, KEEPALIVE_MS);
	struct rist_peer_config *rx_pcfg = NULL;
	if (rist_parse_address2(rx_url, (void *)&rx_pcfg) != 0) {
		fprintf(stderr, "rx url parse failed\n"); rist_destroy(rx); rist_destroy(tx1); return 99;
	}
	struct rist_peer *rx_peer = NULL;
	if (rist_peer_create(rx, &rx_peer, rx_pcfg) != 0) {
		fprintf(stderr, "rx peer create failed\n"); free(rx_pcfg); rist_destroy(rx); rist_destroy(tx1); return 99;
	}
	free(rx_pcfg);
	if (rist_enable_eap_srp_2(rx_peer, SRP_USER, SRP_PASS, NULL, NULL) != 0) {
		fprintf(stderr, "rx SRP enable failed\n"); rist_destroy(rx); rist_destroy(tx1); return 99;
	}
	if (rist_receiver_data_callback_set2(rx, rx_data_cb, NULL) != 0) {
		fprintf(stderr, "rx data callback set failed\n"); rist_destroy(rx); rist_destroy(tx1); return 99;
	}
	if (rist_start(rx) != 0) {
		fprintf(stderr, "rx start failed\n"); rist_destroy(rx); rist_destroy(tx1); return 99;
	}

	/* wait for the initial SRP handshake */
	usleep(5000000);

	/* Confirm the pre-restart data path carries payload. */
	send_burst(tx1, 0, 25);
	usleep(1000000);
	if (rx_data_snapshot() == 0) {
		fprintf(stderr, "INDETERMINATE: no data before restart; setup broken.\n");
		rist_destroy(rx); rist_destroy(tx1); free(log_settings); return 2;
	}
	fprintf(stderr, "== initial auth + data path OK (%u blocks) ==\n", rx_data_snapshot());

	/* Restart the authenticator: destroy and immediately recreate on the same
	 * port. The caller never goes silent (long session_timeout), so the socket
	 * rebind cannot fire -- only the identity re-auth path can recover us. */
	fprintf(stderr, "== restarting authenticator (fresh EAP state, same port) ==\n");
	rist_destroy(tx1);
	usleep(200000); /* brief gap, well under session_timeout/keepalive windows */
	struct rist_ctx *tx2 = spawn_authenticator(listen_port);
	if (!tx2) {
		fprintf(stderr, "second authenticator create failed\n");
		rist_destroy(rx); free(log_settings); return 99;
	}

	/* Give the fresh authenticator time to re-challenge (IDENTITY) and the
	 * caller time to notice the persistence and re-run the SRP handshake. */
	usleep(8000000);

	unsigned data_before = rx_data_snapshot();
	send_burst(tx2, 1000, 50);
	usleep(1200000);
	unsigned data_after = rx_data_snapshot();

	uint32_t rebinds = rx_peer->rebind_attempts;
	bool dead = rx_peer->dead;

	rist_destroy(rx);
	rist_destroy(tx2);
	free(log_settings);

	fprintf(stderr, "== after restart: data_before=%u data_after=%u "
	                "rebind_attempts=%"PRIu32" dead=%d ==\n",
	        data_before, data_after, rebinds, dead);

	if (data_after <= data_before) {
		fprintf(stderr, "FAIL: caller did NOT recover after the authenticator "
		                "restart; no data flowed (locked in SUCCESS, refusing "
		                "the fresh IDENTITY forever).\n");
		return 1;
	}
	if (rebinds != 0) {
		fprintf(stderr, "FAIL: recovery came from the socket rebind "
		                "(rebind_attempts=%"PRIu32"), not the identity re-auth "
		                "path this test targets; tighten the timing.\n", rebinds);
		return 1;
	}

	fprintf(stderr, "PASS: caller re-authenticated against the restarted "
	                "authenticator on its own (%u blocks flowed after restart, "
	                "no socket rebind) -- no operator intervention.\n",
	        data_after - data_before);
	return 0;
}
