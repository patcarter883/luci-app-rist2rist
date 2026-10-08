/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* risttunnel: point-to-point IP tunnel over RIST with ARQ recovery
 *
 * This tool uses librist's data_fd API to hand the TUN file descriptor
 * directly to the library. librist handles all packet forwarding
 * internally — no application-level read/write loop is needed.
 */

#include <librist/librist.h>
#include <librist/oob.h>
#include <librist/tun.h>
#include "librist/version.h"
#include "config.h"
#if HAVE_SRP_SUPPORT
#include "librist/librist_srp.h"
#include "srp_shared.h"
#endif
#include "vcs_version.h"
#include "risturlhelp.h"
#include "pthread-shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <stdbool.h>
#include "getopt-shim.h"

#if defined(__unix) || defined(__APPLE__)
#include <unistd.h>
#include <poll.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

#define RISTTUNNEL_VERSION "2"
#define DEFAULT_MTU 1400
#define DEFAULT_RTT_MULTIPLIER 3
#define DEFAULT_STATS_INTERVAL 1000

static volatile int keep_running = 1;
static struct rist_logging_settings logging_settings = LOGGING_SETTINGS_INITIALIZER;

static void sig_handler(int sig)
{
	(void)sig;
	keep_running = 0;
}

static int cb_stats(void *arg, const struct rist_stats *stats_container)
{
	(void)arg;
	rist_log(&logging_settings, RIST_LOG_INFO, "%s\n", stats_container->stats_json);
	rist_stats_free(stats_container);
	return 0;
}

/* ---- single-port mode (one UDP port, bidirectional) -------------------
 * A single RIST connection carries both directions on one socket:
 *   - forward  rides the RTP data_fd path  -> ARQ-protected
 *   - reverse  rides the RIST OOB channel  -> best-effort (no ARQ)
 *
 * Roles are asymmetric (one connection only has one sender + one receiver):
 *   caller   (sender side):   data_fd reads TUN -> RTP (forward out);
 *                             OOB callback writes inbound OOB -> TUN (reverse in)
 *   listener (receiver side): data_fd writes inbound RTP -> TUN (forward in);
 *                             a reader thread reads TUN -> OOB (reverse out)
 *
 * The heavy direction of a support tunnel (device -> concentrator: shell
 * output, log/file pulls) is the forward/RTP/ARQ-protected path; the light
 * reverse direction (keystrokes/commands) tolerates best-effort OOB.
 */
struct sp_reverse {
	struct rist_ctx *ctx;            /* context that owns the OOB channel */
	struct rist_peer *volatile peer; /* connected remote peer (listener side) */
	int tun_fd;
	int mtu;
};

/* OOB received from the peer -> inject into the local TUN. */
static int sp_oob_to_tun(void *arg, const struct rist_oob_block *oob_block)
{
	int tun_fd = *(int *)arg;
	if (oob_block && oob_block->payload && oob_block->payload_len > 0)
		rist_tun_write(tun_fd, (const uint8_t *)oob_block->payload,
		               oob_block->payload_len);
	return 0;
}

/* Listener side: librist only auto-learns oob_current_peer from *received*
 * OOB. The caller sends only forward RTP, so capture the connecting peer
 * here and hand it explicitly to rist_oob_write() for the reverse path. */
static int sp_conn_cb(void *arg, const char *connecting_ip, uint16_t connecting_port,
                      const char *local_ip, uint16_t local_port, struct rist_peer *peer)
{
	(void)connecting_ip; (void)connecting_port; (void)local_ip; (void)local_port;
	struct sp_reverse *r = (struct sp_reverse *)arg;
	if (r)
		r->peer = peer;
	return 0;
}

static int sp_disconn_cb(void *arg, struct rist_peer *peer)
{
	struct sp_reverse *r = (struct sp_reverse *)arg;
	if (r && r->peer == peer)
		r->peer = NULL;
	return 0;
}

/* Read packets off the local TUN -> send to the peer over OOB. */
static PTHREAD_START_FUNC(sp_tun_to_oob, arg)
{
	struct sp_reverse *r = (struct sp_reverse *)arg;
	size_t bufsize = (r->mtu > 0 ? (size_t)r->mtu : 1500) + 64;
	uint8_t *buf = malloc(bufsize);
	if (!buf)
		return 0;
	while (keep_running) {
#if defined(__unix) || defined(__APPLE__)
		struct pollfd pfd = { .fd = r->tun_fd, .events = POLLIN, .revents = 0 };
		if (poll(&pfd, 1, 200) <= 0)
			continue;   /* timeout -> re-check keep_running */
#endif
		int n = rist_tun_read(r->tun_fd, buf, bufsize);
		if (n <= 0)
			continue;
		if (!r->peer)
			continue;            /* no peer connected yet -> drop */
		struct rist_oob_block ob;
		memset(&ob, 0, sizeof(ob));
		ob.peer = r->peer;         /* explicit reverse destination */
		ob.payload = buf;
		ob.payload_len = (size_t)n;
		rist_oob_write(r->ctx, &ob);
	}
	free(buf);
	return 0;
}

#if HAVE_SRP_SUPPORT
static int cb_auth_connect(void *arg, const char *connecting_ip,
                           uint16_t connecting_port, const char *local_ip,
                           uint16_t local_port, struct rist_peer *peer)
{
	(void)arg; (void)connecting_ip; (void)connecting_port;
	(void)local_ip; (void)local_port; (void)peer;
	rist_log(&logging_settings, RIST_LOG_INFO,
	         "Peer %s:%u connected\n", connecting_ip, connecting_port);
	return 0;
}

static int cb_auth_disconnect(void *arg, struct rist_peer *peer)
{
	(void)arg; (void)peer;
	return 0;
}
#endif

static void usage(const char *name)
{
	fprintf(stderr,
		"risttunnel %s / libRIST %s API %s\n"
		"IP tunnel over RIST with ARQ packet recovery\n\n"
		"Usage: %s [options]\n\n"
		"Required:\n"
		"  -l, --local-ip IP/PREFIX    Local tunnel IP (e.g. 10.0.0.1/24 or fd00::1/64)\n"
		"  -o, --output-url URL        RIST URL for sending\n"
		"  -b, --input-url URL         RIST URL for receiving\n\n"
		"Optional:\n"
		"  -i, --interface NAME        TUN interface name (default: auto)\n"
		"  -m, --mtu INT               TUN MTU (default: %d)\n"
		"  -M, --rtt-multiplier INT    RIST buffer RTT multiplier (default: %d)\n"
		"  -s, --secret STRING         PSK shared secret\n"
		"  -e, --encryption-type INT   AES type: 128 or 256 (default: 128)\n"
		"  -S, --statsinterval INT     Stats interval in ms (default: %d, 0=off)\n"
		"  -v, --verbose-level INT     Log level 0-6 (default: 3)\n"
		"  -p, --profile INT           RIST profile: 0=simple, 1=main, 2=advanced (default: 2)\n"
		"  -1, --single-port           One UDP port (forward=RTP/ARQ, reverse=OOB).\n"
		"                              Give exactly one of -o (caller) or -b (listener).\n"
#if HAVE_SRP_SUPPORT
		"  -F, --srpfile PATH          EAP-SRP verifier file (server side)\n"
#endif
		"  -h, --help                  Show this help\n\n"
		"Example (server / listener side, two ports):\n"
		"  sudo %s -l 10.0.0.1/24 -b rist://@:5000 -o rist://@:5001\n\n"
		"Example (client / caller side, two ports):\n"
		"  sudo %s -l 10.0.0.2/24 -b rist://server:5001 -o rist://server:5000\n\n"
		"Example (single port, listener):  sudo %s -1 -l 10.0.0.1/24 -b rist://@:443\n"
		"Example (single port, caller):    sudo %s -1 -l 10.0.0.2/24 -o rist://server:443\n\n"
		"%s",
		RISTTUNNEL_VERSION, librist_version(), librist_api_version(),
		name, DEFAULT_MTU, DEFAULT_RTT_MULTIPLIER, DEFAULT_STATS_INTERVAL,
		name, name, name, name, help_urlstr);
	exit(1);
}

static int parse_ip_prefix(const char *cidr, char *ip_out, size_t ip_len, int *prefix_out)
{
	return rist_tun_parse_cidr(cidr, ip_out, ip_len, prefix_out);
}

int main(int argc, char *argv[])
{
	int exitcode = 0;
	char *local_ip_cidr = NULL;
	char *interface_name = NULL;
	char *output_url = NULL;
	char *input_url = NULL;
	char *secret = NULL;
#if HAVE_SRP_SUPPORT
	char *srpfile = NULL;
#endif
	int mtu = DEFAULT_MTU;
	int rtt_multiplier = DEFAULT_RTT_MULTIPLIER;
	int encryption_type = 0;
	int statsinterval = DEFAULT_STATS_INTERVAL;
	enum rist_log_level loglevel = RIST_LOG_WARN;
	enum rist_profile profile = RIST_DEFAULT_PROFILE;
	struct rist_ctx *sender_ctx = NULL;
	struct rist_ctx *receiver_ctx = NULL;
	int tun_fd = -1;
	int single_port = 0;
	pthread_t sp_thread = 0;
	int sp_thread_started = 0;
	struct sp_reverse sp_rev = { 0 };

	static struct option long_options[] = {
		{ "local-ip",        required_argument, NULL, 'l' },
		{ "interface",       required_argument, NULL, 'i' },
		{ "output-url",      required_argument, NULL, 'o' },
		{ "input-url",       required_argument, NULL, 'b' },
		{ "mtu",             required_argument, NULL, 'm' },
		{ "rtt-multiplier",  required_argument, NULL, 'M' },
		{ "secret",          required_argument, NULL, 's' },
		{ "encryption-type", required_argument, NULL, 'e' },
		{ "statsinterval",   required_argument, NULL, 'S' },
		{ "verbose-level",   required_argument, NULL, 'v' },
		{ "profile",         required_argument, NULL, 'p' },
		{ "single-port",     no_argument,       NULL, '1' },
#if HAVE_SRP_SUPPORT
		{ "srpfile",         required_argument, NULL, 'F' },
#endif
		{ "help",            no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

#if HAVE_SRP_SUPPORT
	const char *optstring = "l:i:o:b:m:M:s:e:S:v:p:1F:h";
#else
	const char *optstring = "l:i:o:b:m:M:s:e:S:v:p:1h";
#endif

	int opt;
	while ((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1) {
		switch (opt) {
		case 'l': local_ip_cidr = strdup(optarg); break;
		case 'i': interface_name = strdup(optarg); break;
		case 'o': output_url = strdup(optarg); break;
		case 'b': input_url = strdup(optarg); break;
		case 'm': mtu = atoi(optarg); break;
		case 'M': rtt_multiplier = atoi(optarg); break;
		case 's': secret = strdup(optarg); break;
		case 'e': encryption_type = atoi(optarg); break;
		case 'S': statsinterval = atoi(optarg); break;
		case 'v': loglevel = (enum rist_log_level)atoi(optarg); break;
		case 'p': profile = (enum rist_profile)atoi(optarg); break;
		case '1': single_port = 1; break;
#if HAVE_SRP_SUPPORT
		case 'F': srpfile = strdup(optarg); break;
#endif
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (!local_ip_cidr)
		usage(argv[0]);
	if (single_port) {
		/* one connection only: exactly one of -o (caller) / -b (listener) */
		if ((!output_url && !input_url) || (output_url && input_url)) {
			fprintf(stderr, "single-port mode: specify exactly one of "
			        "-o (caller) or -b (listener)\n");
			usage(argv[0]);
		}
		if (profile == RIST_PROFILE_SIMPLE) {
			fprintf(stderr, "single-port mode requires main or advanced "
			        "profile (OOB is unavailable in simple profile)\n");
			usage(argv[0]);
		}
	} else if (!output_url || !input_url) {
		usage(argv[0]);
	}

	/* Append secret/encryption to whichever RIST URLs are present */
	if (secret) {
		char url_suffix[512];
		int enc = encryption_type > 0 ? encryption_type : 128;
		if (output_url) {
			snprintf(url_suffix, sizeof(url_suffix), "%csecret=%s&aes-type=%d",
			         strchr(output_url, '?') ? '&' : '?', secret, enc);
			char *new_out = malloc(strlen(output_url) + strlen(url_suffix) + 1);
			if (!new_out) {
				fprintf(stderr, "Out of memory\n");
				exitcode = 1;
				goto cleanup;
			}
			sprintf(new_out, "%s%s", output_url, url_suffix);
			free(output_url);
			output_url = new_out;
		}
		if (input_url) {
			snprintf(url_suffix, sizeof(url_suffix), "%csecret=%s&aes-type=%d",
			         strchr(input_url, '?') ? '&' : '?', secret, enc);
			char *new_in = malloc(strlen(input_url) + strlen(url_suffix) + 1);
			if (!new_in) {
				fprintf(stderr, "Out of memory\n");
				exitcode = 1;
				goto cleanup;
			}
			sprintf(new_in, "%s%s", input_url, url_suffix);
			free(input_url);
			input_url = new_in;
		}
	}

	/* Parse IP/prefix */
	char ip_addr[64];
	int prefix_len;
	if (parse_ip_prefix(local_ip_cidr, ip_addr, sizeof(ip_addr), &prefix_len) != 0) {
		fprintf(stderr, "Invalid IP/prefix: %s\n", local_ip_cidr);
		exitcode = 1;
		goto cleanup;
	}

	/* Signal handling */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	/* Logging.  Point log_ptr at the static settings like the other tools:
	 * rist_logging_set() only allocates a new struct when *log_ptr is NULL,
	 * otherwise it configures the pointed-to settings in place.  Leaving it
	 * uninitialised let a garbage non-NULL value through and caused a write
	 * to an invalid address (intermittent SIGSEGV at startup). */
	struct rist_logging_settings *log_ptr = &logging_settings;
	if (rist_logging_set(&log_ptr, loglevel, NULL, NULL, NULL, stderr) != 0) {
		fprintf(stderr, "Failed to setup logging\n");
		exitcode = 1;
		goto cleanup;
	}

	/* Open and configure TUN device (using librist TUN API) */
	char actual_ifname[64] = {0};
	tun_fd = rist_tun_open(interface_name, actual_ifname, sizeof(actual_ifname));
	if (tun_fd < 0) {
		fprintf(stderr, "Failed to open TUN device (are you root?)\n");
		exitcode = 1;
		goto cleanup;
	}

	if (rist_tun_set_mtu(actual_ifname, mtu) != 0 ||
	    rist_tun_set_ip(actual_ifname, ip_addr, prefix_len) != 0 ||
	    rist_tun_bring_up(actual_ifname) != 0) {
		fprintf(stderr, "Failed to configure TUN interface %s\n", actual_ifname);
		exitcode = 1;
		goto cleanup;
	}

	rist_log(&logging_settings, RIST_LOG_INFO,
	         "TUN %s: %s/%d MTU %d\n", actual_ifname, ip_addr, prefix_len, mtu);

	/* RIST sender (TUN → network): hand tun_fd to librist.
	 * Built when -o is present: always in two-port mode, and for the
	 * caller role in single-port mode. */
	if (output_url) {
		if (rist_sender_create(&sender_ctx, profile, 0, log_ptr) != 0) {
			fprintf(stderr, "Failed to create RIST sender\n");
			exitcode = 1;
			goto cleanup;
		}
		if (rtt_multiplier > 0)
			rist_recovery_rtt_multiplier_set(sender_ctx, rtt_multiplier);

		rist_sender_data_fd_set(sender_ctx, tun_fd, (size_t)mtu, RIST_DATA_FD_FLAG_TUN);

		struct rist_peer_config *sender_peer_cfg = NULL;
		if (rist_parse_address2(output_url, &sender_peer_cfg) != 0) {
			fprintf(stderr, "Failed to parse sender URL: %s\n", output_url);
			exitcode = 1;
			goto cleanup;
		}
		if (mtu < 1400 && sender_peer_cfg->split_mode == LIBRIST_SPLIT_MODE_OFF) {
			rist_log(&logging_settings, RIST_LOG_INFO,
			         "MTU %d < 1400: auto-enabling split=half on sender\n", mtu);
			sender_peer_cfg->split_mode = LIBRIST_SPLIT_MODE_HALF;
		}
		struct rist_peer *sender_peer = NULL;
		if (rist_peer_create(sender_ctx, &sender_peer, sender_peer_cfg) != 0) {
			fprintf(stderr, "Failed to create sender peer\n");
			exitcode = 1;
			goto cleanup;
		}
#if HAVE_SRP_SUPPORT
		/* Present SRP credentials supplied on the sender URL
		 * (?username=...&password=...), the same way ristsender does.
		 * Without this the credentials are parsed into the peer config but
		 * never handed to EAP, so authentication to an SRP-protected
		 * listener never starts. */
		if (strlen(sender_peer_cfg->srp_username) > 0 &&
		    strlen(sender_peer_cfg->srp_password) > 0) {
			if (rist_enable_eap_srp_2(sender_peer, sender_peer_cfg->srp_username,
			                          sender_peer_cfg->srp_password, NULL, NULL) != 0) {
				fprintf(stderr, "Failed to enable EAP-SRP on sender\n");
				exitcode = 1;
				goto cleanup;
			}
		}
#endif
		if (statsinterval > 0)
			rist_stats_callback_set(sender_ctx, statsinterval, cb_stats, NULL);
	}

	/* RIST receiver (network → TUN): hand tun_fd to librist.
	 * Built when -b is present: always in two-port mode, and for the
	 * listener role in single-port mode. */
	if (input_url) {
		if (rist_receiver_create(&receiver_ctx, profile, log_ptr) != 0) {
			fprintf(stderr, "Failed to create RIST receiver\n");
			exitcode = 1;
			goto cleanup;
		}
		if (rtt_multiplier > 0)
			rist_recovery_rtt_multiplier_set(receiver_ctx, rtt_multiplier);

		rist_receiver_data_fd_set(receiver_ctx, tun_fd, RIST_DATA_FD_FLAG_TUN);

#if HAVE_SRP_SUPPORT
		if (srpfile) {
			if (rist_auth_handler_set(receiver_ctx, cb_auth_connect, cb_auth_disconnect, receiver_ctx) != 0) {
				fprintf(stderr, "Failed to set auth handler\n");
				exitcode = 1;
				goto cleanup;
			}
		}
#endif

		struct rist_peer_config *recv_peer_cfg = NULL;
		if (rist_parse_address2(input_url, &recv_peer_cfg) != 0) {
			fprintf(stderr, "Failed to parse receiver URL: %s\n", input_url);
			exitcode = 1;
			goto cleanup;
		}
		if (mtu < 1400 && recv_peer_cfg->merge_mode == LIBRIST_MERGE_MODE_OFF) {
			rist_log(&logging_settings, RIST_LOG_INFO,
			         "MTU %d < 1400: auto-enabling merge=auto on receiver\n", mtu);
			recv_peer_cfg->merge_mode = LIBRIST_MERGE_MODE_AUTO;
		}
		struct rist_peer *recv_peer = NULL;
		if (rist_peer_create(receiver_ctx, &recv_peer, recv_peer_cfg) != 0) {
			fprintf(stderr, "Failed to create receiver peer\n");
			exitcode = 1;
			goto cleanup;
		}

#if HAVE_SRP_SUPPORT
		/* Receiver leg acts as an SRP client when credentials are supplied on
		 * the input URL (a two-port client connecting out to a listener);
		 * otherwise it is the server that verifies callers against -F. */
		if (strlen(recv_peer_cfg->srp_username) > 0 &&
		    strlen(recv_peer_cfg->srp_password) > 0) {
			if (rist_enable_eap_srp_2(recv_peer, recv_peer_cfg->srp_username,
			                          recv_peer_cfg->srp_password, NULL, NULL) != 0) {
				fprintf(stderr, "Failed to enable EAP-SRP (receiver credentials)\n");
				exitcode = 1;
				goto cleanup;
			}
		} else if (srpfile) {
			if (rist_enable_eap_srp_2(recv_peer, NULL, NULL, user_verifier_lookup, (void *)srpfile) != 0) {
				fprintf(stderr, "Failed to enable EAP-SRP\n");
				exitcode = 1;
				goto cleanup;
			}
		}
#endif

		if (statsinterval > 0)
			rist_stats_callback_set(receiver_ctx, statsinterval, cb_stats, NULL);
	}

	/* single-port: enable the OOB channel that carries the reverse
	 * direction on the same socket. The caller installs a callback to
	 * inject inbound OOB into the TUN; the listener only needs OOB
	 * enabled so its reader thread can rist_oob_write() back. */
	if (single_port) {
		struct rist_ctx *oob_ctx = sender_ctx ? sender_ctx : receiver_ctx;
		oob_callback_func_t oob_cb = sender_ctx ? sp_oob_to_tun : NULL;
		if (rist_oob_callback_set(oob_ctx, oob_cb, &tun_fd) != 0) {
			fprintf(stderr, "Failed to enable OOB channel for single-port mode\n");
			exitcode = 1;
			goto cleanup;
		}
		if (receiver_ctx) {
			/* listener: prep the reverse path and capture the peer on connect */
			sp_rev.ctx = receiver_ctx;
			sp_rev.tun_fd = tun_fd;
			sp_rev.mtu = mtu;
			sp_rev.peer = NULL;
			if (rist_auth_handler_set(receiver_ctx, sp_conn_cb, sp_disconn_cb, &sp_rev) != 0) {
				fprintf(stderr, "Failed to set connect handler for single-port listener\n");
				exitcode = 1;
				goto cleanup;
			}
		}
	}

	/* Start whichever contexts exist — librist forwards internally */
	if ((sender_ctx && rist_start(sender_ctx) != 0) ||
	    (receiver_ctx && rist_start(receiver_ctx) != 0)) {
		fprintf(stderr, "Failed to start RIST\n");
		exitcode = 1;
		goto cleanup;
	}

	if (single_port)
		rist_log(&logging_settings, RIST_LOG_INFO,
		         "Tunnel active (single-port %s): %s/%d via RIST %s\n",
		         sender_ctx ? "caller" : "listener", ip_addr, prefix_len,
		         output_url ? output_url : input_url);
	else
		rist_log(&logging_settings, RIST_LOG_INFO,
		         "Tunnel active: %s/%d via RIST (%s -> %s)\n",
		         ip_addr, prefix_len, input_url, output_url);

	/* single-port listener: pump the local TUN -> OOB (reverse direction).
	 * The caller's reverse path is handled by the OOB receive callback. */
	if (single_port && receiver_ctx) {
		/* sp_rev was populated above; conn_cb fills sp_rev.peer on connect */
		if (pthread_create(&sp_thread, NULL, sp_tun_to_oob, &sp_rev) != 0) {
			fprintf(stderr, "Failed to start reverse OOB thread\n");
			exitcode = 1;
			goto cleanup;
		}
		sp_thread_started = 1;
	}

	/* Wait for signal — librist handles all forwarding internally */
	while (keep_running) {
#if defined(__unix) || defined(__APPLE__)
		sleep(1);
#else
		Sleep(1000);
#endif
	}

	if (sp_thread_started) {
		pthread_join(sp_thread, NULL);
		sp_thread_started = 0;
	}

	/* Print stats (only for contexts that exist) */
	if (sender_ctx) {
		struct rist_data_fd_stats tx_stats;
		rist_data_fd_stats_get(sender_ctx, &tx_stats);
		rist_log(&logging_settings, RIST_LOG_INFO,
		         "Shutting down. TX: %lu pkts / %lu bytes\n",
		         (unsigned long)tx_stats.tx_packets,
		         (unsigned long)tx_stats.tx_bytes);
	}
	if (receiver_ctx) {
		struct rist_data_fd_stats rx_stats;
		rist_data_fd_stats_get(receiver_ctx, &rx_stats);
		rist_log(&logging_settings, RIST_LOG_INFO,
		         "Shutting down. RX: %lu pkts / %lu bytes\n",
		         (unsigned long)rx_stats.rx_packets,
		         (unsigned long)rx_stats.rx_bytes);
	}

cleanup:
	if (sp_thread_started)
		pthread_join(sp_thread, NULL);
	if (receiver_ctx)
		rist_destroy(receiver_ctx);
	if (sender_ctx)
		rist_destroy(sender_ctx);
	if (tun_fd >= 0)
		rist_tun_close(tun_fd);

	rist_logging_unset_global();

	free(local_ip_cidr);
	free(interface_name);
	free(output_url);
	free(input_url);
	free(secret);
#if HAVE_SRP_SUPPORT
	free(srpfile);
#endif

	return exitcode;
}
