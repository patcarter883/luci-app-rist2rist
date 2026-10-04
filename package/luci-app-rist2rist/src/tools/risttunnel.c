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
#include "librist/version.h"
#include "config.h"
#if HAVE_SRP_SUPPORT
#include "librist/librist_srp.h"
#include "srp_shared.h"
#endif
#include "vcs_version.h"
#include "risturlhelp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include "getopt-shim.h"

#if defined(__unix) || defined(__APPLE__)
#include <unistd.h>
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
		"  -l, --local-ip IP/PREFIX    Local tunnel IP (e.g. 10.0.0.1/24)\n"
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
		"  -p, --profile INT           RIST profile: 0=simple, 1=main (default: 1)\n"
#if HAVE_SRP_SUPPORT
		"  -F, --srpfile PATH          EAP-SRP verifier file (server side)\n"
#endif
		"  -h, --help                  Show this help\n\n"
		"Example (server / listener side):\n"
		"  sudo %s -l 10.0.0.1/24 -b rist://@:5000 -o rist://@:5001\n\n"
		"Example (client / caller side):\n"
		"  sudo %s -l 10.0.0.2/24 -b rist://server:5001 -o rist://server:5000\n\n"
		"%s",
		RISTTUNNEL_VERSION, librist_version(), librist_api_version(),
		name, DEFAULT_MTU, DEFAULT_RTT_MULTIPLIER, DEFAULT_STATS_INTERVAL,
		name, name, help_urlstr);
	exit(1);
}

static int parse_ip_prefix(const char *cidr, char *ip_out, size_t ip_len, int *prefix_out)
{
	const char *slash = strchr(cidr, '/');
	if (!slash) {
		strncpy(ip_out, cidr, ip_len - 1);
		*prefix_out = 32;
		return 0;
	}

	size_t ip_part_len = (size_t)(slash - cidr);
	if (ip_part_len >= ip_len)
		return -1;

	memcpy(ip_out, cidr, ip_part_len);
	ip_out[ip_part_len] = '\0';
	*prefix_out = atoi(slash + 1);

	if (*prefix_out < 0 || *prefix_out > 32)
		return -1;

	return 0;
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
	enum rist_profile profile = RIST_PROFILE_MAIN;
	struct rist_ctx *sender_ctx = NULL;
	struct rist_ctx *receiver_ctx = NULL;
	int tun_fd = -1;

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
#if HAVE_SRP_SUPPORT
		{ "srpfile",         required_argument, NULL, 'F' },
#endif
		{ "help",            no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

#if HAVE_SRP_SUPPORT
	const char *optstring = "l:i:o:b:m:M:s:e:S:v:p:F:h";
#else
	const char *optstring = "l:i:o:b:m:M:s:e:S:v:p:h";
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
#if HAVE_SRP_SUPPORT
		case 'F': srpfile = strdup(optarg); break;
#endif
		case 'h':
		default:
			usage(argv[0]);
		}
	}

	if (!local_ip_cidr || !output_url || !input_url)
		usage(argv[0]);

	/* Append secret/encryption to RIST URLs if specified */
	if (secret) {
		char url_suffix[512];
		int enc = encryption_type > 0 ? encryption_type : 128;
		snprintf(url_suffix, sizeof(url_suffix), "%csecret=%s&aes-type=%d",
		         strchr(output_url, '?') ? '&' : '?', secret, enc);

		char *new_out = malloc(strlen(output_url) + strlen(url_suffix) + 1);
		char *new_in = malloc(strlen(input_url) + strlen(url_suffix) + 1);
		if (!new_out || !new_in) {
			fprintf(stderr, "Out of memory\n");
			exitcode = 1;
			goto cleanup;
		}
		sprintf(new_out, "%s%s", output_url, url_suffix);
		free(output_url);
		output_url = new_out;

		snprintf(url_suffix, sizeof(url_suffix), "%csecret=%s&aes-type=%d",
		         strchr(input_url, '?') ? '&' : '?', secret, enc);
		sprintf(new_in, "%s%s", input_url, url_suffix);
		free(input_url);
		input_url = new_in;
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

	/* Logging */
	struct rist_logging_settings *log_ptr;
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

	/* RIST sender (TUN → network): hand tun_fd to librist */
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
	if (statsinterval > 0)
		rist_stats_callback_set(sender_ctx, statsinterval, cb_stats, NULL);

	/* RIST receiver (network → TUN): hand tun_fd to librist */
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
	if (srpfile) {
		if (rist_enable_eap_srp_2(recv_peer, NULL, NULL, user_verifier_lookup, (void *)srpfile) != 0) {
			fprintf(stderr, "Failed to enable EAP-SRP\n");
			exitcode = 1;
			goto cleanup;
		}
	}
#endif

	if (statsinterval > 0)
		rist_stats_callback_set(receiver_ctx, statsinterval, cb_stats, NULL);

	/* Start both — librist handles all forwarding internally */
	if (rist_start(sender_ctx) != 0 || rist_start(receiver_ctx) != 0) {
		fprintf(stderr, "Failed to start RIST\n");
		exitcode = 1;
		goto cleanup;
	}

	rist_log(&logging_settings, RIST_LOG_INFO,
	         "Tunnel active: %s/%d via RIST (%s -> %s)\n",
	         ip_addr, prefix_len, input_url, output_url);

	/* Wait for signal — no forwarding loop needed */
	while (keep_running) {
#if defined(__unix) || defined(__APPLE__)
		sleep(1);
#else
		Sleep(1000);
#endif
	}

	/* Print stats */
	struct rist_data_fd_stats tx_stats, rx_stats;
	rist_data_fd_stats_get(sender_ctx, &tx_stats);
	rist_data_fd_stats_get(receiver_ctx, &rx_stats);
	rist_log(&logging_settings, RIST_LOG_INFO,
	         "Shutting down. TX: %lu pkts / %lu bytes, RX: %lu pkts / %lu bytes\n",
	         (unsigned long)tx_stats.tx_packets, (unsigned long)tx_stats.tx_bytes,
	         (unsigned long)rx_stats.rx_packets, (unsigned long)rx_stats.rx_bytes);

cleanup:
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
