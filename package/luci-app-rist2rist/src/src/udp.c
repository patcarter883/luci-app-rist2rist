/* librist. Copyright © 2019-2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Kuldeep Singh Dhaka <kuldeep@madresistor.com>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "logging.h"
#include "proto/gre.h"
#include "proto/protocol_gre.h"
#include "udp-private.h"
#include "rist-private.h"
#include "rist-retx-domain.h"
#include "log-private.h"
#include "socket-shim.h"
#include "endian-shim.h"
#include "proto/rist_time.h"
#include "proto/protocol_rtp.h"
#if HAVE_SRP_SUPPORT
#include "proto/eap.h"
#endif
#include "crypto/psk.h"
#include "mpegts.h"
#include <lz4.h>
#include "transport-private.h"
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <fcntl.h>

/* EMSGSIZE-aware send-failure logger, rate-limited to one line per peer
 * every 5 seconds to avoid drowning the log when the application is
 * pushing a stream of oversized packets. The hint on the PMTU case is
 * deliberately explicit and actionable: an operator who sees this once
 * should be able to fix it by lowering the application packet size
 * (e.g. risttunnel -m), without having to chase ICMP filtering. */
void _librist_log_send_error(struct rist_peer *p, int sock_errno,
                             size_t attempted, const char *origin)
{
	struct rist_common_ctx *ctx = get_cctx(p);
	uint64_t now = timestampNTP_u64();
	bool is_pmtu;
#ifdef _WIN32
	is_pmtu = (sock_errno == WSAEMSGSIZE);
#else
	is_pmtu = (sock_errno == EMSGSIZE);
#endif
	if (is_pmtu) {
		const uint64_t five_seconds = (uint64_t)5 * 65536 * 1000;
		if (p->last_pmtu_error_log != 0 &&
		    now - p->last_pmtu_error_log < five_seconds)
			return;
		p->last_pmtu_error_log = now;
		rist_log_priv(ctx, RIST_LOG_ERROR,
			"PMTU exceeded sending %zu-byte datagram via %s (errno=%d). The path "
			"MTU to this peer is smaller than our RIST packet size and the "
			"don't-fragment bit is set, so the kernel refused to fragment. "
			"Lower the application packet size (e.g. risttunnel -m, or upstream "
			"MPEG-TS UDP size) so that payload + ~40 bytes of headers fits in the "
			"path MTU. Further PMTU errors on this peer will be silenced for 5s.\n",
			attempted, origin, sock_errno);
	} else {
		rist_log_priv(ctx, RIST_LOG_ERROR,
			"Send failed via %s: errno=%d, size=%zu, socket=%d\n",
			origin, sock_errno, attempted, p->sd);
	}
}

size_t rist_send_seq_rtcp(struct rist_peer *p, uint32_t seq_rtp, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, bool retry, uint16_t ts_null_bytes)
{
	struct rist_common_ctx *ctx = get_cctx(p);
	uint8_t *data;
	size_t len;
	size_t hdr_len = 0;
	ssize_t ret = 0;

	uint8_t *_payload = NULL;
	_payload = payload;

	/* Advanced Profile (VSF TR-06-3): build RTP-based packet directly,
	 * bypassing GRE framing entirely. Control and OOB are handled
	 * separately through rist_adv_send_control().
	 *
	 * TR-06-3 Section 9 (interop): an Advanced device "shall start in Main
	 * Profile mode" and only switch to Advanced framing for a peer once that
	 * peer advertises Advanced capability (I=1 in its Main keep-alives, which
	 * sets remote_supports_advanced). Until then we emit Main-conformant
	 * media so a Main-only peer can decode it. */
	if (ctx->profile == RIST_PROFILE_ADVANCED &&
	    p->remote_supports_advanced &&
	    payload_type != RIST_PAYLOAD_TYPE_DATA_OOB &&
	    payload_type != RIST_PAYLOAD_TYPE_RTCP &&
	    payload_type != RIST_PAYLOAD_TYPE_RTCP_NACK) {
		uint8_t adv_buf[RIST_MAX_PACKET_SIZE + RIST_ADV_MAX_FIXED_HEADER];
		struct rist_adv_params params;
		memset(&params, 0, sizeof(params));

		params.seq = seq_rtp;
		params.timestamp = timestampRTP_u32(1, source_time);
		params.ssrc = rist_adv_ssrc_protected(ctx->adv_ssrc_base);
		params.enc_type = RIST_ADV_TYPE_DIRECT;
		params.psk_mode = RIST_ADV_PSK_NONE;
		params.lpc_mode = RIST_ADV_LPC_NONE;
		params.first_frag = true;
		params.last_frag = true;
		params.expedite = false;
		params.retransmit = retry;

		struct rist_adv_flow_id fid;
		if (dst_port || src_port) {
			fid.outer = htons(dst_port);
			fid.inner_hi = (uint8_t)((src_port >> 4) & 0xFF);
			fid.inner_lo_sub = (uint8_t)((src_port & 0x0F) << 4);
			params.flow_id = &fid;
		}

		uint8_t *wire_payload = payload;
		size_t wire_payload_len = payload_len;
		uint8_t lz4_buf[RIST_MAX_PACKET_SIZE];
		uint8_t enc_buf[RIST_MAX_PACKET_SIZE];
		uint8_t psk_iv_bytes[RIST_ADV_PSK_IV_SIZE];

		if (p->compression && payload_len > 0) {
			int bound = LZ4_compressBound((int)payload_len);
			if (bound > 0 && (size_t)bound <= sizeof(lz4_buf)) {
				int clen = LZ4_compress_default((const char *)payload,
					(char *)lz4_buf, (int)payload_len, (int)sizeof(lz4_buf));
				if (clen > 0 && (size_t)clen < payload_len) {
					wire_payload = lz4_buf;
					wire_payload_len = (size_t)clen;
					params.lpc_mode = RIST_ADV_LPC_LZ4;
				}
			}
		}

		if (p->key_tx.key_size > 0) {
			uint32_t seq_nbe = htobe32(seq_rtp);
			params.psk_mode = RIST_ADV_PSK_AES_CTR;
			uint8_t old_nonce[4];
			memcpy(old_nonce, p->key_tx.gre_nonce, 4);
			_librist_crypto_psk_encrypt(&p->key_tx, seq_nbe, 1,
			                            wire_payload, enc_buf, wire_payload_len);
			if (p->key_tx.csprng_failed) {
				rist_log_priv(ctx, RIST_LOG_ERROR,
					"Advanced Profile: PSK encrypt failed (CSPRNG)\n");
				return 0;
			}
			if (memcmp(old_nonce, p->key_tx.gre_nonce, 4) != 0)
				rist_adv_send_psk_nonce(p, p->key_tx.gre_nonce,
				                        (uint16_t)p->key_tx.key_size);
			wire_payload = enc_buf;
			params.psk_nonce = p->key_tx.gre_nonce;
			memcpy(psk_iv_bytes, &seq_nbe, sizeof(seq_nbe));
			params.psk_iv = psk_iv_bytes;
		}

		int total = rist_adv_build(adv_buf, &params, wire_payload, wire_payload_len);
		if (total < 0) {
			rist_log_priv(ctx, RIST_LOG_ERROR, "Advanced Profile: failed to build packet\n");
			return 0;
		}

		if (RIST_UNLIKELY((p->sender_ctx && p->sender_ctx->simulate_loss) ||
		                   (p->receiver_ctx && p->receiver_ctx->simulate_loss))) {
			uint16_t loss_percentage = p->sender_ctx ?
				p->sender_ctx->loss_percentage : p->receiver_ctx->loss_percentage;
			uint16_t compare = rand() % 1001;
			if (compare <= loss_percentage) {
				ret = total;
				goto adv_out;
			}
		}

		int retries_count = 0;
		int errorcode = 0;
		do {
			ret = rist_transport_sendto(p, adv_buf, (size_t)total, 0);
			if (RIST_UNLIKELY(ret < 0)) {
				errorcode = errno;
				retries_count++;
			} else {
				errorcode = 0;
				break;
			}
		} while (errorcode == EAGAIN && retries_count < RIST_MAX_SEND_RETRIES);

		if (RIST_UNLIKELY(ret < 0))
			_librist_log_send_error(p, errorcode, (size_t)total, "advanced-profile sendto");

adv_out:
		if (ret > 0) {
			p->stats_sender_instant.sent++;
			p->stats_sender_instant.sent_bytes += (uint64_t)ret;
			if (ts_null_bytes)
				p->stats_sender_instant.ts_null++;
			p->stats_receiver_instant.sent_rtcp++;
			rist_calculate_bitrate((size_t)ret, &p->bw);
			rist_calculate_bitrate(ts_null_bytes, &p->ts_nulls_bw);
		}
		return (size_t)ret;
	}

	// TODO: write directly on the payload to make it faster
	uint8_t header_buf[RIST_MAX_HEADER_SIZE] = {0};
	uint16_t proto_type;
	if (RIST_UNLIKELY(payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)) {
		proto_type = RIST_GRE_PROTOCOL_TYPE_FULL;
	} else {
		proto_type = RIST_GRE_PROTOCOL_TYPE_REDUCED;
		struct rist_protocol_hdr *hdr = (void *) (header_buf);
		hdr->src_port = htobe16(src_port);
		hdr->dst_port = htobe16(dst_port);
		if (payload_type == RIST_PAYLOAD_TYPE_RTCP || payload_type == RIST_PAYLOAD_TYPE_RTCP_NACK)
		{
			hdr_len = RIST_GRE_PROTOCOL_REDUCED_SIZE;
		}
		else
		{
			hdr_len = sizeof(*hdr);
			// RTP header for data packets
			hdr->rtp.flags = RTP_MPEGTS_FLAGS;
			if (payload_type == RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT)
				SET_BIT(hdr->rtp.flags, 4);
			hdr->rtp.ssrc = htobe32(p->adv_flow_id);
			hdr->rtp.seq = htobe16(seq_rtp);
			if (retry)
			{
				// This is a retransmission
				//rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\tResending: %"PRIu32"/%"PRIu16"/%"PRIu32"\n", seq, seq_rtp, ctx->seq);
				/* Mark SSRC for retransmission (change the last bit of the ssrc to 1) */
				//hdr->rtp.ssrc |= (1 << 31);
				hdr->rtp.ssrc = htobe32(p->adv_flow_id | 0x01);
			}
			hdr->rtp.payload_type = RTP_PTYPE_MPEGTS;
			hdr->rtp.ts = htobe32(timestampRTP_u32(0, source_time));
		}
		// copy the rtp header data (needed for encryption)
		memcpy(_payload - hdr_len, hdr, hdr_len);
	}

	if (RIST_UNLIKELY(payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)) {
		/* OOB uses GRE FULL protocol with no reduced/RTP header prepended,
		   so send the raw payload without the reduced-header offset */
		len = payload_len;
		data = _payload;
	} else {
		len =  hdr_len + payload_len - RIST_GRE_PROTOCOL_REDUCED_SIZE;
		data = _payload - hdr_len + RIST_GRE_PROTOCOL_REDUCED_SIZE;
	}


	// TODO: compare p->sender_ctx->sender_queue_read_index and p->sender_ctx->sender_queue_write_index
	// and warn when the difference is a multiple of 10 (slow CPU or overtaxed algorithm)
	// The difference should always stay very low < 10

	if (RIST_UNLIKELY((p->sender_ctx && p->sender_ctx->simulate_loss) || (p->receiver_ctx && p->receiver_ctx->simulate_loss))) {
		uint16_t loss_percentage = p->sender_ctx? p->sender_ctx->loss_percentage : p->receiver_ctx->loss_percentage;
		/* very crude calculation to see if we "randomly" drop packets, good enough for testing */
		uint16_t compare = rand() % 1001;
		if (compare <= loss_percentage) {
			ret = len;
			goto out;
		}
	}

	int retries = 0;
	int errorcode = 0;
	if (ctx->profile == RIST_PROFILE_SIMPLE) {
		// retry when kernel buffer is full instead of dropping packet (EAGAIN)
		do {
			ret = rist_transport_sendto(p, data, len, 0);
			if (RIST_UNLIKELY(ret < 0))
			{
				errorcode = errno;
				retries++;
			}
			else {
				errorcode = 0;
				break;
			}
		} while (errorcode == EAGAIN && retries < RIST_MAX_SEND_RETRIES);
		if (RIST_UNLIKELY(retries > (RIST_MAX_SEND_RETRIES / 5)))
			rist_log_priv(ctx, RIST_LOG_WARN, "UDP Pacing Send Succeded after retries=%d, ret=%d, socket=%d\n", retries, ret, p->sd);
		if (RIST_UNLIKELY(ret < 0))
			_librist_log_send_error(p, errorcode, len, "simple-profile sendto");
	}
	else
		ret = _librist_proto_gre_send_data(p, payload_type, proto_type, data, len, src_port, dst_port, p->rist_gre_version);

out:
	if (RIST_UNLIKELY(ret <= 0 && ctx->profile == RIST_PROFILE_SIMPLE && errorcode == 0)) {
		/* Generic safety net for ret == 0 or ret < 0 without errorcode
		 * captured (out-of-band failure paths). PMTU-aware send errors
		 * have already been logged above. */
		rist_log_priv(ctx, RIST_LOG_ERROR, "\tSend failed: errno=%d, ret=%d, socket=%d\n", errno, ret, p->sd);
	} else if (ret > 0) {
		p->stats_sender_instant.sent++;
		p->stats_sender_instant.sent_bytes += (uint64_t)ret;
		if (ts_null_bytes)
			p->stats_sender_instant.ts_null++;
		p->stats_receiver_instant.sent_rtcp++;
	}

	return ret;
}

/* This function is used by receiver for all and by sender only for rist-data and oob-data */
int rist_send_common_rtcp(struct rist_peer *p, uint8_t payload_type, uint8_t *payload, size_t payload_len, uint64_t source_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp, uint16_t ts_null_bytes)
{
	// This can only and will most likely be zero for data packets. RTCP should always have a value.
	assert(payload_type != RIST_PAYLOAD_TYPE_DATA_RAW && payload_type != RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT && payload_type != RIST_PAYLOAD_TYPE_DATA_OOB ? dst_port != 0 : 1);
	if (dst_port == 0)
		dst_port = p->config.virt_dst_port;
	if (src_port == 0)
		src_port = 32768 + p->adv_peer_id;

	struct rist_common_ctx *cctx = get_cctx(p);
	if (p->sd < 0 || !p->address_len) {
		rist_log_priv(cctx, RIST_LOG_ERROR, "rist_send_common_rtcp failed\n");
		return -1;
	}

	if (payload_type == RIST_PAYLOAD_TYPE_DATA_RAW || payload_type == RIST_PAYLOAD_TYPE_DATA_OOB)
	{
		if (cctx->oob_current_peer == NULL || cctx->oob_current_peer->dead)
			cctx->oob_current_peer = p;
	}

	if (RIST_UNLIKELY(p->config.timing_mode == RIST_TIMING_MODE_ARRIVAL) && !p->receiver_mode)
		source_time = timestampNTP_u64();

	size_t ret = rist_send_seq_rtcp(p, seq_rtp, payload_type, payload, payload_len, source_time, src_port, dst_port, false, ts_null_bytes);

	if ((!p->compression && ret < payload_len) || ret == (size_t)-1)
	{
		if (p->address_family == AF_INET6) {
			// TODO: print IP and port (and error number?)
			rist_log_priv(cctx, RIST_LOG_ERROR,
				"\tError on transmission sendto for seq #%"PRIu32"\n", seq_rtp);
		} else {
			struct sockaddr_in *sin4 = (struct sockaddr_in *)&p->u.address;
			unsigned char *ip = (unsigned char *)&sin4->sin_addr.s_addr;
			rist_log_priv(cctx, RIST_LOG_ERROR,
				"\tError on transmission sendto, ret=%d to %d.%d.%d.%d:%d/%d, seq #%"PRIu32", %d bytes\n",
					ret, ip[0], ip[1], ip[2], ip[3], htons(sin4->sin_port),
					p->local_port, seq_rtp, payload_len);
		}
	}
	else
	{
		/* Advanced-profile media is already bitrate-accounted in
		 * rist_send_seq_rtcp (it builds and sends before this shared
		 * path); counting it again here would double-count p->bw. */
		bool adv_media_accounted = (cctx->profile == RIST_PROFILE_ADVANCED &&
			p->remote_supports_advanced &&
			payload_type != RIST_PAYLOAD_TYPE_DATA_OOB &&
			payload_type != RIST_PAYLOAD_TYPE_RTCP &&
			payload_type != RIST_PAYLOAD_TYPE_RTCP_NACK);
		if (!adv_media_accounted) {
			// update bandwidth value
			rist_calculate_bitrate(ret, &p->bw);
			rist_calculate_bitrate(ts_null_bytes, &p->ts_nulls_bw);
		}
	}

	// TODO:
	// This should return something meaningful, however ret is always >= 0 by virtue of being unsigned.
	/*if (ret >= 0)
	 *	return 0;
	 * else
	 *	return -1;
	 */
	return 0;
}

int rist_set_url(struct rist_peer *peer)
{
	char host[512];
	uint16_t port = 0;
	int local;
	if (!peer->url) {
		if (peer->local_port > 0) {
			/* Put sender in IPv4 learning mode */
			peer->address_family = AF_INET;
			peer->address_len = sizeof(struct sockaddr_in);
			memset(&peer->u.address, 0, sizeof(struct sockaddr_in));
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
					"Sender: in learning mode\n");
		}
		return 1;
	}
	if (udpsocket_parse_url(peer->url, host, 512, &port, &local) != 0) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "%s / %s\n", strerror(errno), peer->url);
		return -1;
	} else {
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "URL parsed successfully: Host %s, Port %hu\n",
				(char *) host, port);
	}
	if (udpsocket_resolve_host(host, port, &peer->u.address) < 0) {
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Host %s cannot be resolved\n",
				(char *) host);
		return -1;
	}
	if (peer->u.inaddr6.sin6_family == AF_INET6) {
		peer->address_family = AF_INET6;
		peer->address_len = sizeof(struct sockaddr_in6);
	} else {
		peer->address_family = AF_INET;
		peer->address_len = sizeof(struct sockaddr_in);
	}
	if (local) {
		peer->listening = 1;
		peer->local_port = port;
	} else {
		peer->listening = 0;
		peer->remote_port = port;
	}
	if (peer->address_family == AF_INET) {
		peer->u.inaddr.sin_port = htons(port);
	} else {
		peer->u.inaddr6.sin6_port = htons(port);
	}
	return 0;
}

void rist_populate_cname(struct rist_peer *peer)
{
	int fd = peer->sd;
	char *identifier = peer->cname;
	struct rist_common_ctx *ctx = get_cctx(peer);
	if (strlen((char *)ctx->cname) != 0)
	{
		ctx->cname[RIST_MAX_HOSTNAME-1] = 0;
		strncpy(identifier, (char * )ctx->cname, RIST_MAX_HOSTNAME);
		return;
	}
	/* Set the CNAME Identifier as host@ip:port and fallback to hostname if needed */
	char hostname[RIST_MAX_HOSTNAME];
	struct sockaddr_storage peer_sockaddr;
	peer_sockaddr.ss_family = AF_UNSPEC;
	int name_length = 0;
	socklen_t peer_socklen = sizeof(peer_sockaddr);
	int ret_hostname = gethostname(hostname, RIST_MAX_HOSTNAME);
	if (ret_hostname == -1) {
		snprintf(hostname, RIST_MAX_HOSTNAME, "UnknownHost");
	}

	int ret_sockname = getsockname(fd, (struct sockaddr *)&peer_sockaddr, &peer_socklen);
	if (ret_sockname == 0)
	{
		struct sockaddr *xsa = (struct sockaddr *)&peer_sockaddr;
		// TODO: why is this returning non-sense?
		if (xsa->sa_family == AF_INET) {
			char addr[INET_ADDRSTRLEN] = {'\0'};
			struct sockaddr_in *xin = (struct sockaddr_in*)&peer_sockaddr;
			inet_ntop(AF_INET, &xin->sin_addr, addr, INET_ADDRSTRLEN);
			if (strcmp(addr, "0.0.0.0") != 0) {
				name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
										addr, ntohs(xin->sin_port));
				if (name_length >= RIST_MAX_HOSTNAME)
					identifier[RIST_MAX_HOSTNAME-1] = 0;
			}
		}/* else if (xsa->sa_family == AF_INET6) {
			struct sockaddr_in6 *xin6 = (void*)peer;
			char str[INET6_ADDRSTRLEN];
			inet_ntop(xin6->sin6_family, &xin6->sin6_addr, str, sizeof(struct in6_addr));
			name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s@%s:%u", hostname,
							str, ntohs(xin6->sin6_port));
			if (name_length >= RIST_MAX_HOSTNAME)
				identifier[RIST_MAX_HOSTNAME-1] = 0;
		}*/
	}

	if (name_length == 0)
	{
		name_length = snprintf(identifier, RIST_MAX_HOSTNAME, "%s", hostname);
		if (name_length >= RIST_MAX_HOSTNAME)
			identifier[RIST_MAX_HOSTNAME-1] = 0;
	}
}

void rist_create_socket(struct rist_peer *peer)
{
	if(!peer->address_family && rist_set_url(peer)) {
		return;
	}

	if (peer->listening) {
		const char* host;
		uint16_t port = 0;

		char buffer[256];
		if (peer->u.address.sa_family == AF_INET) {
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			host = inet_ntop(AF_INET, &(addrv4->sin_addr), buffer, sizeof(buffer));
			port = htons(addrv4->sin_port);
		} else {
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			host = inet_ntop(AF_INET6, &(addrv6->sin6_addr), buffer, sizeof(buffer));
			port = htons(addrv6->sin6_port);
		}
		if (!host) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "failed to convert address to string (errno=%d)", errno);
			return;
		}

		if (peer->u.address.sa_family == AF_INET)
		{
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			peer->multicast_receiver = IN_MULTICAST(ntohl(addrv4->sin_addr.s_addr));
		}
		else
		{
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			peer->multicast_receiver = IN6_IS_ADDR_MULTICAST(&addrv6->sin6_addr);
		}

		peer->sd = udpsocket_open_bind_mcast(host, port, peer->miface,
			peer->config.multicast_ttl, peer->config.multicast_source);
		if (peer->sd >= 0) {
			if (port == 0)
			{
				// Populate peer->local_port with ephemeral port assigned
				struct sockaddr_storage local_addr;
				socklen_t n = sizeof( struct sockaddr_storage );
				if( getsockname( peer->sd, (struct sockaddr *) &local_addr, &n ) != 0)
					rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Could not find assigned port (socket# %d)\n", peer->sd);
				else
				{
					if (local_addr.ss_family == AF_INET) {
						struct sockaddr_in *a = (struct sockaddr_in *)&local_addr;
						port = a->sin_port;
					} else {
						/* ipv6 */
						struct sockaddr_in6 *a = (struct sockaddr_in6 *)&local_addr;
						port = a->sin6_port;
					}
					peer->local_port = port;
				}
			}
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL listening mode (socket# %d)\n", peer->sd);
		} else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL listening mode. %s\n", strerror(errno));
		}

		// Set non-blocking only for receive sockets
		udpsocket_set_nonblocking(peer->sd);
	}
	else {
		if (peer->u.address.sa_family == AF_INET)
		{
			struct sockaddr_in *addrv4 = (struct sockaddr_in *)&(peer->u);
			peer->multicast_sender = IN_MULTICAST(ntohl(addrv4->sin_addr.s_addr));
		}
		else
		{
			struct sockaddr_in6 *addrv6 = (struct sockaddr_in6 *)&(peer->u);
			peer->multicast_sender = IN6_IS_ADDR_MULTICAST(&addrv6->sin6_addr);
		}
		if (peer->multicast_sender) {
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Peer configured for multicast\n");
		}
		// We use sendto ... so, no need to connect directly here
		peer->sd = udpsocket_open(peer->address_family);
		if (peer->sd >= 0)
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Starting in URL connect mode (%d)\n", peer->sd);
		else {
			rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not start in URL connect mode. %s\n", strerror(errno));
		}
		if (peer->miface[0] != '\0') {
			struct sockaddr_storage ss = {0};
			rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Binding socket to %s\n", peer->miface);
			if (inet_pton(AF_INET, peer->miface,  &((struct sockaddr_in *)&ss)->sin_addr) != 0) {
				((struct sockaddr_in *)&ss)->sin_family = AF_INET;
				((struct sockaddr_in *)&ss)->sin_port = htons(peer->config.local_port);
				if (bind(peer->sd, (struct sockaddr*)&ss, sizeof(struct sockaddr_in)) != 0) {
#ifdef _WIN32
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s:%u: WSAGetLastError=%d\n", peer->miface, peer->config.local_port, WSAGetLastError());
#else
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s:%u: %s\n", peer->miface, peer->config.local_port, strerror(errno));
#endif
				}
			}
			else if (inet_pton(AF_INET6, peer->miface, &((struct sockaddr_in6 *)&ss)->sin6_addr) != 0) {
				((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
				((struct sockaddr_in6 *)&ss)->sin6_port = htons(peer->config.local_port);
				if (bind(peer->sd, (struct sockaddr*)&ss, sizeof(struct sockaddr_in6)) != 0) {
#ifdef _WIN32
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s:%u: WSAGetLastError=%d\n", peer->miface, peer->config.local_port, WSAGetLastError());
#else
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s:%u: %s\n", peer->miface, peer->config.local_port, strerror(errno));
#endif
				}
			}
#ifdef __linux__
			else {
				struct ifreq ifr = {0};
				memcpy(ifr.ifr_name, peer->miface, IF_NAMESIZE);
				if (setsockopt(peer->sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) != 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
				}
			}
#elif defined(__APPLE__)
			else {
				int idx = if_nametoindex(peer->miface);
				if (idx == 0) {
					rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't get device %s index: %s\n", peer->miface, strerror(errno));
				} else {
					int proto = peer->u.address.sa_family == AF_INET? IPPROTO_IP : IPPROTO_IPV6;
					int bound = peer->u.address.sa_family == AF_INET? IP_BOUND_IF : IPV6_BOUND_IF;
					if (setsockopt(peer->sd, proto, bound, &idx, sizeof(idx)) != 0) {
						rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Couldn't bind to %s: %s\n", peer->miface, strerror(errno));
					}
				}
			}
#else
			else {
				rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "No method available to bind to %s please supply an IP to bind to\n", peer->miface);
			}
#endif
		} else if (peer->config.local_port > 0) {
			struct sockaddr_storage ss = {0};
			if (peer->address_family == AF_INET6) {
				((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
				((struct sockaddr_in6 *)&ss)->sin6_port = htons(peer->config.local_port);
				((struct sockaddr_in6 *)&ss)->sin6_addr = in6addr_any;
			} else {
				((struct sockaddr_in *)&ss)->sin_family = AF_INET;
				((struct sockaddr_in *)&ss)->sin_port = htons(peer->config.local_port);
				((struct sockaddr_in *)&ss)->sin_addr.s_addr = INADDR_ANY;
			}
			socklen_t ss_len = peer->address_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
			if (bind(peer->sd, (struct sockaddr *)&ss, ss_len) != 0) {
#ifdef _WIN32
				rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Couldn't bind to local port %u: WSAGetLastError=%d\n", peer->config.local_port, WSAGetLastError());
#else
				rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Couldn't bind to local port %u: %s\n", peer->config.local_port, strerror(errno));
#endif
			} else {
				rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Bound caller socket to local port %u\n", peer->config.local_port);
			}
		}
		if (peer->multicast_sender && peer->config.multicast_ttl > 0)
			udpsocket_set_mcast_ttl(peer->sd, peer->address_family, peer->config.multicast_ttl);
		udpsocket_set_dontfragment(peer->sd, peer->address_family);
		if (peer->config.local_port > 0)
			peer->local_port = peer->config.local_port;
		else
			peer->local_port = 32768 + (get_cctx(peer)->peer_counter % 28232);
#ifdef _WIN32
		udpsocket_set_nonblocking(peer->sd);
#endif
	}

	// Increase default OS udp receive buffer size
	if (udpsocket_set_optimal_buffer_size(peer->sd)) {
		rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Unable to set the socket receive buffer size to %d Bytes. %s\n",
			UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
	} else {
		uint32_t current_recvbuf = udpsocket_get_buffer_size(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Configured the starting socket receive buffer size to %d Bytes.\n",
			current_recvbuf);
	}
	// Increase default OS udp send buffer size
	if (udpsocket_set_optimal_buffer_send_size(peer->sd)) {
		rist_log_priv(get_cctx(peer), RIST_LOG_WARN, "Unable to set the socket send buffer size to %d Bytes. %s\n",
			UDPSOCKET_SOCK_BUFSIZE, strerror(errno));
	} else {
		uint32_t current_sendbuf = udpsocket_get_buffer_send_size(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Configured the starting socket send buffer size to %d Bytes.\n",
			current_sendbuf);
	}

	if (peer->cname[0] == 0)
		rist_populate_cname(peer);
	rist_log_priv(get_cctx(peer), RIST_LOG_INFO, "Peer cname is %s\n", peer->cname);
#ifndef _WIN32
	if (fcntl(peer->sd, F_SETFD, FD_CLOEXEC) == -1) {
		udpsocket_close(peer->sd);
		rist_log_priv(get_cctx(peer), RIST_LOG_ERROR, "Could not set close-on-exec\n");
		peer->sd = -1;
	}
#endif
}

int rist_receiver_periodic_rtcp(struct rist_peer *peer) {
	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_rr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (peer->echo_enabled == false)
		rist_rtcp_write_xr_echoreq(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0, 0);
}

static int rist_receiver_send_nacks_advanced(struct rist_peer *peer, uint32_t seq_array[], size_t array_len)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint32_t media_ssrc = rist_adv_ssrc_protected(ctx->adv_ssrc_base);

	if (peer->receiver_ctx->nack_type == RIST_NACK_BITMASK) {
		uint32_t pss = seq_array[0];
		uint32_t blp = 0;
		for (size_t i = 1; i < array_len; i++) {
			uint32_t offset = seq_array[i] - pss;
			if (offset >= 1 && offset <= 32) {
				blp |= (1u << (offset - 1));
			} else {
				rist_adv_send_nack_bitmask(peer, media_ssrc, pss, blp);
				pss = seq_array[i];
				blp = 0;
			}
		}
		rist_adv_send_nack_bitmask(peer, media_ssrc, pss, blp);
	} else {
		uint32_t pss = seq_array[0];
		uint32_t nalp = 0;
		for (size_t i = 1; i < array_len; i++) {
			if (seq_array[i] == pss + nalp + 1) {
				nalp++;
			} else {
				rist_adv_send_nack_range(peer, media_ssrc, pss, nalp);
				pss = seq_array[i];
				nalp = 0;
			}
		}
		rist_adv_send_nack_range(peer, media_ssrc, pss, nalp);
	}
	return 0;
}

int rist_receiver_send_nacks(struct rist_peer *peer, uint32_t seq_array[], size_t array_len)
{
	if (get_cctx(peer)->debug && array_len > 0)
		rist_log_priv(get_cctx(peer), RIST_LOG_DEBUG, "Sending %zu nacks starting with %"PRIu32"\n",
		array_len, seq_array[0]);

	if (get_cctx(peer)->profile == RIST_PROFILE_ADVANCED &&
	    peer->is_advanced && peer->remote_supports_advanced &&
	    array_len > 0) {
		return rist_receiver_send_nacks_advanced(peer, seq_array, array_len);
	}

	uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;

	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (RIST_LIKELY(array_len > 0)) {
		struct rist_rtp_nack_record *rec;
		uint32_t fci_count = 1;

		if (peer->receiver_ctx->nack_type == RIST_NACK_BITMASK)
		{
			struct rist_rtcp_nack_bitmask *rtcp = (struct rist_rtcp_nack_bitmask *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len);
			rtcp->flags = RTCP_NACK_BITMASK_FLAGS;
			rtcp->ptype = PTYPE_NACK_BITMASK;
			rtcp->ssrc_source = 0; // TODO
			rtcp->ssrc = htobe32(peer->adv_flow_id);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + RTCP_FB_HEADER_SIZE);
			uint32_t last_seq, tmp_seq;
			tmp_seq = last_seq = seq_array[0];
			uint32_t boundary = tmp_seq +16;
			rec->start = htons((uint16_t)tmp_seq);
			uint16_t extra = 0;
			for (size_t i = 1; i < array_len; i++)
			{
				tmp_seq = seq_array[i];
				if (last_seq < tmp_seq && tmp_seq <= boundary) {
					uint32_t bitnum = tmp_seq - last_seq;
					SET_BIT(extra, (bitnum -1));
				} else {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					extra = 0;
					rec->start = htons((uint16_t)tmp_seq);
					last_seq = tmp_seq;
					boundary = tmp_seq + 16;
				}
			}
			rec->extra = htons(extra);
			rtcp->len = htons((uint16_t)(2 + fci_count));
		}
		else // PTYPE_NACK_CUSTOM
		{
			struct rist_rtcp_nack_range *rtcp = (struct rist_rtcp_nack_range *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len);
			rtcp->flags = RTCP_NACK_RANGE_FLAGS;
			rtcp->ptype = PTYPE_NACK_CUSTOM;
			rtcp->ssrc_source = htobe32(peer->adv_flow_id);
			memcpy(rtcp->name, "RIST", 4);
			rec = (struct rist_rtp_nack_record *)(rtcp_buf + RIST_MAX_PAYLOAD_OFFSET + payload_len + RTCP_FB_HEADER_SIZE);
			uint16_t tmp_seq = (uint16_t)seq_array[0];
			uint16_t last_seq = tmp_seq;
			rec->start = htons(tmp_seq);
			uint16_t extra = 0;
			for (size_t i = 1; i < array_len; i++)
			{
				tmp_seq = (uint16_t)seq_array[i];
				if (RIST_UNLIKELY(extra == UINT16_MAX)) {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					rec->start = htons(tmp_seq);
					extra = 0;
				} else if (tmp_seq == last_seq +1) {
					extra++;
				} else {
					rec->extra = htons(extra);
					rec++;
					fci_count++;
					rec->start = htons(tmp_seq);
					extra = 0;
				}
				last_seq = tmp_seq;
			}
			rec->extra = htons(extra);
			rtcp->len = htons((uint16_t)(2 + fci_count));
		}
		int nack_bufsize = RTCP_FB_HEADER_SIZE + RTCP_FB_FCI_GENERIC_NACK_SIZE * fci_count;
		payload_len += nack_bufsize;
		payload_type = RIST_PAYLOAD_TYPE_RTCP_NACK;
	}

	// We use direct send from receiver to sender (no fifo to keep track of seq/idx)
	return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0, 0);
}

static void rist_sender_send_rtcp(uint8_t *rtcp_buf, int payload_len, struct rist_peer *peer) {
	rist_send_common_rtcp(peer, RIST_PAYLOAD_TYPE_RTCP, rtcp_buf, payload_len, 0, peer->local_port, peer->remote_port, 0, 0);
}

void rist_sender_periodic_rtcp(struct rist_peer *peer) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;

	rist_rtcp_write_sr(rtcp_buf, &payload_len, peer);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	if (peer->echo_enabled)
		rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	// Push it to the FIFO buffer to be sent ASAP (even in the simple profile case)
	rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
	return;
}

int rist_respond_echoreq(struct rist_peer *peer, const uint64_t echo_request_time, uint32_t ssrc) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoresp(rtcp_buf, &payload_len, echo_request_time, ssrc);
	if (peer->receiver_mode) {
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0, 0);
	} else {
		/* I do this to not break advanced mode, however echo responses should really NOT be resend when lost ymmv */
		rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
		return 0;
	}
}

int rist_request_echo(struct rist_peer *peer) {
	uint8_t *rtcp_buf = get_cctx(peer)->buf.rtcp;
	int payload_len = 0;
	rist_rtcp_write_empty_rr(rtcp_buf, &payload_len, peer->adv_flow_id);
	rist_rtcp_write_sdes(rtcp_buf, &payload_len, peer->cname, peer->adv_flow_id);
	rist_rtcp_write_echoreq(rtcp_buf, &payload_len, peer->peer_ssrc);
	if (peer->receiver_mode)
	{
		uint8_t payload_type = RIST_PAYLOAD_TYPE_RTCP;
		return rist_send_common_rtcp(peer, payload_type, &rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, 0, peer->local_port, peer->remote_port, 0, 0);
	}
	else
	{
		rist_sender_send_rtcp(&rtcp_buf[RIST_MAX_PAYLOAD_OFFSET], payload_len, peer);
		return 0;
	}
}

int rist_sender_enqueue(struct rist_sender *ctx, const void *data, size_t len, uint64_t datagram_time, uint16_t src_port, uint16_t dst_port, uint32_t seq_rtp)
{
	uint8_t payload_type = RIST_PAYLOAD_TYPE_DATA_RAW;
	const void * payload = data;
	if (ctx->common.PEERS == NULL) {
		// Do not cache data if the lib user has not added peers
		return -1;
	}

	/* insert into sender fifo queue */

	pthread_mutex_lock(&ctx->queue_lock);
	size_t sender_write_index = atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire);
	if (RIST_UNLIKELY(ctx->sender_queue_size >= ctx->sender_queue_max - 1)) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\nSender queue is full (size=%zu max=%zu), dropping packet, decrease bitrate, buffer time length or increase packet size\n",
				ctx->sender_queue_size,
				ctx->sender_queue_max);
		// Another solution is to increase the size of RIST_SERVER_QUEUE_BUFFERS at compile time
		pthread_mutex_unlock(&ctx->queue_lock);
		return -2;
	}

	ctx->last_datagram_time = datagram_time;
	/* Worst-case write into payload_out is (count - 1) * 204 = 6 * 204 = 1224
	 * bytes (if exactly one of the seven 204-byte packets is suppressed),
	 * sitting after the 8-byte rist_rtp_hdr_ext at offset 0. The previous
	 * sizing of 6 * 204 + 4 was 4 bytes short and let suppress_null_packets
	 * smash four bytes of stack past tmp_buf. */
	uint8_t tmp_buf[7 * 204 + sizeof(struct rist_rtp_hdr_ext)];
	int ts_null_bytes = 0;
	if (ctx->null_packet_suppression && len <= 7 * 204)
	{

		struct rist_rtp_hdr_ext *hdr_ext = (struct rist_rtp_hdr_ext *)&tmp_buf;
		memset(tmp_buf, 0, sizeof(*hdr_ext));//hdr_ext
		ts_null_bytes = suppress_null_packets(data, &tmp_buf[sizeof(*hdr_ext)], &len, hdr_ext);
		if (ts_null_bytes > 0)
		{
			memcpy(&hdr_ext->identifier, "RI", 2);
			hdr_ext->length = htobe16(1);
			len += sizeof(*hdr_ext);
			payload = tmp_buf;
			payload_type = RIST_PAYLOAD_TYPE_DATA_RAW_RTP_EXT;
		}
	}

	ctx->sender_queue[sender_write_index] = rist_new_buffer(&ctx->common, payload, len, payload_type, 0, datagram_time, src_port, dst_port);
	if (RIST_UNLIKELY(!ctx->sender_queue[sender_write_index])) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "\t Could not create packet buffer inside sender buffer, OOM\n");
		pthread_mutex_unlock(&ctx->queue_lock);
		return -3;
	}
	ctx->sender_queue[sender_write_index]->seq_rtp = (uint16_t)seq_rtp;
	ctx->sender_queue[sender_write_index]->ts_null_bytes = (uint16_t)ts_null_bytes;
	ctx->sender_queue_bytesize += len;
	ctx->sender_queue_size++;
	atomic_store_explicit(&ctx->sender_queue_write_index, (sender_write_index + 1) & (ctx->sender_queue_max - 1), memory_order_release);
	pthread_mutex_unlock(&ctx->queue_lock);

	return 0;
}

/* Share this leg should take in the weighted payload rotation. Normally the
 * configured weight, but a leg that just rejoined after an RTT mute ramps back
 * linearly over the rejoin dwell: it drained while muted, so it measures well
 * until it carries again, and handing back the full share at once simply
 * refills the queue and mutes it a second later. */
static uint32_t rist_peer_effective_weight(const struct rist_peer *peer, uint64_t now)
{
	/* Ramp over the rejoin dwell, which is twice the drop dwell. */
	return rist_rtt_ramped_weight(peer->config.weight, peer->rtt_ramp_start,
				      (uint64_t)peer->config.rtt_drop_settle * RIST_CLOCK * 2,
				      now);
}

void rist_sender_send_data_balanced(struct rist_sender *ctx, struct rist_buffer *buffer)
{
	struct rist_peer *peer;
	struct rist_peer *selected_peer_by_weight = NULL;
	struct rist_peer *fallback = NULL;
	uint64_t fallback_rtt = UINT64_MAX;
	uint32_t max_remainder = 0;
	int peercnt;
	bool looped = false;

	//We can do it safely here, since this function is only to be called once per packet
	buffer->seq = ctx->common.seq++;
	uint32_t wire_seq = (ctx->common.profile == RIST_PROFILE_ADVANCED) ? buffer->seq : (uint32_t)buffer->seq_rtp;
	uint64_t now = timestampNTP_u64();

peer_select:

	peercnt = 0;
	for (peer = ctx->common.PEERS; peer; peer = peer->next) {

		if (!peer->is_data || peer->parent)
			continue;
#if HAVE_SRP_SUPPORT
		if (!peer->listening && !peer->multicast_sender && !eap_is_authenticated(peer->eap_ctx))
			continue;
#endif
		bool hard_dead = !rist_peer_may_send(peer->dead, peer->dead_since,
						     peer->recovery_buffer_ticks, now);
		if ((!peer->listening && !peer->authenticated) || hard_dead
			|| (peer->listening && !peer->child_alive_count)) {
			ctx->weight_counter -= peer->config.weight;
			if (ctx->weight_counter <= 0) {
				ctx->weight_counter = ctx->total_weight;
			}
			peer->w_count = rist_peer_effective_weight(peer, now);
			continue;
		}

		/* RTT-muted leg: skipped in the unique-payload rotation. With
		 * ?rtt-drop-trickle=N, still send a deduped duplicate every Nth packet
		 * so RTT keeps sampling for a warm restore without stalling the buffer.
		 * A stalled (briefly silent) leg is skipped too but never trickled: its
		 * return path is down, so RTCP/keepalive alone probes for recovery.
		 * The trickle also stops once the leg is queued deeper than the buffer,
		 * where it can only deliver unusable packets; RTCP keeps measuring RTT,
		 * and with nothing queued behind them those measurements get honest. */
		if (peer->rtt_muted || peer->stalled) {
			if (peer->rtt_muted && peer->config.rtt_drop_trickle > 0 && !looped && !peer->dead
				&& rist_rtt_trickle_useful(peer->eight_times_rtt / 8,
							   (uint64_t)peer->config.recovery_length_max * RIST_CLOCK)) {
				if (++peer->rtt_trickle_counter >= peer->config.rtt_drop_trickle) {
					peer->rtt_trickle_counter = 0;
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
				}
			}
			ctx->weight_counter -= peer->config.weight;
			if (ctx->weight_counter <= 0) {
				ctx->weight_counter = ctx->total_weight;
			}
			peer->w_count = rist_peer_effective_weight(peer, now);
			/* Remember the best skipped leg for the safety net below: a
			 * muted (late but deliverable) leg beats a stalled one (return
			 * path down); lowest RTT breaks ties. */
			if (!peer->dead) {
				uint64_t s = peer->eight_times_rtt ? peer->eight_times_rtt / 8 : UINT64_MAX;
				if (!fallback
				    || (fallback->stalled && !peer->stalled)
				    || (fallback->stalled == peer->stalled && s < fallback_rtt)) {
					fallback = peer;
					fallback_rtt = s;
				}
			}
			continue;
		}
		peercnt++;

		/*************************************/
		/* * * * * * * * * * * * * * * * * * */
		/** Heuristics for sender goes here **/
		/* * * * * * * * * * * * * * * * * * */
		/*************************************/

		if (peer->config.weight == RIST_PEER_WEIGHT_DUPLICATE && !looped) {
			if (peer->listening) {
				struct rist_peer *child = peer->child;
				while (child) {
#if HAVE_SRP_SUPPORT
					if (!eap_is_authenticated(child->eap_ctx))
					{
						//do nothing
					} else
#endif
					if (child->authenticated && child->is_data && rist_peer_may_send(child->dead, child->dead_since, peer->recovery_buffer_ticks, now)) {
						uint8_t *payload = buffer->data;
						rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
					}
					child = child->sibling_next;
				}
			} else {
				/* Eligibility already decided by hard_dead above. */
				uint8_t *payload = buffer->data;
				rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
			}
		} else {
			/* Election of next peer */
			// printf("peer election: considering %p, count=%d (wc: %d)\n",
			// peer, peer->w_count, ctx->weight_counter);
			if (peer->w_count > max_remainder) {
				max_remainder = peer->w_count;
				selected_peer_by_weight = peer;
			}
		}
	}
	looped = true;
	if (selected_peer_by_weight) {
		peer = selected_peer_by_weight;
		if (peer->listening) {
			struct rist_peer *child = peer->child;
			while (child) {
#if HAVE_SRP_SUPPORT
					if (!eap_is_authenticated(child->eap_ctx))
					{
						//do nothing
					} else
#endif
				if (child->authenticated && child->is_data && rist_peer_may_send(child->dead, child->dead_since, peer->recovery_buffer_ticks, now)) {
					uint8_t *payload = buffer->data;
					rist_send_common_rtcp(child, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
				}
				child = child->sibling_next;
			}
		} else {
			/* Eligibility already decided by hard_dead above. */
			uint8_t *payload = buffer->data;
			rist_send_common_rtcp(peer, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
		}
		ctx->weight_counter--;
		peer->w_count--;
	}

	if (ctx->total_weight > 0 && (ctx->weight_counter == 0 || !selected_peer_by_weight)) {
		peer = ctx->common.PEERS;
		ctx->weight_counter = ctx->total_weight;
		for (; peer; peer = peer->next) {
			peer->w_count = rist_peer_effective_weight(peer, now);
		}
		if (!looped && !selected_peer_by_weight && peercnt > 0)
			goto peer_select;
	}

	/* Safety net: every eligible leg was rtt-muted or stalled, so nothing
	 * carried this packet. The mute and stall guards run independently and
	 * can jointly leave no carrier; never silently drop a live packet when a
	 * usable leg exists. Egress on the best skipped leg. */
	if (peercnt == 0 && !selected_peer_by_weight && fallback) {
		uint8_t *payload = buffer->data;
		rist_send_common_rtcp(fallback, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, buffer->src_port, buffer->dst_port, wire_seq, buffer->ts_null_bytes);
	}
}

static size_t rist_sender_index_get(struct rist_sender *ctx, uint32_t seq,
				     const struct rist_peer *target)
{
	if (ctx->common.profile == RIST_PROFILE_ADVANCED) {
		/* A peer that negotiated down to Main NACKs in the 16-bit RTP
		 * sequence domain (nack_seq_msb = 0), which never matches the
		 * 32-bit advanced seq_index. Serve its retransmits from the
		 * parallel RTP index. Advanced-negotiated peers keep the 32-bit
		 * path, so the production Advanced<->Advanced lookup is unchanged. */
		if (ctx->seq_rtp_index && target &&
		    rist_retx_use_rtp_domain(ctx->common.profile, target->remote_supports_advanced))
			return ctx->seq_rtp_index[(uint16_t)seq];
		return ctx->seq_index[seq & (ctx->sender_queue_max - 1)];
	}
	return ctx->seq_index[(uint16_t)seq];
}

size_t rist_get_sender_retry_queue_size(struct rist_sender *ctx)
{
	size_t retry_queue_size = (ctx->sender_retry_queue_write_index - ctx->sender_retry_queue_read_index)
							& (ctx->sender_retry_queue_size - 1);
	return retry_queue_size;
}

/* Pick the lowest-RTT healthy bonded sibling in the same sequence domain to
 * egress a retransmit when the NACK's own leg is RTT-muted or stalled (its
 * latency/silence would make the recovery packet arrive too late). Returns the
 * original leg if none qualifies. Caller holds peerlist_lock. */
static struct rist_peer *rist_retx_healthy_egress(struct rist_sender *ctx,
						  struct rist_peer *muted)
{
	uint64_t now = timestampNTP_u64();
	struct rist_peer *best = NULL;
	uint64_t best_rtt = UINT64_MAX;
	for (struct rist_peer *peer = ctx->common.PEERS; peer; peer = peer->next) {
		if (!peer->is_data || peer->parent || peer->listening)
			continue;
		if (peer->rtt_muted || peer->stalled || !peer->authenticated)
			continue;
		if (!rist_peer_may_send(peer->dead, peer->dead_since, peer->recovery_buffer_ticks, now))
			continue;
		struct rist_peer *egress = peer->peer_data ? peer->peer_data : peer;
		if (egress->remote_supports_advanced != muted->remote_supports_advanced)
			continue;
		uint64_t rtt = egress->eight_times_rtt ? egress->eight_times_rtt : UINT64_MAX;
		if (rtt < best_rtt) {
			best_rtt = rtt;
			best = egress;
		}
	}
	return best ? best : muted;
}

/* This function must return, 0 when there is nothing to send, < 0 on error and > 0 for bytes sent */
ssize_t rist_retry_dequeue(struct rist_sender *ctx)
{
	size_t sender_retry_queue_read_index = (ctx->sender_retry_queue_read_index + 1)& (ctx->sender_retry_queue_size -1);

	if (sender_retry_queue_read_index == ctx->sender_retry_queue_write_index) {
		return 0;
	}

	ctx->sender_retry_queue_read_index = sender_retry_queue_read_index;
	struct rist_retry *retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_read_index];

	/* The peer this retry belongs to may have been destroyed while this
	 * entry was sitting in the queue. rist_peer_remove() scrubs the slot
	 * to NULL under peerlist_lock, and we are called with peerlist_lock
	 * held, so seeing NULL here simply means the retry is stale; drop
	 * it and let the caller move on to the next entry (returning 0 would
	 * abort sender_send_nacks() and starve legitimate retries queued
	 * behind this one). */
	if (RIST_UNLIKELY(!retry->peer)) {
		retry->active = false;
		return -1;
	}

	/* The peer that will actually receive this retransmission. Its
	 * negotiated profile (remote_supports_advanced) decides both the
	 * retransmit framing (rist_send_seq_rtcp) and, for an Advanced sender,
	 * which sequence domain to resolve the request in. */
	struct rist_peer *idx_target = retry->peer->peer_data ? retry->peer->peer_data : retry->peer;
	bool main_domain_retx = rist_retx_use_rtp_domain(ctx->common.profile,
							 idx_target->remote_supports_advanced);

	/* Redirect off a muted/stalled leg to a healthy sibling (unchanged when
	 * none qualifies, so no behaviour change unless a leg was pulled). */
	struct rist_peer *egress = idx_target;
	if (idx_target->rtt_muted || idx_target->stalled)
		egress = rist_retx_healthy_egress(ctx, idx_target);

	// If they request a non-sense seq number, we will catch it when we check the seq number against
	// the one on that buffer position and it does not match

	size_t idx = rist_sender_index_get(ctx, retry->seq, idx_target);
	if (RIST_UNLIKELY(ctx->sender_queue[idx] == NULL)) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			" Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), consider increasing the buffer size\n",
			retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx));
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	} else if (RIST_UNLIKELY(
		(ctx->common.profile == RIST_PROFILE_ADVANCED && !main_domain_retx)
			? (retry->seq != ctx->sender_queue[idx]->seq)
			: ((uint16_t)retry->seq != ctx->sender_queue[idx]->seq_rtp))) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			" Couldn't find block %" PRIu32 " (i=%zu/r=%zu/w=%zu/d=%zu/rs=%zu), found an old one instead %" PRIu32 " (%" PRIu64 "), bitrate is too high\n",
			retry->seq, idx, atomic_load_explicit(&ctx->sender_queue_read_index, memory_order_acquire), atomic_load_explicit(&ctx->sender_queue_write_index, memory_order_acquire), ctx->sender_queue_delete_index,
			rist_get_sender_retry_queue_size(ctx), ctx->sender_queue[idx]->seq, ctx->sender_queue_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}
	/* we're consuming the retry for an existing buffer, set it to false to allow new retries to come in */
	ctx->sender_queue[idx]->retry_queued = false;
	retry->active = false;

	// TODO: re-enable rist_send_data_allowed (cooldown feature)

	struct rist_bandwidth_estimation *retry_bw = &retry->peer->retry_bw;
	struct rist_bandwidth_estimation *cli_bw = &retry->peer->bw;
	if (retry->peer->peer_data)
	{
		retry_bw = &retry->peer->peer_data->retry_bw;
	}
	// update bandwidth values
	rist_calculate_bitrate(0, cli_bw);
	rist_calculate_bitrate(0, retry_bw);

	// Make sure we do not flood the network with retries
	size_t current_bitrate = 0;
	size_t data_bitrate = 0;
	size_t retry_bitrate = 0;
	if (retry->peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
		data_bitrate = cli_bw->eight_times_bitrate_fast / 8;
		retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	} else if (retry->peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_NORMAL) {
		data_bitrate = cli_bw->eight_times_bitrate / 8;
		retry_bitrate = retry_bw->eight_times_bitrate_fast / 8;
	} else {
		data_bitrate = cli_bw->eight_times_bitrate / 8;
		retry_bitrate = retry_bw->eight_times_bitrate / 8;
	}
	current_bitrate =  data_bitrate + retry_bitrate;
	size_t max_bitrate = retry->peer->config.recovery_maxbitrate * 1000;
	if (current_bitrate > max_bitrate) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG, "Max bandwidth exceeded: (%zu + %zu) > %zu, not resending packet %"PRIu64".\n",
			data_bitrate, retry_bitrate, max_bitrate, idx);
		retry->peer->stats_sender_instant.bandwidth_skip++;
		return -2;
	}

	// Check buffer element age
	uint64_t now = timestampNTP_u64();
	/* queue_time holds the original insertion time for this seq */
	uint64_t data_age = (now - ctx->sender_queue[idx]->time) / RIST_CLOCK;
	uint64_t retry_age = (now - retry->insert_time) / RIST_CLOCK;
	if (RIST_UNLIKELY(retry_age > retry->peer->config.recovery_length_max)) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Retry-request of element %" PRIu32 " (idx %zu) that was sent %" PRIu64
				"ms ago has been in the queue too long to matter: %"PRIu64"ms > %ums\n",
			retry->seq, idx, data_age, retry_age, retry->peer->config.recovery_length_max);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	struct rist_buffer *buffer = ctx->sender_queue[idx];
	if (ctx->common.debug)
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Resending %"PRIu32"/%"PRIu32"/%"PRIu16" (idx %zu) after %" PRIu64
			"ms of first transmission and %"PRIu64"ms in queue, bitrate is %zu + %zu, %zu\n",
			retry->seq, buffer->seq, buffer->seq_rtp, idx, data_age, retry_age, data_bitrate,
			retry_bitrate, current_bitrate);

	uint8_t *payload = buffer->data;

	size_t ret = 0;
	if (buffer->transmit_count >= retry->peer->config.max_retries) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR, "Datagram %"PRIu32
			" is missing, but nack count is too large (%u), age is %"PRIu64"ms, retry #%lu\n",
			retry->seq, buffer->transmit_count, data_age, buffer->transmit_count);
			retry->peer->stats_sender_instant.retrans_skip++;
			return -1;
	}

	uint16_t src_port = buffer->src_port;
	if (src_port == 0)
		src_port = 32768 + egress->adv_peer_id;
	uint32_t retry_wire_seq = (ctx->common.profile == RIST_PROFILE_ADVANCED && !main_domain_retx) ? buffer->seq : (uint32_t)buffer->seq_rtp;
	ret = rist_send_seq_rtcp(egress, retry_wire_seq, buffer->type, &payload[RIST_MAX_PAYLOAD_OFFSET], buffer->size, buffer->source_time, src_port, (egress->config.virt_dst_port & ~1UL), true, ctx->sender_queue[idx]->ts_null_bytes);
	// update bandwidth value
	rist_calculate_bitrate(ret, retry_bw);

	if ((ret == (size_t)-1) || (!egress->compression && ret < buffer->size)) {
		rist_log_priv(&ctx->common, RIST_LOG_ERROR,
			"Resending of packet failed %zu != %zu for seq %"PRIu32"\n", ret, buffer->size, retry->seq);
		retry->peer->stats_sender_instant.retrans_skip++;
		return -1;
	}

	buffer->transmit_count++;
	egress->stats_sender_instant.retrans++;
	egress->stats_sender_instant.retransmitted_bytes += (uint64_t)ret;
	return ret;
}

void rist_retry_enqueue(struct rist_sender *ctx, uint32_t seq, struct rist_peer *peer)
{
	uint64_t now = timestampNTP_u64();
	struct rist_peer *idx_target = peer ? (peer->peer_data ? peer->peer_data : peer) : NULL;
	size_t idx = rist_sender_index_get(ctx, seq, idx_target);
	struct rist_buffer *buffer = ctx->sender_queue[idx];
	struct rist_retry *retry;

	// Even though all the checks are on the dequeue function, we leave one here
	// to prevent the flooding of our fifo .. It is based on the date of the
	// last queued item with the same seq for this peer.
	// The policy of whether to allow or not allow duplicate inactive seq entries in the retry queue
	// is dependent on the bloat_mode.
	// No duplicate unhandled (i.e.: still queued) retries are accepted.
	// bloat_mode disabled mode = unlimited duplicates
	// bloat_mode normal mode = we enforce rtt spacing and allow duplicates
	// bloat_mode aggressive mode = we enforce 2*rtt spacing and allow duplicates
	// This is a safety check to protect against buggy or non compliant receivers that request the
	// same seq number without waiting one RTT.

	if (peer->config.recovery_mode == RIST_RECOVERY_MODE_DISABLED) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Nack request for seq %"PRIu32" but nack processing is disabled for this peer\n", seq);
			peer->stats_sender_instant.retrans_skip++;
		return;
	}
	else if (!buffer) {
		rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
			"Nack request for seq %"PRIu32" but we do not have it in the buffer (%zu ms)\n", seq,
			ctx->sender_recover_min_time);
			peer->stats_sender_instant.retrans_skip++;
		return;
	} else {
		uint64_t age_ticks =  (now - buffer->time);
		if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_OFF) {
			// All duplicates allowed, just report it
			if (ctx->common.debug)
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Nack request for seq %" PRIu32 " with age %" PRIu64 "ms and rtt_min %" PRIu64 " for peer #%d\n",
					seq, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK, peer->adv_peer_id);
		} else if (ctx->peer_lst_len == 1) {
			/* there is a retry outstanding for this buffer, no need to add another */
			if (buffer->retry_queued)
				return;
			// Only one peer (faster algorithm with no lookups)
			if (buffer->last_retry_request != 0)
			{
				// This is a safety check to protect against buggy or non compliant receivers that request the
				// same seq number without waiting one RTT.
				uint64_t delta = (now - buffer->last_retry_request);
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms, age %" PRIu64 "ms and rtt_min %" PRIu64 "\n",
						seq, delta /RIST_CLOCK, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK);
				uint64_t rtt = peer->last_rtt;
				if (peer->config.recovery_rtt_min > rtt)
					rtt = peer->config.recovery_rtt_min;
				if (peer->config.recovery_rtt_max < rtt)
					rtt = peer->config.recovery_rtt_max;
				if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE) {
					// Aggressive congestion control only allows every two RTTs
					rtt = rtt * 2;
				}
				if (delta < rtt)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 ", age %"PRIu64"ms, is already queued (too soon to add another one), skipped, %" PRIu64 " < %" PRIu64 " ms\n",
						seq, age_ticks / RIST_CLOCK, delta / RIST_CLOCK, rtt);
					peer->stats_sender_instant.bloat_skip++;
					return;
				}
				buffer->retry_queued = true;
			}
			else
			{
				if (ctx->common.debug)
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"First nack request for seq %"PRIu32", age %"PRIu64"ms\n", seq, age_ticks / RIST_CLOCK);
			}
		} else {
			// Multiple peers, we need to search for other retries in the queue for comparison
			uint64_t delta = 0;
			//We work backwards from the write index till we either find a retry with same peer & seq
			//or it's too old to matter,looking up to 8 RTT's ago (4 in normal mode, 8 in aggressive)
			size_t index = (ctx->sender_retry_queue_write_index -1) & (ctx->sender_retry_queue_size -1);
			uint64_t rtt = peer->last_rtt;
			if (peer->config.recovery_length_min > rtt)
				rtt = peer->config.recovery_length_min;
			// Aggressive congestion control only allows every two RTTs
			if (peer->config.congestion_control_mode == RIST_CONGESTION_CONTROL_MODE_AGGRESSIVE)
				rtt *= 2;
			struct rist_retry *lookup = NULL;
			uint64_t search_period = rtt * 4;
			while (index != ctx->sender_retry_queue_write_index) {
				lookup = &ctx->sender_retry_queue[index];
				if (lookup->seq == seq && lookup->peer == peer)
					break;
				if (lookup->insert_time < (now - search_period))
					break;
				index = (index -1 ) & (ctx->sender_retry_queue_size -1);
			}
			retry = &ctx->sender_retry_queue[index];
			if (retry->seq == seq && retry->peer == peer) {
				delta = (now - retry->insert_time);
				/* this retry hasn't been handled yet, it makes no sense to insert a duplicate */
				if (retry->active)
					return;
				if (delta < rtt)
				{
					rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
						"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) is already queued (too soon to add another one), skipped, peer #%d '%s'\n",
						seq, delta / RIST_CLOCK, age_ticks / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
					peer->stats_sender_instant.bloat_skip++;
					return;
				}
			}
			if (ctx->common.debug) {
				rist_log_priv(&ctx->common, RIST_LOG_DEBUG,
					"Nack request for seq %" PRIu32 " with delta %" PRIu64 "ms (age %"PRIu64"ms) and rtt_min %" PRIu64 " for peer #%"PRIu32" '%s'\n",
					seq, delta / RIST_CLOCK, age_ticks / RIST_CLOCK, peer->config.recovery_rtt_min / RIST_CLOCK, peer->adv_peer_id, peer->receiver_name);
			}
		}
	}
	// Now insert into the missing queue
	buffer->last_retry_request = now;
	retry = &ctx->sender_retry_queue[ctx->sender_retry_queue_write_index];
	retry->seq = seq;
	retry->peer = peer;
	retry->insert_time = now;
	retry->active = true;
	if (++ctx->sender_retry_queue_write_index >= ctx->sender_retry_queue_size) {
		ctx->sender_retry_queue_write_index = 0;
	}
}

void rist_print_inet_info(char *prefix, struct rist_peer *peer)
{
	char ipstr[INET6_ADDRSTRLEN];
	uint32_t port;
	// deal with both IPv4 and IPv6:
	struct sockaddr_in6 *s = (struct sockaddr_in6 *) &peer->u.address;
	inet_ntop(peer->address_family, &s->sin6_addr, ipstr, sizeof ipstr);
	if (peer->address_family == AF_INET6) {
		port = ntohs(s->sin6_port);
	} else {
		struct sockaddr_in *addr = (void *) &peer->u.address;
		port = ntohs(addr->sin_port);
	}

	struct rist_common_ctx *ctx = get_cctx(peer);
	if (ctx->profile == RIST_PROFILE_SIMPLE)
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"%sPeer Information, IP:Port => %s:%u (%d), id: %"PRIu32", simple profile\n",
			prefix, ipstr, port, peer->listening, peer->adv_peer_id);
	}
	else
	{
		rist_log_priv(get_cctx(peer), RIST_LOG_INFO,
			"%sPeer Information, IP:Port => %s:%u (%d), id: %"PRIu32", ports: %u->%u\n",
			prefix, ipstr, port, peer->listening, peer->adv_peer_id,
			peer->local_port, peer->remote_port);
	}

}

