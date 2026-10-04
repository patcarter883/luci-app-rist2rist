/*
 * Copyright © 2024-2026 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * VSF TR-06-3:2024 — RIST Advanced Profile control message
 * serialization and deserialization.
 */

#include "proto/adv.h"
#include "rist-private.h"
#include "udp-private.h"
#include "transport-private.h"
#include "log-private.h"
#include "proto/rist_time.h"
#include "crypto/psk.h"
#include "cjson/cJSON.h"
#include <string.h>
#include <errno.h>

/* --------------------------------------------------------------------------
 * All Advanced Profile control messages are sent as:
 *   Type = 4 (Control), E = 1 (Expedite), F = L = 1 (unfragmented),
 *   PSK = 0 (no encryption for now), LPC = 0 (no compression).
 *
 * The payload of a Type 4 packet is:
 *   | Control Index (16 bits) | Length (16 bits) |
 *   |       ... body per CI ...                  |
 * -------------------------------------------------------------------------- */

/* Build the outer Advanced Profile packet for a control message.
 * ctrl_payload: serialized control body (CI + Length + data)
 * ctrl_len: length of ctrl_payload
 * Returns total packet length written into buf, or -1 on error. */
static int rist_adv_build_control(uint8_t *buf, uint32_t seq, uint32_t timestamp,
                                  uint32_t ssrc, const uint8_t *ctrl_payload,
                                  size_t ctrl_len)
{
	struct rist_adv_params params;
	memset(&params, 0, sizeof(params));
	params.seq = seq;
	params.timestamp = timestamp;
	params.ssrc = ssrc;
	params.enc_type = RIST_ADV_TYPE_CONTROL;
	params.psk_mode = RIST_ADV_PSK_NONE;
	params.lpc_mode = RIST_ADV_LPC_NONE;
	params.first_frag = true;
	params.last_frag = true;
	params.expedite = true;
	params.retransmit = false;

	return rist_adv_build(buf, &params, ctrl_payload, ctrl_len);
}

/* --------------------------------------------------------------------------
 * NACK Bitmask (CI=0x0000, Section 5.3.2)
 *
 * Body (repeatable 12-byte entries):
 *   | SSRC of Media Source (32) |
 *   | PSS — Packet Start Seq (32) |
 *   | BLP — Bitmask of Lost Packets (32) |
 * -------------------------------------------------------------------------- */

int rist_adv_send_nack_bitmask(struct rist_peer *peer,
                               uint32_t media_ssrc,
                               uint32_t pss, uint32_t blp)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 12]; /* CI(2) + Len(2) + one 12-byte entry */
	size_t off = 0;

	/* Control header */
	ctrl[off++] = (RIST_ADV_CI_NACK_BITMASK >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_NACK_BITMASK & 0xFF;
	uint16_t body_len = 12;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	/* SSRC of media source */
	ctrl[off++] = (media_ssrc >> 24) & 0xFF;
	ctrl[off++] = (media_ssrc >> 16) & 0xFF;
	ctrl[off++] = (media_ssrc >> 8) & 0xFF;
	ctrl[off++] = media_ssrc & 0xFF;

	/* PSS */
	ctrl[off++] = (pss >> 24) & 0xFF;
	ctrl[off++] = (pss >> 16) & 0xFF;
	ctrl[off++] = (pss >> 8) & 0xFF;
	ctrl[off++] = pss & 0xFF;

	/* BLP */
	ctrl[off++] = (blp >> 24) & 0xFF;
	ctrl[off++] = (blp >> 16) & 0xFF;
	ctrl[off++] = (blp >> 8) & 0xFF;
	ctrl[off++] = blp & 0xFF;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint32_t ts = (uint32_t)((timestampNTP_u64() * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-nack-bitmask sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * NACK Range (CI=0x0001, Section 5.3.3)
 *
 * Body (repeatable 12-byte entries):
 *   | SSRC of Media Source (32) |
 *   | PSS — Packet Start Seq (32) |
 *   | NALP — Number of Additional Lost Packets (32) |
 * -------------------------------------------------------------------------- */

int rist_adv_send_nack_range(struct rist_peer *peer,
                             uint32_t media_ssrc,
                             uint32_t pss, uint32_t nalp)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 12];
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_NACK_RANGE >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_NACK_RANGE & 0xFF;
	uint16_t body_len = 12;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	ctrl[off++] = (media_ssrc >> 24) & 0xFF;
	ctrl[off++] = (media_ssrc >> 16) & 0xFF;
	ctrl[off++] = (media_ssrc >> 8) & 0xFF;
	ctrl[off++] = media_ssrc & 0xFF;

	ctrl[off++] = (pss >> 24) & 0xFF;
	ctrl[off++] = (pss >> 16) & 0xFF;
	ctrl[off++] = (pss >> 8) & 0xFF;
	ctrl[off++] = pss & 0xFF;

	ctrl[off++] = (nalp >> 24) & 0xFF;
	ctrl[off++] = (nalp >> 16) & 0xFF;
	ctrl[off++] = (nalp >> 8) & 0xFF;
	ctrl[off++] = nalp & 0xFF;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint32_t ts = (uint32_t)((timestampNTP_u64() * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-nack-range sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * RTT Echo Request (CI=0x0010, Section 5.3.4)
 *
 * Body:
 *   | Requester SSRC (32) |
 *   | Timestamp MSW (32)  |
 *   | Timestamp LSW (32)  |
 *   | Processing Delay (32, microseconds) |
 *   | Padding (n * 32 bits) |
 * -------------------------------------------------------------------------- */

int rist_adv_send_rtt_echo_request(struct rist_peer *peer)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 16]; /* CI(2) + Len(2) + 4 words */
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_RTT_ECHO_REQ >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_RTT_ECHO_REQ & 0xFF;
	uint16_t body_len = 16;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	uint32_t req_ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);
	ctrl[off++] = (req_ssrc >> 24) & 0xFF;
	ctrl[off++] = (req_ssrc >> 16) & 0xFF;
	ctrl[off++] = (req_ssrc >> 8) & 0xFF;
	ctrl[off++] = req_ssrc & 0xFF;

	uint64_t ntp = timestampNTP_u64();
	uint32_t msw = (uint32_t)(ntp >> 32);
	uint32_t lsw = (uint32_t)(ntp & 0xFFFFFFFF);

	ctrl[off++] = (msw >> 24) & 0xFF;
	ctrl[off++] = (msw >> 16) & 0xFF;
	ctrl[off++] = (msw >> 8) & 0xFF;
	ctrl[off++] = msw & 0xFF;

	ctrl[off++] = (lsw >> 24) & 0xFF;
	ctrl[off++] = (lsw >> 16) & 0xFF;
	ctrl[off++] = (lsw >> 8) & 0xFF;
	ctrl[off++] = lsw & 0xFF;

	/* Processing delay = 0 for request */
	ctrl[off++] = 0; ctrl[off++] = 0; ctrl[off++] = 0; ctrl[off++] = 0;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);

	int total = rist_adv_build_control(pkt, seq, ts, req_ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-rtt-echo-req sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * RTT Echo Response (CI=0x0011, Section 5.3.4)
 *
 * Mirror the request body, fill in processing delay.
 * -------------------------------------------------------------------------- */

int rist_adv_send_rtt_echo_response(struct rist_peer *peer,
                                    uint32_t requester_ssrc,
                                    uint32_t orig_msw, uint32_t orig_lsw,
                                    uint32_t processing_delay_us)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 16];
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_RTT_ECHO_RESP >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_RTT_ECHO_RESP & 0xFF;
	uint16_t body_len = 16;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	ctrl[off++] = (requester_ssrc >> 24) & 0xFF;
	ctrl[off++] = (requester_ssrc >> 16) & 0xFF;
	ctrl[off++] = (requester_ssrc >> 8) & 0xFF;
	ctrl[off++] = requester_ssrc & 0xFF;

	ctrl[off++] = (orig_msw >> 24) & 0xFF;
	ctrl[off++] = (orig_msw >> 16) & 0xFF;
	ctrl[off++] = (orig_msw >> 8) & 0xFF;
	ctrl[off++] = orig_msw & 0xFF;

	ctrl[off++] = (orig_lsw >> 24) & 0xFF;
	ctrl[off++] = (orig_lsw >> 16) & 0xFF;
	ctrl[off++] = (orig_lsw >> 8) & 0xFF;
	ctrl[off++] = orig_lsw & 0xFF;

	ctrl[off++] = (processing_delay_us >> 24) & 0xFF;
	ctrl[off++] = (processing_delay_us >> 16) & 0xFF;
	ctrl[off++] = (processing_delay_us >> 8) & 0xFF;
	ctrl[off++] = processing_delay_us & 0xFF;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint64_t ntp = timestampNTP_u64();
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-rtt-echo-resp sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * Keep-Alive (CI=0x8000, Section 5.3.6)
 *
 * Wraps Main Profile keep-alive format with additional capability bits:
 *   C (bit 29): Compression capable
 *   G (bit 30): GRE key rotation capable
 *   I (bit 31): Advanced Profile capable
 *
 * For now we send a minimal keep-alive with the I bit set.
 * -------------------------------------------------------------------------- */

#define RIST_ADV_KEEPALIVE_CAP_I  (1u << 31)
#define RIST_ADV_KEEPALIVE_CAP_G  (1u << 30)
#define RIST_ADV_KEEPALIVE_CAP_C  (1u << 29)

int rist_adv_send_keepalive(struct rist_peer *peer)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];

	/*
	 * Keep-alive body layout (Section 5.3.6):
	 *   | MAC Address (6 bytes) |
	 *   | Capabilities (4 bytes, with C/G/I bits) |
	 *   | JSON (optional, variable) |
	 *
	 * We encode it as CI(2) + Len(2) + MAC(6) + Capabilities(4) = 14 body bytes
	 */
	uint8_t ctrl[4 + 6 + 4];
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_KEEPALIVE >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_KEEPALIVE & 0xFF;
	uint16_t body_len = 10; /* MAC(6) + Capabilities(4) */
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	/* MAC address from the peer struct */
	memcpy(&ctrl[off], peer->mac_addr, 6);
	off += 6;

	/* Capabilities with I bit set to signal Advanced Profile support */
	uint32_t caps = RIST_ADV_KEEPALIVE_CAP_I;
	ctrl[off++] = (caps >> 24) & 0xFF;
	ctrl[off++] = (caps >> 16) & 0xFF;
	ctrl[off++] = (caps >> 8) & 0xFF;
	ctrl[off++] = caps & 0xFF;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint64_t ntp = timestampNTP_u64();
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-keepalive sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * Control Message Unsupported Response (CI=0x8020, Section 5.3.10)
 *
 * Body:
 *   | Responder SSRC (32) |
 *   | Incoming CI (16) | Reserved (16) |
 *   | First 48 bits of incoming payload (48) | Padding (16) |
 * -------------------------------------------------------------------------- */

int rist_adv_send_unsupported(struct rist_peer *peer,
                              uint16_t incoming_ci,
                              const uint8_t *incoming_payload,
                              size_t incoming_len)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 16];
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_UNSUPPORTED >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_UNSUPPORTED & 0xFF;
	uint16_t body_len = 12;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	uint32_t resp_ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);
	ctrl[off++] = (resp_ssrc >> 24) & 0xFF;
	ctrl[off++] = (resp_ssrc >> 16) & 0xFF;
	ctrl[off++] = (resp_ssrc >> 8) & 0xFF;
	ctrl[off++] = resp_ssrc & 0xFF;

	ctrl[off++] = (incoming_ci >> 8) & 0xFF;
	ctrl[off++] = incoming_ci & 0xFF;
	ctrl[off++] = 0; /* Reserved */
	ctrl[off++] = 0;

	/* Copy first 6 bytes (48 bits) of incoming payload, or pad with zeros */
	size_t copy_len = incoming_len < 6 ? incoming_len : 6;
	if (incoming_payload && copy_len > 0)
		memcpy(&ctrl[off], incoming_payload, copy_len);
	if (copy_len < 6)
		memset(&ctrl[off + copy_len], 0, 6 - copy_len);
	off += 6;
	/* Padding to 32-bit boundary */
	ctrl[off++] = 0;
	ctrl[off++] = 0;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint64_t ntp = timestampNTP_u64();
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);

	int total = rist_adv_build_control(pkt, seq, ts, resp_ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-unsupported sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * Type 8 — GRE-over-Advanced Profile (Section 5.2, Type=8)
 *
 * Wraps a complete Main Profile GRE packet inside an Advanced Profile
 * envelope.  The receiver strips the AP header and falls through to
 * normal GRE processing.  This enables rist2rist relay/bridge devices
 * and is used during Section 9 transition.
 * -------------------------------------------------------------------------- */

int rist_adv_send_type8(struct rist_peer *peer,
                        const uint8_t *gre_packet, size_t gre_len)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE + RIST_ADV_MAX_FIXED_HEADER];

	if (gre_len > RIST_MAX_PACKET_SIZE)
		return -1;

	struct rist_adv_params params;
	memset(&params, 0, sizeof(params));
	params.seq = ctx->adv_seq_unprotected++;
	params.timestamp = (uint32_t)((timestampNTP_u64() * 1000000ULL) >> 16);
	params.ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);
	params.enc_type = RIST_ADV_TYPE_GRE_MAIN;
	params.psk_mode = RIST_ADV_PSK_NONE;
	params.lpc_mode = RIST_ADV_LPC_NONE;
	params.first_frag = true;
	params.last_frag = true;
	params.expedite = true;
	params.retransmit = false;

	int total = rist_adv_build(pkt, &params, gre_packet, gre_len);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-type8 sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * PSK Future Nonce Announcement (CI=0x8011, Section 5.3.9)
 *
 * Body:
 *   | Future Nonce (4 bytes) |
 *   | Key Size (2 bytes) | Reserved (2 bytes) |
 *
 * Sent by the sender before rotating to a new nonce so the receiver
 * can pre-derive the AES key (PBKDF2 is expensive) before the first
 * data packet with the new nonce arrives.
 * -------------------------------------------------------------------------- */

int rist_adv_send_psk_nonce(struct rist_peer *peer,
                            const uint8_t nonce[4], uint16_t key_size_bits)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];
	uint8_t ctrl[4 + 8]; /* CI(2) + Len(2) + Nonce(4) + KeySize(2) + Rsvd(2) */
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_PSK_NONCE >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_PSK_NONCE & 0xFF;
	uint16_t body_len = 8;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	memcpy(&ctrl[off], nonce, 4);
	off += 4;

	ctrl[off++] = (key_size_bits >> 8) & 0xFF;
	ctrl[off++] = key_size_bits & 0xFF;
	ctrl[off++] = 0; /* Reserved */
	ctrl[off++] = 0;

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint64_t ntp = timestampNTP_u64();
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-psk-nonce sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * Flow Attribute (CI=0x8001, Section 5.3.7)
 *
 * Body: JSON object describing session and flow metadata.
 * Sent periodically by the sender (~1 Hz).
 *
 * Minimal JSON schema:
 *   { "session": "<cname>",
 *     "flow_id": <outer>, "flow_inner": <inner>,
 *     "virt_dst_port": <port>, "profile": "advanced" }
 * -------------------------------------------------------------------------- */

int rist_adv_send_flow_attr(struct rist_peer *peer)
{
	struct rist_common_ctx *ctx = get_cctx(peer);
	uint8_t pkt[RIST_MAX_PACKET_SIZE];

	cJSON *root = cJSON_CreateObject();
	if (!root)
		return -1;

	cJSON_AddStringToObject(root, "session", peer->cname);
	cJSON_AddNumberToObject(root, "virt_dst_port", peer->config.virt_dst_port);
	cJSON_AddStringToObject(root, "profile", "advanced");

	uint16_t outer = peer->config.virt_dst_port;
	uint16_t inner = 0;
	cJSON_AddNumberToObject(root, "flow_id", outer);
	cJSON_AddNumberToObject(root, "flow_inner", inner);

	char *json = cJSON_PrintUnformatted(root);
	cJSON_Delete(root);
	if (!json)
		return -1;

	size_t json_len = strlen(json);
	if (json_len > RIST_MAX_PACKET_SIZE - RIST_ADV_MAX_FIXED_HEADER - 4) {
		free(json);
		return -1;
	}

	uint8_t ctrl[4 + RIST_MAX_PACKET_SIZE];
	size_t off = 0;

	ctrl[off++] = (RIST_ADV_CI_FLOW_ATTR >> 8) & 0xFF;
	ctrl[off++] = RIST_ADV_CI_FLOW_ATTR & 0xFF;
	uint16_t body_len = (uint16_t)json_len;
	ctrl[off++] = (body_len >> 8) & 0xFF;
	ctrl[off++] = body_len & 0xFF;

	memcpy(&ctrl[off], json, json_len);
	off += json_len;
	free(json);

	uint32_t seq = ctx->adv_seq_unprotected++;
	uint64_t ntp = timestampNTP_u64();
	uint32_t ts = (uint32_t)((ntp * 1000000ULL) >> 16);
	uint32_t ssrc = rist_adv_ssrc_unprotected(ctx->adv_ssrc_base);

	int total = rist_adv_build_control(pkt, seq, ts, ssrc, ctrl, off);
	if (total < 0)
		return -1;

	ssize_t ret = rist_transport_sendto(peer, pkt, (size_t)total, 0);
	if (ret < 0)
		_librist_log_send_error(peer, errno, (size_t)total, "adv-flow-attr sendto");

	return (ret > 0) ? 0 : -1;
}

/* --------------------------------------------------------------------------
 * Control message receive dispatcher
 *
 * Called from the Advanced Profile receive path when enc_type == CONTROL.
 * Returns 0 on success, -1 on error/unknown CI.
 * -------------------------------------------------------------------------- */

int rist_adv_recv_control(struct rist_peer *peer,
                          const uint8_t *ctrl_payload,
                          size_t ctrl_len)
{
	struct rist_common_ctx *ctx = get_cctx(peer);

	if (ctrl_len < RIST_ADV_CTRL_HDR_SIZE)
		return -1;

	uint16_t ci = (uint16_t)((ctrl_payload[0] << 8) | ctrl_payload[1]);
	uint16_t body_len = (uint16_t)((ctrl_payload[2] << 8) | ctrl_payload[3]);

	if ((size_t)4 + body_len > ctrl_len)
		return -1;

	const uint8_t *body = ctrl_payload + 4;

	switch (ci) {
	case RIST_ADV_CI_NACK_BITMASK: {
		if (body_len < 12)
			return -1;
		uint32_t media_ssrc = (uint32_t)body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3];
		uint32_t pss = (uint32_t)body[4] << 24 | body[5] << 16 | body[6] << 8 | body[7];
		uint32_t blp = (uint32_t)body[8] << 24 | body[9] << 16 | body[10] << 8 | body[11];
		(void)media_ssrc;
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced NACK Bitmask received: PSS=%u BLP=0x%08x\n", pss, blp);

		/* Enqueue retransmissions for pss and each bit set in blp */
		if (peer->sender_ctx) {
			struct rist_sender *sender = peer->sender_ctx;
			rist_retry_enqueue(sender, pss, peer);
			for (int i = 0; i < 32; i++) {
				if (blp & (1u << i))
					rist_retry_enqueue(sender, pss + 1 + (uint32_t)i, peer);
			}
		}
		return 0;
	}

	case RIST_ADV_CI_NACK_RANGE: {
		if (body_len < 12)
			return -1;
		uint32_t media_ssrc = (uint32_t)body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3];
		uint32_t pss = (uint32_t)body[4] << 24 | body[5] << 16 | body[6] << 8 | body[7];
		uint32_t nalp = (uint32_t)body[8] << 24 | body[9] << 16 | body[10] << 8 | body[11];
		(void)media_ssrc;
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced NACK Range received: PSS=%u NALP=%u\n", pss, nalp);

		if (peer->sender_ctx) {
			struct rist_sender *sender = peer->sender_ctx;
			for (uint32_t i = 0; i <= nalp && i < 10000; i++)
				rist_retry_enqueue(sender, pss + i, peer);
		}
		return 0;
	}

	case RIST_ADV_CI_RTT_ECHO_REQ: {
		if (body_len < 16)
			return -1;
		uint32_t req_ssrc = (uint32_t)body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3];
		uint32_t orig_msw = (uint32_t)body[4] << 24 | body[5] << 16 | body[6] << 8 | body[7];
		uint32_t orig_lsw = (uint32_t)body[8] << 24 | body[9] << 16 | body[10] << 8 | body[11];
		/* processing_delay in the request is always 0 */
		rist_log_priv(ctx, RIST_LOG_DEBUG, "Advanced RTT Echo Request from SSRC %u\n", req_ssrc);
		return rist_adv_send_rtt_echo_response(peer, req_ssrc, orig_msw, orig_lsw, 0);
	}

	case RIST_ADV_CI_RTT_ECHO_RESP: {
		if (body_len < 16)
			return -1;
		uint32_t req_ssrc = (uint32_t)body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3];
		uint32_t orig_msw = (uint32_t)body[4] << 24 | body[5] << 16 | body[6] << 8 | body[7];
		uint32_t orig_lsw = (uint32_t)body[8] << 24 | body[9] << 16 | body[10] << 8 | body[11];
		uint32_t proc_delay = (uint32_t)body[12] << 24 | body[13] << 16 | body[14] << 8 | body[15];
		(void)req_ssrc;

		uint64_t orig_ntp = ((uint64_t)orig_msw << 32) | orig_lsw;
		uint64_t now = timestampNTP_u64();
		uint64_t rtt_ntp = now - orig_ntp;
		/* Convert NTP ticks to microseconds: rtt_us = rtt_ntp * 1e6 / 2^16 */
		uint64_t rtt_us = (rtt_ntp * 1000000) >> 16;
		rtt_us -= proc_delay;
		peer->last_rtt = rtt_us;
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced RTT Echo Response: RTT=%"PRIu64" us\n", rtt_us);
		return 0;
	}

	case RIST_ADV_CI_KEEPALIVE: {
		if (body_len < 10)
			return -1;
		/* Parse capabilities to detect I bit */
		uint32_t caps = (uint32_t)body[6] << 24 | body[7] << 16 | body[8] << 8 | body[9];
		peer->remote_supports_advanced = !!(caps & RIST_ADV_KEEPALIVE_CAP_I);
		peer->last_pkt_received = timestampNTP_u64();
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced Keep-Alive: caps=0x%08x (I=%d)\n",
			caps, peer->remote_supports_advanced);
		return 0;
	}

	case RIST_ADV_CI_FLOW_ATTR: {
		if (body_len == 0)
			return 0;
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced Flow Attribute received (%u bytes)\n", body_len);
		if (peer->receiver_ctx) {
			struct rist_receiver *rcv = peer->receiver_ctx;
			if (rcv->receiver_flow_attr_callback) {
				char json_buf[RIST_MAX_PACKET_SIZE];
				size_t copy_len = body_len < sizeof(json_buf) - 1 ? body_len : sizeof(json_buf) - 1;
				memcpy(json_buf, body, copy_len);
				json_buf[copy_len] = '\0';
				rcv->receiver_flow_attr_callback(
					rcv->receiver_flow_attr_callback_argument,
					peer, json_buf, copy_len);
			}
		}
		return 0;
	}

	case RIST_ADV_CI_PSK_NONCE: {
		if (body_len < 8)
			return -1;
		uint8_t future_nonce[4];
		memcpy(future_nonce, body, 4);
		uint16_t key_bits = (uint16_t)((body[4] << 8) | body[5]);

		bool odd = CHECK_BIT(future_nonce[0], 7);
		struct rist_key *ak = odd ? &peer->key_rx_odd : &peer->key_rx;
		if (ak->password_len > 0) {
			pthread_mutex_lock(&peer->peer_lock);
			_librist_crypto_psk_preannounce_nonce(ak, future_nonce, key_bits);
			pthread_mutex_unlock(&peer->peer_lock);
		}

		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Advanced PSK Future Nonce: nonce=0x%02x%02x%02x%02x key_bits=%u\n",
			future_nonce[0], future_nonce[1], future_nonce[2], future_nonce[3],
			key_bits);
		return 0;
	}

	case RIST_ADV_CI_UNSUPPORTED: {
		if (body_len < 8)
			return -1;
		uint16_t unsup_ci = (uint16_t)((body[4] << 8) | body[5]);
		rist_log_priv(ctx, RIST_LOG_WARN,
			"Remote does not support control message CI=0x%04x\n", unsup_ci);
		return 0;
	}

	default:
		rist_log_priv(ctx, RIST_LOG_DEBUG,
			"Unknown Advanced Profile control CI=0x%04x, sending unsupported response\n", ci);
		rist_adv_send_unsupported(peer, ci, body, body_len);
		return -1;
	}
}
