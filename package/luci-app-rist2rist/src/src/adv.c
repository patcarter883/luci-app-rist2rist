/*
 * Copyright © 2019-2020 SipRadius LLC
 * Copyright © 2024-2026 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * VSF TR-06-3:2024 — RIST Advanced Profile packet parser and builder.
 */

#include "proto/adv.h"
#include <string.h>

size_t rist_adv_header_size(const struct rist_adv_params *params)
{
	size_t sz = RIST_ADV_HEADER_MIN; /* RTP (12) + ext (4) */

	if (params->flow_id)
		sz += RIST_ADV_FLOW_ID_SIZE;

	sz += rist_adv_psk_hdr_size(params->psk_mode);

	if (params->lpc_mode == RIST_ADV_LPC_FIELD_PRESENT && params->compression)
		sz += RIST_ADV_COMPRESSION_SIZE;

	if (params->pfd)
		sz += RIST_ADV_PFD_SIZE;

	if (params->hdr_ext && params->hdr_ext_len > 0)
		sz += params->hdr_ext_len;

	return sz;
}

int rist_adv_parse(const uint8_t *buf, size_t len,
                   struct rist_adv_parsed *out)
{
	if (!buf || !out || len < RIST_ADV_HEADER_MIN)
		return -1;

	memset(out, 0, sizeof(*out));

	const struct rist_rtp_hdr *rtp = (const struct rist_rtp_hdr *)buf;

	/* Validate RTP: V=2 */
	if ((rtp->flags & 0xC0) != 0x80)
		return -1;

	/* PT must be 127 (or a dynamic PT >= 96 if SDP is in use) */
	uint8_t pt = rtp->payload_type & 0x7F;
	if (pt != RIST_ADV_PT && pt < 96)
		return -1;

	out->rtp_padding = !!(rtp->flags & 0x20);
	out->rtp_ext_present = !!(rtp->flags & 0x10);

	/* CC must be 0 per spec */
	uint8_t cc = rtp->flags & 0x0F;

	out->timestamp = ntohl(rtp->ts);
	out->ssrc = ntohl(rtp->ssrc);

	size_t offset = sizeof(struct rist_rtp_hdr); /* 12 */

	/* Skip CSRC entries (should be 0, but be safe) */
	offset += (size_t)cc * 4;
	if (offset > len)
		return -1;

	/* Skip RFC 3550 RTP Header Extension if X=1 (line 4 of Figure 1) */
	if (out->rtp_ext_present) {
		if (offset + 4 > len)
			return -1;
		uint16_t ext_len_words = ntohs(*(const uint16_t *)(buf + offset + 2));
		offset += 4 + (size_t)ext_len_words * 4;
		if (offset > len)
			return -1;
	}

	/* Profile-defined extension (line 5 of Figure 1) */
	if (offset + RIST_ADV_EXT_SIZE > len)
		return -1;

	const struct rist_adv_ext *ext =
		(const struct rist_adv_ext *)(buf + offset);
	offset += RIST_ADV_EXT_SIZE;

	out->seq = rist_adv_seq32(rtp, ext);
	out->first_frag  = !!(ext->flags & RIST_ADV_FLAG_F);
	out->last_frag   = !!(ext->flags & RIST_ADV_FLAG_L);
	out->expedite    = !!(ext->flags & RIST_ADV_FLAG_E);
	out->retransmit  = !!(ext->flags & RIST_ADV_FLAG_R);
	out->has_flow_id = !!(ext->flags & RIST_ADV_FLAG_I);
	out->has_pfd     = !!(ext->flags & RIST_ADV_FLAG_P);
	out->has_hdr_ext = !!(ext->flags & RIST_ADV_FLAG_H);

	out->psk_mode = rist_adv_get_psk(ext);
	out->lpc_mode = rist_adv_get_lpc(ext);
	out->enc_type = rist_adv_get_type(ext);

	out->has_psk = (out->psk_mode > 0);
	out->has_compression = (out->lpc_mode == RIST_ADV_LPC_FIELD_PRESENT);

	/* Optional fields must be consumed in order per spec:
	 *   Flow ID, PSK Hash, PSK Nonce, PSK IV,
	 *   Compression, PFD, RIST Header Extension */

	/* Flow ID (4 bytes, if I=1) */
	if (out->has_flow_id) {
		if (offset + RIST_ADV_FLOW_ID_SIZE > len)
			return -1;
		out->flow_id = (const struct rist_adv_flow_id *)(buf + offset);
		offset += RIST_ADV_FLOW_ID_SIZE;
	}

	/* PSK fields (variable, per Table 1) */
	if (rist_adv_psk_has_hash(out->psk_mode)) {
		if (offset + RIST_ADV_PSK_HASH_SIZE > len)
			return -1;
		out->psk_hash = buf + offset;
		offset += RIST_ADV_PSK_HASH_SIZE;
	}
	if (rist_adv_psk_has_nonce(out->psk_mode)) {
		if (offset + RIST_ADV_PSK_NONCE_SIZE > len)
			return -1;
		out->psk_nonce = buf + offset;
		offset += RIST_ADV_PSK_NONCE_SIZE;
	}
	if (rist_adv_psk_has_iv(out->psk_mode)) {
		if (offset + RIST_ADV_PSK_IV_SIZE > len)
			return -1;
		out->psk_iv = buf + offset;
		offset += RIST_ADV_PSK_IV_SIZE;
	}

	/* Payload Compression field (4 bytes, if LPC==3) */
	if (out->has_compression) {
		if (offset + RIST_ADV_COMPRESSION_SIZE > len)
			return -1;
		out->compression = buf + offset;
		offset += RIST_ADV_COMPRESSION_SIZE;
	}

	/* Payload Format Descriptor (4 bytes, if P=1) */
	if (out->has_pfd) {
		if (offset + RIST_ADV_PFD_SIZE > len)
			return -1;
		out->pfd = (const struct rist_adv_pfd *)(buf + offset);
		offset += RIST_ADV_PFD_SIZE;
	}

	/* RIST Header Extension (if H=1) — same format as RFC 3550 extension */
	if (out->has_hdr_ext) {
		if (offset + 4 > len)
			return -1;
		uint16_t hdr_ext_words = ntohs(*(const uint16_t *)(buf + offset + 2));
		size_t hdr_ext_total = 4 + (size_t)hdr_ext_words * 4;
		if (offset + hdr_ext_total > len)
			return -1;
		out->hdr_ext = buf + offset;
		out->hdr_ext_len = hdr_ext_total;
		offset += hdr_ext_total;
	}

	/* Remaining bytes are payload */
	out->payload = buf + offset;
	out->payload_len = len - offset;

	return 0;
}

int rist_adv_build(uint8_t *buf, const struct rist_adv_params *params,
                   const uint8_t *payload, size_t payload_len)
{
	if (!buf || !params)
		return -1;

	size_t offset = 0;

	/* RTP header (12 bytes) */
	struct rist_rtp_hdr *rtp = (struct rist_rtp_hdr *)buf;
	rtp->flags = RIST_ADV_RTP_FLAGS;
	rtp->payload_type = RIST_ADV_PT;
	rtp->ts = htonl(params->timestamp);
	rtp->ssrc = htonl(params->ssrc);
	offset += sizeof(struct rist_rtp_hdr);

	/* Profile-defined extension (4 bytes) */
	struct rist_adv_ext *ext = (struct rist_adv_ext *)(buf + offset);
	memset(ext, 0, sizeof(*ext));
	offset += RIST_ADV_EXT_SIZE;

	rist_adv_set_seq32(rtp, ext, params->seq);

	/* Build flags byte */
	ext->flags = 0;
	if (params->first_frag)  ext->flags |= RIST_ADV_FLAG_F;
	if (params->last_frag)   ext->flags |= RIST_ADV_FLAG_L;
	if (params->expedite)    ext->flags |= RIST_ADV_FLAG_E;
	if (params->retransmit)  ext->flags |= RIST_ADV_FLAG_R;
	if (params->flow_id)     ext->flags |= RIST_ADV_FLAG_I;
	if (params->pfd)         ext->flags |= RIST_ADV_FLAG_P;
	if (params->hdr_ext && params->hdr_ext_len > 0)
		ext->flags |= RIST_ADV_FLAG_H;

	/* Build params byte + PSK bits that span both bytes */
	rist_adv_set_psk(ext, params->psk_mode);
	rist_adv_set_lpc(ext, params->lpc_mode);
	rist_adv_set_type(ext, params->enc_type);

	/* Optional fields in spec order */

	/* Flow ID */
	if (params->flow_id) {
		memcpy(buf + offset, params->flow_id, RIST_ADV_FLOW_ID_SIZE);
		offset += RIST_ADV_FLOW_ID_SIZE;
	}

	/* PSK Hash */
	if (rist_adv_psk_has_hash(params->psk_mode) && params->psk_hash) {
		memcpy(buf + offset, params->psk_hash, RIST_ADV_PSK_HASH_SIZE);
		offset += RIST_ADV_PSK_HASH_SIZE;
	}

	/* PSK Nonce */
	if (rist_adv_psk_has_nonce(params->psk_mode) && params->psk_nonce) {
		memcpy(buf + offset, params->psk_nonce, RIST_ADV_PSK_NONCE_SIZE);
		offset += RIST_ADV_PSK_NONCE_SIZE;
	}

	/* PSK IV */
	if (rist_adv_psk_has_iv(params->psk_mode) && params->psk_iv) {
		memcpy(buf + offset, params->psk_iv, RIST_ADV_PSK_IV_SIZE);
		offset += RIST_ADV_PSK_IV_SIZE;
	}

	/* Payload Compression field */
	if (params->lpc_mode == RIST_ADV_LPC_FIELD_PRESENT && params->compression) {
		memcpy(buf + offset, params->compression, RIST_ADV_COMPRESSION_SIZE);
		offset += RIST_ADV_COMPRESSION_SIZE;
	}

	/* Payload Format Descriptor */
	if (params->pfd) {
		memcpy(buf + offset, params->pfd, RIST_ADV_PFD_SIZE);
		offset += RIST_ADV_PFD_SIZE;
	}

	/* RIST Header Extension */
	if (params->hdr_ext && params->hdr_ext_len > 0) {
		memcpy(buf + offset, params->hdr_ext, params->hdr_ext_len);
		offset += params->hdr_ext_len;
	}

	/* Payload */
	if (payload && payload_len > 0)
		memcpy(buf + offset, payload, payload_len);

	return (int)(offset + payload_len);
}
