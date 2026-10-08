/*
 * Copyright © 2019-2020 SipRadius LLC
 * Copyright © 2024-2026 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * VSF TR-06-3:2024 — RIST Advanced Profile wire format definitions.
 */

#ifndef RIST_PROTO_ADV_H
#define RIST_PROTO_ADV_H

#include "common/attributes.h"
#include "proto/rtp.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/*
 * VSF TR-06-3 Advanced Profile top-level tunnel packet format (Figure 1).
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V=2|P|X| CC  |M|   PT=127     |     Sequence Number (low 16)  |  RTP
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  (12 B)
 * |                      Timestamp (1 MHz)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         SSRC identifier                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * :             RTP Header Extension (if X=1)                     :
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Seq Number Extension (16)   |F|L|E|R|I|P|H|PSK |LPC| Type |  Profile-
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  defined
 * |              Flow ID (if I=1, 4 bytes)                        |  header
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              PSK Hash (if present, 16 bytes)                  |
 * |              PSK Nonce (if present, 4 bytes)                  |
 * |              PSK IV (if present, 4 bytes)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Payload Compression (if LPC=11, 4 bytes)         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |              Payload Format Descriptor (if P=1, 4 bytes)      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * :              RIST Header Extension (if H=1, variable)         :
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Payload ...                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/* --------------------------------------------------------------------------
 * RTP constants for Advanced Profile
 * -------------------------------------------------------------------------- */

/* PT=127 when SDP is not in use (Section 5.2.1) */
#define RIST_ADV_PT             127

/* Default timestamp frequency: 1 MHz (Section 5.2.1) */
#define RIST_ADV_CLOCK_HZ       1000000

/*
 * Default RTP flags byte: V=2, P=0, X=0, CC=0 = 0x80.
 * The profile-defined header (seq_ext + flags) is NOT an RFC 3550 header
 * extension — it's part of the RTP "payload" interpreted by the Advanced
 * Profile.  X is only set when an actual RFC 3550 header extension is used.
 */
#define RIST_ADV_RTP_FLAGS      0x80

/* --------------------------------------------------------------------------
 * Profile-defined header: fixed extension (always present, 4 bytes)
 * -------------------------------------------------------------------------- */

RIST_PACKED_STRUCT(rist_adv_ext, {
	uint16_t seq_ext;   /* Sequence Number Extension (high 16 bits) */
	uint8_t  flags;     /* F|L|E|R|I|P|H|PSK[2] */
	uint8_t  params;    /* PSK[1:0]|LPC[1:0]|Type[3:0] */
})

/* flags byte (byte 2 of the extension, bits 16-23 of line 5) */
#define RIST_ADV_FLAG_F     0x80    /* First fragment */
#define RIST_ADV_FLAG_L     0x40    /* Last fragment */
#define RIST_ADV_FLAG_E     0x20    /* Expedite */
#define RIST_ADV_FLAG_R     0x10    /* Retransmit */
#define RIST_ADV_FLAG_I     0x08    /* Flow ID present */
#define RIST_ADV_FLAG_P     0x04    /* Payload Format Descriptor present */
#define RIST_ADV_FLAG_H     0x02    /* RIST Header Extension present */
#define RIST_ADV_PSK2_MASK  0x01    /* PSK field bit 2 (MSB of 3-bit PSK) */

/* params byte (byte 3 of the extension, bits 24-31 of line 5) */
#define RIST_ADV_PSK10_SHIFT    6   /* PSK[1:0] in bits 7-6 */
#define RIST_ADV_PSK10_MASK     0xC0
#define RIST_ADV_LPC_SHIFT      4   /* LPC[1:0] in bits 5-4 */
#define RIST_ADV_LPC_MASK       0x30
#define RIST_ADV_TYPE_MASK      0x0F /* Type[3:0] in bits 3-0 */

/* --------------------------------------------------------------------------
 * PSK mode extraction / insertion
 *
 *  The 3-bit PSK field spans two bytes:
 *    PSK[2]   = ext->flags  bit 0
 *    PSK[1:0] = ext->params bits 7-6
 * -------------------------------------------------------------------------- */

static inline uint8_t rist_adv_get_psk(const struct rist_adv_ext *ext)
{
	return (uint8_t)(((ext->flags & RIST_ADV_PSK2_MASK) << 2) |
	                 ((ext->params & RIST_ADV_PSK10_MASK) >> RIST_ADV_PSK10_SHIFT));
}

static inline void rist_adv_set_psk(struct rist_adv_ext *ext, uint8_t psk)
{
	ext->flags  = (ext->flags & ~RIST_ADV_PSK2_MASK) | ((psk >> 2) & 0x01);
	ext->params = (ext->params & ~RIST_ADV_PSK10_MASK) |
	              (uint8_t)((psk & 0x03) << RIST_ADV_PSK10_SHIFT);
}

/* LPC extraction / insertion */
static inline uint8_t rist_adv_get_lpc(const struct rist_adv_ext *ext)
{
	return (uint8_t)((ext->params & RIST_ADV_LPC_MASK) >> RIST_ADV_LPC_SHIFT);
}

static inline void rist_adv_set_lpc(struct rist_adv_ext *ext, uint8_t lpc)
{
	ext->params = (ext->params & ~RIST_ADV_LPC_MASK) |
	              (uint8_t)((lpc & 0x03) << RIST_ADV_LPC_SHIFT);
}

/* Type extraction / insertion */
static inline uint8_t rist_adv_get_type(const struct rist_adv_ext *ext)
{
	return ext->params & RIST_ADV_TYPE_MASK;
}

static inline void rist_adv_set_type(struct rist_adv_ext *ext, uint8_t type)
{
	ext->params = (ext->params & ~RIST_ADV_TYPE_MASK) | (type & 0x0F);
}

/* --------------------------------------------------------------------------
 * Encapsulation type constants (Type[3:0], Section 5.2.3)
 * -------------------------------------------------------------------------- */
#define RIST_ADV_TYPE_RESERVED      0
#define RIST_ADV_TYPE_IPV4          1
#define RIST_ADV_TYPE_IPV6          2
#define RIST_ADV_TYPE_REDUCED_UDP   3
#define RIST_ADV_TYPE_CONTROL       4
#define RIST_ADV_TYPE_DIRECT        5
#define RIST_ADV_TYPE_LAYER2        6
#define RIST_ADV_TYPE_GRE_RFC2784   7
#define RIST_ADV_TYPE_GRE_MAIN      8

/* --------------------------------------------------------------------------
 * PSK mode constants (PSK[2:0], Section 5.2.3)
 * -------------------------------------------------------------------------- */
#define RIST_ADV_PSK_NONE               0   /* No Encryption */
#define RIST_ADV_PSK_AES_CTR            1   /* AES-CTR (Main Profile compat) */
#define RIST_ADV_PSK_HMAC_SHA256        2   /* HMAC-SHA256 (no encryption) */
#define RIST_ADV_PSK_AES_CTR_HMAC       3   /* AES-CTR-HMAC-SHA256 */
#define RIST_ADV_PSK_AES_GCM            4   /* AES-GCM */
#define RIST_ADV_PSK_CHACHA20_POLY1305  5   /* CHACHA20-POLY1305 */
#define RIST_ADV_PSK_USER_NOHASH        6   /* User-defined, no hash */
#define RIST_ADV_PSK_USER_HASH          7   /* User-defined, with hash */

/* --------------------------------------------------------------------------
 * PSK header sizes per Table 1 (Section 5.2.3)
 *
 *   Hash (16 B) + Nonce (4 B) + IV (4 B) — presence per mode.
 * -------------------------------------------------------------------------- */

#define RIST_ADV_PSK_HASH_SIZE   16
#define RIST_ADV_PSK_NONCE_SIZE   4
#define RIST_ADV_PSK_IV_SIZE      4

static inline bool rist_adv_psk_has_hash(uint8_t psk)
{
	return psk == 2 || psk == 3 || psk == 4 || psk == 5 || psk == 7;
}

static inline bool rist_adv_psk_has_nonce(uint8_t psk)
{
	return psk >= 1;
}

static inline bool rist_adv_psk_has_iv(uint8_t psk)
{
	return psk == 1 || psk >= 3;
}

static inline size_t rist_adv_psk_hdr_size(uint8_t psk)
{
	size_t sz = 0;
	if (rist_adv_psk_has_hash(psk))  sz += RIST_ADV_PSK_HASH_SIZE;
	if (rist_adv_psk_has_nonce(psk)) sz += RIST_ADV_PSK_NONCE_SIZE;
	if (rist_adv_psk_has_iv(psk))    sz += RIST_ADV_PSK_IV_SIZE;
	return sz;
}

/* --------------------------------------------------------------------------
 * LPC mode constants (LPC[1:0], Section 5.2.3)
 * -------------------------------------------------------------------------- */
#define RIST_ADV_LPC_NONE           0   /* No Compression */
#define RIST_ADV_LPC_LZ4            1   /* LZ4 Compression */
#define RIST_ADV_LPC_RESERVED       2   /* Reserved */
#define RIST_ADV_LPC_FIELD_PRESENT  3   /* Payload Compression field present */

/* --------------------------------------------------------------------------
 * Control Index values (Table 2, Section 5.3)
 * -------------------------------------------------------------------------- */
#define RIST_ADV_CI_NACK_BITMASK        0x0000
#define RIST_ADV_CI_NACK_RANGE          0x0001
#define RIST_ADV_CI_RTT_ECHO_REQ        0x0010
#define RIST_ADV_CI_RTT_ECHO_RESP       0x0011
#define RIST_ADV_CI_FEC_2022_5_ROW      0x0020
#define RIST_ADV_CI_FEC_2022_5_COL      0x0021
#define RIST_ADV_CI_FEC_2022_1_ROW      0x0022
#define RIST_ADV_CI_FEC_2022_1_COL      0x0023
#define RIST_ADV_CI_KEEPALIVE           0x8000
#define RIST_ADV_CI_FLOW_ATTR           0x8001
#define RIST_ADV_CI_SRP_AUTH            0x8010
#define RIST_ADV_CI_PSK_NONCE           0x8011
#define RIST_ADV_CI_UNSUPPORTED         0x8020

/* --------------------------------------------------------------------------
 * Flow ID field (4 bytes, Section 5.2.4, Figure 4)
 * -------------------------------------------------------------------------- */

RIST_PACKED_STRUCT(rist_adv_flow_id, {
	uint16_t outer;             /* Outer Flow ID */
	uint8_t  inner_hi;          /* Inner Flow ID bits [11:4] */
	uint8_t  inner_lo_sub;      /* Inner Flow ID bits [3:0] | IFSID [3:0] */
})

static inline uint16_t rist_adv_flow_outer(const struct rist_adv_flow_id *f)
{
	return ntohs(f->outer);
}

static inline uint16_t rist_adv_flow_inner(const struct rist_adv_flow_id *f)
{
	return (uint16_t)((f->inner_hi << 4) | ((f->inner_lo_sub >> 4) & 0x0F));
}

static inline uint8_t rist_adv_flow_sub(const struct rist_adv_flow_id *f)
{
	return f->inner_lo_sub & 0x0F;
}

/* --------------------------------------------------------------------------
 * Payload Format Descriptor (4 bytes, Section 5.2.7, Figure 6)
 * -------------------------------------------------------------------------- */

RIST_PACKED_STRUCT(rist_adv_pfd, {
	uint32_t value;     /* ID Type (4 bits) | ID Value (28 bits) */
})

static inline uint8_t rist_adv_pfd_id_type(const struct rist_adv_pfd *p)
{
	return (uint8_t)(ntohl(p->value) >> 28);
}

static inline uint32_t rist_adv_pfd_id_value(const struct rist_adv_pfd *p)
{
	return ntohl(p->value) & 0x0FFFFFFF;
}

/* --------------------------------------------------------------------------
 * Header size constants
 * -------------------------------------------------------------------------- */
#define RIST_ADV_RTP_SIZE           12  /* Standard RTP header */
#define RIST_ADV_EXT_SIZE            4  /* Profile-defined extension */
#define RIST_ADV_HEADER_MIN         16  /* RTP (12) + ext (4) */
#define RIST_ADV_FLOW_ID_SIZE        4
#define RIST_ADV_COMPRESSION_SIZE    4
#define RIST_ADV_PFD_SIZE            4

/* Maximum header: RTP(12) + ext(4) + flow_id(4) + hash(16) + nonce(4) + iv(4) + comp(4) + pfd(4) = 52
 * (RIST Header Extension is variable-length on top of this) */
#define RIST_ADV_MAX_FIXED_HEADER   52

/* Control message sub-header */
#define RIST_ADV_CTRL_HDR_SIZE       4  /* Control Index (2) + Length (2) */

/* --------------------------------------------------------------------------
 * 32-bit sequence number helpers
 * -------------------------------------------------------------------------- */

static inline uint32_t rist_adv_seq32(const struct rist_rtp_hdr *rtp,
                                       const struct rist_adv_ext *ext)
{
	return ((uint32_t)ntohs(ext->seq_ext) << 16) | ntohs(rtp->seq);
}

static inline void rist_adv_set_seq32(struct rist_rtp_hdr *rtp,
                                       struct rist_adv_ext *ext,
                                       uint32_t seq)
{
	rtp->seq = htons((uint16_t)(seq & 0xFFFF));
	ext->seq_ext = htons((uint16_t)(seq >> 16));
}

/* --------------------------------------------------------------------------
 * Fragment flag helpers
 *
 *   F=1, L=1 -> unfragmented
 *   F=1, L=0 -> first fragment
 *   F=0, L=0 -> middle fragment
 *   F=0, L=1 -> last fragment
 * -------------------------------------------------------------------------- */

static inline bool rist_adv_is_unfragmented(uint8_t flags)
{
	return (flags & (RIST_ADV_FLAG_F | RIST_ADV_FLAG_L)) ==
	       (RIST_ADV_FLAG_F | RIST_ADV_FLAG_L);
}

static inline bool rist_adv_is_fragmented(uint8_t flags)
{
	return !rist_adv_is_unfragmented(flags);
}

static inline bool rist_adv_is_first_fragment(uint8_t flags)
{
	return (flags & RIST_ADV_FLAG_F) && !(flags & RIST_ADV_FLAG_L);
}

static inline bool rist_adv_is_last_fragment(uint8_t flags)
{
	return !(flags & RIST_ADV_FLAG_F) && (flags & RIST_ADV_FLAG_L);
}

/* Sequence difference for wrap-around comparison */
static inline int32_t rist_adv_seq_diff(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b);
}

/* SSRC parity helpers (Section 5.2.1) */
static inline bool rist_adv_ssrc_is_protected(uint32_t ssrc)
{
	return (ssrc & 1) == 0;
}

static inline uint32_t rist_adv_ssrc_protected(uint32_t ssrc_base)
{
	return ssrc_base & ~(uint32_t)1;
}

static inline uint32_t rist_adv_ssrc_unprotected(uint32_t ssrc_base)
{
	return ssrc_base | 1;
}

/* --------------------------------------------------------------------------
 * Parse output structure
 * -------------------------------------------------------------------------- */

struct rist_adv_parsed {
	/* From RTP header */
	uint32_t seq;               /* Full 32-bit sequence number */
	uint32_t timestamp;         /* RTP timestamp (1 MHz clock) */
	uint32_t ssrc;
	bool     rtp_ext_present;   /* X bit in RTP header */
	bool     rtp_padding;       /* P bit in RTP header */

	/* From profile-defined extension */
	bool     first_frag;        /* F bit */
	bool     last_frag;         /* L bit */
	bool     expedite;          /* E bit */
	bool     retransmit;        /* R bit */
	uint8_t  psk_mode;          /* PSK[2:0] (0-7) */
	uint8_t  lpc_mode;          /* LPC[1:0] (0-3) */
	uint8_t  enc_type;          /* Type[3:0] (0-15) */

	/* Optional fields — pointers into original buffer (NULL if absent) */
	bool     has_flow_id;       /* I flag */
	const struct rist_adv_flow_id *flow_id;

	bool     has_psk;           /* PSK mode > 0 */
	const uint8_t *psk_hash;    /* NULL if no hash for this mode */
	const uint8_t *psk_nonce;   /* NULL if no nonce */
	const uint8_t *psk_iv;      /* NULL if no IV */

	bool     has_compression;   /* LPC == 3 */
	const uint8_t *compression; /* 4-byte compression field */

	bool     has_pfd;           /* P flag */
	const struct rist_adv_pfd *pfd;

	bool     has_hdr_ext;       /* H flag */
	const uint8_t *hdr_ext;     /* Points to RFC 3550-style extension header */
	size_t   hdr_ext_len;       /* Total bytes of RIST header extension */

	/* Payload */
	const uint8_t *payload;
	size_t   payload_len;
};

/* --------------------------------------------------------------------------
 * Build input structure
 * -------------------------------------------------------------------------- */

struct rist_adv_params {
	uint32_t seq;
	uint32_t timestamp;
	uint32_t ssrc;
	uint8_t  enc_type;          /* Type[3:0] */
	uint8_t  psk_mode;          /* PSK[2:0] */
	uint8_t  lpc_mode;          /* LPC[1:0] */
	bool     first_frag;
	bool     last_frag;
	bool     expedite;
	bool     retransmit;

	/* Optional fields — NULL/zero to omit */
	const struct rist_adv_flow_id *flow_id;
	const uint8_t *psk_hash;
	const uint8_t *psk_nonce;
	const uint8_t *psk_iv;
	const uint8_t *compression;     /* 4 bytes if LPC==3 */
	const struct rist_adv_pfd *pfd;
	const uint8_t *hdr_ext;
	size_t   hdr_ext_len;
};

/* --------------------------------------------------------------------------
 * Function declarations
 * -------------------------------------------------------------------------- */

/* Parse an Advanced Profile packet.
 * buf: pointer to the start of the RTP header
 * len: total packet length
 * out: populated on success
 * Returns 0 on success, -1 on malformed packet. */
RIST_PRIV int rist_adv_parse(const uint8_t *buf, size_t len,
                             struct rist_adv_parsed *out);

/* Build an Advanced Profile packet.
 * buf: output buffer (caller ensures sufficient space)
 * params: packet parameters
 * payload: inner payload data (may be NULL if payload_len == 0)
 * payload_len: inner payload length
 * Returns total packet length on success, or -1 on error. */
RIST_PRIV int rist_adv_build(uint8_t *buf, const struct rist_adv_params *params,
                             const uint8_t *payload, size_t payload_len);

/* Compute the header size for given parameters (without payload). */
RIST_PRIV size_t rist_adv_header_size(const struct rist_adv_params *params);

/* --------------------------------------------------------------------------
 * Control message API (adv_ctrl.c)
 * -------------------------------------------------------------------------- */

/* Forward declaration for control message API */
struct rist_peer;

RIST_PRIV int rist_adv_send_nack_bitmask(struct rist_peer *peer,
                                          uint32_t media_ssrc,
                                          uint32_t pss, uint32_t blp);
RIST_PRIV int rist_adv_send_nack_range(struct rist_peer *peer,
                                        uint32_t media_ssrc,
                                        uint32_t pss, uint32_t nalp);
RIST_PRIV int rist_adv_send_rtt_echo_request(struct rist_peer *peer);
RIST_PRIV int rist_adv_send_rtt_echo_response(struct rist_peer *peer,
                                               uint32_t requester_ssrc,
                                               uint32_t orig_msw,
                                               uint32_t orig_lsw,
                                               uint32_t processing_delay_us);
RIST_PRIV int rist_adv_send_keepalive(struct rist_peer *peer);
RIST_PRIV int rist_adv_send_unsupported(struct rist_peer *peer,
                                         uint16_t incoming_ci,
                                         const uint8_t *incoming_payload,
                                         size_t incoming_len);
RIST_PRIV int rist_adv_send_type8(struct rist_peer *peer,
                                   const uint8_t *gre_packet,
                                   size_t gre_len);
RIST_PRIV int rist_adv_send_psk_nonce(struct rist_peer *peer,
                                       const uint8_t nonce[4],
                                       uint16_t key_size_bits);
RIST_PRIV int rist_adv_send_flow_attr(struct rist_peer *peer);
RIST_PRIV int rist_adv_recv_control(struct rist_peer *peer,
                                     const uint8_t *ctrl_payload,
                                     size_t ctrl_len);

#endif /* RIST_PROTO_ADV_H */
