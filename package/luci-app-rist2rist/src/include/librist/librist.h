/*
 * Copyright © 2020, VideoLAN and librist authors
 * Copyright © 2019-2020 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_H
#define LIBRIST_H

#include "common.h"
#include "receiver.h"
#include "sender.h"
#include "peer.h"
#include "stats.h"
#include "logging.h"
#include "librist_srp.h"
#include "opt.h"
#include "oob.h"
#include "headers.h"
#include "tun.h"
#include "tunnel.h"
#include "transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set RIST max jitter
 *
 * Set max jitter
 *
 * @param ctx RIST context
 * @param t max jitter in ms
 * @return 0 on success, -1 on error
 */
RIST_API int rist_jitter_max_set(struct rist_ctx *ctx, int t);

/**
 * @brief Set the recovery buffer RTT multiplier
 *
 * Controls how aggressively the auto-scaling buffer grows relative to
 * the measured RTT. The recovery buffer is calculated as:
 *   buffer = multiplier * smoothed_rtt + reorder_buffer
 *
 * Default is 7 (per RIST spec recommendation). Lower values (2-3) are
 * suitable for low-latency LAN scenarios. Must be >= 1.
 *
 * Only effective on receiver contexts when auto-scaling is enabled
 * (i.e., recovery_length_min != recovery_length_max).
 *
 * Can be called at any time, before or after rist_start(). Changes
 * take effect on the next buffer recalculation cycle (~1 second).
 *
 * @param ctx RIST context
 * @param multiplier RTT multiplier (>= 1, default 7)
 * @return 0 on success, -1 on error
 */
RIST_API int rist_recovery_rtt_multiplier_set(struct rist_ctx *ctx, int multiplier);

/**
 * @brief Set the Advanced-profile recovery (retransmit) buffer depth
 *
 * Sizes the retransmission ring used by the Advanced profile. `depth` is the
 * base-2 exponent of the ring size: the ring holds (65536 << depth) packets,
 * i.e. 2^depth times the 16-bit base buffer. The addressable NACK window is
 * roughly half the ring. Each step up doubles the buffer (and the RAM). This
 * is equivalent to the ?recovery-depth= URL parameter (same numeric value).
 *
 * Depth sizing (ring capacity / approx NACK window):
 *   0   (1x)      65536 / 32768 packets
 *   3   (8x)     524288 / 262144 packets   (default, historical behavior)
 *   6  (64x)    4194304 / 2097152 packets
 *  16 (65536x)  4294967296 / 2147483648 packets  (full 32-bit seq space)
 *
 * Valid range is RIST_RECOVERY_DEPTH_MIN..RIST_RECOVERY_DEPTH_MAX (0..16);
 * out-of-range values are clamped. Large depths are limited by available RAM
 * and will fail to allocate.
 *
 * This ONLY affects the Advanced profile. Simple and Main are inherently
 * 16-bit and remain capped at 65536 packets (32768-packet window) regardless
 * of this setting.
 *
 * Must be called after rist_sender_create() / rist_receiver_create() and
 * BEFORE rist_start().
 *
 * @param ctx   RIST context
 * @param depth desired recovery-depth exponent (0..16)
 * @return 0 on success, -1 on bad context or if called after rist_start(),
 *         -2 on allocation failure
 */
RIST_API int rist_recovery_depth_set(struct rist_ctx *ctx, uint8_t depth);

/**
 * @brief Starts the RIST sender or receiver
 *
 * After all the peers have been added, this function triggers
 * the RIST sender/receiver to start
 *
 * @param ctx RIST context
 * @return 0 on success, -1 in case of error.
 */
RIST_API int rist_start(struct rist_ctx *ctx);

/**
 * @brief Destroy RIST sender/receiver
 *
 * Destroys the RIST instance
 *
 * @param ctx RIST context
 * @return 0 on success, -1 on error
 */
RIST_API int rist_destroy(struct rist_ctx *ctx);

/**
 * @brief Parses udp url for udp config data (multicast interface, stream-id, prefix, etc)
 *
 * Use this API to parse a generic URL string and turn it into a meaningful udp_config structure
 *
 * @param url a pointer to a url to be parsed, i.e. udp://myserver.net:1234?miface=eth0&stream-id=1968
 * @param[out] udp_config a pointer to a the rist_udp_config structure (NULL is allowed).
 * When passing NULL, the library will allocate a new rist_udp_config structure with the latest
 * default values and it expects the application to free it when it is done using it.
 * @return 0 on success or non-zero on error. The value returned is actually the number
 * of parameters that are valid
 */
RIST_DEPRECATED RIST_API int rist_parse_udp_address(const char *url, const struct rist_udp_config **peer_config);
RIST_API int rist_parse_udp_address2(const char *url, struct rist_udp_config **peer_config);

/**
 * @brief Free the rist_udp_config structure memory allocation
 *
 * @return 0 on success or non-zero on error.
 */
RIST_DEPRECATED RIST_API int rist_udp_config_free(const struct rist_udp_config **udp_config);
RIST_API int rist_udp_config_free2(struct rist_udp_config **udp_config);

/**
 * @brief Get the version of libRIST
 *
 * @return String representing the version of libRIST
 */
RIST_API const char *librist_version(void);

/**
 * @brief Get the API version of libRIST
 */
RIST_API const char *librist_api_version(void);

#ifdef __cplusplus
}
#endif

#endif
