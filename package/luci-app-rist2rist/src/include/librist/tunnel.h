/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_TUNNEL_H
#define LIBRIST_TUNNEL_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Tunnel I/O statistics for the data fd path.
 *
 * TX = packets/bytes read from the sender's data fd and sent over RIST.
 * RX = packets/bytes received from RIST and written to the receiver's data fd.
 */
struct rist_data_fd_stats {
	uint64_t tx_packets;
	uint64_t tx_bytes;
	uint64_t rx_packets;
	uint64_t rx_bytes;
};

#define RIST_DATA_FD_FLAG_TUN (1 << 0)

/**
 * @brief Set a file descriptor as the data source for a sender.
 *
 * When set, librist spawns an internal thread that reads from the fd
 * and feeds packets into the RIST sender. The fd can be a TUN device,
 * pipe, socket, or any readable fd that delivers framed packets.
 *
 * When RIST_DATA_FD_FLAG_TUN is set in flags, librist uses rist_tun_read()
 * to handle platform-specific TUN framing (e.g. macOS utun AF header).
 *
 * Must be called before rist_start(). The fd is NOT owned by librist —
 * the caller is responsible for closing it after rist_destroy().
 *
 * @param ctx RIST sender context
 * @param fd  Readable file descriptor (TUN, pipe, socket, etc.)
 * @param max_packet_size Maximum bytes per read (e.g. 1500 for TUN MTU)
 * @param flags Bitmask: RIST_DATA_FD_FLAG_TUN for TUN device framing
 * @return 0 on success, -1 on error
 */
RIST_API int rist_sender_data_fd_set(struct rist_ctx *ctx, int fd,
                                      size_t max_packet_size, uint32_t flags);

/**
 * @brief Set a file descriptor as the data sink for a receiver.
 *
 * When set, received RIST data is written directly to the fd from
 * librist's internal output thread — bypassing the FIFO queue and
 * any data callback. This is the lowest-latency output path.
 *
 * When RIST_DATA_FD_FLAG_TUN is set in flags, librist uses rist_tun_write()
 * to handle platform-specific TUN framing.
 *
 * Must be called before rist_start(). The fd is NOT owned by librist.
 *
 * @param ctx RIST receiver context
 * @param fd  Writable file descriptor (TUN, pipe, socket, etc.)
 * @param flags Bitmask: RIST_DATA_FD_FLAG_TUN for TUN device framing
 * @return 0 on success, -1 on error
 */
RIST_API int rist_receiver_data_fd_set(struct rist_ctx *ctx, int fd, uint32_t flags);

/**
 * @brief Retrieve cumulative tunnel I/O statistics.
 *
 * Returns stats for whichever mode the context is in (sender or receiver).
 *
 * @param ctx RIST sender or receiver context
 * @param[out] stats Populated with current counters
 * @return 0 on success, -1 on error
 */
RIST_API int rist_data_fd_stats_get(struct rist_ctx *ctx,
                                     struct rist_data_fd_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* LIBRIST_TUNNEL_H */
