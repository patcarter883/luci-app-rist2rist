/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_TUN_H
#define LIBRIST_TUN_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Open a TUN device (layer 3, IP packets only).
 *
 * Cross-platform: macOS (utun), Linux (/dev/net/tun), Windows (stub).
 * Requires root/admin privileges on most platforms.
 *
 * @param requested_name  Desired interface name (e.g. "rist0" or "utun5"), or NULL for auto.
 * @param actual_name     Buffer to receive the actual interface name assigned.
 * @param name_len        Size of actual_name buffer.
 * @return                File descriptor on success, -1 on failure.
 */
RIST_API int rist_tun_open(const char *requested_name, char *actual_name, size_t name_len);

/**
 * @brief Close a TUN device.
 */
RIST_API void rist_tun_close(int fd);

/**
 * @brief Read one IP packet from the TUN device.
 *
 * Platform-specific framing (e.g. macOS 4-byte AF header) is handled
 * transparently — the caller always receives a raw IP packet.
 *
 * @return  Number of bytes read, or -1 on error.
 */
RIST_API int rist_tun_read(int fd, uint8_t *buf, size_t len);

/**
 * @brief Write one IP packet to the TUN device.
 *
 * Platform-specific framing is added transparently.
 *
 * @return  Number of bytes written (IP payload only), or -1 on error.
 */
RIST_API int rist_tun_write(int fd, const uint8_t *buf, size_t len);

/**
 * @brief Assign an IP address and prefix length to the TUN interface.
 *
 * @param dev         Interface name (e.g. "utun3").
 * @param ip          IP address string (e.g. "10.0.0.1").
 * @param prefix_len  Prefix length (e.g. 24).
 * @return            0 on success, -1 on failure.
 */
RIST_API int rist_tun_set_ip(const char *dev, const char *ip, int prefix_len);

/**
 * @brief Set the MTU on the TUN interface.
 *
 * @return  0 on success, -1 on failure.
 */
RIST_API int rist_tun_set_mtu(const char *dev, int mtu);

/**
 * @brief Bring the TUN interface up (IFF_UP).
 *
 * @return  0 on success, -1 on failure.
 */
RIST_API int rist_tun_bring_up(const char *dev);

#ifdef __cplusplus
}
#endif

#endif /* LIBRIST_TUN_H */
