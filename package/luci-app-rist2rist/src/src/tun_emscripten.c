/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TUN device stubs for Emscripten/WASM — no network interfaces available.
 */

#ifdef __EMSCRIPTEN__

#include "librist/tun.h"
#include <errno.h>

int rist_tun_open(const char *requested_name, char *actual_name, size_t name_len)
{
	(void)requested_name;
	(void)actual_name;
	(void)name_len;
	errno = ENOTSUP;
	return -1;
}

int rist_tun_read(int fd, uint8_t *buf, size_t len)
{
	(void)fd;
	(void)buf;
	(void)len;
	errno = ENOTSUP;
	return -1;
}

int rist_tun_write(int fd, const uint8_t *buf, size_t len)
{
	(void)fd;
	(void)buf;
	(void)len;
	errno = ENOTSUP;
	return -1;
}

#endif /* __EMSCRIPTEN__ */
