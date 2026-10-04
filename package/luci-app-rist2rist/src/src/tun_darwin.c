/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

/* utun sockets and <sys/kern_control.h> / <net/if_utun.h> only exist in the
 * macOS SDK. iOS / tvOS / watchOS / visionOS expose __APPLE__ but do not ship
 * those headers, so narrow the guard to plain macOS. */
#if defined(__APPLE__) && TARGET_OS_OSX

#include "librist/tun.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>

/*
 * macOS utun devices deliver/expect a 4-byte protocol header (AF family)
 * before each IP packet. We handle this transparently in rist_tun_read/rist_tun_write.
 */
#define UTUN_HEADER_SIZE 4
#define TUN_DARWIN_BUFSIZE (65536 + UTUN_HEADER_SIZE)

int rist_tun_open(const char *requested_name, char *actual_name, size_t name_len)
{
	int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (fd < 0) {
		perror("socket PF_SYSTEM");
		return -1;
	}

	struct ctl_info ci;
	memset(&ci, 0, sizeof(ci));
	strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name) - 1);

	if (ioctl(fd, CTLIOCGINFO, &ci) < 0) {
		perror("ioctl CTLIOCGINFO");
		close(fd);
		return -1;
	}

	struct sockaddr_ctl sc;
	memset(&sc, 0, sizeof(sc));
	sc.sc_len = sizeof(sc);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id = ci.ctl_id;

	/*
	 * sc_unit maps to utunN where N = sc_unit - 1.
	 * Unit 0 = let the kernel pick.
	 */
	unsigned int unit = 0;
	if (requested_name && requested_name[0]) {
		if (strncmp(requested_name, "utun", 4) == 0) {
			const char *suffix = requested_name + 4;
			char *endptr = NULL;
			errno = 0;
			unsigned long parsed = strtoul(suffix, &endptr, 10);
			if (suffix[0] != '\0' && errno == 0 &&
			    endptr != suffix && *endptr == '\0' &&
			    parsed < (UINT_MAX - 1)) {
				unit = (unsigned int)parsed + 1;
			}
		}
	}
	sc.sc_unit = unit;

	if (connect(fd, (struct sockaddr *)&sc, sizeof(sc)) < 0) {
		perror("connect utun");
		close(fd);
		return -1;
	}

	if (actual_name && name_len > 0) {
		socklen_t optlen = (socklen_t)name_len;
		if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, actual_name, &optlen) < 0) {
			perror("getsockopt UTUN_OPT_IFNAME");
			close(fd);
			return -1;
		}
	}

	return fd;
}

void rist_tun_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

int rist_tun_read(int fd, uint8_t *buf, size_t len)
{
	uint8_t tmp[TUN_DARWIN_BUFSIZE];
	size_t readlen = len + UTUN_HEADER_SIZE;
	if (readlen > sizeof(tmp))
		readlen = sizeof(tmp);

	int nread = (int)read(fd, tmp, readlen);
	if (nread <= UTUN_HEADER_SIZE)
		return nread < 0 ? -1 : 0;

	int payload_len = nread - UTUN_HEADER_SIZE;
	if ((size_t)payload_len > len)
		payload_len = (int)len;

	memcpy(buf, tmp + UTUN_HEADER_SIZE, payload_len);
	return payload_len;
}

int rist_tun_write(int fd, const uint8_t *buf, size_t len)
{
	uint8_t tmp[TUN_DARWIN_BUFSIZE];
	if (len > sizeof(tmp) - UTUN_HEADER_SIZE)
		return -1;

	uint32_t af;
	if (len > 0 && (buf[0] >> 4) == 6)
		af = htonl(AF_INET6);
	else
		af = htonl(AF_INET);

	memcpy(tmp, &af, UTUN_HEADER_SIZE);
	memcpy(tmp + UTUN_HEADER_SIZE, buf, len);

	int written = (int)write(fd, tmp, len + UTUN_HEADER_SIZE);
	if (written <= UTUN_HEADER_SIZE)
		return written < 0 ? -1 : 0;

	return written - UTUN_HEADER_SIZE;
}

int rist_tun_set_ip(const char *dev, const char *ip, int prefix_len)
{
	if (prefix_len < 0 || prefix_len > 32) {
		fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
		return -1;
	}
	struct ifaliasreq ifra;
	memset(&ifra, 0, sizeof(ifra));
	strncpy(ifra.ifra_name, dev, IFNAMSIZ - 1);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifra.ifra_addr;
	addr->sin_len = sizeof(*addr);
	addr->sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", ip);
		return -1;
	}

	struct sockaddr_in *mask = (struct sockaddr_in *)&ifra.ifra_mask;
	mask->sin_len = sizeof(*mask);
	mask->sin_family = AF_INET;
	if (prefix_len == 0)
		mask->sin_addr.s_addr = 0;
	else if (prefix_len == 32)
		mask->sin_addr.s_addr = htonl(0xFFFFFFFFu);
	else
		mask->sin_addr.s_addr = htonl(~((1U << (32 - prefix_len)) - 1));

	struct sockaddr_in *dst = (struct sockaddr_in *)&ifra.ifra_broadaddr;
	dst->sin_len = sizeof(*dst);
	dst->sin_family = AF_INET;
	dst->sin_addr = addr->sin_addr;

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket AF_INET");
		return -1;
	}

	if (ioctl(s, SIOCAIFADDR, &ifra) < 0) {
		perror("ioctl SIOCAIFADDR");
		close(s);
		return -1;
	}

	close(s);
	return 0;
}

int rist_tun_set_mtu(const char *dev, int mtu)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket AF_INET");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	ifr.ifr_mtu = mtu;

	if (ioctl(s, SIOCSIFMTU, &ifr) < 0) {
		perror("ioctl SIOCSIFMTU");
		close(s);
		return -1;
	}

	close(s);
	return 0;
}

int rist_tun_bring_up(const char *dev)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket AF_INET");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		perror("ioctl SIOCGIFFLAGS");
		close(s);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		perror("ioctl SIOCSIFFLAGS");
		close(s);
		return -1;
	}

	close(s);
	return 0;
}

#elif defined(__APPLE__)

/* Embedded Apple platforms (iOS, tvOS, watchOS, visionOS) do not ship
 * <sys/kern_control.h> / <net/if_utun.h> and therefore cannot provide a
 * real utun implementation. Provide stub entry points with the same
 * signatures so that rist.c / rist-common.c still link cleanly. All
 * calls fail with -1, matching tun_win.c's behaviour on platforms
 * without native TUN support. */

#include "librist/tun.h"
#include <stdio.h>

int rist_tun_open(const char *requested_name, char *actual_name, size_t name_len)
{
	(void)requested_name;
	(void)actual_name;
	(void)name_len;
	fprintf(stderr, "librist: TUN is not supported on this Apple platform\n");
	return -1;
}

void rist_tun_close(int fd)
{
	(void)fd;
}

int rist_tun_read(int fd, uint8_t *buf, size_t len)
{
	(void)fd;
	(void)buf;
	(void)len;
	return -1;
}

int rist_tun_write(int fd, const uint8_t *buf, size_t len)
{
	(void)fd;
	(void)buf;
	(void)len;
	return -1;
}

int rist_tun_set_ip(const char *dev, const char *ip, int prefix_len)
{
	(void)dev;
	(void)ip;
	(void)prefix_len;
	return -1;
}

int rist_tun_set_mtu(const char *dev, int mtu)
{
	(void)dev;
	(void)mtu;
	return -1;
}

int rist_tun_bring_up(const char *dev)
{
	(void)dev;
	return -1;
}

#endif /* defined(__APPLE__) && TARGET_OS_OSX / embedded Apple */
