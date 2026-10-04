/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifdef __linux__

#include "librist/tun.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

int rist_tun_open(const char *requested_name, char *actual_name, size_t name_len)
{
	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open /dev/net/tun");
		return -1;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (requested_name && requested_name[0])
		strncpy(ifr.ifr_name, requested_name, IFNAMSIZ - 1);

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		perror("ioctl TUNSETIFF");
		close(fd);
		return -1;
	}

	if (actual_name && name_len > 0)
		strncpy(actual_name, ifr.ifr_name, name_len - 1);

	return fd;
}

void rist_tun_close(int fd)
{
	if (fd >= 0)
		close(fd);
}

int rist_tun_read(int fd, uint8_t *buf, size_t len)
{
	return (int)read(fd, buf, len);
}

int rist_tun_write(int fd, const uint8_t *buf, size_t len)
{
	return (int)write(fd, buf, len);
}

static int tun_ioctl_socket(void)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		perror("socket AF_INET");
	return s;
}

int rist_tun_set_ip(const char *dev, const char *ip, int prefix_len)
{
	if (prefix_len < 0 || prefix_len > 32) {
		fprintf(stderr, "Invalid prefix length: %d\n", prefix_len);
		return -1;
	}
	int s = tun_ioctl_socket();
	if (s < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;

	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1) {
		fprintf(stderr, "Invalid IP address: %s\n", ip);
		close(s);
		return -1;
	}

	if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
		perror("ioctl SIOCSIFADDR");
		close(s);
		return -1;
	}

	uint32_t mask;
	if (prefix_len == 0)
		mask = 0;
	else if (prefix_len == 32)
		mask = htonl(0xFFFFFFFFu);
	else
		mask = htonl(~((1U << (32 - prefix_len)) - 1));
	struct sockaddr_in *netmask = (struct sockaddr_in *)&ifr.ifr_netmask;
	netmask->sin_family = AF_INET;
	netmask->sin_addr.s_addr = mask;

	if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
		perror("ioctl SIOCSIFNETMASK");
		close(s);
		return -1;
	}

	close(s);
	return 0;
}

int rist_tun_set_mtu(const char *dev, int mtu)
{
	int s = tun_ioctl_socket();
	if (s < 0)
		return -1;

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
	int s = tun_ioctl_socket();
	if (s < 0)
		return -1;

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

#endif /* __linux__ */
