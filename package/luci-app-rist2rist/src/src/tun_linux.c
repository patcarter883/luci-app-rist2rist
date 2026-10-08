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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
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

static int tun_ioctl_socket(int family)
{
	int s = socket(family, SOCK_DGRAM, 0);
	if (s < 0)
		perror(family == AF_INET6 ? "socket AF_INET6" : "socket AF_INET");
	return s;
}

static int tun_set_ipv4(const char *dev, const char *ip, int prefix_len)
{
	int s = tun_ioctl_socket(AF_INET);
	if (s < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
	addr->sin_family = AF_INET;

	if (inet_pton(AF_INET, ip, &addr->sin_addr) != 1) {
		fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
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

static int tun_netlink_ack(int fd)
{
	char buf[512];
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct sockaddr_nl sa;
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (recvmsg(fd, &msg, 0) < 0) {
		perror("netlink recvmsg");
		return -1;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error != 0) {
			errno = -err->error;
			perror("netlink RTM_NEWADDR");
			return -1;
		}
	}
	return 0;
}

static int tun_add_rtattr(struct nlmsghdr *nlh, size_t max_len,
                          unsigned short type, const void *data, size_t len)
{
	struct rtattr *rta;
	size_t new_len;

	new_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(RTA_LENGTH(len));
	if (new_len > max_len)
		return -1;

	rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = (unsigned short)RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = (unsigned int)new_len;
	return 0;
}

static int tun_set_ipv6(const char *dev, const char *ip, int prefix_len)
{
	struct in6_addr addr6;
	unsigned int ifindex;
	int fd;
	char reqbuf[512];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	struct sockaddr_nl sa;

	if (inet_pton(AF_INET6, ip, &addr6) != 1) {
		fprintf(stderr, "Invalid IPv6 address: %s\n", ip);
		return -1;
	}

	ifindex = if_nametoindex(dev);
	if (ifindex == 0) {
		perror("if_nametoindex");
		return -1;
	}

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0) {
		perror("socket AF_NETLINK");
		return -1;
	}

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	ifa = (struct ifaddrmsg *)(nlh + 1);

	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nlh->nlmsg_type = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
	nlh->nlmsg_seq = 1;

	ifa->ifa_family = AF_INET6;
	ifa->ifa_prefixlen = (unsigned char)prefix_len;
	ifa->ifa_flags = IFA_F_NODAD;
	ifa->ifa_scope = RT_SCOPE_UNIVERSE;
	ifa->ifa_index = ifindex;

	if (tun_add_rtattr(nlh, sizeof(reqbuf), IFA_LOCAL, &addr6, sizeof(addr6)) != 0 ||
	    tun_add_rtattr(nlh, sizeof(reqbuf), IFA_ADDRESS, &addr6, sizeof(addr6)) != 0) {
		fprintf(stderr, "netlink attribute too large\n");
		close(fd);
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	struct iovec iov = { .iov_base = reqbuf, .iov_len = nlh->nlmsg_len };
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};

	if (sendmsg(fd, &msg, 0) < 0) {
		perror("netlink sendmsg");
		close(fd);
		return -1;
	}

	if (tun_netlink_ack(fd) != 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

int rist_tun_set_ip(const char *dev, const char *ip, int prefix_len)
{
	struct in6_addr addr6;
	struct in_addr addr4;

	if (inet_pton(AF_INET6, ip, &addr6) == 1) {
		if (prefix_len < 0 || prefix_len > 128) {
			fprintf(stderr, "Invalid IPv6 prefix length: %d\n", prefix_len);
			return -1;
		}
		return tun_set_ipv6(dev, ip, prefix_len);
	}

	if (inet_pton(AF_INET, ip, &addr4) == 1) {
		if (prefix_len < 0 || prefix_len > 32) {
			fprintf(stderr, "Invalid IPv4 prefix length: %d\n", prefix_len);
			return -1;
		}
		return tun_set_ipv4(dev, ip, prefix_len);
	}

	fprintf(stderr, "Invalid IP address: %s\n", ip);
	return -1;
}

int rist_tun_set_mtu(const char *dev, int mtu)
{
	int s = tun_ioctl_socket(AF_INET);
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
	int s = tun_ioctl_socket(AF_INET);
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
