/* librist. Copyright © 2020 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/udpsocket.h"
#include "log-private.h"
#include "pthread-shim.h"
#ifdef _WIN32
#include <ws2ipdef.h>
#include <mstcpip.h>
#ifndef MCAST_JOIN_GROUP
#define MCAST_JOIN_GROUP 41
#endif
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 45
#endif
/* SIO_UDP_CONNRESET lives in mstcpip.h but some MinGW SDKs are stale; the
 * IOCTL code itself is stable (XP+). Provide a fallback definition. */
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#endif

/* Private functions */
static const int yes = 1; // no = 0;

#ifdef _WIN32
/* WSAStartup must run before the first socket()/getaddrinfo() call in the
 * process. init_common_ctx() does it for code paths that go through
 * rist_sender_create()/rist_receiver_create(), but tools can hit
 * udpsocket_open_connect() earlier via rist_logging_set() (e.g. when
 * ristreceiver -r is used to forward stats over UDP). Initialise here on
 * first use, guarded by InitOnceExecuteOnce / pthread_once so concurrent
 * callers don't race. WSAStartup is ref-counted by Windows, so the
 * duplicate call from init_common_ctx (kept for backwards-compat with
 * out-of-tree callers that link directly against rist-common.c) is
 * harmless. */

#if !defined(_WIN32) || HAVE_PTHREADS
#if defined(__GNU__)
static pthread_once_t winsock_init_once = {__PTHREAD_ONCE_INIT};
#else
static pthread_once_t winsock_init_once = PTHREAD_ONCE_INIT;
#endif
#endif
#if defined(_WIN32) && !HAVE_PTHREADS
static INIT_ONCE winsock_init_once = INIT_ONCE_STATIC_INIT;
#endif

#if HAVE_PTHREADS
static void _librist_udpsocket_init_winsock_func(void)
#else
static BOOL WINAPI _librist_udpsocket_init_winsock_func(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context)
#endif
{
	WSADATA wsaData;
	int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (ret != 0) {
		rist_log_priv3(RIST_LOG_ERROR, "WSAStartup failed: %d\n", ret);
	}
#if !HAVE_PTHREADS
	return TRUE;
#endif
}

static void _librist_udpsocket_init_winsock(void)
{
#if HAVE_PTHREADS
	pthread_once(&winsock_init_once, _librist_udpsocket_init_winsock_func);
#else
	InitOnceExecuteOnce(&winsock_init_once, _librist_udpsocket_init_winsock_func, NULL, NULL);
#endif
}
#else
static inline void _librist_udpsocket_init_winsock(void) { }
#endif

/* Public API */

int udpsocket_resolve_host(const char *host, uint16_t port, struct sockaddr *addr)
{
	struct sockaddr_in *a4 = (struct sockaddr_in *)addr;
	struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)addr;

	_librist_udpsocket_init_winsock();

	/* Pre-check for numeric IPv6 */
	if (inet_pton(AF_INET6, host, &a6->sin6_addr) > 0) {
		a6->sin6_family = AF_INET6;
		a6->sin6_port = htons(port);
	}
	/* Pre-check for numeric IPv4 */
	else if (inet_pton(AF_INET, host, &a4->sin_addr) > 0) {
		a4->sin_family = AF_INET;
		a4->sin_port = htons(port);
		/* Try to resolve host */
	} else {
		struct addrinfo *res;
		int gai_ret = getaddrinfo(host, NULL, NULL, &res);
		if (gai_ret != 0) {
			rist_log_priv3( RIST_LOG_ERROR, "Failure resolving host %s: %s\n", host, gai_strerror(gai_ret));
			return -1;
		}
		if (res[0].ai_family == AF_INET6) {
			memcpy(a6, res[0].ai_addr, sizeof(struct sockaddr_in6));
			a6->sin6_port = htons(port);
		} else {
			memcpy(a4, res[0].ai_addr, sizeof(struct sockaddr_in));
			a4->sin_port = htons(port);
		}
		freeaddrinfo(res);
	}
	return 0;
}

/* Set IP-level "don't fragment" so the kernel surfaces EMSGSIZE when our
 * UDP datagrams exceed the path MTU, instead of silently IP-fragmenting
 * them and watching the fragments black-hole at an intermediate router.
 * This matches the behaviour of every other modern UDP transport.
 *
 * Best-effort: any platform that does not understand the option keeps the
 * default (fragmenting) behaviour. We log the failure so it is visible. */
void udpsocket_set_dontfragment(int sd, uint16_t af)
{
#if defined(__linux__) && defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
	if (af == AF_INET) {
		int val = IP_PMTUDISC_DO;
		if (setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IP_MTU_DISCOVER=DO) failed: %s; oversized "
				"datagrams may be silently IP-fragmented\n", strerror(errno));
	}
#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_DO)
	else if (af == AF_INET6) {
		int val = IPV6_PMTUDISC_DO;
		if (setsockopt(sd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(val)) < 0)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IPV6_MTU_DISCOVER=DO) failed: %s\n", strerror(errno));
	}
#endif
#elif defined(_WIN32) && defined(IP_DONTFRAGMENT)
	DWORD val = 1;
	if (af == AF_INET) {
		if (setsockopt(sd, IPPROTO_IP, IP_DONTFRAGMENT,
		               (const char *)&val, sizeof(val)) == SOCKET_ERROR)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IP_DONTFRAGMENT) failed: WSAGetLastError=%d\n",
				WSAGetLastError());
	}
#if defined(IPV6_DONTFRAG)
	else if (af == AF_INET6) {
		if (setsockopt(sd, IPPROTO_IPV6, IPV6_DONTFRAG,
		               (const char *)&val, sizeof(val)) == SOCKET_ERROR)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IPV6_DONTFRAG) failed: WSAGetLastError=%d\n",
				WSAGetLastError());
	}
#endif
#elif defined(IP_DONTFRAG)
	int val = 1;
	if (af == AF_INET) {
		if (setsockopt(sd, IPPROTO_IP, IP_DONTFRAG, &val, sizeof(val)) < 0)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IP_DONTFRAG) failed: %s\n", strerror(errno));
	}
#if defined(IPV6_DONTFRAG)
	else if (af == AF_INET6) {
		if (setsockopt(sd, IPPROTO_IPV6, IPV6_DONTFRAG, &val, sizeof(val)) < 0)
			rist_log_priv3(RIST_LOG_WARN,
				"setsockopt(IPV6_DONTFRAG) failed: %s\n", strerror(errno));
	}
#endif
#else
	(void)sd; (void)af;
#endif
}

int udpsocket_set_mcast_ttl(int sd, uint16_t af, uint32_t ttl)
{
	if (ttl == 0)
		return 0;
	if (af == AF_INET6) {
#ifdef IPV6_MULTICAST_HOPS
		int hops = (int)ttl;
		if (setsockopt(sd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (const char *)&hops, sizeof(hops)) < 0) {
#ifdef _WIN32
			rist_log_priv3(RIST_LOG_WARN, "setsockopt(IPV6_MULTICAST_HOPS) failed: WSAGetLastError=%d\n", WSAGetLastError());
#else
			rist_log_priv3(RIST_LOG_WARN, "setsockopt(IPV6_MULTICAST_HOPS) failed: %s\n", strerror(errno));
#endif
			return -1;
		}
#else
		(void)sd; (void)ttl;
#endif
	} else {
#ifdef IP_MULTICAST_TTL
		int val = (int)ttl;
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, (const char *)&val, sizeof(val)) < 0) {
#ifdef _WIN32
			rist_log_priv3(RIST_LOG_WARN, "setsockopt(IP_MULTICAST_TTL) failed: WSAGetLastError=%d\n", WSAGetLastError());
#else
			rist_log_priv3(RIST_LOG_WARN, "setsockopt(IP_MULTICAST_TTL) failed: %s\n", strerror(errno));
#endif
			return -1;
		}
#else
		(void)sd; (void)ttl;
#endif
	}
	return 0;
}

int udpsocket_open(uint16_t af)
{
	_librist_udpsocket_init_winsock();
	int sd = socket(af, SOCK_DGRAM, 0);
	if (sd < 0) {
#ifdef _WIN32
		sd = -1 * WSAGetLastError();
#endif
		return sd;
	}
#ifdef _WIN32
	/* Disable the synthetic WSAECONNRESET indication that Windows enqueues
	 * on a UDP socket when an outbound packet provokes an ICMP
	 * port-unreachable reply. The indication has a long-standing data-loss
	 * footgun: the error sits in the recv queue and, on some orderings,
	 * the next recvfrom() drains a real datagram alongside it (or returns
	 * WSAEMSGSIZE and silently consumes one whole datagram). librist
	 * already detects peer loss via RTCP keepalive timeouts, so we don't
	 * need this signal. See rist/librist#209. */
	BOOL connreset_new_behavior = FALSE;
	DWORD connreset_bytes = 0;
	if (WSAIoctl(sd, SIO_UDP_CONNRESET,
	             &connreset_new_behavior, sizeof(connreset_new_behavior),
	             NULL, 0, &connreset_bytes, NULL, NULL) == SOCKET_ERROR) {
		rist_log_priv3(RIST_LOG_WARN,
			"WSAIoctl(SIO_UDP_CONNRESET, FALSE) failed: WSAGetLastError=%d; "
			"WSAECONNRESET indications remain enabled\n",
			WSAGetLastError());
	}
#endif
	return sd;
}

int udpsocket_set_optimal_buffer_size(int sd)
{
	/* Request the OS-allowed maximum; the kernel clamps to net.core.rmem_max. */
	uint32_t current_recvbuf = udpsocket_get_buffer_size(sd);
	uint32_t bufsize = UDPSOCKET_SOCK_BUFSIZE_MAX;
	if (current_recvbuf < bufsize){
		setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t));
		current_recvbuf = udpsocket_get_buffer_size(sd);
#if defined(SO_RCVBUFFORCE)
		if (current_recvbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_RCVBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_recvbuf = udpsocket_get_buffer_size(sd);
		}
#endif
	}
	/* A clamped result above the 1 MB floor is fine; only fall back below it. */
	if (current_recvbuf < UDPSOCKET_SOCK_BUFSIZE){
		// Settle for a smaller size
		bufsize = UDPSOCKET_SOCK_BUFSIZE/5;
		setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t));
		current_recvbuf = udpsocket_get_buffer_size(sd);
#if defined(SO_RCVBUFFORCE)
		if (current_recvbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_RCVBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_recvbuf = udpsocket_get_buffer_size(sd);
		}
#endif
		if (current_recvbuf < bufsize){
			rist_log_priv3( RIST_LOG_ERROR, "Your UDP receive buffer is set < 200 kbytes (%"PRIu32") and the kernel denied our request for an increase. It's recommended to set your net.core.rmem_max setting to at least 200 kbyte for best results.", current_recvbuf);
			return -1;
		}
	}
	return 0;
}

int udpsocket_set_optimal_buffer_send_size(int sd)
{
	/* Mirror the recv path: request the OS max, clamp to net.core.wmem_max. */
	uint32_t current_sendbuf = udpsocket_get_buffer_send_size(sd);
	uint32_t bufsize = UDPSOCKET_SOCK_BUFSIZE_MAX;
	if (current_sendbuf < bufsize){
		setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t));
		current_sendbuf = udpsocket_get_buffer_send_size(sd);
#if defined(SO_SNDBUFFORCE)
		if (current_sendbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_SNDBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_sendbuf = udpsocket_get_buffer_send_size(sd);
		}
#endif
	}
	if (current_sendbuf < UDPSOCKET_SOCK_BUFSIZE){
		// Settle for a smaller size
		bufsize = UDPSOCKET_SOCK_BUFSIZE/5;
		setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t));
		current_sendbuf = udpsocket_get_buffer_send_size(sd);
#if defined(SO_SNDBUFFORCE)
		if (current_sendbuf < bufsize){
			setsockopt(sd, SOL_SOCKET, SO_SNDBUFFORCE, (char *)&bufsize, sizeof(uint32_t));
			current_sendbuf = udpsocket_get_buffer_send_size(sd);
		}
#endif
		if (current_sendbuf < bufsize){
			rist_log_priv3( RIST_LOG_ERROR, "Your UDP send buffer is set < 200 kbytes (%"PRIu32") and the kernel denied our request for an increase. It's recommended to set your net.core.wmem_max setting to at least 200 kbyte for best results.", current_sendbuf);
			return -1;
		}
	}
	return 0;
}

int udpsocket_set_buffer_size(int sd, uint32_t bufsize)
{
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, sizeof(uint32_t)) < 0)
		return -1;
	return 0;
}

int udpsocket_set_buffer_send_size(int sd, uint32_t bufsize)
{
	if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, sizeof(uint32_t)) < 0)
		return -1;
	return 0;
}

uint32_t udpsocket_get_buffer_size(int sd)
{
	uint32_t bufsize;
	socklen_t val_size = sizeof(uint32_t);
	if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *)&bufsize, &val_size) < 0)
		return 0;
	return bufsize;
}

uint32_t udpsocket_get_buffer_send_size(int sd)
{
	uint32_t bufsize;
	socklen_t val_size = sizeof(uint32_t);
	if (getsockopt(sd, SOL_SOCKET, SO_SNDBUF, (char *)&bufsize, &val_size) < 0)
		return 0;
	return bufsize;
}

int udpsocket_set_mcast_iface(int sd, const char *mciface, uint16_t family)
{
#ifndef _WIN32
	int scope = if_nametoindex(mciface);
#else
	int scope = atoi(mciface);
#endif
	if (scope == 0)
		return -1;
#ifdef _WIN32
	RIST_MARK_UNUSED(family);
	return setsockopt(sd, SOL_IP, IP_MULTICAST_IF, (char *)&scope, sizeof(scope));
#else
	if (family == AF_INET6) {
		return setsockopt(sd, SOL_IPV6, IPV6_MULTICAST_IF, &scope, sizeof(scope));
	} else {
		struct ip_mreqn req = { .imr_ifindex = scope };
		return setsockopt(sd, SOL_IP, IP_MULTICAST_IF, &req, sizeof(req));
	}
	return -1;
#endif
}

bool is_ip_address(const char *ipaddress, int family) {
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} buf;
	return inet_pton(family, ipaddress, &buf) == 1;
}

int udpsocket_join_mcast_group(int sd, const char* miface, struct sockaddr* sa, uint16_t family, const char *ssm_source) {
	char mcastaddress[INET6_ADDRSTRLEN];
	uint32_t src_addr = htonl(INADDR_ANY);
	int ifindex = 0;

	if (miface != NULL && miface[0] != '\0') {
		if (is_ip_address(miface, AF_INET)) {
			inet_pton(AF_INET, miface, &src_addr);
		} else {
#ifndef _WIN32
			ifindex = if_nametoindex(miface);
#else
			ifindex = atoi(miface);
#endif
			if (!ifindex) {
				rist_log_priv3(RIST_LOG_ERROR, "Failed to get interface index error: %s\n", strerror(errno));
				rist_log_priv3(RIST_LOG_INFO, "Falling back to joining via default route\n");
			}
		}
	}

	if (family == AF_INET6) {
		struct sockaddr_in6 *mcast_v6 = (struct sockaddr_in6 *)sa;
		inet_ntop(AF_INET6, &mcast_v6->sin6_addr, mcastaddress, INET6_ADDRSTRLEN);
#ifdef MCAST_JOIN_GROUP
		struct group_req gr;
		memset(&gr, 0, sizeof(gr));
		gr.gr_interface = ifindex;
		memcpy(&gr.gr_group, sa, sizeof(struct sockaddr_in6));
		rist_log_priv3(RIST_LOG_INFO, "Joining IPv6 multicast address: %s\n", mcastaddress);
		if (setsockopt(sd, IPPROTO_IPV6, MCAST_JOIN_GROUP, (const char *)&gr, sizeof(gr)) == 0)
			return 0;
#endif
#ifdef IPV6_JOIN_GROUP
		{
			struct ipv6_mreq mreq6;
			memcpy(&mreq6.ipv6mr_multiaddr, &mcast_v6->sin6_addr, sizeof(mreq6.ipv6mr_multiaddr));
			mreq6.ipv6mr_interface = ifindex;
			if (setsockopt(sd, IPPROTO_IPV6, IPV6_JOIN_GROUP, (const char *)&mreq6, sizeof(mreq6)) < 0) {
#ifdef _WIN32
				rist_log_priv3(RIST_LOG_ERROR, "Failed to join IPv6 multicast group: WSAGetLastError=%d\n", WSAGetLastError());
#else
				rist_log_priv3(RIST_LOG_ERROR, "Failed to join IPv6 multicast group: %s\n", strerror(errno));
#endif
				return -1;
			}
			return 0;
		}
#endif
		rist_log_priv3(RIST_LOG_ERROR, "IPv6 multicast join not supported on this platform\n");
		return -1;
	}

	/* IPv4 path */
	struct sockaddr_in *mcast_v4 = (struct sockaddr_in *)sa;
	inet_ntop(AF_INET, &(mcast_v4->sin_addr), mcastaddress, INET_ADDRSTRLEN);

	/* SSM (source-specific multicast) when ssm_source is provided */
	if (ssm_source != NULL && ssm_source[0] != '\0') {
#ifdef IP_ADD_SOURCE_MEMBERSHIP
		struct ip_mreq_source mreqs;
		memset(&mreqs, 0, sizeof(mreqs));
		mreqs.imr_multiaddr = mcast_v4->sin_addr;
		mreqs.imr_interface.s_addr = src_addr;
		if (inet_pton(AF_INET, ssm_source, &mreqs.imr_sourceaddr) != 1) {
			rist_log_priv3(RIST_LOG_ERROR, "Invalid SSM source address: %s\n", ssm_source);
			return -1;
		}
		rist_log_priv3(RIST_LOG_INFO, "SSM join: group %s source %s\n", mcastaddress, ssm_source);
		if (setsockopt(sd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, (const char *)&mreqs, sizeof(mreqs)) < 0) {
#ifdef _WIN32
			rist_log_priv3(RIST_LOG_ERROR, "Failed to join SSM group (IP_ADD_SOURCE_MEMBERSHIP): WSAGetLastError=%d\n", WSAGetLastError());
#else
			rist_log_priv3(RIST_LOG_ERROR, "Failed to join SSM group (IP_ADD_SOURCE_MEMBERSHIP): %s\n", strerror(errno));
#endif
			return -1;
		}
		return 0;
#else
		rist_log_priv3(RIST_LOG_ERROR, "SSM (source-specific multicast) not supported on this platform\n");
		return -1;
#endif
	}

	/* ASM (any-source multicast) */
#ifdef MCAST_JOIN_GROUP
	if (ifindex) {
		struct group_req gr;
		memset(&gr, 0, sizeof(gr));
		gr.gr_interface = ifindex;
		memcpy(&gr.gr_group, mcast_v4, sizeof(*mcast_v4));
		rist_log_priv3(RIST_LOG_INFO, "Joining multicast address: %s with %s\n", mcastaddress, miface);
		if (setsockopt(sd, SOL_IP, MCAST_JOIN_GROUP, (const char *)&gr, sizeof(gr)) == 0) {
			return 0;
		}
	}
#endif
	{
		char address[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET, &(src_addr), address, INET_ADDRSTRLEN);
		rist_log_priv3(RIST_LOG_INFO, "Joining multicast address: %s from IP %s\n", mcastaddress, address);
	}
	struct ip_mreq group;
	group.imr_multiaddr.s_addr = mcast_v4->sin_addr.s_addr;
	group.imr_interface.s_addr = src_addr;
	if (setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
		rist_log_priv3(RIST_LOG_ERROR, "Failed to join multicast group\n");
		return -1;
	}
	return 0;
}

int udpsocket_open_connect(const char *host, uint16_t port, const char *mciface)
{
	int sd;
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	uint16_t proto;
	uint32_t ttlcmd;
	const uint32_t ttl = UDPSOCKET_MAX_HOPS;

	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	sd = udpsocket_open(raw.sin6_family);
	if (sd < 0)
		return sd;

	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		proto = IPPROTO_IPV6;
		ttlcmd = IPV6_MULTICAST_HOPS;
	} else {
		addrlen = sizeof(struct sockaddr_in);
		proto = IPPROTO_IP;
		ttlcmd = IP_MULTICAST_TTL;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(int)) < 0) {
		/* Non-critical error */
#ifdef _WIN32
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set SO_REUSEADDR: WSAGetLastError=%d\n", WSAGetLastError());
#else
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set SO_REUSEADDR: %s\n", strerror(errno));
#endif
	}
	if (setsockopt(sd, proto, ttlcmd, (char *)&ttl, sizeof(ttl)) < 0) {
		/* Non-critical error */
#ifdef _WIN32
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set socket MAX HOPS: WSAGetLastError=%d\n", WSAGetLastError());
#else
		rist_log_priv3( RIST_LOG_ERROR,"Cannot set socket MAX HOPS: %s\n", strerror(errno));
#endif
	}
	if (mciface && mciface[0] != '\0')
		udpsocket_set_mcast_iface(sd, mciface, raw.sin6_family);

	if (connect(sd, (struct sockaddr *)&raw, addrlen) < 0) {
#ifdef _WIN32
		int winerr = WSAGetLastError();
		rist_log_priv3( RIST_LOG_ERROR, "connect() failed: WSAGetLastError=%d\n", winerr);
		udpsocket_close(sd);
		return -1;
#else
		int err = errno;
		udpsocket_close(sd);
		errno = err;
		return -1;
#endif
	}
	udpsocket_set_dontfragment(sd, raw.sin6_family);

	return sd;
}

int udpsocket_open_bind_mcast(const char *host, uint16_t port, const char *mciface,
                               uint32_t ttl, const char *ssm_source)
{
	int sd;
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	sd = udpsocket_open(raw.sin6_family);
	if (sd < 0)
		return sd;

	int is_multicast = 0;
	if (raw.sin6_family == AF_INET6) {
		addrlen = sizeof(struct sockaddr_in6);
		is_multicast = IN6_IS_ADDR_MULTICAST(&raw.sin6_addr);
	} else {
		struct sockaddr_in *tmp = (struct sockaddr_in*)&raw;
		addrlen = sizeof(struct sockaddr_in);
		is_multicast = IN_MULTICAST(ntohl(tmp->sin_addr.s_addr));
	}
	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(int)) < 0) {
#ifdef _WIN32
		rist_log_priv3(RIST_LOG_ERROR, "Cannot set SO_REUSEADDR: WSAGetLastError=%d\n", WSAGetLastError());
#else
		rist_log_priv3(RIST_LOG_ERROR, "Cannot set SO_REUSEADDR: %s\n", strerror(errno));
#endif
	}
	if (bind(sd, (struct sockaddr *)&raw, addrlen) < 0) {
#ifdef _WIN32
		rist_log_priv3(RIST_LOG_ERROR, "Could not bind to interface: WSAGetLastError=%d\n", WSAGetLastError());
#else
		rist_log_priv3(RIST_LOG_ERROR, "Could not bind to interface: %s\n", strerror(errno));
#endif
		udpsocket_close(sd);
		return -1;
	}
	udpsocket_set_dontfragment(sd, raw.sin6_family);
	if (is_multicast) {
		if (ttl > 0)
			udpsocket_set_mcast_ttl(sd, raw.sin6_family, ttl);
		if (udpsocket_join_mcast_group(sd, mciface, (struct sockaddr *)&raw, raw.sin6_family, ssm_source) != 0) {
			rist_log_priv3(RIST_LOG_ERROR, "Could not join multicast group: %s on %s\n", host, mciface);
			udpsocket_close(sd);
			return -1;
		}
	}
	return sd;
}

int udpsocket_open_bind(const char *host, uint16_t port, const char *mciface)
{
	return udpsocket_open_bind_mcast(host, port, mciface, 0, NULL);
}

int udpsocket_set_nonblocking(int sd)
{
#ifdef _WIN32
	u_long iMode=1;
	if (ioctlsocket(sd, FIONBIO, &iMode) != 0) {
		rist_log_priv3(RIST_LOG_WARN, "ioctlsocket(FIONBIO) failed: WSAGetLastError=%d\n", WSAGetLastError());
		return -1;
	}
#else
	RIST_MARK_UNUSED(sd);
#endif
	return 0;
}

int udpsocket_send_nonblocking(int sd, const void *buf, size_t size)
{
	return (int)send(sd, buf, size, MSG_DONTWAIT);
}

int udpsocket_send(int sd, const void *buf, size_t size)
{
	return (int)send(sd, buf, size, 0);
}

int udpsocket_sendto(int sd, const void *buf, size_t size, const char *host, uint16_t port)
{
	struct sockaddr_in6 raw;
	uint16_t addrlen;
	if (udpsocket_resolve_host(host, port, (struct sockaddr *)&raw) < 0)
		return -1;

	if (raw.sin6_family == AF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else
		addrlen = sizeof(struct sockaddr_in);
	return (int)sendto(sd, buf, size, 0, (struct sockaddr *)(&raw), addrlen);
}

int udpsocket_recv(int sd, void *buf, size_t size)
{
	return (int)recv(sd, buf, size, 0);
}

int udpsocket_recvfrom(int sd, void *buf, size_t size, int flags, struct sockaddr *addr, socklen_t *addr_len)
{
	return (int)recvfrom(sd, buf, size, flags, addr, addr_len);
}

int udpsocket_close(int sd)
{
#ifndef _WIN32
	return close(sd);
#else
	return closesocket(sd);
#endif
}

int udpsocket_parse_url_parameters(char *url, udpsocket_url_param_t *params, int max_params,
	uint32_t *clean_url_len)
{
	const char* query = NULL;
	int i = 0;
	char *token = NULL;

	query = strchr( url, '?' );
	if (query != NULL)
		*clean_url_len = (uint32_t)(query - url + 1);
	else
		*clean_url_len = (uint32_t)(strlen(url) + 1);

	if (!query || *query == '\0')
		return -1;
	if (!params || max_params == 0)
		return 0;

	const char amp[2] = "&";
	token = strtok( (char*)query + 1, amp );
	while (token != NULL && i < max_params) {
		params[i].key = token;
		params[i].val = NULL;
		if ((params[i].val = strchr( params[i].key, '=' )) != NULL) {
			size_t val_len = strlen( params[i].val );
			*(params[i].val) = '\0';
			if (val_len > 1) {
				params[i].val++;
				if (params[i].key[0])
					i++;
			};
		}
		token = strtok( NULL, amp );
	}
	return i;
}

int udpsocket_parse_url(char *url, char *address, int address_maxlen, uint16_t *port, int *local)
{
	char *p_port = NULL, *p_addr = (char *)url;
	int using_sqbrkts = 0;
	char *p;
	if (!url)
		return -1;

	p = url;
	if (strlen(p) < 1)
		return -1;

	while (1) {
		char *p_slash;
		p_slash = strchr(p, '/');
		if (!p_slash)
			break;
		p = p_slash + 1;
	}
	p_addr = p;
	if (*p_addr == '@') {
		*local = 1;
		p_addr++;
	} else
		*local = 0;

	if (*p_addr == '[') {
		using_sqbrkts = 1;
		p_addr++;
	}
	p = p_addr;
	if (using_sqbrkts) {
		char *p_end;
		p_end = strchr(p, ']');
		if (!p_end)
			return -1;
		*p_end = 0;
		p = p_end + 1;
	}
	p_port = strchr(p, ':');
	if (p_port) {
		*p_port = 0;
		p_port++;
	}
	if (p_port && (strlen(p_port) > 0))
		*port = (uint16_t)atoi(p_port);

	if (strlen(p_addr) > 0) {
		strncpy(address, p_addr, address_maxlen);
		address[address_maxlen - 1] = '\0';
	} else if ( !using_sqbrkts) {
		sprintf(address, "0.0.0.0");
	} else {
		sprintf(address, "::");
	}
	return 0;
}
