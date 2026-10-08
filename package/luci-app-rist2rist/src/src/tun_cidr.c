/* librist. Copyright © 2026 SipRadius LLC. All right reserved.
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "librist/tun.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <stdlib.h>
#include <string.h>

int rist_tun_parse_cidr(const char *cidr, char *ip_out, size_t ip_len, int *prefix_out)
{
	const char *slash;
	size_t ip_part_len;
	int prefix;
	int family;

	if (!cidr || !ip_out || ip_len == 0 || !prefix_out)
		return -1;

	slash = strchr(cidr, '/');
	if (!slash) {
		if (strlen(cidr) >= ip_len)
			return -1;
		strncpy(ip_out, cidr, ip_len - 1);
		ip_out[ip_len - 1] = '\0';
		prefix = strchr(cidr, ':') ? 128 : 32;
	} else {
		ip_part_len = (size_t)(slash - cidr);
		if (ip_part_len == 0 || ip_part_len >= ip_len)
			return -1;
		memcpy(ip_out, cidr, ip_part_len);
		ip_out[ip_part_len] = '\0';
		prefix = atoi(slash + 1);
	}

	if (strchr(ip_out, ':') != NULL)
		family = AF_INET6;
	else
		family = AF_INET;

	if (family == AF_INET6) {
		struct in6_addr addr6;

		if (inet_pton(AF_INET6, ip_out, &addr6) != 1)
			return -1;
		if (prefix < 0 || prefix > 128)
			return -1;
	} else {
		struct in_addr addr4;

		if (inet_pton(AF_INET, ip_out, &addr4) != 1)
			return -1;
		if (prefix < 0 || prefix > 32)
			return -1;
	}

	*prefix_out = prefix;
	return 0;
}
