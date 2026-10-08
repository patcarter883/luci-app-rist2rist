/* librist. Copyright © 2019 SipRadius LLC. All right reserved.
 * Author: Daniele Lacamera <root@danielinux.net>
 * Author: Sergio Ammirata, Ph.D. <sergio@ammirata.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __LIBEVSOCKET
#define __LIBEVSOCKET

#include "common/attributes.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <poll.h>
#endif

struct evsocket_event;
struct evsocket_ctx;

typedef int (*evsocket_poll_func)(void *opaque, struct pollfd *fds,
                                  int nfds, int timeout_ms);

RIST_PRIV void evsocket_set_poll_override(struct evsocket_ctx *ctx,
                                          evsocket_poll_func func,
                                          void *opaque);

#endif

