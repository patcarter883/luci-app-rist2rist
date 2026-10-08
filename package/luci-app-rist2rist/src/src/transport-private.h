/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef RIST_TRANSPORT_PRIVATE_H
#define RIST_TRANSPORT_PRIVATE_H

/* struct pollfd for the rist_transport_poll() prototype below, gated on
 * _WIN32_WINNT >= 0x0600 in mingw-w64.  Mirrors src/libevsocket.c. */
#ifdef _WIN32
# if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
#  undef _WIN32_WINNT
#  define _WIN32_WINNT 0x0600
# endif
# include <winsock2.h>
#else
# include <poll.h>
#endif

#include "common/attributes.h"
#include "librist/transport.h"

#include <stddef.h>

struct rist_peer;
struct rist_common_ctx;

/**
 * Wrappers that route through the transport ops vtable when one is
 * installed, falling back to the real POSIX syscalls otherwise.
 * These are the ONLY functions that should touch the wire in the
 * library hot-path — raw sendto/recvfrom/poll/sendmsg calls must
 * not appear anywhere else.
 */

RIST_PRIV ssize_t rist_transport_sendto(struct rist_peer *peer,
                                        const void *buf, size_t len,
                                        int flags);

RIST_PRIV ssize_t rist_transport_recvfrom(struct rist_peer *peer,
                                          void *buf, size_t len,
                                          int flags,
                                          struct sockaddr *addr,
                                          socklen_t *addrlen);

RIST_PRIV int rist_transport_poll(struct rist_common_ctx *ctx,
                                  struct pollfd *fds, int nfds,
                                  int timeout_ms);

#ifndef _WIN32
RIST_PRIV ssize_t rist_transport_sendmsg(struct rist_peer *peer,
                                         const struct msghdr *msg,
                                         int flags);
#endif

#endif /* RIST_TRANSPORT_PRIVATE_H */
