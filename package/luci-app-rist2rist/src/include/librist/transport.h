/*
 * Copyright © 2024 SipRadius LLC
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef LIBRIST_TRANSPORT_H
#define LIBRIST_TRANSPORT_H

#include "common.h"
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <basetsd.h>     /* SSIZE_T; lowercase spelling for mingw cross-builds */
#ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#define _SSIZE_T_DEFINED
#endif
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct rist_ctx;

/**
 * @brief Transport operations vtable for abstracting network I/O.
 *
 * All function pointers follow POSIX socket semantics.  The default
 * implementation (used when no custom ops are installed) delegates
 * directly to the real syscalls, so existing behaviour is unchanged.
 *
 * For non-POSIX backends (e.g. WebAssembly/WebTransport, unit-test
 * harnesses, userspace network stacks) the application provides its
 * own implementations via rist_transport_set().
 *
 * @a opaque is passed as the first argument to every callback and
 * can point to arbitrary per-context state owned by the backend.
 */
struct rist_transport_ops {
	void *opaque;

	/**
	 * Send a datagram to a specific destination.
	 * Semantics match POSIX sendto(2) — returns bytes sent or -1.
	 */
	ssize_t (*sendto)(void *opaque, int fd, const void *buf, size_t len,
	                  int flags, const struct sockaddr *addr, socklen_t addrlen);

	/**
	 * Receive a datagram, capturing the source address.
	 * Semantics match POSIX recvfrom(2) — returns bytes received or -1.
	 */
	ssize_t (*recvfrom)(void *opaque, int fd, void *buf, size_t len,
	                    int flags, struct sockaddr *addr, socklen_t *addrlen);

	/**
	 * Wait for I/O readiness on a set of descriptors.
	 * Semantics match POSIX poll(2) — returns the number of ready
	 * descriptors, 0 on timeout, or -1 on error.
	 */
	int (*poll)(void *opaque, struct pollfd *fds, int nfds, int timeout_ms);

	/**
	 * Scatter-gather send (optional).
	 * Semantics match POSIX sendmsg(2).  If NULL, the library
	 * linearises the iov and falls back to the sendto callback.
	 */
#ifndef _WIN32
	ssize_t (*sendmsg)(void *opaque, int fd, const struct msghdr *msg,
	                   int flags);
#endif
};

/**
 * @brief Install custom transport operations on a RIST context.
 *
 * Must be called after rist_sender_create() / rist_receiver_create()
 * but BEFORE rist_start().  The library takes a shallow copy of @a ops;
 * the caller must keep the pointees (callbacks, opaque) alive for the
 * lifetime of @a ctx.
 *
 * Passing NULL restores the default (POSIX socket) transport.
 *
 * @param ctx   RIST sender or receiver context
 * @param ops   Transport ops to install, or NULL for defaults
 * @return 0 on success, -1 on error (e.g. context already started)
 */
RIST_API int rist_transport_set(struct rist_ctx *ctx,
                                const struct rist_transport_ops *ops);

#ifdef __cplusplus
}
#endif

#endif /* LIBRIST_TRANSPORT_H */
