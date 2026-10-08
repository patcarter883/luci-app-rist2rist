/* librist. Copyright © 2024 SipRadius LLC. All right reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "transport-private.h"
#include "rist-private.h"
#include "libevsocket.h"
#include "librist/transport.h"

#ifdef _WIN32
#if !defined(_WIN32_WINNT) || _WIN32_WINNT < 0x0600
# undef _WIN32_WINNT
# define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>

typedef unsigned long int nfds_t;
#include "contrib/poll_win.c"
#else
#include <sys/socket.h>
#include <poll.h>
#endif

#include <string.h>
#include <errno.h>

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

int rist_transport_set(struct rist_ctx *ctx,
                       const struct rist_transport_ops *ops)
{
	struct rist_common_ctx *cctx = rist_struct_get_common(ctx);
	if (!cctx)
		return -1;

	if (atomic_load_explicit(&cctx->startup_complete, memory_order_acquire)) {
		return -1;
	}

	if (ops) {
		cctx->transport = *ops;
		cctx->transport_active = true;
		if (cctx->evctx && ops->poll)
			evsocket_set_poll_override(cctx->evctx, ops->poll,
			                           ops->opaque);
	} else {
		memset(&cctx->transport, 0, sizeof(cctx->transport));
		cctx->transport_active = false;
		if (cctx->evctx)
			evsocket_set_poll_override(cctx->evctx, NULL, NULL);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* Internal wrappers                                                   */
/* ------------------------------------------------------------------ */

ssize_t rist_transport_sendto(struct rist_peer *peer,
                              const void *buf, size_t len,
                              int flags)
{
	struct rist_common_ctx *cctx = get_cctx(peer);

	if (cctx->transport_active && cctx->transport.sendto) {
		return cctx->transport.sendto(cctx->transport.opaque,
		                              peer->sd, buf, len, flags,
		                              &peer->u.address,
		                              peer->address_len);
	}

	return sendto(peer->sd, (const char *)buf, len, flags,
	              &peer->u.address, peer->address_len);
}

ssize_t rist_transport_recvfrom(struct rist_peer *peer,
                                void *buf, size_t len,
                                int flags,
                                struct sockaddr *addr,
                                socklen_t *addrlen)
{
	struct rist_common_ctx *cctx = get_cctx(peer);

	if (cctx->transport_active && cctx->transport.recvfrom) {
		return cctx->transport.recvfrom(cctx->transport.opaque,
		                                peer->sd, buf, len, flags,
		                                addr, addrlen);
	}

	return recvfrom(peer->sd, (char *)buf, len, flags, addr, addrlen);
}

int rist_transport_poll(struct rist_common_ctx *ctx,
                        struct pollfd *fds, int nfds,
                        int timeout_ms)
{
	if (ctx->transport_active && ctx->transport.poll) {
		return ctx->transport.poll(ctx->transport.opaque,
		                           fds, nfds, timeout_ms);
	}

	return poll(fds, nfds, timeout_ms);
}

#ifndef _WIN32
ssize_t rist_transport_sendmsg(struct rist_peer *peer,
                               const struct msghdr *msg,
                               int flags)
{
	struct rist_common_ctx *cctx = get_cctx(peer);

	if (cctx->transport_active && cctx->transport.sendmsg) {
		return cctx->transport.sendmsg(cctx->transport.opaque,
		                               peer->sd, msg, flags);
	}

	/* If custom transport is active but sendmsg is NULL, linearise
	 * and fall back to the sendto callback. */
	if (cctx->transport_active && cctx->transport.sendto) {
		size_t total = 0;
		for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++)
			total += msg->msg_iov[i].iov_len;

		uint8_t stackbuf[RIST_MAX_PACKET_SIZE + 128];
		uint8_t *flat = (total <= sizeof(stackbuf)) ? stackbuf : malloc(total);
		if (!flat)
			return -1;

		size_t off = 0;
		for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
			memcpy(flat + off, msg->msg_iov[i].iov_base,
			       msg->msg_iov[i].iov_len);
			off += msg->msg_iov[i].iov_len;
		}

		ssize_t ret = cctx->transport.sendto(
			cctx->transport.opaque, peer->sd,
			flat, total, flags,
			msg->msg_name, msg->msg_namelen);

		if (flat != stackbuf)
			free(flat);

		return ret;
	}

	return sendmsg(peer->sd, msg, flags);
}
#endif
