/* SPDX-License-Identifier: GPL-2.0 */

#ifndef IOU_NAPI_H
#define IOU_NAPI_H

#include <linux/kernel.h>
#include <linux/io_uring.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL

// Initializes NAPI (Network API) context for the given IO ring context
void io_napi_init(struct io_ring_ctx *ctx);
// Frees NAPI (Network API) resources associated with the ring context
void io_napi_free(struct io_ring_ctx *ctx);

// Registers NAPI for the given ring context using user-provided configuration
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);
// Unregisters previously registered NAPI for the given ring context
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);

// Adds a NAPI ID to the ring context's busy poll list and hash table
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);

// Performs busy-loop polling on NAPI-enabled devices to optimize network performance
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);
// Executes busy polling for SQ poll thread when NAPI is registered
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

// Checks if the context has any NAPI entries registered
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return !list_empty(&ctx->napi_list);
}

// Wrapper function that calls __io_napi_busy_loop if NAPI is enabled for the context
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
	if (!io_napi(ctx))
		return;
	__io_napi_busy_loop(ctx, iowq);
}

/*
 * io_napi_add() - Add napi id to the busy poll list
 * @req: pointer to io_kiocb request
 *
 * Add the napi id of the socket to the napi busy poll list and hash table.
 */
// Extracts and adds the NAPI ID from a socket associated with the request to the busy poll list
static inline void io_napi_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct socket *sock;

	if (READ_ONCE(ctx->napi_track_mode) != IO_URING_NAPI_TRACKING_DYNAMIC)
		return;

	sock = sock_from_file(req->file);
	if (sock && sock->sk)
		__io_napi_add_id(ctx, READ_ONCE(sock->sk->sk_napi_id));
}

#else

// No-op implementation when CONFIG_NET_RX_BUSY_POLL is not defined
static inline void io_napi_init(struct io_ring_ctx *ctx)
{
}
// No-op implementation when CONFIG_NET_RX_BUSY_POLL is not defined
static inline void io_napi_free(struct io_ring_ctx *ctx)
{
}
// Returns EOPNOTSUPP error when CONFIG_NET_RX_BUSY_POLL is not defined
static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
// Returns EOPNOTSUPP error when CONFIG_NET_RX_BUSY_POLL is not defined
static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
// Always returns false when CONFIG_NET_RX_BUSY_POLL is not defined
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return false;
}
// No-op implementation when CONFIG_NET_RX_BUSY_POLL is not defined
static inline void io_napi_add(struct io_kiocb *req)
{
}
// No-op implementation when CONFIG_NET_RX_BUSY_POLL is not defined
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
}
// Always returns 0 when CONFIG_NET_RX_BUSY_POLL is not defined
static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

#endif
