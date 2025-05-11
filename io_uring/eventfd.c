// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/eventfd.h>
#include <linux/eventpoll.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>

#include "io-wq.h"
#include "eventfd.h"

struct io_ev_fd {
	struct eventfd_ctx	*cq_ev_fd;
	unsigned int		eventfd_async;
	/* protected by ->completion_lock */
	unsigned		last_cq_tail;
	refcount_t		refs;
	atomic_t		ops;
	struct rcu_head		rcu;
};

enum {
	IO_EVENTFD_OP_SIGNAL_BIT,
};

/*
 * frees an io_ev_fd structure after an RCU grace period. releases the
 * eventfd context and deallocates the memory used by the structure.
 */
static void io_eventfd_free(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_ctx_put(ev_fd->cq_ev_fd);
	kfree(ev_fd);
}

/*
 * decreases the reference count on an io_ev_fd structure. schedules
 * it for deferred freeing via RCU when the reference count reaches zero.
 */
static void io_eventfd_put(struct io_ev_fd *ev_fd)
{
	if (refcount_dec_and_test(&ev_fd->refs))
		call_rcu(&ev_fd->rcu, io_eventfd_free);
}

/*
 * signals an eventfd from a safe context using an RCU callback. this
 * is used when the original context cannot directly signal the eventfd.
 */
static void io_eventfd_do_signal(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
	io_eventfd_put(ev_fd);
}

/*
 * releases an io_ev_fd structure after use. optionally decreases
 * the reference count if requested by the caller.
 */
static void io_eventfd_release(struct io_ev_fd *ev_fd, bool put_ref)
{
	if (put_ref)
		io_eventfd_put(ev_fd);
	rcu_read_unlock();
}

/*
 * signals an eventfd if allowed by the current context. uses an RCU
 * callback if signaling is not directly possible.
 */
static bool __io_eventfd_signal(struct io_ev_fd *ev_fd)
{
	if (eventfd_signal_allowed()) {
		eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
		return true;
	}
	if (!atomic_fetch_or(BIT(IO_EVENTFD_OP_SIGNAL_BIT), &ev_fd->ops)) {
		call_rcu_hurry(&ev_fd->rcu, io_eventfd_do_signal);
		return false;
	}
	return true;
}

/*
 * determines whether an eventfd should be triggered. checks if the
 * caller is an async worker or if eventfd_async is not set.
 */
static bool io_eventfd_trigger(struct io_ev_fd *ev_fd)
{
	if (ev_fd)
		return !ev_fd->eventfd_async || io_wq_current_is_worker();
	return false;
}

/*
 * grabs a reference to an io_ev_fd structure and holds the RCU read
 * lock. returns NULL if the eventfd is disabled or unavailable.
 */
static struct io_ev_fd *io_eventfd_grab(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	if (READ_ONCE(ctx->rings->cq_flags) & IORING_CQ_EVENTFD_DISABLED)
		return NULL;

	rcu_read_lock();

	/*
	 * rcu_dereference ctx->io_ev_fd once and use it for both for checking
	 * and eventfd_signal
	 */
	ev_fd = rcu_dereference(ctx->io_ev_fd);

	/*
	 * Check again if ev_fd exists in case an io_eventfd_unregister call
	 * completed between the NULL check of ctx->io_ev_fd at the start of
	 * the function and rcu_read_lock.
	 */
	if (io_eventfd_trigger(ev_fd) && refcount_inc_not_zero(&ev_fd->refs))
		return ev_fd;

	rcu_read_unlock();
	return NULL;
}

/*
 * signals the eventfd associated with an io_uring context. this
 * notifies the completion queue of new events being added.
 */
void io_eventfd_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd)
		io_eventfd_release(ev_fd, __io_eventfd_signal(ev_fd));
}

/*
 * signals the eventfd only if the completion queue tail has changed.
 * avoids unnecessary wakeups when no new completions are added.
 */
void io_eventfd_flush_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd) {
		bool skip, put_ref = true;

		/*
		 * Eventfd should only get triggered when at least one event
		 * has been posted. Some applications rely on the eventfd
		 * notification count only changing IFF a new CQE has been
		 * added to the CQ ring. There's no dependency on 1:1
		 * relationship between how many times this function is called
		 * (and hence the eventfd count) and number of CQEs posted to
		 * the CQ ring.
		 */
		spin_lock(&ctx->completion_lock);
		skip = ctx->cached_cq_tail == ev_fd->last_cq_tail;
		ev_fd->last_cq_tail = ctx->cached_cq_tail;
		spin_unlock(&ctx->completion_lock);

		if (!skip)
			put_ref = __io_eventfd_signal(ev_fd);

		io_eventfd_release(ev_fd, put_ref);
	}
}

/*
 * registers an eventfd for io_uring completion notifications. the
 * eventfd is identified by a file descriptor passed from user space.
 */
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async)
{
	struct io_ev_fd *ev_fd;
	__s32 __user *fds = arg;
	int fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd)
		return -EBUSY;

	if (copy_from_user(&fd, fds, sizeof(*fds)))
		return -EFAULT;

	ev_fd = kmalloc(sizeof(*ev_fd), GFP_KERNEL);
	if (!ev_fd)
		return -ENOMEM;

	ev_fd->cq_ev_fd = eventfd_ctx_fdget(fd);
	if (IS_ERR(ev_fd->cq_ev_fd)) {
		int ret = PTR_ERR(ev_fd->cq_ev_fd);

		kfree(ev_fd);
		return ret;
	}

	spin_lock(&ctx->completion_lock);
	ev_fd->last_cq_tail = ctx->cached_cq_tail;
	spin_unlock(&ctx->completion_lock);

	ev_fd->eventfd_async = eventfd_async;
	ctx->has_evfd = true;
	refcount_set(&ev_fd->refs, 1);
	atomic_set(&ev_fd->ops, 0);
	rcu_assign_pointer(ctx->io_ev_fd, ev_fd);
	return 0;
}

/*
 * unregisters a previously registered eventfd from an io_uring
 * context. returns an error if no eventfd was registered.
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = rcu_dereference_protected(ctx->io_ev_fd,
					lockdep_is_held(&ctx->uring_lock));
	if (ev_fd) {
		ctx->has_evfd = false;
		rcu_assign_pointer(ctx->io_ev_fd, NULL);
		io_eventfd_put(ev_fd);
		return 0;
	}

	return -ENXIO;
}

