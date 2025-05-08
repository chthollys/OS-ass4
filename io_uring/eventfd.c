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

/**
 * struct io_ev_fd - Structure containing eventfd context and state
 * @cq_ev_fd: Pointer to eventfd context for completion queue notifications
 * @eventfd_async: Flag controlling whether notifications should be sent from async context
 * @last_cq_tail: Last observed completion queue tail position (protected by completion_lock)
 * @refs: Reference counter tracking active users of this eventfd
 * @ops: Atomic flags for tracking pending operations on the eventfd
 * @rcu: RCU head for deferred freeing of the structure
 *
 * This structure maintains the state for a registered eventfd notification
 * mechanism used to signal I/O completions in io_uring.
 */
struct io_ev_fd {
	struct eventfd_ctx	*cq_ev_fd;
	unsigned int		eventfd_async;
	/* protected by ->completion_lock */
	unsigned		last_cq_tail;
	refcount_t		refs;
	atomic_t		ops;
	struct rcu_head		rcu;
};

/**
 * enum io_eventfd_op_bits - Bit flags for tracking eventfd operations
 * @IO_EVENTFD_OP_SIGNAL_BIT: Indicates a pending eventfd signal operation
 *
 * These flags track operations that are in progress on the eventfd.
 */
enum {
	IO_EVENTFD_OP_SIGNAL_BIT,
};

/**
 * io_eventfd_free - Free an io_ev_fd structure after RCU grace period
 * @rcu: RCU head embedded in the io_ev_fd structure being freed
 *
 * This function is called after an RCU grace period to clean up an
 * io_ev_fd structure that's no longer used. It releases the eventfd context
 * and frees the memory allocated for the structure.
 */
static void io_eventfd_free(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_ctx_put(ev_fd->cq_ev_fd);
	kfree(ev_fd);
}

/**
 * io_eventfd_put - Decrease the reference count on an io_ev_fd
 * @ev_fd: The io_ev_fd structure to put
 *
 * Decreases the reference count on the io_ev_fd structure and schedules
 * it for freeing via RCU when the count reaches zero.
 */
static void io_eventfd_put(struct io_ev_fd *ev_fd)
{
	if (refcount_dec_and_test(&ev_fd->refs))
		call_rcu(&ev_fd->rcu, io_eventfd_free);
}

/**
 * io_eventfd_do_signal - RCU callback to signal an eventfd
 * @rcu: RCU head embedded in the io_ev_fd structure
 *
 * This function is called after scheduling via call_rcu_hurry to signal
 * the eventfd from a safe context when the original context couldn't directly
 * signal the eventfd.
 */
static void io_eventfd_do_signal(struct rcu_head *rcu)
{
	struct io_ev_fd *ev_fd = container_of(rcu, struct io_ev_fd, rcu);

	eventfd_signal_mask(ev_fd->cq_ev_fd, EPOLL_URING_WAKE);
	io_eventfd_put(ev_fd);
}

/**
 * io_eventfd_release - Release an io_ev_fd after it's been used
 * @ev_fd: The io_ev_fd structure to release
 * @put_ref: Whether to also decrease the reference count
 *
 * Releases the RCU read lock and, if requested, also drops a reference
 * to the io_ev_fd structure.
 */
static void io_eventfd_release(struct io_ev_fd *ev_fd, bool put_ref)
{
	if (put_ref)
		io_eventfd_put(ev_fd);
	rcu_read_unlock();
}

/*
 * Returns true if the caller should put the ev_fd reference, false if not.
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
 * Trigger if eventfd_async isn't set, or if it's set and the caller is
 * an async worker. If ev_fd isn't valid, obviously return false.
 */
static bool io_eventfd_trigger(struct io_ev_fd *ev_fd)
{
	if (ev_fd)
		return !ev_fd->eventfd_async || io_wq_current_is_worker();
	return false;
}

/*
 * On success, returns with an ev_fd reference grabbed and the RCU read
 * lock held.
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

/**
 * io_eventfd_signal - Signal an eventfd for an io_uring completion queue
 * @ctx: The io_uring context
 *
 * Signals the eventfd associated with the io_uring context to notify of
 * completion events. This function is called when new completion queue entries
 * are added to the ring buffer.
 */
void io_eventfd_signal(struct io_ring_ctx *ctx)
{
	struct io_ev_fd *ev_fd;

	ev_fd = io_eventfd_grab(ctx);
	if (ev_fd)
		io_eventfd_release(ev_fd, __io_eventfd_signal(ev_fd));
}

/**
 * io_eventfd_flush_signal - Signal eventfd only if completion queue has changed
 * @ctx: The io_uring context
 *
 * Like io_eventfd_signal(), but only signals the eventfd if the completion queue
 * tail has changed since the last notification. This helps avoid unnecessary
 * wakeups when no new completions have been added.
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

/**
 * io_eventfd_register - Register an eventfd for io_uring completion notifications
 * @ctx: The io_uring context
 * @arg: User space pointer to an eventfd file descriptor
 * @eventfd_async: Flag indicating whether eventfd should be signaled from async context
 *
 * Registers an eventfd that will be signaled when entries are added to the
 * completion queue. The eventfd is identified by a file descriptor passed from
 * user space.
 *
 * Return: 0 on success, negative error code on failure
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

/**
 * io_eventfd_unregister - Unregister an eventfd from an io_uring context
 * @ctx: The io_uring context
 *
 * Removes a previously registered eventfd from the io_uring context.
 *
 * Return: 0 on success, -ENXIO if no eventfd was registered
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

