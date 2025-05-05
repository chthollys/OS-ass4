// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

#define IO_POLL_ALLOC_CACHE_MAX 32

enum {
	IO_APOLL_OK,
	IO_APOLL_ABORTED,
	IO_APOLL_READY
};

struct io_poll {
	struct file			*file;
	struct wait_queue_head		*head;
	__poll_t			events;
	int				retries;
	struct wait_queue_entry		wait;
};

struct async_poll {
	struct io_poll		poll;
	struct io_poll		*double_poll;
};

/*
 * Must only be called inside issue_flags & IO_URING_F_MULTISHOT, or
 * potentially other cases where we already "own" this poll request.
 */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
	atomic_inc(&req->poll_refs);
}

/**
 * Prepares a poll request for addition to the ring context.
 * Checks the provided submission queue entry and prepares the poll request by setting appropriate flags and data.
 */
int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * Adds a poll request to the ring context, preparing it for processing by the kernel.
 * Ensures the poll request is properly added and managed within the system, including handling events and retries.
 */
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

/**
 * Prepares a poll request for removal from the ring context.
 * Processes the submission queue entry and prepares the poll request for removal, including updating flags and user data if needed.
 */
int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * Removes a poll request from the ring context, cleaning up any associated data and state.
 * Ensures that the poll request is properly removed, with necessary state updates and error handling.
 */
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

struct io_cancel_data;
/**
 * Cancels a poll request based on the provided cancel data.
 * Locates and cancels the poll request, updating the necessary states and handling flags for cancelation.
 */
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		   unsigned issue_flags);
		   /**
 * Arms the poll handler, associating the poll mask and flags with the request.
 * Prepares the poll request to handle incoming events by setting the necessary mask and flags.
 */
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);

/**
 * Removes all poll requests for a specific task, optionally canceling all of them.
 * Iterates through the cancel table, finds matching poll requests, and removes or cancels them based on the provided flags.
 */
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			bool cancel_all);


/**
 * Handles the task completion for an IO poll request, ensuring the appropriate task work is triggered.
 * Triggers the completion callback when the IO poll request is done, signaling the task that the operation has finished.
 */
void io_poll_task_func(struct io_kiocb *req, io_tw_token_t tw);
