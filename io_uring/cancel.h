// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

/**
 * struct io_cancel_data - Data structure for cancellation requests
 * @ctx:    IO context the cancellation belongs to
 * @data:   User provided data for identifying the request to cancel
 * @file:   File to cancel requests on (used for IORING_OP_CANCEL_FD)
 * @opcode: Operation code indicating the type of cancellation
 * @flags:  Cancellation flags
 * @seq:    Sequence number for identifying specific request
 *
 * This structure holds information needed to identify and cancel
 * pending IO operations.
 */
struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};

/**
 * io_async_cancel_prep - Prepare an async cancellation request
 * @req: The cancellation request
 * @sqe: Submission queue entry for the cancel operation
 *
 * Prepares a cancellation request from the provided SQE.
 *
 * Return: 0 on success, negative error code on failure
 */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_async_cancel - Process an async cancellation request
 * @req: The cancellation request
 * @issue_flags: Flags affecting issue behavior
 *
 * Performs the actual cancellation operation for an async request.
 *
 * Return: 0 on success, negative error code on failure
 */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_try_cancel - Try to cancel a request
 * @tctx: Task's io_uring context
 * @cd: Cancellation data
 * @issue_flags: Flags affecting cancel behavior
 *
 * Attempts to cancel an operation identified by the cancellation data.
 *
 * Return: Number of operations cancelled or negative error code
 */
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

/**
 * io_sync_cancel - Handle a synchronous cancellation request
 * @ctx: IO ring context
 * @arg: User-provided argument containing cancellation data
 *
 * Processes a synchronous request to cancel operations.
 *
 * Return: Number of operations cancelled or negative error code
 */
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);

/**
 * io_cancel_req_match - Check if a request matches cancellation criteria
 * @req: The request to check
 * @cd: Cancellation data containing match criteria
 *
 * Determines if the given request matches the cancellation criteria.
 *
 * Return: true if the request matches, false otherwise
 */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

/**
 * io_cancel_remove_all - Remove and cancel all matching requests
 * @ctx: IO ring context
 * @tctx: Task's io_uring context
 * @list: List containing requests to check
 * @cancel_all: Whether to cancel all matching requests or just one
 * @cancel: Function to call for each request to be cancelled
 *
 * Scans through a list of requests, cancelling those that match criteria.
 *
 * Return: true if any operations were cancelled, false otherwise
 */
bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

/**
 * io_cancel_remove - Remove and cancel a specific request
 * @ctx: IO ring context
 * @cd: Cancellation data
 * @issue_flags: Flags affecting cancel behavior
 * @list: List containing requests to check
 * @cancel: Function to call for each request to be cancelled
 *
 * Scans through a list of requests, cancelling those that match the criteria
 * specified in the cancellation data.
 *
 * Return: Number of operations cancelled or negative error code
 */
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

/**
 * io_cancel_match_sequence - Check if a request matches a sequence number
 * @req: The request to check
 * @sequence: Sequence number to match against
 *
 * Checks if the request has a matching sequence number. If the request
 * doesn't have a sequence number set, it assigns the provided one and
 * returns false.
 *
 * Return: true if request already has the matching sequence, false otherwise
 */
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}

#endif

