// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

/* 
 * holds information needed to identify and cancel pending io operations. 
 * includes context, user data, file, opcode, flags, and sequence number. 
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

/* 
 * prepares a cancellation request from the provided sqe. 
 * validates the sqe and sets up the request for cancellation. 
 */
int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/* 
 * performs the actual cancellation operation for an async request. 
 * cancels the request based on the provided issue flags and criteria. 
 */
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);

/* 
 * attempts to cancel an operation identified by the cancellation data. 
 * tries to match and cancel requests in the task's io_uring context. 
 */
int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);

/* 
 * processes a synchronous request to cancel operations. 
 * handles cancellation requests that require immediate processing. 
 */
int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);

/* 
 * checks if the given request matches the cancellation criteria. 
 * compares the request with the provided cancellation data. 
 */
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);

/* 
 * scans through a list of requests, cancelling those that match criteria. 
 * cancels all matching requests or stops after the first if cancel_all is false. 
 */
bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));

/* 
 * scans through a list of requests, cancelling those that match the criteria. 
 * removes matching requests from the list and invokes the cancel callback. 
 */
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));

/* 
 * checks if the request has a matching sequence number. 
 * assigns the sequence number if not already set and returns false. 
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

