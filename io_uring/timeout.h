// SPDX-License-Identifier: GPL-2.0

// Structure to hold timeout data, including the request, timer, timestamp, mode, and flags.
struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
	u32				flags;
};

// Function to disarm a linked timeout request. Returns the linked request if it exists and is a timeout operation.
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

// Inline function to disarm a linked timeout request. Checks if the linked request is a timeout operation and calls the disarm function.
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

// Function to flush all timeouts in the given io_ring context. Marked as cold to indicate infrequent use.
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);
struct io_cancel_data;
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);
void io_queue_linked_timeout(struct io_kiocb *req);
void io_disarm_next(struct io_kiocb *req);

int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);
