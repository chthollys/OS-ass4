// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

struct io_waitid_async {
	struct io_kiocb *req;
	struct wait_opts wo;
};

// Prepares an io_waitid request for execution
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes an io_waitid request
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

// Cancels an io_waitid request
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);

// Removes all io_waitid requests for a given context
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);
