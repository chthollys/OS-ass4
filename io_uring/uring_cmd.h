// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

// Structure representing an asynchronous io_uring command
struct io_async_cmd {
	struct io_uring_cmd_data	data;
	struct iou_vec			vec;
	struct io_uring_sqe		sqes[2];
};

// Executes an io_uring command
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

// Prepares an io_uring command by validating and setting up its fields
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Cleans up resources associated with an io_kiocb request
void io_uring_cmd_cleanup(struct io_kiocb *req);

// Attempts to cancel io_uring commands that are marked as cancelable
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

// Frees the memory allocated for an asynchronous command entry
void io_cmd_cache_free(const void *entry);

// Imports a fixed vector for an io_uring command
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);
