// SPDX-License-Identifier: GPL-2.0

// Represents a node in the io_uring task context
struct io_tctx_node {
	struct list_head	ctx_node;
	struct task_struct	*task;
	struct io_ring_ctx	*ctx;
};

// Allocates the io_uring task context for a given task
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);

// Removes the io_uring file to task mapping
void io_uring_del_tctx_node(unsigned long index);

// Adds a task context node to the io_uring context
int __io_uring_add_tctx_node(struct io_ring_ctx *ctx);

// Adds a task context node to the io_uring context from a submission
int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx);

// Cleans up the io_uring task context
void io_uring_clean_tctx(struct io_uring_task *tctx);

// Unregisters the ring file descriptors for the io_uring task
void io_uring_unreg_ringfd(void);

// Registers a ring file descriptor for the io_uring context
int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg,
		       unsigned nr_args);

// Unregisters a ring file descriptor for the io_uring context
int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg,
			 unsigned nr_args);

static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx)
{
	struct io_uring_task *tctx = current->io_uring;

	if (likely(tctx && tctx->last == ctx))
		return 0;

	return __io_uring_add_tctx_node_from_submit(ctx);
}
