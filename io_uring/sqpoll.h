// SPDX-License-Identifier: GPL-2.0

struct io_sq_data {
	refcount_t		refs;
	atomic_t		park_pending;
	struct mutex		lock;

	/* ctx's that are using this sqd */
	struct list_head	ctx_list;

	struct task_struct	*thread;
	struct wait_queue_head	wait;

	unsigned		sq_thread_idle;
	int			sq_cpu;
	pid_t			task_pid;
	pid_t			task_tgid;

	u64			work_time;
	unsigned long		state;
	struct completion	exited;
};

/*
 * Create SQ thread for async submission processing.
 * Sets up thread affinity, params, and links to ctx.
 */
int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p);
 /*
  * Cleanup SQ thread resources when ctx exits.
  * Called during ring destruction to release thread resources.
  */
void io_sq_thread_finish(struct io_ring_ctx *ctx);
 
 /*
  * Stop and terminate the SQ thread.
  * Used during shutdown to cleanly stop the submission queue processor.
  */
void io_sq_thread_stop(struct io_sq_data *sqd);
 /*
  * Park (pause) the SQ thread.
  * Temporarily halts processing while maintaining thread state.
  */
void io_sq_thread_park(struct io_sq_data *sqd);
 /*
  * Unpark (resume) the SQ thread.
  * Restarts processing after being parked.
  */
void io_sq_thread_unpark(struct io_sq_data *sqd);
 /*
  * Release SQ data reference.
  * Called when last reference to sqd is dropped to free resources.
  */
void io_put_sq_data(struct io_sq_data *sqd);
 /*
  * Wait for SQ thread to consume all submissions.
  * Used to ensure completion before shutdown or similar operations.
  */
void io_sqpoll_wait_sq(struct io_ring_ctx *ctx);
 
 /*
  * Set CPU affinity for SQ poll thread.
  * Updates which CPUs the submission queue thread can run on.
  */
int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask);
