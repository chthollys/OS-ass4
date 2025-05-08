#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq;

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	/* cancelled before started */
	IO_WQ_CANCEL_RUNNING,	/* found, running, and attempted cancelled */
	IO_WQ_CANCEL_NOTFOUND,	/* work not found */
};

typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
typedef void (io_wq_work_fn)(struct io_wq_work *);

struct io_wq_hash {
	refcount_t refs;
	unsigned long map;
	struct wait_queue_head wait;
};

// Decrements the reference count of the hash and frees it when it reaches zero
static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))
		kfree(hash);
}

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

// Creates a new IO work queue with specified parameters
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);
// Initiates the shutdown process for an IO work queue
void io_wq_exit_start(struct io_wq *wq);
// Decreases reference count and exits the IO work queue
void io_wq_put_and_exit(struct io_wq *wq);

// Adds a work item to the IO work queue for processing
void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
// Associates a hash value with a work item for faster lookup
void io_wq_hash_work(struct io_wq_work *work, void *val);

// Sets CPU affinity for IO work queue tasks
int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
// Sets or gets the maximum number of workers in the IO work queue
int io_wq_max_workers(struct io_wq *wq, int *new_count);
// Checks if the IO work queue worker has been stopped
bool io_wq_worker_stopped(void);

// Checks if a work item is hashed based on its flags
static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;
}

// Checks if a work item is hashed by reading its atomic flags
static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

// Cancels work items in the IO work queue based on callback criteria
enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)
// Notifies that an IO work queue worker is entering sleep state
extern void io_wq_worker_sleeping(struct task_struct *);
// Notifies that an IO work queue worker is entering running state
extern void io_wq_worker_running(struct task_struct *);
#else
// Empty implementation for when IO work queue worker enters sleep state
static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
// Empty implementation for when IO work queue worker enters running state
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

// Determines if the current task is an IO worker
static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&
		current->worker_private;
}
#endif
