## Task 1 : Information about io_uring source

## Source

### advise.c

Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice.

### allo_cache.c

Manages allocation and caching mechanisms within io_uring. It includes functions for efficient memory allocation, caching frequently used objects, and ensuring proper cleanup to optimize performance and reduce overhead during I/O operations.

### cancel.c

Handles cancellation of io_uring requests. It includes functions to identify and cancel pending requests based on specific criteria, such as task or request type. The implementation ensures proper cleanup and resource deallocation for canceled requests.

### epoll.c

Manages epoll-related operations within io_uring. It integrates epoll functionality to monitor file descriptors for readiness, enabling efficient I/O multiplexing. The code ensures compatibility with io_uring's asynchronous nature.

### eventfd.c

Handles eventfd operations within io_uring. It includes support for creating, managing, and signaling eventfds, ensuring efficient communication and synchronization between processes or threads during asynchronous I/O operations.

### fdinfo.c

Provides detailed information about file descriptors used in io_uring. This includes tracking and managing file descriptor states, ensuring proper reference counting, and supporting debugging or introspection tools.

### filetable.c

Implements a table structure to manage files registered with io_uring. It includes functions for adding, removing, and looking up files, ensuring efficient access and minimal overhead during I/O operations.

### fs.c

Handles filesystem-related operations in io_uring. This includes support for open, close, and other file operations, ensuring seamless integration with the underlying filesystem APIs.

### futex.c

Handles futex operations within io_uring. It includes functions for managing fast user-space mutexes, ensuring efficient synchronization between threads or processes during asynchronous I/O operations.

### io_uring.c

Implements the core functionality of io_uring. It includes the main logic for submission and completion queue management, request handling, and integration with the kernel's asynchronous I/O mechanisms, ensuring high performance and low overhead.

### io-wq.c

Implements the workqueue mechanism for io_uring. It manages the execution of asynchronous tasks, ensuring proper scheduling, concurrency control, and resource management.

### kbuf.c

Manages kernel buffers used in io_uring operations. It includes functions for allocating, deallocating, and managing buffer lifecycles, ensuring efficient memory usage and minimal overhead.

### memmap.c
It is responsible for managing memory mappings and related operations. The code likely includes functionality for mapping memory regions, handling memory synchronization, and interacting with io_uring's submission and completion queues. This is a critical component for efficient I/O operations in the io_uring framework.

### msg_ring.c

Handles message ring operations in io_uring. It includes functions for sending and receiving messages between rings, ensuring proper synchronization and data integrity.

### napi.c

Handles NAPI (New API) integration within io_uring. It includes functions to manage and process network packet reception efficiently, leveraging io_uring's asynchronous capabilities to optimize performance and reduce latency in network I/O operations.

### net.c

Implements network-related operations for io_uring. This includes support for socket operations, ensuring efficient and asynchronous network I/O.

### nop.c

Provides a no-operation (NOP) implementation for io_uring. This is used for testing, benchmarking, or as a placeholder for future functionality.

### notif.c

Manages notifications within io_uring. It includes functions for sending and receiving notifications, ensuring proper synchronization and efficient handling of notification events.

### opdef.c

Defines operation structures and attributes for io_uring. This includes specifying preparation and issue functions for various operations, ensuring modularity and extensibility.

### openclose.c

Handles open and close operations for files in io_uring. It ensures proper resource management and integration with the underlying filesystem APIs.

### poll.c

Implements polling mechanisms for io_uring. This includes support for monitoring file descriptors for readiness, ensuring efficient I/O multiplexing.

### register.c

Handles registration operations in io_uring. It includes functions for registering and unregistering resources such as buffers, files, and eventfd objects. The implementation ensures efficient management and tracking of registered resources, enabling optimized I/O operations and reducing overhead.

### rsrc.c

Manages resources used in io_uring. This includes functions for allocating, deallocating, and tracking resources, ensuring efficient usage and proper cleanup.

### rw.c

Handles read and write operations in io_uring. It includes support for synchronous and asynchronous I/O, ensuring efficient data transfer and minimal overhead.

### splice.c

Implements splice operations for io_uring. This includes support for moving data between file descriptors without copying, ensuring efficient data transfer.

### sqpoll.c

Manages submission queue polling in io_uring. It includes functions for monitoring and processing submission queue entries, ensuring efficient and timely execution of I/O operations.

### statx.c

Handles statx operations in io_uring. This includes support for retrieving file attributes, ensuring compatibility with the underlying filesystem APIs.

### sync.c

Implements synchronization mechanisms for io_uring. This includes support for barriers, locks, and other synchronization primitives, ensuring proper coordination between tasks.

### tctx.c

Manages task contexts in io_uring. This includes functions for creating, destroying, and managing task-specific data structures, ensuring efficient task management.

### timeout.c

Handles timeout operations in io_uring. This includes support for setting, canceling, and managing timeouts, ensuring proper handling of time-sensitive operations.

### truncate.c

Handles file truncation operations within io_uring. It includes functions for preparing, executing, and managing truncation requests, ensuring efficient handling of file size adjustments and proper integration with the underlying filesystem APIs.

### uring_cmd.c

Implements command handling for io_uring. This includes support for processing and executing commands, ensuring proper synchronization and efficient execution.

### waitid.c

Handles waitid system call integration within io_uring. It includes functions to manage asynchronous task waiting, ensuring proper synchronization and efficient handling of process state changes.

### xattr.c

Handles extended attribute (xattr) operations in io_uring. This includes support for setting, getting, and managing extended attributes, ensuring compatibility with the underlying filesystem APIs.


## Header

### advise.h

1. `int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_madvise(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_fadvise(struct io_kiocb *req, unsigned int issue_flags)`

### allo_cache.h
1. `void io_alloc_cache_free(struct io_alloc_cache *cache, void (*free)(const void *))`
2. `bool io_alloc_cache_init(struct io_alloc_cache *cache, unsigned max_nr, unsigned int size, unsigned int init_bytes)`
3. `static inline void io_alloc_cache_kasan(struct iovec **iov, int *nr)`
4. `static inline bool io_alloc_cache_put (struct io_alloc_cache *cache, struct void *entry)`
5. `static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)`
6. `static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp)`

### cancel.h
1. `int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd, unsigned int issue_flags)`
4. `int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg)`
5. `bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd)`
6. `static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)`

### epoll.h
1. `int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags)`

### eventfd.h
1. `int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg, unsigned int eventfd_async)`
2. `int io_eventfd_unregister(struct io_ring_ctx *ctx)`
3. `void io_eventfd_flush_signal(struct io_ring_ctx *ctx)`
4. `void io_eventfd_signal(struct io_ring_ctx *ctx)`

### fdinfo.h
1. `void io_uring_show_fdinfo(struct seq_file *m, struct file *f)`

### filetable.h
1. `bool io_alloc_file_tables(struct io_file_table *table, unsigned nr_files)`
2. `void io_free_file_tables(struct io_file_table *table)`
3. `int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags, struct file *file, unsigned int file_slot)`
4. `int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file, unsigned int file_slot)`
5. `int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)`
6. `int io_register_file_alloc_range(struct io_ring_ctx *ctx, struct io_uring_file_index_range __user *arg)`
7. `io_req_flags_t io_file_get_flags(struct file *file)`
8. `static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)`
9. `static inline void io_file_bitmap_set(struct io_file_table *table, int bit)`
10. `static inline unsigned int io_slot_flags(struct io_rsrc_node *node)`
11. `static inline struct file *io_slot_file(struct io_rsrc_node *node)`
12. `static inline void io_fixed_file_set(struct io_rsrc_node *node, struct file *file)`
13. `static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx, unsigned off, len)`

### fs.h
1. `int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);`
2. `int io_renameat(struct io_kiocb *req, unsigned int issue_flags);`
3. `void io_renameat_cleanup(struct io_kiocb *req);`
4. `int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);`
5. `int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);`
6. `void io_unlinkat_cleanup(struct io_kiocb *req);`
7. `int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);`
8. `int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);`
9. `void io_mkdirat_cleanup(struct io_kiocb *req);`
10. `int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);`
11. `int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);`
12. `int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);`
13. `int io_linkat(struct io_kiocb *req, unsigned int issue_flags);`
14. `void io_link_cleanup(struct io_kiocb *req);`

### futex.h
1. `int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags)`
4. `int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags)`
5. `int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags)`
6. `int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd, unsigned int issue_flags)`
7. `bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx, bool cancel_all)`
8. `bool io_futex_cache_init(struct io_ring_ctx *ctx)`
9. `void io_futex_cache_free(struct io_ring_ctx *ctx)`
10. `static inline int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd, unsigned int issue_flags)`
11. `static inline bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx, bool cancel_all)`
12. `static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)`
13. `static inline void io_futex_cache_free(struct io_ring_ctx *ctx)`

### io_uring.h

1. `unsigned long rings_size(unsigned int flags, unsigned int sq_entries, unsigned int cq_entries, size_t *sq_offset)`
2. `int io_uring_fill_params(unsigned entries, struct io_uring_params *p)`
3. `bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow)`
4. `int io_run_task_work_sig(struct io_ring_ctx *ctx)`
5. `void io_req_defer_failed(struct io_kiocb *req, s32 res)`
6. `bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags)`
7. `void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags)`
8. `bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags)`
9. `void __io_commit_cqring_flush(struct io_ring_ctx *ctx)`
10. `struct file *io_file_get_normal(struct io_kiocb *req, int fd)`
11. `struct file *io_file_get_fixed(struct io_kiocb *req, int fd, unsigned issue_flags)`
12. `void __io_req_task_work_add(struct io_kiocb *req, unsigned flags)`
13. `void io_req_task_work_add_remote(struct io_kiocb *req, struct io_ring_ctx *ctx, unsigned flags)`
14. `bool io_alloc_async_data(struct io_kiocb *req)`
15. `void io_req_task_queue(struct io_kiocb *req)`
16. `void io_req_task_complete(struct io_kiocb *req, struct io_tw_state *ts)`
17. `void io_req_task_queue_fail(struct io_kiocb *req, int ret)`
18. `void io_req_task_submit(struct io_kiocb *req, struct io_tw_state *ts)`
19. `struct llist_node *io_handle_tw_list(struct llist_node *node, unsigned int *count, unsigned int max_entries)`
20. `struct llist_node *tctx_task_work_run(struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count)`
21. `void tctx_task_work(struct callback_head *cb)`
22. `__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd)`
23. `int io_uring_alloc_task_context(struct task_struct *task, struct io_ring_ctx *ctx)`
24. `int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file, int start, int end)`
25. `void io_req_queue_iowq(struct io_kiocb *req)`
26. `int io_poll_issue(struct io_kiocb *req, struct io_tw_state *ts)`
27. `int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr)`
28. `int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin)`
29. `void __io_submit_flush_completions(struct io_ring_ctx *ctx)`
30. `struct io_wq_work *io_wq_free_work(struct io_wq_work *work)`
31. `void io_wq_submit_work(struct io_wq_work *work)`
32. `void io_free_req(struct io_kiocb *req)`
33. `void io_queue_next(struct io_kiocb *req)`
34. `void io_task_refs_refill(struct io_uring_task *tctx)`
35. `bool __io_alloc_req_refill(struct io_ring_ctx *ctx)`
36. `bool io_match_task_safe(struct io_kiocb *head, struct io_uring_task *tctx, bool cancel_all)`
37. `void io_activate_pollwq(struct io_ring_ctx *ctx)`
38. `static inline void io_lockdep_assert_cq_locked(struct io_ring_ctx *ctx)`
39. `static inline void io_req_task_work_add(struct io_kiocb *req)`
40. `static inline void io_submit_flush_completions(struct io_ring_ctx *ctx)`
41. `static inline bool io_get_cqe_overflow(struct io_ring_ctx *ctx, struct io_uring_cqe **ret, bool overflow)`
42. `static inline bool io_get_cqe(struct io_ring_ctx *ctx, struct io_uring_cqe **ret)`
43. `static __always_inline bool io_fill_cqe_req(struct io_ring_ctx *ctx, struct io_kiocb *req)`
44. `static inline void req_set_fail(struct io_kiocb *req)`
45. `static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)`
46. `static inline void *io_uring_alloc_async_data(struct io_alloc_cache *cache, struct io_kiocb *req)`
47. `static inline bool req_has_async_data(struct io_kiocb *req)`
s8a `c inline void io_put_file(struct io_kiocb *req)`
49. `static inline void io_ring_submit_unlock(struct io_ring_ctx *ctx, unsigned issue_flags)`
50. `static inline void io_ring_submit_lock(struct io_ring_ctx *ctx, unsigned issue_flags)`
51. `static inline void io_commit_cqring(struct io_ring_ctx *ctx)`
52. `static inline void io_poll_wq_wake(struct io_ring_ctx *ctx)`
53. `static inline void io_cqring_wake(struct io_ring_ctx *ctx)`
54. `static inline bool io_sqring_full(struct io_ring_ctx *ctx)`
55. `static inline unsigned int io_sqring_entries(struct io_ring_ctx *ctx)`
56. `tatic inline int io_run_task_work(void)`
57. `static inline bool io_local_work_pending(struct io_ring_ctx *ctx)`
58. `static inline bool io_task_work_pending(struct io_ring_ctx *ctx)`
59. `static inline void io_tw_lock(struct io_ring_ctx *ctx, struct io_tw_state *ts)`
60. `static inline void io_req_complete_defer(struct io_kiocb *req) __must_hold(&req->ctx->uring_lock)`
61. `static inline void io_commit_cqring_flush(struct io_ring_ctx *ctx)`
62. `tatic inline void io_get_task_refs(int nr)`
63. `static inline bool io_req_cache_empty(struct io_ring_ctx *ctx)`
64. `static inline struct io_kiocb *io_extract_req(struct io_ring_ctx *ctx)`
65. `static inline bool io_alloc_req(struct io_ring_ctx *ctx, struct io_kiocb **req)`
66. `static inline bool io_allowed_defer_tw_run(struct io_ring_ctx *ctx)`
67. `static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)`
68. `tatic inline bool io_should_terminate_tw(void)`
69. `static inline void io_req_queue_tw_complete(struct io_kiocb *req, s32 res)`
70. `static inline size_t uring_sqe_size(struct io_ring_ctx *ctx)`
71. `static inline bool io_file_can_poll(struct io_kiocb *req)`
72. `static inline ktime_t io_get_time(struct io_ring_ctx *ctx)`
73. `static inline bool io_has_work(struct io_ring_ctx *ctx)`

### io-wq.h
1. `static inline void io_wq_put_hash(struct io_wq_hash *hash)`
2. `struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data)`
3. `void io_wq_exit_start(struct io_wq *wq)`
4. `void io_wq_put_and_exit(struct io_wq *wq)`
5. `void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work)`
6. `void io_wq_hash_work(struct io_wq_work *work, void *val)`
7. `int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask)`
8. `int io_wq_max_workers(struct io_wq *wq, int *new_count)`
9. `bool io_wq_worker_stopped(void)`
10. `static inline bool io_wq_is_hashed(struct io_wq_work *work)`
11. `typedef bool (work_cancel_fn)(struct io_wq_work *, void *)`
12. `enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel, void *data, bool cancel_all)`
13. `extern void io_wq_worker_sleeping(struct task_struct *)`
14. `extern void io_wq_worker_running(struct task_struct *)`
15. `static inline void io_wq_worker_sleeping(struct task_struct *tsk)`
16. `static inline void io_wq_worker_running(struct task_struct *tsk)`
17. `static inline bool io_wq_current_is_worker(void)`
`
### `kbuf.h
1. `void __user *io_buffer_select(struct io_kiocb *req, size_t *len, unsigned int issue_flags)`
2. `void io_destroy_buffers(struct io_ring_ctx *ctx)`
3. `int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags)`
5. `int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
6. `int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags)`
7. `int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)`
8. `int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg)`
9. `unsigned int __io_put_kbuf(struct io_kiocb *req, unsigned issue_flags)`
10. `void io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags)`
11. `void *io_pbuf_get_address(struct io_ring_ctx *ctx, unsigned long bgid)`
12. `static inline void io_kbuf_recycle_ring(struct io_kiocb *req)`
13. `static inline bool io_do_buffer_select(struct io_kiocb *req)`
14. `static inline void io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)`
15. `static inline unsigned int __io_put_kbuf_list(struct io_kiocb *req, struct list_head *list)`
16. `static inline unsigned int io_put_kbuf_comp(struct io_kiocb *req)`
17. `static inline unsigned int io_put_kbuf(struct io_kiocb *req, unsigned issue_flags)`

### memmap.h
1. `struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages)`
2. `unsigned int io_uring_nommu_mmap_capabilities(struct file *file)`
3. `unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags)`
4. `int io_uring_mmap(struct file *file, struct vm_area_struct *vma)`
5. `void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr)`
6. `int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr, struct io_uring_region_desc *reg, unsigned long mmap_offset)`
7. `int io_create_region_mmap_safe(struct io_ring_ctx *ctx, struct io_mapped_region *mr, struct io_uring_region_desc *reg, unsigned long mmap_offset)`
8. `static inline void *io_region_get_ptr(struct io_mapped_region *mr)`
9. `static inline bool io_region_is_set(struct io_mapped_region *mr)`

### msg_ring.
1. `int io_uring_sync_msg_ring(struct io_uring_sqe *sqe)`
2. `int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags)`
4. `void io_msg_ring_cleanup(struct io_kiocb *req)`

### napi.h
1. `void io_napi_init(struct io_ring_ctx *ctx)`
2. `void io_napi_free(struct io_ring_ctx *ctx)`
3. `int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)`
4. `int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)`
5. `int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id)`
6. `void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq)`
7. `int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)`
8. `static inline bool io_napi(struct io_ring_ctx *ctx)`
9. `static inline void io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq)`
10. `static inline void io_napi_add(struct io_kiocb *req)`
11. `static inline void io_napi_init(struct io_ring_ctx *ctx)`
12. `static inline void io_napi_free(struct io_ring_ctx *ctx)`
13. `static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)`
14. `static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)`
15. `static inline bool io_napi(struct io_ring_ctx *ctx)`
16. `static inline void io_napi_add(struct io_kiocb *req)`
17. `static inline void io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq)`
18. `static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)`

### net.h
1. `int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_shutdown(struct io_kiocb *req, unsigned int issue_flags)`
3. `void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req)`
4. `int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
5. `int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags)`
6. `int io_send(struct io_kiocb *req, unsigned int issue_flags)`
7. `int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
8. `int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags)`
9. `int io_recv(struct io_kiocb *req, unsigned int issue_flags)`
10. `void io_sendrecv_fail(struct io_kiocb *req)`
11. `int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
12. `int io_accept(struct io_kiocb *req, unsigned int issue_flags)`
13. `int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
14. `int io_socket(struct io_kiocb *req, unsigned int issue_flags)`
15. `int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
16. `int io_connect(struct io_kiocb *req, unsigned int issue_flags)`
17. `int io_send_zc(struct io_kiocb *req, unsigned int issue_flags)`
18. `int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags)`
19. `int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
20. `void io_send_zc_cleanup(struct io_kiocb *req)`
21. `int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
22. `int io_bind(struct io_kiocb *req, unsigned int issue_flags)`
23. `int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
24. `int io_listen(struct io_kiocb *req, unsigned int issue_flags)`
25. `void io_netmsg_cache_free(const void *entry)`
26. `static inline void io_netmsg_cache_free(const void *entry)`

### nop.h
1. `int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_nop(struct io_kiocb *req, unsigned int issue_flags)`

### notif.h
1. `struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx)`
2. `void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg, bool success)`
3. `static inline struct io_notif_data *io_notif_to_data(struct io_kiocb *notif)`
4. `static inline void io_notif_flush(struct io_kiocb *notif) __must_hold(&notif->ctx->uring_lock)`
5. `static inline int io_notif_account_mem(struct io_kiocb *notif, unsigned len)`

### opdef.h
1. `bool io_uring_op_supported(u8 opcode)`
2. `void io_uring_optable_init(void)`

### openclose.h
1. `int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags, unsigned int offset)`
2. `int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `int io_openat(struct io_kiocb *req, unsigned int issue_flags)`
4. `void io_open_cleanup(struct io_kiocb *req);                  `
5. `int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
6. `int io_openat2(struct io_kiocb *req, unsigned int issue_flags)`
7. `int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
8. `int io_close(struct io_kiocb *req, unsigned int issue_flags);`
9. `int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
10. `int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags)`

### poll.h
1. `int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_poll_add(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags)`
5. `int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd, unsigned issue_flags)`
6. `int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags)`
7. `bool io_poll_remove_all(struct io_ring_ctx *ctx, struct task_struct *tsk, bool cancel_all)`
8. `void io_apoll_cache_free(struct io_cache_entry *entry)`
9. `void io_poll_task_func(struct io_kiocb *req, struct io_tw_state *ts)`

### refs.h
1. `static inline bool req_ref_inc_not_zero(struct io_kiocb *req)`
2. `static inline bool req_ref_put_and_test(struct io_kiocb *req)`
3. `static inline void req_ref_get(struct io_kiocb *req)`
4. `static inline void req_ref_put(struct io_kiocb *req)`
5. `static inline void __io_req_set_refcount(struct io_kiocb *req, int nr)`
6. `static inline void io_req_set_refcount(struct io_kiocb *req)`

### register.h
1. `int io_eventfd_unregister(struct io_ring_ctx *ctx)`
2. `int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id)`
3. `struct file *io_uring_register_get_file(unsigned int fd, bool registered)`

### rsrc.h
1. `struct io_rsrc_node *io_rsrc_node_alloc(int type)`
2. `void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)`
3. `void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data)`
4. `int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr)`
5. `int io_import_fixed(int ddir, struct iov_iter *iter, struct io_mapped_ubuf *imu, u64 buf_addr, size_t len)`
6. `int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg)`
7. `int io_sqe_buffers_unregister(struct io_ring_ctx *ctx)`
8. `int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg, unsigned int nr_args, u64 __user *tags)`
9. `int io_sqe_files_unregister(struct io_ring_ctx *ctx)`
10. `int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg, unsigned nr_args, u64 __user *tags)`
11. `int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg, unsigned nr_args)`
12. `int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg, unsigned size, unsigned type)`
13. `int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg, unsigned int size, unsigned int type)`
14. `bool io_check_coalesce_buffer(struct page **page_array, int nr_pages, struct io_imu_folio_data *data);`
15. `static inline struct io_rsrc_node *io_rsrc_node_lookup(struct io_rsrc_data *data, int index)`
16. `static inline void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)`
17. `static inline bool io_reset_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_data *data, int index)`
18. `static inline void io_req_put_rsrc_nodes(struct io_kiocb *req)`
19. `static inline void io_req_assign_rsrc_node(struct io_rsrc_node **dst_node, struct io_rsrc_node *node)`
20. `static inline void io_req_assign_buf_node(struct io_kiocb *req, struct io_rsrc_node *node)`
21. `int io_files_update(struct io_kiocb *req, unsigned int issue_flags)`
22. `int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
23. `int __io_account_mem(struct user_struct *user, unsigned long nr_pages)`
24. `static inline void __io_unaccount_mem(struct user_struct *user, unsigned long nr_pages)`

### rw.h
1. `int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
5. `int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
6. `int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
7. `int io_read(struct io_kiocb *req, unsigned int issue_flags)`
8. `int io_write(struct io_kiocb *req, unsigned int issue_flags)`
9. `void io_readv_writev_cleanup(struct io_kiocb *req)`
10. `void io_rw_fail(struct io_kiocb *req)`
11. `void io_req_rw_complete(struct io_kiocb *req, struct io_tw_state *ts)`
12. `int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
13. `int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags)`
14. `void io_rw_cache_free(const void *entry)`

### slist.h
1. `static inline void wq_list_add_after(struct io_wq_work_node *node, struct io_wq_work_node *pos, struct io_wq_work_list *list)`
2. `static inline void wq_list_add_tail(struct io_wq_work_node *node, struct io_wq_work_list *list)`
3. `static inline void wq_list_add_head(struct io_wq_work_node *node, struct io_wq_work_list *list)`
4. `static inline void wq_list_cut(struct io_wq_work_list *list, struct io_wq_work_node *last, struct io_wq_work_node *prev)`
5. `static inline void __wq_list_splice(struct io_wq_work_list *list, struct io_wq_work_node *to)`
6. `static inline bool wq_list_splice(struct io_wq_work_list *list,  io_wq_work_node *to)`
7. `static inline void wq_stack_add_head(struct io_wq_work_node *node, struct io_wq_work_node *stack)`
8. `static inline void wq_list_del(struct io_wq_work_list *list, struct io_wq_work_node *node, struct io_wq_work_node *prev)`
9. `static struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)`
10. `static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)`

### splice.h
1. `int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_tee(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_splice(struct io_kiocb *req, unsigned int issue_flags)`

### sqpoll.h
1. `int io_sq_offload_create(struct io_ring_ctx *ctx, struct io_uring_params *p)`
2. `void io_sq_thread_finish(struct io_ring_ctx *ctx)`
3. `void io_sq_thread_stop(struct io_sq_data *sqd)`
4. `void io_sq_thread_park(struct io_sq_data *sqd)`
5. `void io_sq_thread_unpark(struct io_sq_data *sqd)`
6. `void io_put_sq_data(struct io_sq_data *sqd)`
7. `void io_sqpoll_wait_sq(struct io_ring_ctx *ctx)`
8. `int io_sqpoll_wq_cpu_affinity(struct io_ring_ctx *ctx, cpumask_var_t mask)`

### statx.h
1. `int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_statx(struct io_kiocb *req, unsigned int issue_flags)`
3. `void io_statx_cleanup(struct io_kiocb *req)`

### sync.h
1. `int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
4. `int io_fsync(struct io_kiocb *req, unsigned int issue_flags)`
5. `int io_fallocate(struct io_kiocb *req, unsigned int issue_flags)`
6. `int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`

### tctx.h
1. `int io_uring_alloc_task_context(struct task_struct *task, struct io_ring_ctx *ctx)`
2. `void io_uring_del_tctx_node(unsigned long index)`
3. `int __io_uring_add_tctx_node(struct io_ring_ctx *ctx)`
4. `int __io_uring_add_tctx_node_from_submit(struct io_ring_ctx *ctx)`
5. `void io_uring_clean_tctx(struct io_uring_task *tctx)`
6. `void io_uring_unreg_ringfd(void)`
7. `int io_ringfd_register(struct io_ring_ctx *ctx, void __user *__arg, unsigned nr_args)`
8. `int io_ringfd_unregister(struct io_ring_ctx *ctx, void __user *__arg, unsigned nr_args)`
9. `static inline int io_uring_add_tctx_node(struct io_ring_ctx *ctx`

### timeout.h
1. `struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req, struct io_kiocb *link)`
2. `static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req`
3. `__cold void io_flush_timeouts(struct io_ring_ctx *ctx))`
4. `int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd)`
5. `__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx, bool cancel_all)`
6. `void io_queue_linked_timeout(struct io_kiocb *req)`
7. `void io_disarm_next(struct io_kiocb *req)`
8. `int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
9. `int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
10. `int io_timeout(struct io_kiocb *req, unsigned int issue_flags)`
11. `int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
12. `int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags)`

### truncate.h
1. `int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags)`

### uring_cmd.h
1. `int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags)`
2. `int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx, struct io_uring_task *tctx, bool cancel_all)`

### waitid.h
1. `int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
2. `int io_waitid(struct io_kiocb *req, unsigned int issue_flags)`
3. `int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd, unsigned int issue_flags)`
4. `bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx, bool cancel_all)`

### xattr.h
1. `void io_xattr_cleanup(struct io_kiocb *req)`
2. `int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
3. `int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags)`
4. `int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
5. `int io_setxattr(struct io_kiocb *req, unsigned int issue_flags)`
6. `int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
7. `int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags)`
8. `int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)`
9. `int io_getxattr(struct io_kiocb *req, unsigned int issue_flags)`
