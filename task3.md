## Name : Jason Januardy
## NIM  : 1313623035
# Task 3: Data Structure Investigation

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
io_fadvise     | io_uring/advise.c | struct file, u64, u64, u32 | io_fadvise_prep | io_uring/advise.c | function parameter
| | | | io_fadvise | io_uring/advise.c | function parameter
io_madvise     | io_uring/advise.c | struct file, u64, u64, u32 | io_madvise_prep | io_uring/advise.c | function parameter
| | | | io_madvise | io_uring/advise.c | function parameter
io_alloc_cache | io_uring/alloc_cache.c | void **, unsigned, unsigned, unsigned int, unsigned int | io_alloc_cache_free | io_uring/alloc_cache.c | function parameter
| | | | io_alloc_cache_init | | |
| | | | io_cache_alloc_new | | |
io_cancel      | io_uring/cancel.c | struct file, u64, u32, s32, u8 | io_async_cancel_prep | io_uring/cancel.c | function parameter
| | | | io_async_cancel | | |
| | | | io_sync_cancel | | |
io_epoll       | io_uring/epoll.c | struct file *file, int epfd, int op, int fd, struct epoll_event event | io_epoll_ctl_prep | io_uring/epoll.c | local variable
| | | | io_epoll_ctl | | |
io_futex       | io_uring/futex.c | struct file, union { u32 __user *uaddr; struct futex_waitv __user *uwaitv; }, unsigned long futex_val, unsigned long futex_mask, unsigned long futexv_owned, u32 futex_flags, unsigned int futex_nr, bool futexv_unqueued | io_futex_cache_init | io_uring/futex.c | function parameter
| | | | io_futex_cache_free | | |
| | | | io_futex_complete | | |
| | | | io_futexv_complete | | |
| | | | io_futex_cancel | | |
| | | | io_futex_remove_all | | |
| | | | io_futex_prep | | |
| | | | io_futexv_prep | | |
| | | | io_futex_wait | | |
| | | | io_futex_wake | | |
io_futex_data  | io_uring/futex.c | struct futex_q q, struct io_kiocb *req | io_futex_cache_init | io_uring/futex.c | function parameter
| | | | io_futex_cache_free | | |
| | | | io_futex_complete | | |
| | | | io_futexv_complete | | |
| | | | io_futex_wait | | |
| | | | io_futex_wake | | |
io_rename      | io_uring/fs.c | struct file *file, int old_dfd, int new_dfd, struct filename *oldpath, struct filename *newpath, int flags | io_renameat_prep | io_uring/fs.c | function parameter
| | | | io_renameat | | |
| | | | io_renameat_cleanup | | |
io_unlink      | io_uring/fs.c | struct file *file, int dfd, int flags, struct filename *filename | io_unlinkat_prep | io_uring/fs.c | function parameter
| | | | io_unlinkat | | |
| | | | io_unlinkat_cleanup | | |
io_mkdir       | io_uring/fs.c | struct file *file, int dfd, umode_t mode, struct filename *filename | io_mkdirat_prep | io_uring/fs.c | function parameter
| | | | io_mkdirat | | |
| | | | io_mkdirat_cleanup | | |
io_link        | io_uring/fs.c | struct file *file, int old_dfd, int new_dfd, struct filename *oldpath, struct filename *newpath, int flags | io_symlinkat_prep | io_uring/fs.c | function parameter
| | | | io_symlinkat | | |
| | | | io_linkat_prep | | |
| | | | io_linkat | | |
| | | | io_link_cleanup | | |
io_defer_entry | io_uring/io_uring.c | struct list_head list, struct io_kiocb *req, u32 seq | io_drain_req | io_uring/io_uring.c | local variable
kmem_cache     | io_uring/io_uring.c | - | io_alloc_req, io_free_req | io_uring/io_uring.c | function parameter
io_ring_ctx    | io_uring/io_uring.c | ctx->rings, ctx->flags, ctx->cq_wait_nr | io_uring_try_cancel_requests | io_uring/io_uring.c | function parameter, local variable
| | | | io_alloc_hash_table | | |
io_worker      | io_uring/io-wq.c | struct hlist_nulls_node nulls_node, struct list_head all_list, struct task_struct *task, struct io_wq *wq, struct io_wq_work *cur_work, struct completion ref_done, struct callback_head create_work, union { struct rcu_head rcu; struct delayed_work work; } | io_worker_exit | io_uring/io-wq.c | local variable, function parameter
| | | | io_worker_handle_work | | |
| | | | create_io_worker | | |
io_wq_acct     | io_uring/io-wq.c | unsigned nr_workers, unsigned max_workers, int index, atomic_t nr_running, raw_spinlock_t lock, struct io_wq_work_list work_list | io_acct_run_queue | io_uring/io-wq.c | local variable
| | | | io_wq_create_worker | | |
io_wq          | io_uring/io-wq.c | unsigned long state, struct io_wq_hash *hash, struct completion worker_done, struct hlist_node cpuhp_node, struct task_struct *task, struct io_wq_acct acct[IO_WQ_ACCT_NR] | io_wq_create | io_uring/io-wq.c | function parameter, local variable
| | | | io_wq_exit_workers | | |
| | | | io_wq_destroy | | |
kmem_cache     | io_uring/kbuf.c | - | io_refill_buffer_cache | io_uring/kbuf.c | local variable |
| | | | io_destroy_buffers | | |
io_provide_buf | io_uring/kbuf.c | struct file *file, __u64 addr, __u32 len, __u32 bgid, __u32 nbufs, __u16 bid | io_provide_buffers_prep | io_uring/kbuf.c | function parameter, local variable |
| | | | io_provide_buffers | | |
io_ring_ctx    | io_uring/memmap.c | struct io_mapped_region ring_region, struct io_mapped_region sq_region, struct io_mapped_region param_region, struct mutex mmap_lock, void *user | io_free_region | io_uring/memmap.c | function parameter, local variable
| | | | io_region_pin_pages | | |
| | | | io_region_allocate_pages | | |
| | | | io_create_region | | |
| | | | io_create_region_mmap_safe | | |
| | | | io_mmap_get_region | | |
| | | | io_region_validate_mmap | | |
| | | | io_region_mmap | | |
| | | | io_uring_mmap* | | |
| | | | io_uring_get_unmapped_area | | |
io_mapped_region | io_uring/memmap.c | struct page **pages, unsigned long nr_pages, unsigned int flags, void *ptr | io_free_region | io_uring/memmap.c | function parameter, local variable
| | | | io_region_init_ptr | | |
| | | | io_region_allocate_pages | | |
| | | | io_region_pin_pages | | |
| | | | io_create_region | | |
| | | | io_create_region_mmap_safe | | |
| | | | io_mmap_get_region | | |
| | | | io_region_validate_mmap | | |
| | | | io_region_mmap | | |
io_uring_region_desc | io_uring/memmap.c | unsigned long user_addr, unsigned long size, unsigned long mmap_offset, unsigned int flags, unsigned int id, char __resv[16] | io_region_pin_pages | io_uring/memmap.c | function parameter
| | | | io_region_allocate_pages | | |
| | | | io_create_region | | |
| | | | io_create_region_mmap_safe | | |
io_msg          | io_uring/msg_ring.c | struct file *file, struct file *src_file, struct callback_head tw, u64 user_data, u32 len, u32 cmd, u32 src_fd, union { u32 dst_fd; u32 cqe_flags; }, u32 flags | io_msg_ring_cleanup | io_uring/msg_ring.c | function parameter, local variable
| | | | io_msg_tw_complete | | |
| | | | io_msg_remote_post | | |
| | | | io_msg_get_kiocb | | |
| | | | io_msg_data_remote | | |
| | | | __io_msg_ring_data | | |
| | | | io_msg_ring_data | | |
| | | | io_msg_grab_file | | |
| | | | io_msg_install_complete | | |
| | | | io_msg_tw_fd_complete | | |
| | | | io_msg_fd_remote | | |
| | | | io_msg_send_fd | | |
| | | | __io_msg_ring_prep | | |
| | | | io_msg_ring_prep | | |
| | | | io_msg_ring | | |
| | | | io_uring_sync_msg_ring | | |
io_napi_entry | io_uring/napi.c | unsigned int napi_id, struct list_head list, unsigned long timeout, struct hlist_node node, struct rcu_head rcu | io_napi_hash_find | io_uring/napi.c | local variable
| | | | __io_napi_add_id | | |
| | | | __io_napi_del_id | | |
| | | | __io_napi_remove_stale | | |
| | | | static_tracking_do_busy_loop | | |
| | | | dynamic_tracking_do_busy_loop | | |
| | | | io_napi_free | | |
io_shutdown | io_uring/net.c | struct file *file, int how | io_shutdown_prep | io_uring/net.c | function parameter
| | | | io_shutdown | io_uring/net.c | function parameter
io_accept | io_uring/net.c | struct file *file, struct sockaddr __user *addr, int __user *addr_len, int flags, int iou_flags, u32 file_slot, unsigned long nofile | io_accept_prep | io_uring/net.c | function parameter
| | | | io_accept | | |
io_socket | io_uring/net.c | struct file *file, int domain, int type, int protocol, int flags, u32 file_slot, unsigned long nofile | io_socket_prep | io_uring/net.c | function parameter
| | | | io_socket | | |
io_connect | io_uring/net.c | struct file *file, struct sockaddr __user *addr, int addr_len, bool in_progress, bool seen_econnaborted | io_connect_prep | io_uring/net.c | function parameter
| | | | io_connect | | |
io_bind | io_uring/net.c | struct file *file, int addr_len | io_bind_prep | io_uring/net.c | function parameter
| | | | io_bind | | |
io_listen | io_uring/net.c | struct file *file, int backlog | io_listen_prep | io_uring/net.c | function parameter
| | | | io_listen | | |
io_sr_msg | io_uring/net.c | struct file *file, union { struct compat_msghdr __user *umsg_compat; struct user_msghdr __user *umsg; void __user *buf; }, int len, unsigned done_io, unsigned msg_flags, unsigned nr_multishot_loops, u16 flags, u16 buf_group, u16 buf_index, void __user *msg_control, struct io_kiocb *notif | io_sendmsg_prep | io_uring/net.c | function parameter
| | | | io_sendmsg | | |
| | | | io_recvmsg_prep | | |
| | | | io_recvmsg | | |
| | | | io_send_zc_prep | | |
| | | | io_send_zc | | |
| | | | io_sendmsg_zc | | |
io_nop          | io_uring/nop.c | struct file *file, int result, int fd, int buffer, unsigned int flags | io_nop_prep | io_uring/nop.c | local variable, function parameter
| | | | io_nop | | |
io_kiocb       | io_uring/notif.c | opcode, flags, file, tctx, file_node, buf_node | io_alloc_notif | io_uring/notif.c | local variable, return value
io_notif_data | io_uring/notif.c | zc_report, account_pages, next, head, uarg | io_alloc_notif | io_uring/notif.c | local variable
ubuf_info     | io_uring/notif.c | flags, ops, refcnt | io_alloc_notif | io_uring/notif.c | local variable
io_issue_def | io_uring/opdef.c | int audit_skip, int iopoll, int needs_file, int unbound_nonreg_file, int pollin, int pollout, int vectored, int async_size, int plug, int ioprio, int iopoll_queue, int buffer_select, int poll_exclusive, int hash_reg_file, int cleanup, int fail, int prep, int issue | io_uring_optable_init | io_uring/opdef.c | local variable
io_cold_def | io_uring/opdef.c | const char *name, int cleanup, int fail | io_uring_optable_init | io_uring/opdef.c | local variable
io_open          | io_uring/openclose.c | struct file *file, int dfd, u32 file_slot, struct filename *filename, struct open_how how, unsigned long nofile | io_openat_prep | io_uring/openclose.c | function parameter, local variable
| | | | io_openat2_prep | | |
| | | | io_openat2 | | |
| | | | io_openat | | |
| | | | io_open_cleanup | | |
io_close         | io_uring/openclose.c | struct file *file, int fd, u32 file_slot | io_close_prep | io_uring/openclose.c | function parameter, local variable
| | | | io_close | | |
| | | | io_close_fixed | | |
io_fixed_install | io_uring/openclose.c | struct file *file, unsigned int o_flags | io_install_fixed_fd_prep | io_uring/openclose.c | function parameter, local variable
| | | | io_install_fixed_fd | | |
io_poll_update | io_uring/poll.c | struct file *file, u64 old_user_data, u64 new_user_data, __poll_t events, bool update_events, bool update_user_data | io_poll_remove | io_uring/poll.c | function parameter, local variable
| | | | io_poll_remove_prep | | |
io_poll_table | io_uring/poll.c | struct poll_table_struct pt, struct io_kiocb *req, int nr_entries, int error, bool owning, __poll_t result_mask | io_poll_check_events | io_uring/poll.c | local variable, function parameter
| | | | io_poll_queue_proc | | |
io_poll | io_uring/poll.c | struct wait_queue_head *head, __poll_t events, struct wait_queue_entry wait | io_poll_add | io_uring/poll.c | local variable, function parameter
| | | | io_poll_remove_entries | | |
async_poll | io_uring/poll.c | struct io_poll poll, struct io_poll *double_poll | io_req_alloc_apoll | io_uring/poll.c | local variable, function parameter
| | | | io_async_queue_proc | | |
io_ring_ctx_rings | io_uring/register.c | struct io_rings *rings, struct io_uring_sqe *sq_sqes, struct io_mapped_region sq_region, struct io_mapped_region ring_region | io_register_free_rings | io_uring/register.c | local variable
| | | | io_register_resize_rings | | |
io_uring_mem_region_reg | io_uring/register.c | struct io_uring_mem_region_reg reg, struct io_uring_region_desc __user *rd_uptr, struct io_uring_region_desc rd | io_register_mem_region | io_uring/register.c | local variable
io_restriction | io_uring/register.c | unsigned long register_op, unsigned long sqe_op, unsigned int sqe_flags_allowed, unsigned int sqe_flags_required | io_parse_restrictions | io_uring/register.c | function parameter, local variable
| | | | io_register_restrictions | | |
io_ring_ctx | io_uring/register.c | struct io_rings *rings, struct io_uring_sqe *sq_sqes, struct io_mapped_region sq_region, struct io_mapped_region ring_region, unsigned int sq_entries, unsigned int cq_entries, unsigned int flags, struct mutex uring_lock | __io_uring_register | io_uring/register.c | function parameter, local variable
| | | | io_register_resize_rings | | |
| | | | io_register_mem_region | | |
io_rsrc_update | io_uring/rsrc.c | struct file *file, u64 arg, u32 nr_args, u32 offset | io_files_update_prep | io_uring/rsrc.c | function parameter, local variable
| | | | io_files_update_with_index_alloc | | |
| | | | io_files_update | | |
io_rsrc_node | io_uring/rsrc.c | int type, int refs, struct io_mapped_ubuf *buf, u64 tag | io_rsrc_node_alloc | io_uring/rsrc.c | return value, local variable
| | | | io_free_rsrc_node | | |
| | | | io_sqe_buffer_register | | |
io_rsrc_data | io_uring/rsrc.c | unsigned nr, struct io_rsrc_node **nodes | io_rsrc_data_alloc | io_uring/rsrc.c | function parameter, local variable
| | | | io_rsrc_data_free | | |
io_mapped_ubuf | io_uring/rsrc.c | unsigned long ubuf, size_t len, unsigned int nr_bvecs, unsigned int folio_shift, refcount_t refs, struct bio_vec bvec[] | io_sqe_buffer_register | io_uring/rsrc.c | local variable, function parameter
| | | | io_import_fixed | | |
io_imu_folio_data | io_uring/rsrc.c | unsigned int nr_pages_head, unsigned int nr_pages_mid, unsigned int nr_folios, unsigned int folio_shift | io_check_coalesce_buffer | io_uring/rsrc.c | local variable
| | | | io_coalesce_buffer | | |
io_rw | io_uring/rw.c | struct kiocb kiocb, u64 addr, u32 len, rwf_t flags | io_prep_rw | io_uring/rw.c | function parameter, local variable
| | | | io_prep_read | | |
| | | | io_prep_write | | |
| | | | io_prep_readv | | |
| | | | io_prep_writev | | |
| | | | io_prep_rw_fixed | | |
| | | | io_prep_read_fixed | | |
| | | | io_prep_write_fixed | | |
| | | | io_read | | |
| | | | io_write | | |
io_async_rw | io_uring/rw.c | struct iovec *free_iovec, unsigned int free_iov_nr, struct iov_iter iter, struct iov_iter_state iter_state, size_t bytes_done, struct wait_page_queue wpq, struct io_rw_meta meta, struct io_rw_meta_state meta_state | io_rw_alloc_async | io_uring/rw.c | local variable, function parameter
| | | | io_import_iovec | | |
| | | | io_rw_recycle | | |
| | | | io_req_rw_cleanup | | |
| | | | io_rw_should_retry | | |
| | | | io_meta_save_state | | |
| | | | io_meta_restore | | |
io_rw_meta | io_uring/rw.c | unsigned int flags, unsigned short app_tag, unsigned short seed, struct iov_iter iter | io_meta_save_state | io_uring/rw.c | local variable
| | | | io_meta_restore | | |
io_rw_meta_state | io_uring/rw.c | unsigned short seed, struct iov_iter_state iter_meta | io_meta_save_state | io_uring/rw.c | local variable
| | | | io_meta_restore | | |
wait_page_queue | io_uring/rw.c | struct wait_queue_entry wait, struct wait_page_key key | io_rw_should_retry,  | io_uring/rw.c | local variable
| | | | io_async_buf_func | | |
io_splice | io_uring/splice.c | struct file *file_out, loff_t off_out, loff_t off_in, u64 len, int splice_fd_in, unsigned int flags, struct io_rsrc_node *rsrc_node | __io_splice_prep | io_uring/splice.c | function parameter, local variable
| | | | io_splice_prep | | |
| | | | io_splice | | |
| | | | io_tee_prep | | |
| | | | io_tee | | |
io_sq_data | io_uring/sqpoll.c | struct list_head ctx_list, struct mutex lock, struct wait_queue_head wait, struct completion exited, struct task_struct *thread, struct io_ring_ctx *ctx, unsigned long state, unsigned sq_thread_idle, int sq_cpu, pid_t task_pid, pid_t task_tgid, atomic_t park_pending, refcount_t refs, unsigned long work_time | io_sq_thread_unpark | io_uring/sqpoll.c | function parameter, local variable
| | | | io_sq_thread_park | | |
| | | | io_sq_thread_stop | | |
| | | | io_put_sq_data | | |
| | | | io_sq_thread_finish | | |
| | | | io_attach_sq_data | | |
| | | | io_get_sq_data | | |
| | | | io_sq_update_worktime | | |
| | | | io_sq_thread | | |
| | | | io_sqpoll_wait_sq | | |
| | | | io_sq_offload_create | | |
| | | | io_sqpoll_wq_cpu_affinity | | |
io_statx | io_uring/statx.c | struct file *file, int dfd, unsigned int mask, unsigned int flags, struct filename *filename, struct statx __user *buffer | io_statx_prep | io_uring/statx.c | function parameter, local variable
| | | | io_statx | | |
| | | | io_statx_cleanup | | |
io_sync          | io_uring/sync.c | struct file *file, loff_t len, loff_t off, int flags, int mode | io_sfr_prep | io_uring/sync.c | function parameter, local variable
| | | | io_sync_file_range | | |
| | | | io_fsync_prep | | |
| | | | io_fsync | | |
| | | | io_fallocate_prep | | |
| | | | io_fallocate | | |
io_uring_task | io_uring/tctx.c | struct percpu_counter inflight, struct io_wq *io_wq, struct xarray xa, struct wait_queue_head wait, struct task_struct *task, struct io_ring_ctx *last, atomic_t in_cancel, atomic_t inflight_tracked, struct llist_head task_list, struct callback_head task_work, struct file *registered_rings[IO_RINGFD_REG_MAX] | io_uring_alloc_task_context | io_uring/tctx.c | function parameter, local variable
| | | | __io_uring_free | | |
| | | | io_uring_clean_tctx | | |
| | | | io_ringfd_register | | |
| | | | io_ringfd_unregister | | |
io_tctx_node | io_uring/tctx.c | struct io_ring_ctx *ctx, struct task_struct *task, struct list_head ctx_node | __io_uring_add_tctx_node | io_uring/tctx.c | local variable, function parameter
| | | | io_uring_del_tctx_node | | |
io_wq_hash | io_uring/tctx.c | struct wait_queue_head wait, refcount_t refs | io_init_wq_offload | io_uring/tctx.c | local variable
io_wq_data | io_uring/tctx.c | struct io_wq_hash *hash, struct task_struct *task, void (*free_work)(struct io_wq_work *), void (*do_work)(struct io_wq_work *) | io_init_wq_offload | io_uring/tctx.c | local variable
io_timeout | io_uring/timeout.c | struct file *file, u32 off, u32 target_seq, u32 repeats, struct list_head list, struct io_kiocb *head, struct io_kiocb *prev | io_timeout_prep | io_uring/timeout.c | function parameter, local variable
| | | | io_timeout | | |
| | | | io_timeout_remove | | |
| | | | io_timeout_cancel | | |
| | | | io_timeout_update | | |
| | | | io_timeout_remove_prep | | |
| | | | io_timeout_fn | | |
| | | | io_timeout_complete | | |
| | | | io_flush_timeouts | | |
| | | | io_kill_timeout | | |
| | | | io_kill_timeouts | | |
| | | | io_queue_linked_timeout | | |
io_timeout_rem | io_uring/timeout.c | struct file *file, u64 addr, struct timespec64 ts, u32 flags, bool ltimeout | io_timeout_remove_prep | io_uring/timeout.c | function parameter, local variable
| | | | io_timeout_remove | | |
io_ftrunc | io_uring/truncate.c | struct file *file, loff_t len | io_ftruncate_prep | io_uring/truncate.c | function parameter, local variable
| | | | io_ftruncate | | |
io_uring_cmd | io_uring/uring_cmd.c | struct io_uring_cmd_data *cache, struct io_uring_sqe *sqes, unsigned int flags, void (*task_work_cb)(struct io_uring_cmd *, unsigned) | io_uring_cmd_prep | io_uring/uring_cmd.c | function parameter, local variable
| | | | io_uring_cmd | | |
| | | | io_uring_cmd_done | | |
| | | | io_uring_cmd_mark_cancelable | | |
| | | | io_uring_cmd_del_cancelable | | |
| | | | io_uring_cmd_work | | |
| | | | io_uring_cmd_import_fixed | | |
| | | | io_uring_cmd_issue_blocking | | |
io_waitid | io_uring/waitid.c | struct file *file, int which, pid_t upid, int options, atomic_t refs, struct wait_queue_head *head, struct siginfo __user *infop, struct waitid_info info | io_waitid_free | io_uring/waitid.c | function parameter, local variable
| | | | io_waitid_copy_si | | |
| | | | io_waitid_finish | | |
| | | | io_waitid_complete | | |
| | | | __io_waitid_cancel | | |
| | | | io_waitid_cancel | | |
| | | | io_waitid_remove_all | | |
| | | | io_waitid_prep | | |
io_xattr | io_uring/xattr.c | struct file *file, struct kernel_xattr_ctx ctx, struct filename *filename | io_xattr_cleanup | io_uring/xattr.c | function parameter, local variable
| | | | io_xattr_finish | | |
| | | | __io_getxattr_prep | | |
| | | | io_fgetxattr_prep | | |
| | | | io_getxattr_prep | | |
| | | | io_fgetxattr | | |
| | | | io_getxattr | | |
| | | | __io_setxattr_prep | | |
| | | | io_setxattr_prep | | |