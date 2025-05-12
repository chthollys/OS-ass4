# Task 3: Data Structure Investigation

| Structure name | Defined in | Attributes | Caller Function | Source Caller | Usage |
|----------------|------------|------------|-----------------|-----------|-------------------|
| io_fadvise | advise.c | file, u64, u64, u32 | io_fadvise_force_async | advise.c | function parameter |
| | | | io_fadvise_prep | advise.c | local variable |
| | | | io_fadvise | advise.c | local variable |
| io_madvise | advise.c | file, u64, u64, u32 | io_madvise_prep | advise.c | local variable |
| | | | io_madvise | advise.c | local variable |
| io_cancel | cancel.c | file, u64, u32, s32, u8 | io_async_cancel_prep | cancel.c | local variable |
| | | | io_async_cancel | cancel.c | local variable |
| io_epoll | epoll.c | file, int, int, int, epoll_event | io_epoll_ctl_prep | epoll.c | local variable |
| | | | io_epoll_ctl | epoll.c | local variable |
| io_ev_fd | eventfd.c | eventfd_ctx, uint, unsigned, refcount_t, atomic_t, rcu_head | io_eventfd_free | eventfd.c | local variable |
| | | | io_eventfd_put | eventfd.c | function parameter |
| | | | io_eventfd_release | eventfd.c | function parameter |
| | | | io_eventfd_do_signal | eventfd.c | local variable |
| | | | __io_eventfd_signal | eventfd.c | function parameter |
| | | | io_eventfd_trigger | eventfd.c | function parameter |
| | | | io_eventfd_grab | eventfd.c | return value,local variable |
| | | | io_eventfd_signal | eventfd.c | local variable |
| | | | io_eventfd_flush_signal | eventfd.c | local variable |
| | | | io_eventfd_register | eventfd.c | local variable |
| | | | io_eventfd_unregister | eventfd.c | local variable |
| io_rename | fs.c | file, int, int, filename, filename, int | io_renameat_prep | fs.c | local variable |
| | | | io_renameat | fs.c | local variable |
| | | | io_renameat_cleanup | fs.c | local variable |
| io_unlink | fs.c | file, int, int, filename | io_unlinkat_prep | fs.c | local variable |
| | | | io_unlinkat | fs.c | local variable |
| | | | io_unlinkat_cleanup | fs.c | local variable |
| io_mkdir | fs.c | file, int, umode_t, filename | io_mkdirat_prep | fs.c | local variable |
| | | | io_mkdirat | fs.c | local variable |
| | | | io_mkdirat_cleanup | fs.c | local variable |
| io_link | fs.c | file, int, int, filename, filename, int | io_linkat_prep | fs.c | local variable |
| | | | io_linkat | fs.c | local variable |
| | | | io_link_cleanup | fs.c | local variable |
| | | | io_symlinkat_prep | fs.c | local variable |
| | | | io_symlinkat | fs.c | local variable |
| io_futex | futex.c | file, u32, futex_waitv, unsigned, unsigned, unsigned, u32, uint, bool | io_futexv_complete | futex.c | local variable |
| | | | io_futexv_claim | futex.c | function parameter |
| | | | __io_futex_cancel | futex.c | local variable |
| | | | io_futex_prep | futex.c | local variable |
| | | | io_futex_wakev_fn | futex.c | local variable |
| | | | io_futexv_prep | futex.c | local variable |
| | | | io_futexv_wait | futex.c | local variable |
| | | | io_futex_wait | futex.c | local variable |
| | | | io_futex_wake | futex.c | local variable |
| io_futex_data | futex.c | struct futex_q, struct io_kiocb | io_alloc_cache_init | futex.c | type for sizeof |
| | | | __io_futex_cancel | futex.c | local variable |
| | | | io_futex_wake_fn | futex.c | local variable |
| | | | io_futex_wait | futex.c | local variable |
| io_defer_entry | io_uring.c | struct list_head, struct io_kiocb, u32 | io_queue_deferred | io_uring.c | local variable |
| | | | io_drain_req | io_uring.c | local variable |
| | | | io_cancel_defer_files | io_uring.c | local variable |
| ext_arg | io_uring.c | size_t, timespec64, const, ktime_t, bool | __io_cqring_wait_schedule | io_uring.c | function parameter |
| | | | io_cqring_wait_schedule | io_uring.c | function parameter |
| | | | io_cqring_wait | io_uring.c | function parameter |
| | | | io_get_ext_arg | io_uring.c | function parameter |
| | | | SYSCALL_DEFINE6 | io_uring.c | local variable |
| io_tctx_exit | io_uring.c | callback_head, completion, io_ring_ctx | io_tctx_exit_cb | io_uring.c | local variable |
| | | | io_ring_exit_work | io_uring.c | local variable |
| io_task_cancel | io_uring.c | io_uring_task, bool | io_cancel_task_cb | io_uring.c | local variable |
| | | | io_uring_try_cancel_requests | io_uring.c | local variable |
| io_worker | io-wq.c | refcount_t, int, unsigned, hlist_nulls_node, list_head, task_struct, io_wq, io_wq_work, raw_spinlock_t, completion, unsigned, callback_head, int, rcu_head, delayed_work | io_wq_dec_running | io-wq.c | function parameter |
| | | | io_worker_get | io-wq.c | function parameter |
| | | | io_worker_release | io-wq.c | function parameter |
| | | | io_wq_get_acct | io-wq.c | function parameter |
| | | | io_wq_worker_stopped | io-wq.c | local variable |
| | | | io_worker_cancel_cb | io-wq.c | function parameter |
| | | | io_task_worker_match | io-wq.c | local variable |
| | | | io_acct_activate_free_worker | io-wq.c | local variable |
| | | | io_worker_exit | io-wq.c | function parameter |
| | | | io_wq_inc_running | io-wq.c | function parameter |
| | | | create_worker_cb | io-wq.c | local variable |
| | | | io_queue_worker_create | io-wq.c | function parameter |
| | | | io_wq_dec_running | io-wq.c | function parameter |
| | | | __io_worker_busy | io-wq.c | function parameter |
| | | | __io_worker_idle | io-wq.c | function parameter |
| | | | io_assign_current_work | io-wq.c | function parameter |
| | | | io_worker_handle_work | io-wq.c | function parameter |
| | | | io_wq_worker | io-wq.c | local variable |
| | | | io_wq_worker_running | io-wq.c | local variable |
| | | | io_wq_worker_sleeping | io-wq.c | local variable |
| | | | io_init_new_worker | io-wq.c | function parameter |
| | | | io_should_retry_thread | io-wq.c | function parameter |
| | | | queue_create_worker_retry | io-wq.c | function parameter |
| | | | create_worker_cont | io-wq.c | local variable |
| | | | io_workqueue_create | io-wq.c | local variable |
| | | | create_io_worker | io-wq.c | local variable |
| | | | io_acct_for_each_worker | io-wq.c | function parameter |
| | | | io_wq_for_each_worker | io-wq.c | function parameter |
| | | | io_wq_worker_wake | io-wq.c | function parameter |
| | | | __io_wq_worker_cancel | io-wq.c | function parameter |
| | | | io_wq_worker_cancel | io-wq.c | function parameter |
| | | | io_task_work_match | io-wq.c | local variable |
| | | | io_wq_cancel_tw_create | io-wq.c | local variable |
| | | | io_wq_worker_affinity | io-wq.c | function parameter |
| io_wq_acct | io-wq.c | unsigned, unsigned, int, atomic_t, raw_spinlock_t, io_wq_work_list, unsigned | io_acct_cancel_pending_work | io-wq.c | function parameter |
| | | | create_io_worker | io-wq.c | function parameter |
| | | | io_acct_cancel_pending_work | io-wq.c | function parameter |
| | | | io_get_acct | io-wq.c | return value |
| | | | io_work_get_acct | io-wq.c | return value |
| | | | io_wq_get_acct | io-wq.c | return value |
| | | | io_worker_cancel_cb | io-wq.c | local variable |
| | | | io_worker_exit | io-wq.c | local variable |
| | | | __io_acct_run_queue | io-wq.c | function parameter |
| | | | io_acct_run_queue | io-wq.c | function parameter |
| | | | io_acct_activate_free_worker | io-wq.c | function parameter |
| | | | io_wq_create_worker | io-wq.c | function parameter |
| | | | io_get_next_work | io-wq.c | function parameter |
| | | | io_wq_max_workers | io-wq.c | local variable |
| | | | io_wq_inc_running | io-wq.c | local variable |
| | | | create_worker_cb | io-wq.c | local variable |
| | | | io_queue_worker_create | io-wq.c | function parameter |
| | | | io_wq_dec_running | io-wq.c | local variable |
| | | | __io_worker_busy | io-wq.c | function parameter |
| | | | __io_worker_idle | io-wq.c | function parameter |
| | | | io_worker_handle_work | io-wq.c | function parameter |
| | | | io_wq_worker | io-wq.c | local variable |
| | | | io_init_new_worker | io-wq.c | function parameter |
| | | | create_worker_cont | io-wq.c | local variable |
| | | | io_work_queue_create | io-wq.c | local variable |
| | | | io_acct_for_each_worker | io-wq.c | function parameter |
| | | | io_wq_insert_work | io-wq.c | function parameter |
| | | | io_wq_enqueue | io-wq.c | local variable |
| | | | io_wq_remove_pending | io-wq.c | function parameter |
| | | | io_wq_cancel_pending_work | io-wq.c | local variable |
| | | | io_acct_cancel_running_work | io-wq.c | function parameter |
| | | | io_wq_hash_wake | io-wq.c | local variable |
| | | | io_wq_create | io-wq.c | local variable |
| | | | io_wq_max_workers | io-wq.c | local variable |
| io_wq | io-wq.c | unsigned, free_work_fn, io_wq_work_fn, io_wq_hash, atomic_t, completion, hlist_node, task_struct, raw_spinlock_t, hlist_nulls_head, list_head, wait_queue_entry, cpumask_var_t | create_io_worker | cancel.c | function parameter |
| | | | io_acct_cancel_pending_work | io-wq.c | function parameter |
| | | | io_wq_cancel_tw_create | io-wq.c | function parameter |
| | | | io_get_acct | io-wq.c | function parameter |
| | | | io_work_get_acct | io-wq.c | function parameter |
| | | | io_wq_get_acct | io-wq.c | function parameter |
| | | | io_worker_ref_put | io-wq.c | function parameter |
| | | | io_worker_cancel_cb | io-wq.c | local variable |
| | | | io_acct_cancel_running_work | io-wq.c | function parameter |
| | | | io_worker_exit | io-wq.c | local variable |
| | | | io_wq_create_worker | io-wq.c | function parameter |
| | | | create_worker_cb | io-wq.c | local variable |
| | | | io_queue_worker_create | io-wq.c | local variable |
| | | | io_wq_dec_running | io-wq.c | local variable |
| | | | io_wait_on_hash | io-wq.c | function parameter |
| | | | io_acct_cancel_running_work | io-wq.c | function parameter |
| | | | io_get_next_work | io-wq.c | function parameter |
| | | | io_worker_handle_work | io-wq.c | local variable |
| | | | io_wq_worker | io-wq.c | local variable |
| | | | io_init_new_worker | io-wq.c | function parameter |
| | | | create_worker_cont | io-wq.c | local variable |
| | | | create_io_worker | io-wq.c | function parameter |
| | | | io_wq_for_each_worker | io-wq.c | function parameter |
| | | | io_run_cancel | io-wq.c | function parameter |
| | | | io_wq_insert_work | io-wq.c | function parameter |
| | | | io_wq_enqueue | io-wq.c | function parameter |
| | | | io_wq_remove_pending | io-wq.c | function parameter |
| | | | io_acct_cancel_pending_work | io-wq.c | function parameter |
| | | | io_wq_cancel_pending_work | io-wq.c | function parameter |
| | | | io_wq_cancel_running_work | io-wq.c | function parameter |
| | | | io_wq_cancel_cb | io-wq.c | function parameter |
| | | | io_wq_hash_wake | io-wq.c | local variable |
| | | | io_wq_create | io-wq.c | return value, local variable |
| | | | io_wq_exit_start | io-wq.c | function parameter |
| | | | io_wq_cancel_tw_create | io-wq.c | function parameter |
| | | | io_wq_exit_workers | io-wq.c | function parameter |
| | | | io_wq_put_and_exit | io-wq.c | function parameter |
| | | | io_wq_destroy | io-wq.c | function parameter |
| | | | __io_wq_cpu_online | io-wq.c | function parameter |
| | | | io_wq_cpu_online | io-wq.c | local variable |
| | | | io_wq_cpu_offline | io-wq.c | local variable |
| | | | io_wq_max_workers | io-wq.c | function parameter |
| io_cb_cancel_data | io-wq.c | work_cancel_fn, void, int, int, bool | io_acct_cancel_pending_work | io-wq.c | function parameter |
| | | | io_wq_destroy | io-wq.c | local variable |
| | | | create_worker_cont | io-wq.c | local variable |
| | | | io_wq_enqueue | io-wq.c | local variable |
| | | | __io_wq_worker_cancel | io-wq.c | function parameter |
| | | | io_wq_worker_cancel | io-wq.c | struct reference |
| | | | io_wq_cancel_pending_work | io-wq.c | function parameter |
| | | | io_acct_cancel_running_work | io-wq.c | function parameter |
| | | | io_wq_cancel_running_work | io-wq.c | function parameter |
| | | | io_wq_cancel_cb | io-wq.c | local variable |
| | | | io_wq_destroy | io-wq.c | local variable |
| online_data | io-wq.c | unsigned, bool | io_wq_worker_affinity | io-wq.c | struct reference |
| | | | __io_wq_cpu_online | io-wq.c | local variable |
| io_provide_buf | kbuf.c | file, __u64, __u32, __u32, __u32, __u16 | io_put_bl | kbuf.c | struct reference |
| | | | io_remove_buffers_prep | kbuf.c | struct reference |
| | | | io_remove_buffers | kbuf.c | struct reference |
| | | | io_provide_buffers_prep | kbuf.c | struct reference |
| | | | io_add_buffers | kbuf.c | function parameter |
| | | | io_provide_buffers | kbuf.c | struct reference |
| io_msg | msg_ring.c | file, file, callback_head, u64, u32, u32, u32, u32, u32, u32 | io_msg_ring_cleanup | msg_ring.c | struct reference |
| | | | io_msg_data_remote | msg_ring.c | function parameter |
| | | | __io_msg_ring_data | msg_ring.c | function parameter |
| | | | io_msg_ring_data | msg_ring.c | struct reference |
| | | | io_msg_grab_file | msg_ring.c | struct reference |
| | | | io_msg_install_complete | msg_ring.c | struct reference |
| | | | io_msg_tw_fd_complete | msg_ring.c | struct reference |
| | | | io_msg_fd_remote | msg_ring.c | struct reference |
| | | | io_msg_send_fd | msg_ring.c | struct reference |
| | | | __io_msg_ring_prep | msg_ring.c | function parameter |
| | | | io_msg_ring | msg_ring.c | struct reference |
| | | | io_uring_sync_msg_ring | msg_ring.c | struct reference |
| io_napi_entry | napi.c | uint, list_head, unsigned, hlist_node, rcu_head | io_napi_hash_find | napi.c | return type, local variable |
| | | | __io_napi_add_id | napi.c | local variable |
| | | | __io_napi_del_id | napi.c | local variable |
| | | | __io_napi_remove_stale | napi.c | local variable |
| | | | static_tracking_do_busy_loop | napi.c | local variable |
| | | | dynamic_tracking_do_busy_loop | napi.c | local variable |
| | | | io_napi_free | napi.c | local variable |
| io_shutdown | net.c | file, int | io_shutdown_prep | net.c | struct reference |
| | | | io_shutdown | net.c | struct reference |
| io_accept | net.c | file, sockaddr, int, int, int, u32, unsigned | io_accept_prep | net.c | struct reference |
| | | | io_accept | net.c | struct reference |
| io_socket | net.c | file, int, int, int, int, u32, unsigned | io_socket_prep | net.c | struct reference |
| | | | io_socket | net.c | struct reference |
| io_connect | net.c | file, sockaddr, int, bool, bool | io_connect_prep | net.c | struct reference |
| | | | io_connect | net.c | struct reference |
| io_bind | net.c | file, int | io_bind_prep | net.c | struct reference |
| | | | io_bind | net.c | struct reference |
| io_listen | net.c | file, int | io_listen_prep | net.c | struct reference |
| | | | io_listen | net.c | struct reference |
| io_sr_msg | net.c | file, compat_msghdr, user_msghdr, void, int, unsigned, unsigned, unsigned, u16, u16, u16, void, io_kiocb | io_mshot_prep_retry | net.c | struct reference |
| | | | io_compat_msg_copy_hdr | net.c | struct reference |
| | | | io_msg_copy_hdr | net.c | struct reference |
| | | | io_send_setup | net.c | struct reference |
| | | | io_sendmsg_setup | net.c | struct reference |
| | | | io_sendmsg_prep | net.c | struct reference |
| | | | io_send_finish | net.c | struct reference |
| | | | io_sendmsg | net.c | struct reference |
| | | | io_send_select_buffer | net.c | struct reference |
| | | | io_send | net.c | struct reference |
| | | | io_recvmsg_prep_setup | net.c | struct reference |
| | | | io_recvmsg_prep | net.c | struct reference |
| | | | io_recv_finish | net.c | struct reference |
| | | | io_recvmsg_prep_multishot | net.c | struct reference, function parameter |
| | | | io_recvmsg_multishot | net.c | struct reference, function parameter |
| | | | io_recvmsg | net.c | struct reference |
| | | | io_recv_buf_select | net.c | struct reference |
| | | | io_recv | net.c | struct reference |
| | | | io_send_zc_cleanup | net.c | struct reference |
| | | | io_send_zc_prep | net.c | struct reference |
| | | | io_send_zc_import | net.c | struct reference |
| | | | io_send_zc | net.c | struct reference |
| | | | io_sendmsg_zc | net.c | struct reference |
| | | | io_sendrecv_fail | net.c | struct reference |
| io_recvzc | net.c | file, uint, u16, u32, io_zcrx_ifq | io_recvzc_prep | net.c | struct reference |
| | | | io_recvzc | net.c | struct reference |
| io_recvmsg_multishot_hdr | net.c | io_uring_recvmsg_out, sockaddr_storage | io_recvmsg_multishot | net.c | struct reference |
| io_nop | nop.c | file, int, int, int, uint | io_nop_prep | nop.c | struct reference |
| | | | io_nop | nop.c | struct reference |
| io_open | openclose.c | file, int, u32, filename, open_how, unsigned | io_openat_force_async | openclose.c | function parameter |
| | | | __io_openat_prep | openclose.c | struct reference |
| | | | io_openat_prep | openclose.h | struct reference |
| | | | io_openat2_prep | openclose.c | struct reference |
| | | | io_openat2 | openclose.c | struct reference |
| | | | io_open_cleanup | openclose.h | struct reference |
| io_close | openclose.c | file, int, u32 | io_close_fixed | openclose.c | struct reference |
| | | | io_close_prep | openclose.c | struct reference |
| | | | io_close | openclose.c | struct reference |
| io_fixed_install | openclose.c | file, uint | io_install_fixed_fd_prep | openclose.c | struct reference |
| | | | io_install_fixed_fd | openclose.c | struct reference |
| io_poll_update | poll.c | file, u64, u64, __poll_t, bool, bool | io_poll_remove_prep | poll.c | struct reference |
| | | | io_poll_remove | poll.c | struct reference |
| io_poll_table | poll.c | poll_table_struct, io_kiocb, int, int, bool, __poll_t | __io_queue_proc   | poll.c |  function parameter |
| | | | io_poll_queue_proc | poll.c | Local variable |
| | | | io_poll_can_finish_inline | poll.c | function parameter |
| | | | __io_arm_poll_handler | poll.c | function parameter |
| | | | io_async_queue_proc | poll.c | Local variable |
| | | | io_arm_poll_handler | poll.c | Local variable |
| | | | io_poll_add | poll.c | Local variable |
| io_ring_ctx_rings | register.c | io_rings, io_uring_sqe, io_mapped_region, io_mapped_region | io_register_free_rings | register.c | function parameter |
| | | | io_register_resize_rings | register.c | Local variable |
| io_rsrc_update | rsrc.c | file, u64, u32, u32 | io_files_update_prep | rsrc.c | Local variable |
| | | | io_files_update_with_index_alloc | rsrc.c | Local variable |
| | | | io_files_update | rsrc.c | Local variable |
| io_rw | rw.c | kiocb, u64, u32, rwf_t | io_iov_compat_buffer_select_prep | rw.c | function parameter |
| | | | io_iov_buffer_select_prep | rw.c | Local variable |
| | | | __io_import_rw_buffer | rw.c | Local variable |
| | | | io_prep_rw_pi | rw.c | function parameter |
| | | | __io_prep_rw | rw.c | Local variable |
| | | | io_init_rw_fixed | rw.c | Local variable |
| | | | io_rw_import_reg_vec | rw.c | Local variable |
| | | | io_rw_prep_reg_vec | rw.c | Local variable |
| | | | io_read_mshot_prep | rw.c | Local variable |
| | | | io_kiocb_update_pos | rw.c | Local variable |
| | | | io_rw_should_reissue | rw.c | Local variable |
| | | | io_req_end_write | rw.c | Local variable |
| | | | io_req_io_end | rw.c | Local variable |
| | | | io_req_rw_complete | rw.c | Local variable|
| | | | io_complete_rw | rw.c | Local variable |
| | | | io_complete_rw_iopoll | rw.c | Local variable |
| | | | io_rw_done | rw.c | Local variable |
| | | | kiocb_done | rw.c | Local variable |
| | | | loop_rw_iter | rw.c | function parameter |
| | | | io_async_buf_func | rw.c | Local variable |
| | | | io_rw_should_retry | rw.c | Local variable |
| | | | io_iter_do_read | rw.c | function parameter |
| | | | io_rw_init_file | rw.c | Local variable |
| | | | __io_read | rw.c | Local variable |
| | | | io_read_mshot | rw.c | Local variable |
| | | | io_write | rw.c | Local variable |
| | | | io_uring_classic_poll | rw.c | Local variable |
| io_splice | splice.c | file, loff_t, loff_t, u64, int, uint, io_rsrc_node | __io_splice_prep | splice.c | Local variable |
| | | | io_splice_cleanup | splice.c | Local variable |
| | | | io_splice_get_file | splice.c | Local variable |
| | | | io_tee | splice.c | Local variable |
| | | | io_splice_prep | splice.c | Local variable |
| | | | io_splice | splice.c | Local variable |
| io_statx | statx.c | file, int, uint, uint, filename, statx | io_statx_prep | statx.c | Local variable |
| | | | io_statx | statx.c | Local variable |
| | | | io_statx_cleanup | statx.c | Local variable |
| io_sync | sync.c | file, loff_t, loff_t, int, int | io_sfr_prep | sync.c | Local variable |
| | | | io_sync_file_range | sync.c | Local variable |
| | | | io_fsync_prep | sync.c | Local variable |
| | | | io_fsync | sync.c | Local variable |
| | | | io_fallocate_prep | sync.c | Local variable |
| | | | io_fallocate | sync.c | Local variable |
| io_timeout | timeout.c | file, u32, u32, u32, list_head, io_kiocb, io_kiocb | io_is_timeout_noseq | timeout.c | Local variable |
| | | | io_timeout_finish | timeout.c | function parameter |
| | | | io_timeout_complete | timeout.c | Local variable |
| | | | io_flush_killed_timeouts | timeout.c | Local variable |
| | | | io_kill_timeout | timeout.c | Local variable |
| | | | io_flush_timeouts | timeout.c | Local variable |
| | | | __io_disarm_linked_timeout | timeout.c | Local variable |
| | | | io_timeout_fn | timeout.c | Local variable |
| | | | io_timeout_extract | timeout.c | Local variable |
| | | | io_req_task_link_timeout | timeout.c | Local variable |
| | | | io_link_timeout_fn | timeout.c | Local variable |
| | | | io_linked_timeout_update | timeout.c | Local variable |
| | | | io_timeout_update | timeout.c | Local variable |
| | | | __io_timeout_prep | timeout.c | Local variable |
| | | | io_timeout | timeout.c | Local variable |
| | | | io_queue_linked_timeout | timeout.c | Local variable |
| | | | io_kill_timeouts | timeout.c | Local variable |
| io_timeout_rem | timeout.c | file, u64, timespec64, u32, bool | io_timeout_remove_prep | timeout.c | Local variable |
| | | | io_timeout_remove | timeout.c | Local variable |
| io_ftrunc | truncate.c | file, loff_t | io_ftruncate_prep | truncate.c | Local variable |
| | | | io_ftruncate | truncate.c | Local variable |
| io_waitid | waitid.c | file, int, pid_t, int, atomic_t, wait_queue_head, siginfo, waitid_info | io_waitid_compat_copy_si | waitid.c | function parameter |
| | | | io_waitid_copy_si | waitid.c | Local variable |
| | | | io_waitid_complete | waitid.c | Local variable |
| | | | __io_waitid_cancel | waitid.c | Local variable |
| | | | io_waitid_drop_issue_ref | waitid.c | Local variable |
| | | | io_waitid_cb | waitid.c | Local variable |
| | | | io_waitid_prep | waitid.c | Local variable |
| | | | io_waitid_wait | waitid.c | Local variable |
| | | | io_waitid_prep | waitid.c | Local variable |
| | | | io_waitid | waitid.c | Local variable |
| io_xattr | xattr.c | file, kernel_xattr_ctx, filename | io_xattr_cleanup | xattr.c | Local variable |
| | | | __io_getxattr_prep | xattr.c | Local variable |
| | | | io_getxattr_prep | xattr.c | Local variable |
| | | | io_fgetxattr | xattr.c | Local variable |
| | | | io_getxattr | xattr.c | Local variable |
| | | | __io_setxattr_prep | xattr.c | Local variable |
| | | | io_setxattr_prep | xattr.c | Local variable |
| | | | io_fsetxattr | xattr.c | Local variable |
| | | | io_setxattr | xattr.c | Local variable |
| io_zcrx_args | zcrx.c | io_kiocb, io_zcrx_ifq, socket, unsigned | io_zcrx_recv_skb | zcrx.c | Local variable |
| | | | io_zcrx_tcp_recvmsg | zcrx.c | Local variable |
| io_cancel_data | cancel.h | io_ring_ctx, u64, file, u8, u32, int | io_try_cancel| cancel.h |function parameter |
| | | | io_cancel_req_match | cancel.h | function parameter|
| | | | io_cancel_remove | cancel.h | function parameter |
| | | | io_cancel_req_match | cancel.c | function parameter |
| | | | io_cancel_cb | cancel.c | Local variable |
| | | | io_async_cancel_one | cancel.c | function parameter |
| | | | io_try_cancel | cancel.c | function parameter |
| | | | __io_async_cancel | cancel.c | function parameter |
| | | | io_async_cancel | cancel.c | function parameter |
| | | | __io_sync_cancel | cancel.c | function parameter |
| | | | io_sync_cancel | cancel.c | Local variable |
| | | | io_cancel_remove | cancel.c | function parameter |
| | | | io_futex_cancel | futex.c | function parameter |
| | | | io_futex_cancel | futex.h | function parameter |
| | | | io_poll_find | poll.c | function parameter |
| | | | io_poll_file_find | poll.c | function parameter |
| | | | __io_poll_cancel | poll.c | function parameter |
| | | | io_poll_cancel | poll.c | function parameter |
| | | | io_poll_remove | poll.c | Local variable |
| | | | io_timeout_extract | timeout.c | function parameter |
| | | | io_timeout_cancel | timeout.c | function parameter |
| | | | io_req_task_link_timeout | timeout.c | Local variable |
| | | | io_timeout_update | timeout.c | Local variable |
| | | | io_timeout_remove | timeout.c | Local variable |
| | | | io_timeout_cancel | timeout.h | function parameter |
| | | | io_waitid_cancel | waitid.c | function parameter |
| | | | io_waitid_cancel | waitid.h | function parameter |
| io_wait_queue | io_uring.h | wait_queue_entry, io_ring_ctx, unsigned, unsigned, unsigned, int, ktime_t, ktime_t, hrtimer, ktime_t, bool | io_should_wake | io_uring.h | function parameter |
| | | | io_wake_function | io_uring.c | Local variable |
| | | | io_cqring_timer_wakeup | io_uring.c | Local variable |
| | | | io_cqring_min_timer_wakeup | io_uring.c | Local variable |
| | | | io_cqring_schedule_timeout | io_uring.c | function parameter |
| | | | __io_cqring_wait_schedule | io_uring.c | function parameter |
| | | | io_cqring_wait_schedule | io_uring.c | function parameter |
| | | | io_cqring_wait | io_uring.c | Local variable |
| | | | io_napi_busy_loop_should_end | napi.c | Local variable |
| | | | io_napi_blocking_busy_loop | napi.c | function parameter |
| | | | __io_napi_busy_loop | napi.c | function parameter |
| | | | __io_napi_busy_loop | napi.h | function parameter |
| | | | io_napi_busy_loop | napi.h | function parameter |
| | | | io_napi_busy_loop | napi.h | function parameter |
| io_wq_hash | io-wq.h | refcount_t, unsigned, wait_queue_head | io_wq_put_hash | io-wq.h | function parameter |
| | | | io_init_wq_offload | txtc.c | Local variable |
| io_wq_data | io-wq.h | io_wq_hash, task_struct, io_wq_work_fn, free_work_fn |io_wq_create | io-wq.c |  function parameter|
| | | | io_init_wq_offload | txtc.c | Local variable |
| io_buffer_list | kbuf.h | list_head, io_uring_buf_ring, __u16, __u16, __u16, __u16, __u16, __u16, io_mapped_region | io_kbuf_commit | kbuf.h | function parameter|
| | | | io_kbuf_inc_commit | kbuf.c | function parameter |
| | | | io_kbuf_commit | kbuf.c | function parameter |
| | | | io_buffer_get_list | kbuf.c | Return values |
| | | | io_buffer_add_list | kbuf.c | function parameter |
| | | | io_kbuf_recycle_legacy | kbuf.c | Local variable |
| | | | io_provided_buffer_select | kbuf.c | function parameter |
| | | | io_provided_buffers_select | kbuf.c | function parameter |
| | | | io_ring_buffer_select | kbuf.c | function parameter |
| | | | io_buffer_select | kbuf.c | Local variable |
| | | | io_ring_buffers_peek | kbuf.c |function parameter|
| | | | io_buffers_select | kbuf.c | Local variable |
| | | | io_buffers_peek | kbuf.c | Local variable |
| | | | __io_put_kbuf_ring | kbuf.c | Local variable |
| | | | __io_remove_buffers | kbuf.c | function parameter |
| | | | io_put_bl | kbuf.c | function parameter |
| | | | io_destroy_buffers | kbuf.c | Local variable |
| | | | io_destroy_bl | kbuf.c | function parameter |
| | | | io_remove_buffers | kbuf.c | Local variable |
| | | | io_add_buffers | kbuf.c | function parameter |
| | | | io_provide_buffers | kbuf.c | Local variable |
| | | | io_register_pbuf_ring | kbuf.c | Local variable |
| | | | io_unregister_pbuf_ring | kbuf.c | Local variable |
| | | | io_register_pbuf_status | kbuf.c | Local variable |
| | | | io_pbuf_get_region | kbuf.c | Local variable |
| io_buffer | kbuf.h | list_head, __u64, __u32, __u16, __u16 | io_kbuf_recycle_legacy| kbuf.c | Local variable|
| | | | io_provided_buffer_select | kbuf.c | Local variable |
| | | | __io_remove_buffers | kbuf.c | Local variable |
| | | | io_add_buffers | kbuf.c | Local variable |
| buf_sel_arg | kbuf.h | iovec, size_t, size_t, unsigned, unsigned | io_kiocb_to_cmd | net.c | local variable |
| io_async_msghdr | net.h | iovec, int, int, iovec, __kernel_size_t, __kernel_size_t, sockaddr, msghdr, sockaddr_storage | io_netmsg_iovec_free | net.c | function parameter,return value |
| | | | io_netmsg_recycle | net.c | function parameter,return value |
| | | | io_msg_alloc_async | net.c | function parameter,return value |
| | | | io_net_vec_assign | net.c | function parameter,return value |
| | | | io_mshot_prep_retry | net.c | function parameter,return value |
| | | | io_compat_msg_copy_hdr | net.c | function parameter,return value |
| | | | io_msg_copy_hdr | net.c | function parameter,return value |
| | | | io_sendmsg_copy_hdr | net.c | function parameter,return value |
| | | | io_sendmsg_recvmsg_cleanup | net.c | function parameter,return value |
| | | | io_kiocb_to_cmd | net.c | function parameter,return value |
| | | | io_bundle_nbufs | net.c | function parameter,return value |
| | | | io_send_finish | net.c | function parameter,return value |
| | | | io_send_select_buffer | net.c | function parameter,return value |
| | | | io_recvmsg_mshot_prep | net.c | function parameter,return value |
| | | | io_recvmsg_copy_hdr | net.c | function parameter,return value |
| | | | io_recv_finish | net.c | function parameter,return value |
| | | | io_recvmsg_prep_multishot | net.c | function parameter,return value |
| | | | io_recvmsg_multishot | net.c | function parameter,return value |
| | | | io_recv_buf_select | net.c | function parameter,return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| io_notif_data | notif.h | file, ubuf_info, io_notif_data, io_notif_data, unsigned, bool, bool, bool | io_notif_to_data | net.c | return value |
| | | | io_notif_to_data | notif.c | return value |
| | | | io_link_skb | notif.c | return value |
| | | | io_notif_to_data | notif.h | return value |
| | | | io_kiocb_to_cmd | notif.h | function parameter,return value |
| io_issue_def | opdef.h | unsigned | io_prep_async_work | io_uring.c | function parameter,return value |
| | | | io_assign_file | io_uring.c | function parameter,return value |
| | | | io_issue_sqe | io_uring.c | function parameter,return value |
| | | | io_eopnotsupp_prep | opdef.c | local variable,return value |
| | | | io_arm_poll_handler | poll.c | return value |
| | | | __io_import_iovec | rw.c | return value |
| | | | io_cache_alloc | io_uring.h | return value |
| io_cold_def | opdef.h | const | io_account_cq_overflow | io_uring.c | struct reference |
| | | | req_need_defer | io_uring.c | struct reference |
| | | | io_clean_op | io_uring.c | struct reference |
| | | | io_req_complete_post | io_uring.c | struct reference |
| | | | io_req_defer_failed | io_uring.c | struct reference |
| io_poll | poll.h | file, wait_queue_head, __poll_t, int, wait_queue_entry | io_poll_cancel | cancel.c | return value |
| | | | io_poll_wq_wake | io_uring.c | struct reference |
| | | | io_poll_issue | io_uring.c | struct reference |
| | | | io_poll_remove_all | io_uring.c | struct reference |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_poll_wake | poll.c | function parameter,return value |
| | | | io_poll_get_ownership_slowpath | poll.c | function parameter,return value |
| | | | io_poll_get_ownership | poll.c | function parameter,return value |
| | | | io_poll_mark_cancelled | poll.c | function parameter,return value |
| | | | io_poll_get_double | poll.c | function parameter,return value |
| | | | io_poll_get_single | poll.c | function parameter,return value |
| | | | io_kiocb_to_cmd | poll.c | function parameter,return value |
| | | | io_poll_req_insert | poll.c | function parameter,return value |
| | | | io_init_poll_iocb | poll.c | function parameter,return value |
| | | | io_poll_remove_entry | poll.c | function parameter,return value |
| | | | io_poll_remove_entries | poll.c | function parameter,return value |
| | | | __io_poll_execute | poll.c | function parameter,return value |
| | | | io_req_set_res | poll.c | function parameter,return value |
| | | | io_poll_execute | poll.c | function parameter,return value |
| | | | io_poll_check_events | poll.c | function parameter,return value |
| | | | io_poll_issue | poll.c | function parameter,return value |
| | | | io_poll_task_func | poll.c | function parameter,return value |
| | | | io_poll_cancel_req | poll.c | function parameter,return value |
| | | | io_pollfree_wake | poll.c | function parameter,return value |
| | | | io_poll_double_prepare | poll.c | function parameter,return value |
| | | | __io_queue_proc | poll.c | function parameter,return value |
| | | | io_poll_queue_proc | poll.c | function parameter,return value |
| | | | io_poll_can_finish_inline | poll.c | function parameter,return value |
| | | | io_poll_add_hash | poll.c | function parameter,return value |
| | | | __io_arm_poll_handler | poll.c | function parameter,return value |
| | | | io_arm_poll_handler | poll.c | function parameter,return value |
| | | | io_poll_remove_all | poll.c | function parameter,return value |
| | | | io_poll_find | poll.c | function parameter,return value |
| | | | io_poll_file_find | poll.c | function parameter,return value |
| | | | io_poll_disarm | poll.c | function parameter,return value |
| | | | __io_poll_cancel | poll.c | function parameter,return value |
| | | | io_poll_cancel | poll.c | function parameter,return value |
| | | | io_poll_parse_events | poll.c | function parameter,return value |
| | | | io_poll_remove_prep | poll.c | function parameter,return value |
| | | | io_poll_add_prep | poll.c | function parameter,return value |
| | | | io_poll_add | poll.c | function parameter,return value |
| | | | io_poll_remove | poll.c | function parameter,return value |
| | | | io_poll_multishot_retry | rw.c | struct reference |
| | | | io_poll_issue | io_uring.h | struct reference |
| | | | io_poll_wq_wake | io_uring.h | struct reference |
| | | | io_poll_multishot_retry | poll.h | local variable,return value |
| | | | io_poll_add_prep | poll.h | local variable,return value |
| | | | io_poll_add | poll.h | local variable,return value |
| | | | io_poll_remove_prep | poll.h | local variable,return value |
| | | | io_poll_remove | poll.h | local variable,return value |
| | | | io_poll_cancel | poll.h | local variable,return value |
| | | | io_poll_remove_all | poll.h | local variable,return value |
| | | | io_poll_task_func | poll.h | local variable,return value |
| async_poll | poll.h | io_poll, io_poll | io_req_alloc_apoll | poll.c | return value |
| io_rsrc_node | rsrc.h | unsigned, int, u64, unsigned, io_mapped_ubuf | io_rsrc_node_lookup | cancel.c | return value |
| | | | io_rsrc_node_alloc | filetable.c | return value |
| | | | io_fixed_fd_remove | filetable.c | return value |
| | | | io_rsrc_node_lookup | filetable.c | return value |
| | | | io_rsrc_node_lookup | io_uring.c | return value |
| | | | io_kiocb_to_cmd | msg_ring.c | return value |
| | | | io_rsrc_node_lookup | msg_ring.c | return value |
| | | | io_rsrc_node_lookup | net.c | return value |
| | | | io_rsrc_node_lookup | nop.c | return value |
| | | | io_sqe_buffer_register | rsrc.c | function parameter,return value |
| | | | io_buffer_unmap | rsrc.c | function parameter,return value |
| | | | io_rsrc_node_alloc | rsrc.c | function parameter,return value |
| | | | io_free_rsrc_node | rsrc.c | function parameter,return value |
| | | | io_rsrc_node_lookup | rsrc.c | function parameter,return value |
| | | | io_kiocb_to_cmd | rw.c | return value |
| | | | io_rsrc_node_lookup | rw.c | return value |
| | | | io_kiocb_to_cmd | splice.c | return value |
| | | | io_rsrc_node_lookup | splice.c | return value |
| | | | io_rsrc_node_lookup | uring_cmd.c | return value |
| | | | cmd_to_io_kiocb | uring_cmd.c | return value |
| | | | io_slot_flags | filetable.h | function parameter,return value |
| | | | io_slot_file | filetable.h | function parameter,return value |
| | | | io_fixed_file_set | filetable.h | function parameter,return value |
| | | | io_rsrc_node_alloc | rsrc.h | function parameter,return value |
| | | | io_free_rsrc_node | rsrc.h | function parameter,return value |
| | | | io_rsrc_node_lookup | rsrc.h | function parameter,return value |
| | | | io_put_rsrc_node | rsrc.h | function parameter,return value |
| | | | io_reset_rsrc_node | rsrc.h | function parameter,return value |
| | | | io_req_assign_rsrc_node | rsrc.h | function parameter,return value |
| | | | io_req_assign_buf_node | rsrc.h | function parameter,return value |
| io_mapped_ubuf | rsrc.h | u64, uint, uint, uint, refcount_t, unsigned | io_buffer_account_pin | rsrc.c | return value |
| | | | io_import_fixed | rsrc.c | return value |
| | | | io_import_fixed | rsrc.h | return value |
| io_imu_folio_data | rsrc.h | uint, uint, uint, uint | io_region_init_ptr | memmap.c | local variable |
| | | | io_coalesce_buffer | rsrc.c | local variable,return value |
| | | | io_check_coalesce_buffer | rsrc.c | local variable,return value |
| | | | __counted_by | rsrc.h | return value |
| | | | io_check_coalesce_buffer | rsrc.h | return value |
| io_meta_state | rw.h | u32, iov_iter_state | struct_group | rw.h | local variable |
| io_async_rw | rw.h | size_t, iovec, iov_iter, iov_iter_state, iovec, int, wait_page_queue, uio_meta, io_meta_state | io_eopnotsupp_prep | opdef.c | return value |
| | | | __io_import_iovec | rw.c | function parameter,return value |
| | | | io_import_iovec | rw.c | function parameter,return value |
| | | | io_rw_recycle | rw.c | function parameter,return value |
| | | | io_rw_alloc_async | rw.c | function parameter,return value |
| | | | io_prep_rw_setup | rw.c | function parameter,return value |
| | | | io_meta_save_state | rw.c | function parameter,return value |
| | | | io_meta_restore | rw.c | function parameter,return value |
| | | | io_prep_rw_pi | rw.c | function parameter,return value |
| | | | io_kiocb_to_cmd | rw.c | function parameter,return value |
| | | | io_fixup_rw_res | rw.c | function parameter,return value |
| | | | io_rw_should_retry | rw.c | function parameter,return value |
| io_sq_data | sqpoll.h | refcount_t, atomic_t, mutex, list_head, task_struct, wait_queue_head, unsigned, int, pid_t, pid_t, u64, unsigned, completion | io_uring_cancel_generic | io_uring.c | function parameter,return value |
| | | | io_sq_thread_unpark | sqpoll.c | function parameter,return value |
| | | | io_sq_thread_park | sqpoll.c | function parameter,return value |
| | | | io_sq_thread_stop | sqpoll.c | function parameter,return value |
| | | | io_put_sq_data | sqpoll.c | function parameter,return value |
| | | | io_sqd_update_thread_idle | sqpoll.c | function parameter,return value |
| | | | io_sq_thread_finish | sqpoll.c | function parameter,return value |
| | | | io_attach_sq_data | sqpoll.c | function parameter,return value |
| | | | io_get_sq_data | sqpoll.c | function parameter,return value |
| | | | io_sqd_events_pending | sqpoll.c | function parameter,return value |
| | | | io_sqd_handle_event | sqpoll.c | function parameter,return value |
| | | | io_sq_update_worktime | sqpoll.c | function parameter,return value |
| | | | io_sq_thread | sqpoll.c | function parameter,return value |
| | | | io_sqpoll_wq_cpu_affinity | sqpoll.c | function parameter,return value |
| | | | io_uring_cancel_generic | io_uring.h | function parameter,return value |
| | | | io_sq_thread_stop | sqpoll.h | function parameter,return value |
| | | | io_sq_thread_park | sqpoll.h | function parameter,return value |
| | | | io_sq_thread_unpark | sqpoll.h | function parameter,return value |
| | | | io_put_sq_data | sqpoll.h | function parameter,return value |
| io_tctx_node | tctx.h | list_head, task_struct, io_ring_ctx | io_uring_try_cancel_iowq | io_uring.c | return value |
| | | | io_uring_cancel_generic | io_uring.c | return value |
| | | | __io_uring_free | tctx.c | return value |
| | | | __io_uring_add_tctx_node | tctx.c | return value |
| | | | io_uring_del_tctx_node | tctx.c | return value |
| | | | io_uring_clean_tctx | tctx.c | return value |
| io_timeout_data | timeout.h | io_kiocb, hrtimer, timespec64, enum, u32 | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_kiocb_to_cmd | timeout.c | function parameter,return value |
| | | | io_timeout_finish | timeout.c | function parameter,return value |
| | | | io_timeout_get_clock | timeout.c | function parameter,return value |
| io_waitid_async | waitid.h | io_kiocb, wait_opts | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_waitid_free | waitid.c | return value |
| | | | io_kiocb_to_cmd | waitid.c | return value |
| | | | io_waitid_cb | waitid.c | return value |
| io_async_cmd | uring_cmd.h | io_uring_cmd_data	data, iou_vec, io_uring_sqe | io_cmd_cache_free | uring_cmd.c | return value |
| | | | io_req_uring_cleanup | uring_cmd.c | return value |
| | | | io_uring_cmd_prep_setup | uring_cmd.c | return value |
| | | | io_uring_cmd_import_fixed_vec | uring_cmd.c | return value |
| | | | io_ring_ctx_alloc | io_uring.c | return value |
| io_zcrx_area | zcrx.h | net_iov_area nia, io_zcrx_ifq	*ifq, atomic_t *user_refs, bool	is_mapped, u16 area_id, page* *pages, spinlock_t, freelist_lock ____cacheline_aligned_in_smp, u32 free_count, u32 *freelist | io_zcrx_create_area | zcrx.c | return value |
| | | | __io_zcrx_unmap_area | zcrx.c | function parameter |
| | | | io_zcrx_unmap_area | zcrx.c | function parameter |
| | | | io_zcrx_map_area | zcrx.c | return value, function parameter |
| | | | io_get_user_counter | zcrx.c | return value |
| | | | io_zcrx_iov_page | zcrx.c | return value |
| | | | io_zcrx_free_area | zcrx.c | function parameter |
| | | | io_zcrx_create_area | zcrx.c | function parameter, return value |
| | | | __io_zcrx_get_free_niov | zcrx.c | return value, function parameter |
| | | | io_zcrx_return_niov_freelist | zcrx.c | function parameter |
| | | | io_zcrx_scrub | zcrx.c | return value |
| | | | io_zcrx_refill_slow | zcrx.c | return value |
| | | | io_pp_zc_destroy | zcrx.c | return value |
| | | | io_zcrx_queue_cqe | zcrx.c | return value |
| | | | io_zcrx_alloc_fallback | zcrx.c | return value, function parameter |
| | | | io_zcrx_copy_chunk | zcrx.c | return value, function parameter |
| io_zcrx_ifq | zcrx.h | io_ring_ctx, io_zcrx_area, io_uring, io_uring_zcrx_rqe, u32, u32, spinlock_t, u32, device, net_device, netdevice_tracker,  spinlock_t | __io_zcrx_unmap_area | zcrx.c | function parameter |
| | | | io_zcrx_unmap_area | zcrx.c | function parameter |
| | | | io_zcrx_map_area | zcrx.c | function parameter |
| | | | io_allocate_rbuf_ring | zcrx.c | function parameter, return value |
| | | | io_free_rbuf_ring | zcrx.c | function parameter |
| | | | io_zcrx_create_area | zcrx.c | function parameter, return value |
| | | | io_zcrx_ifq_alloc | zcrx.c | function parameter, return value |
| | | | io_zcrx_drop_netdev | zcrx.c | function parameter |
| | | | io_close_queue | zcrx.c | function parameter |
| | | | io_zcrx_ifq_free | zcrx.c | function parameter |
| | | | io_register_zcrx_ifq | zcrx.c | function parameter |
| | | | io_unregister_zcrx_ifqs | zcrx.c | function parameter |
| | | | io_zcrx_scrub | zcrx.c | function parameter |
| | | | io_zcrx_rqring_entries | zcrx.c | function parameter, return value |
| | | | io_zcrx_get_rqe | zcrx.c | function parameter, return value |
| | | | io_zcrx_ring_refill | zcrx.c | function parameter |
| | | | io_zcrx_refill_slow | zcrx.c | function parameter |
| | | | io_pp_zc_alloc_netmems | zcrx.c | function parameter, return value |
| | | | io_pp_zc_init | zcrx.c | return value |
| | | | io_pp_zc_destroy | zcrx.c | return value |
| | | | io_pp_uninstall | zcrx.c | return value |
| | | | io_zcrx_queue_cqe | zcrx.c | function parameter, return value |
| | | | io_zcrx_copy_chunk | zcrx.c | function parameter, return value |
| | | | io_zcrx_copy_frag | zcrx.c | function parameter, return value |
| | | | io_zcrx_recv_frag | zcrx.c | function parameter, return value |
| | | | io_zcrx_recv_skb | zcrx.c | return value |
| | | | io_zcrx_tcp_recvmsg | zcrx.c | function parameter, return value |
| | | | io_zcrx_recv | zcrx.c | function parameter, return value |