# Task 3: Data Structure Investigation

| Structure name | Defined in | Attributes | Caller Function | Source Caller | Usage |
|----------------|------------|------------|-----------------|-----------|-------------------|
| io_fadvise | advise.c | file, u64, u64, u32 | io_fadvise_force_async | advise.c | function parameter,return value |
| | | | io_fadvise_prep | advise.c | function parameter,return value |
| | | | io_kiocb_to_cmd | advise.c | function parameter,return value |
| | | | io_fadvise | advise.c | function parameter,return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_fadvise_prep | advise.h | struct reference |
| | | | io_fadvise | advise.h | struct reference |
| io_madvise | advise.c | file, u64, u64, u32 | io_madvise_prep | advise.c | return value |
| | | | io_madvise | advise.c | return value |
| | | | io_madvise_prep | advise.h | struct reference |
| | | | io_madvise | advise.h | struct reference |
| io_cancel | cancel.c | file, u64, u32, s32, u8 | io_cancel_req_match | cancel.c | function parameter,return value |
| | | | io_cancel_cb | cancel.c | return value |
| | | | io_async_cancel_one | cancel.c | return value |
| | | | io_wq_cancel_cb | cancel.c | function parameter,return value |
| | | | io_try_cancel | cancel.c | function parameter,return value |
| | | | io_kiocb_to_cmd | cancel.c | function parameter,return value |
| | | | io_async_cancel_prep | cancel.c | struct reference |
| | | | __io_async_cancel | cancel.c | function parameter,return value |
| | | | __io_sync_cancel | cancel.c | return value |
| | | | io_async_cancel | cancel.c | local variable |
| | | | io_futex_cancel | futex.c | function parameter |
| | | | io_cancel_ctx_cb | io_uring.c | return value |
| | | | io_wq_cancel_cb | io_uring.c | function parameter,return value |
| | | | io_cancel_task_cb | io_uring.c | return value |
| | | | io_cancel_defer_files | io_uring.c | return value |
| | | | __io_poll_cancel | poll.c | function parameter |
| | | | io_poll_cancel | poll.c | function parameter |
| | | | io_kiocb_to_cmd | poll.c | struct reference |
| | | | io_timeout_cancel | timeout.c | function parameter |
| | | | io_waitid_cancel | waitid.c | function parameter |
| | | | io_try_cancel | cancel.h | function parameter |
| | | | io_cancel_req_match | cancel.h | function parameter |
| | | | io_cancel_match_sequence | cancel.h | struct reference |
| | | | io_futex_cancel | futex.h | function parameter |
| | | | io_poll_remove | poll.h | struct reference |
| | | | io_poll_cancel | poll.h | function parameter |
| | | | io_flush_timeouts | timeout.h | struct reference |
| | | | io_timeout_cancel | timeout.h | function parameter |
| | | | io_waitid_cancel | waitid.h | function parameter |
| io_epoll | epoll.c | file, int, int, int, epoll_event | io_epoll_ctl_prep | epoll.c | return value |
| | | | io_kiocb_to_cmd | epoll.c | function parameter,return value |
| | | | io_epoll_ctl | epoll.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_epoll_ctl_prep | epoll.h | struct reference |
| | | | io_epoll_ctl | epoll.h | struct reference |
| io_ev_fd | eventfd.c | eventfd_ctx, uint, unsigned, refcount_t, atomic_t, rcu_head | io_eventfd_free | eventfd.c | return value |
| | | | io_eventfd_put | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_release | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_do_signal | eventfd.c | return value |
| | | | __io_eventfd_signal | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_trigger | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_grab | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_signal | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_flush_signal | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_register | eventfd.c | function parameter,local variable,return value |
| | | | io_eventfd_unregister | eventfd.c | function parameter,local variable,return value |
| io_rename | fs.c | file, int, int, filename, filename, int | io_renameat_prep | fs.c | return value |
| | | | io_kiocb_to_cmd | fs.c | function parameter,return value |
| | | | io_renameat | fs.c | return value |
| | | | io_renameat_cleanup | fs.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_renameat_prep | fs.h | struct reference |
| | | | io_renameat | fs.h | struct reference |
| | | | io_renameat_cleanup | fs.h | struct reference |
| io_unlink | fs.c | file, int, int, filename | io_unlinkat_prep | fs.c | return value |
| | | | io_unlinkat | fs.c | return value |
| | | | io_unlinkat_cleanup | fs.c | return value |
| | | | io_unlinkat_prep | fs.h | struct reference |
| | | | io_unlinkat | fs.h | struct reference |
| | | | io_unlinkat_cleanup | fs.h | struct reference |
| io_mkdir | fs.c | file, int, umode_t, filename | io_mkdirat_prep | fs.c | return value |
| | | | io_mkdirat | fs.c | return value |
| | | | io_mkdirat_cleanup | fs.c | return value |
| | | | io_mkdirat_prep | fs.h | struct reference |
| | | | io_mkdirat | fs.h | struct reference |
| | | | io_mkdirat_cleanup | fs.h | struct reference |
| io_link | fs.c | file, int, int, filename, filename, int | io_linkat_prep | fs.c | return value |
| | | | io_linkat | fs.c | return value |
| | | | io_link_cleanup | fs.c | return value |
| | | | io_link_skb | notif.c | return value |
| | | | net_zcopy_get | notif.c | return value |
| | | | io_link_timeout_fn | timeout.c | return value |
| | | | io_linked_timeout_update | timeout.c | return value |
| | | | io_timeout_get_clock | timeout.c | return value |
| | | | io_link_timeout_prep | timeout.c | return value |
| | | | io_linkat_prep | fs.h | struct reference |
| | | | io_linkat | fs.h | struct reference |
| | | | io_link_cleanup | fs.h | struct reference |
| | | | io_link_timeout_prep | timeout.h | struct reference |
| | | | io_symlinkat_prep | fs.c | struct reference |
| | | | io_symlinkat | fs.c | struct reference |
| io_futex | futex.c | file, u32, futex_waitv, unsigned, unsigned, unsigned, u32, uint, bool | io_futex_cancel | cancel.c | return value |
| | | | io_futex_cache_init | futex.c | function parameter,return value |
| | | | io_futex_cache_free | futex.c | function parameter,return value |
| | | | __io_futex_complete | futex.c | function parameter,return value |
| | | | io_futex_complete | futex.c | function parameter,return value |
| | | | io_futexv_complete | futex.c | function parameter,return value |
| | | | io_kiocb_to_cmd | futex.c | function parameter,return value |
| | | | io_futexv_claim | futex.c | function parameter,return value |
| | | | __io_futex_cancel | futex.c | function parameter,return value |
| | | | io_futex_cancel | futex.c | function parameter,return value |
| | | | io_futex_remove_all | futex.c | function parameter,return value |
| | | | io_futex_prep | futex.c | function parameter,return value |
| | | | io_futex_wakev_fn | futex.c | function parameter,return value |
| | | | io_req_set_res | futex.c | function parameter,return value |
| | | | io_futexv_prep | futex.c | function parameter,return value |
| | | | futex_parse_waitv | futex.c | function parameter,return value |
| | | | io_futex_wake_fn | futex.c | function parameter,return value |
| | | | io_futexv_wait | futex.c | function parameter,return value |
| | | | io_futex_wait | futex.c | function parameter,return value |
| | | | io_futex_wake | futex.c | function parameter,return value |
| | | | io_futex_cache_init | io_uring.c | struct reference |
| | | | io_futex_cache_free | io_uring.c | struct reference |
| | | | io_futex_remove_all | io_uring.c | struct reference |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_futex_prep | futex.h | struct reference |
| | | | io_futexv_prep | futex.h | struct reference |
| | | | io_futex_wait | futex.h | struct reference |
| | | | io_futexv_wait | futex.h | struct reference |
| | | | io_futex_wake | futex.h | struct reference |
| | | | io_futex_cancel | futex.h | struct reference |
| | | | io_futex_remove_all | futex.h | struct reference |
| | | | io_futex_cache_init | futex.h | struct reference |
| | | | io_futex_cache_free | futex.h | struct reference |
| io_futex_data | futex.c | struct futex_q, struct io_kiocb | io_futex_cache_init | futex.c | struct reference |
| | | | io_alloc_cache_init | futex.c | struct reference |
| | | | io_futex_complete | futex.c | struct reference |
| | | | __io_futex_cancel | futex.c | struct reference |
| | | | io_futex_wake_fn | futex.c | return value |
| | | | io_futex_wait | futex.c | struct reference |
| io_defer_entry | io_uring.c | struct list_head, struct io_kiocb, u32 | io_queue_deferred | io_uring.c | struct reference |
| | | | io_drain_req | io_uring.c | struct reference |
| | | | io_cancel_defer_files | io_uring.c | struct reference |
| ext_arg | io_uring.c | size_t, timespec64, const, ktime_t, bool | __io_cqring_wait_schedule | io_uring.c | local variable,return value |
| | | | io_cqring_wait | io_uring.c | local variable,return value |
| | | | io_get_ext_arg_reg | io_uring.c | local variable,return value |
| | | | io_validate_ext_arg | io_uring.c | local variable,return value |
| | | | io_get_ext_arg | io_uring.c | function parameter,local variable,return value |
| io_tctx_exit | io_uring.c | callback_head, completion, io_ring_ctx | io_has_work | io_uring.c | local variable,return value |
| | | | io_uring_poll | io_uring.c | return value |
| | | | io_tctx_exit_cb | io_uring.c | local variable,return value |
| | | | io_cancel_ctx_cb | io_uring.c | local variable |
| | | | io_ring_exit_work | io_uring.c | local variable |
| io_task_cancel | io_uring.c | io_uring_task, bool | io_req_local_work_add | io_uring.c | struct reference |
| | | | io_ring_ctx_wait_and_kill | io_uring.c | struct reference |
| | | | io_uring_release | io_uring.c | struct reference |
| | | | io_cancel_task_cb | io_uring.c | struct reference |
| | | | io_uring_try_cancel_iowq | io_uring.c | local variable |
| | | | io_uring_try_cancel_requests | io_uring.c | local variable |
| io_worker | io-wq.c | refcount_t, int, unsigned, hlist_nulls_node, list_head, task_struct, io_wq, io_wq_work, raw_spinlock_t, completion, unsigned, callback_head, int, rcu_head, delayed_work | create_io_worker | io-wq.c | function parameter,return value |
| | | | io_wq_dec_running | io-wq.c | function parameter,return value |
| | | | io_worker_get | io-wq.c | function parameter,return value |
| | | | io_worker_release | io-wq.c | function parameter,return value |
| | | | io_wq_get_acct | io-wq.c | function parameter,return value |
| | | | io_worker_ref_put | io-wq.c | function parameter,return value |
| | | | io_wq_worker_stopped | io-wq.c | function parameter,return value |
| | | | io_worker_cancel_cb | io-wq.c | function parameter,return value |
| | | | io_task_worker_match | io-wq.c | function parameter,return value |
| | | | io_worker_exit | io-wq.c | function parameter,return value |
| | | | io_wq_inc_running | io-wq.c | function parameter,return value |
| | | | create_worker_cb | io-wq.c | function parameter,return value |
| | | | io_queue_worker_create | io-wq.c | function parameter,return value |
| | | | __io_worker_busy | io-wq.c | function parameter,return value |
| | | | __io_worker_idle | io-wq.c | function parameter,return value |
| | | | io_assign_current_work | io-wq.c | function parameter,return value |
| | | | io_worker_handle_work | io-wq.c | function parameter,return value |
| | | | io_wq_worker | io-wq.c | function parameter,return value |
| | | | io_wq_worker_running | io-wq.c | function parameter,return value |
| | | | io_wq_worker_sleeping | io-wq.c | function parameter,return value |
| | | | io_init_new_worker | io-wq.c | function parameter,return value |
| | | | io_should_retry_thread | io-wq.c | function parameter,return value |
| | | | queue_create_worker_retry | io-wq.c | function parameter,return value |
| | | | create_worker_cont | io-wq.c | function parameter,return value |
| | | | io_wq_worker_wake | io-wq.c | function parameter,return value |
| | | | __io_wq_worker_cancel | io-wq.c | function parameter,return value |
| | | | io_wq_worker_cancel | io-wq.c | function parameter,return value |
| | | | io_task_work_match | io-wq.c | function parameter,return value |
| | | | task_work_cancel_match | io-wq.c | function parameter,return value |
| | | | io_wq_worker_affinity | io-wq.c | function parameter,return value |
| io_wq_acct | io-wq.c | unsigned, unsigned, int, atomic_t, raw_spinlock_t, io_wq_work_list, unsigned | io_acct_cancel_pending_work | io-wq.c | function parameter,local variable,return value |
| | | | io_get_acct | io-wq.c | function parameter,local variable,return value |
| | | | io_work_get_acct | io-wq.c | function parameter,local variable,return value |
| | | | __io_acct_run_queue | io-wq.c | function parameter,local variable,return value |
| | | | io_acct_run_queue | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_activate_free_worker | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_create_worker | io-wq.c | function parameter,local variable,return value |
| | | | io_get_next_work | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_max_workers | io-wq.c | function parameter,local variable,return value |
| io_wq | io-wq.c | unsigned, free_work_fn, io_wq_work_fn, io_wq_hash, atomic_t, completion, hlist_node, task_struct, raw_spinlock_t, hlist_nulls_head, list_head, wait_queue_entry, cpumask_var_t | io_cancel_cb | cancel.c | function parameter,return value |
| | | | io_async_cancel_one | cancel.c | return value |
| | | | io_wq_cancel_cb | cancel.c | function parameter,return value |
| | | | io_wq_current_is_worker | eventfd.c | return value |
| | | | io_wq_is_hashed | io_uring.c | local variable,return value |
| | | | io_wq_enqueue | io_uring.c | function parameter,local variable,return value |
| | | | io_free_batch_list | io_uring.c | local variable,return value |
| | | | io_wq_free_work | io_uring.c | function parameter,local variable,return value |
| | | | io_wq_submit_work | io_uring.c | function parameter,local variable,return value |
| | | | io_wq_put_hash | io_uring.c | local variable,return value |
| | | | io_cancel_ctx_cb | io_uring.c | function parameter,local variable,return value |
| | | | io_wq_cancel_cb | io_uring.c | function parameter,local variable,return value |
| | | | io_cancel_task_cb | io_uring.c | function parameter,local variable,return value |
| | | | io_uring_try_cancel_iowq | io_uring.c | local variable,return value |
| | | | io_uring_try_cancel_requests | io_uring.c | local variable,return value |
| | | | io_wq_exit_start | io_uring.c | function parameter,local variable,return value |
| | | | io_wq_cancel_tw_create | io-wq.c | function parameter,local variable,return value |
| | | | io_get_work_hash | io-wq.c | function parameter,local variable,return value |
| | | | io_wait_on_hash | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_enqueue | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_work_match_all | io-wq.c | function parameter,local variable,return value |
| | | | create_io_thread | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_for_each_worker | io-wq.c | function parameter,local variable,return value |
| | | | io_run_cancel | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_insert_work | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_work_match_item | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_hash_work | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_remove_pending | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cancel_pending_work | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cancel_running_work | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cancel_cb | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_hash_wake | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_create | io-wq.c | function parameter,local variable,return value |
| | | | cpuhp_state_add_instance_nocalls | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_put_hash | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_exit_start | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_exit_workers | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_destroy | io-wq.c | function parameter,local variable,return value |
| | | | cpuhp_state_remove_instance_nocalls | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_put_and_exit | io-wq.c | function parameter,local variable,return value |
| | | | __io_wq_cpu_online | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cpu_online | io-wq.c | function parameter,local variable,return value |
| | | | hlist_entry_safe | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cpu_offline | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cpu_affinity | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_init | io-wq.c | function parameter,local variable,return value |
| | | | cpuhp_setup_state_multi | io-wq.c | function parameter,local variable,return value |
| | | | io_wq_cpu_affinity | register.c | return value |
| | | | io_wq_max_workers | register.c | function parameter,return value |
| | | | io_do_iopoll | rw.c | struct reference |
| | | | io_wq_cpu_affinity | sqpoll.c | return value |
| | | | io_init_wq_offload | tctx.c | return value |
| | | | io_wq_create | tctx.c | return value |
| | | | io_wq_max_workers | tctx.c | function parameter,return value |
| | | | io_uring_clean_tctx | tctx.c | return value |
| | | | io_wq_put_and_exit | tctx.c | return value |
| | | | io_wq_free_work | io_uring.h | function parameter |
| | | | io_wq_submit_work | io_uring.h | function parameter |
| | | | io_wq_put_hash | io-wq.h | function parameter,return value |
| | | | io_wq_create | io-wq.h | function parameter,return value |
| | | | io_wq_exit_start | io-wq.h | function parameter,return value |
| | | | io_wq_put_and_exit | io-wq.h | function parameter,return value |
| | | | io_wq_enqueue | io-wq.h | function parameter,return value |
| | | | io_wq_hash_work | io-wq.h | function parameter,return value |
| | | | io_wq_cpu_affinity | io-wq.h | function parameter,return value |
| | | | io_wq_max_workers | io-wq.h | function parameter,return value |
| | | | io_wq_worker_stopped | io-wq.h | function parameter,return value |
| | | | io_wq_is_hashed | io-wq.h | function parameter,return value |
| | | | io_wq_cancel_cb | io-wq.h | function parameter,return value |
| | | | io_wq_worker_sleeping | io-wq.h | function parameter,return value |
| | | | io_wq_worker_running | io-wq.h | function parameter,return value |
| | | | io_wq_current_is_worker | io-wq.h | function parameter,return value |
| | | | wq_list_add_after | slist.h | function parameter,return value |
| | | | wq_list_add_tail | slist.h | function parameter,return value |
| | | | wq_list_add_head | slist.h | function parameter,return value |
| | | | wq_list_cut | slist.h | function parameter,return value |
| | | | __wq_list_splice | slist.h | function parameter,return value |
| | | | wq_list_splice | slist.h | function parameter,return value |
| | | | wq_stack_add_head | slist.h | function parameter,return value |
| | | | wq_list_del | slist.h | function parameter,return value |
| | | | wq_stack_extract | slist.h | function parameter,return value |
| | | | wq_next_work | slist.h | function parameter,return value |
| io_cb_cancel_data | io-wq.c | work_cancel_fn, void, int, int, bool | create_io_worker | io-wq.c | struct reference |
| | | | io_wq_dec_running | io-wq.c | struct reference |
| | | | io_acct_cancel_pending_work | io-wq.c | struct reference |
| | | | queue_create_worker_retry | io-wq.c | local variable |
| online_data | io-wq.c | unsigned, bool | io_wq_exit_workers | io-wq.c | struct reference |
| | | | io_wq_destroy | io-wq.c | local variable |
| | | | io_wq_put_and_exit | io-wq.c | local variable |
| | | | io_wq_worker_affinity | io-wq.c | local variable |
| | | | __io_wq_cpu_online | io-wq.c | local variable |
| io_provide_buf | kbuf.c | file, __u64, __u32, __u32, __u32, __u16 | io_kiocb_to_cmd | kbuf.c | function parameter,return value |
| | | | io_put_bl | kbuf.c | struct reference |
| | | | io_destroy_buffers | kbuf.c | struct reference |
| | | | io_destroy_bl | kbuf.c | struct reference |
| | | | io_remove_buffers_prep | kbuf.c | struct reference |
| | | | io_remove_buffers | kbuf.c | struct reference |
| | | | io_provide_buffers_prep | kbuf.c | function parameter,return value |
| | | | io_refill_buffer_cache | kbuf.c | struct reference |
| | | | io_add_buffers | kbuf.c | function parameter,return value |
| | | | io_provide_buffers | kbuf.c | function parameter,return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_add_buffers | kbuf.c | function parameter,return value |
| | | | io_provide_buffers_prep | kbuf.h | struct reference |
| | | | io_provide_buffers | kbuf.h | struct reference |
| io_msg | msg_ring.c | file, file, callback_head, u64, u32, u32, u32, u32, u32, u32 | io_msg_ring_cleanup | msg_ring.c | function parameter,local variable,return value |
| | | | io_kiocb_to_cmd | msg_ring.c | function parameter,local variable,return value |
| | | | io_double_unlock_ctx | msg_ring.c | struct reference |
| | | | io_double_lock_ctx | msg_ring.c | struct reference |
| | | | io_msg_need_remote | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_tw_complete | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_remote_post | msg_ring.c | function parameter,local variable,return value |
| | | | percpu_ref_get | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_get_kiocb | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_data_remote | msg_ring.c | function parameter,local variable,return value |
| | | | __io_msg_ring_data | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_ring_data | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_grab_file | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_install_complete | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_tw_fd_complete | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_fd_remote | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_send_fd | msg_ring.c | function parameter,local variable,return value |
| | | | __io_msg_ring_prep | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_ring_prep | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_ring | msg_ring.c | function parameter,local variable,return value |
| | | | io_uring_sync_msg_ring | msg_ring.c | function parameter,local variable,return value |
| | | | io_msg_alloc_async | net.c | return value |
| | | | io_msg_copy_hdr | net.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_msg_ring_prep | msg_ring.h | struct reference |
| | | | io_msg_ring | msg_ring.h | struct reference |
| | | | io_msg_ring_cleanup | msg_ring.h | struct reference |
| io_napi_entry | napi.c | uint, list_head, unsigned, hlist_node, rcu_head | io_napi_hash_find | napi.c | return value |
| | | | net_to_ktime | napi.c | struct reference |
| | | | ns_to_ktime | napi.c | struct reference |
| | | | __io_napi_add_id | napi.c | struct reference |
| | | | __io_napi_del_id | napi.c | struct reference |
| | | | __io_napi_remove_stale | napi.c | struct reference |
| | | | io_napi_remove_stale | napi.c | struct reference |
| | | | io_napi_busy_loop_timeout | napi.c | struct reference |
| | | | ktime_after | napi.c | struct reference |
| | | | io_napi_busy_loop_should_end | napi.c | struct reference |
| | | | static_tracking_do_busy_loop | napi.c | struct reference |
| | | | io_napi_init | napi.c | struct reference |
| | | | io_napi_free | napi.c | struct reference |
| io_shutdown | net.c | file, int | io_shutdown_prep | net.c | return value |
| | | | io_kiocb_to_cmd | net.c | function parameter,return value |
| | | | io_shutdown | net.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_shutdown_prep | net.h | struct reference |
| | | | io_shutdown | net.h | struct reference |
| io_accept | net.c | file, sockaddr, int, int, int, u32, unsigned | io_accept_prep | net.c | return value |
| | | | io_accept | net.c | return value |
| | | | io_accept_prep | net.h | struct reference |
| | | | io_accept | net.h | struct reference |
| io_socket | net.c | file, int, int, int, int, u32, unsigned | io_socket_prep | net.c | return value |
| | | | io_socket | net.c | return value |
| | | | io_socket_prep | net.h | struct reference |
| | | | io_socket | net.h | struct reference |
| io_connect | net.c | file, sockaddr, int, bool, bool | io_connect_prep | net.c | return value |
| | | | io_connect | net.c | return value |
| | | | io_connect_prep | net.h | struct reference |
| | | | io_connect | net.h | struct reference |
| io_bind | net.c | file, int | io_bind_prep | net.c | return value |
| | | | io_bind | net.c | return value |
| | | | io_bind_prep | net.h | struct reference |
| | | | io_bind | net.h | struct reference |
| io_listen | net.c | file, int | io_listen_prep | net.c | return value |
| | | | io_listen | net.c | return value |
| | | | io_listen_prep | net.h | struct reference |
| | | | io_listen | net.h | struct reference |
| io_sr_msg | net.c | file, compat_msghdr, user_msghdr, void, int, unsigned, unsigned, unsigned, u16, u16, u16, void, io_kiocb | io_recvmsg_prep_multishot | net.c | function parameter,return value |
| | | | io_recvmsg_multishot | net.c | function parameter,return value |
| io_recvmsg_multishot_hdr | net.c | io_uring_recvmsg_out, sockaddr_storage | | | |
| io_nop | nop.c | file, int, int, int, uint | io_nop_prep | nop.c | return value |
| | | | io_kiocb_to_cmd | nop.c | function parameter,return value |
| | | | io_nop | nop.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_nop_prep | nop.h | struct reference |
| | | | io_nop | nop.h | struct reference |
| io_open | openclose.c | file, int, u32, filename, open_how, unsigned | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_openat_force_async | openclose.c | function parameter,return value |
| | | | __io_openat_prep | openclose.c | function parameter,return value |
| | | | io_kiocb_to_cmd | openclose.c | function parameter,return value |
| | | | io_openat_prep | openclose.c | function parameter,return value |
| | | | io_openat2_prep | openclose.c | function parameter,return value |
| | | | io_openat2 | openclose.c | function parameter,return value |
| | | | io_openat | openclose.c | function parameter,return value |
| | | | io_open_cleanup | openclose.c | function parameter,return value |
| | | | io_openat_prep | openclose.h | struct reference |
| | | | io_openat | openclose.h | struct reference |
| | | | io_open_cleanup | openclose.h | struct reference |
| | | | io_openat2_prep | openclose.h | struct reference |
| | | | io_openat2 | openclose.h | struct reference |
| io_close | openclose.c | file, int, u32 | __io_close_fixed | openclose.c | return value |
| | | | io_close_fixed | openclose.c | return value |
| | | | io_close_prep | openclose.c | return value |
| | | | io_close | openclose.c | return value |
| | | | __io_close_fixed | rsrc.c | struct reference |
| | | | __io_close_fixed | openclose.h | struct reference |
| | | | io_close_prep | openclose.h | struct reference |
| | | | io_close | openclose.h | struct reference |
| io_fixed_install | openclose.c | file, uint | io_install_fixed_fd_prep | openclose.c | return value |
| | | | io_install_fixed_fd | openclose.c | return value |
| io_poll_update | poll.c | file, u64, u64, __poll_t, bool, bool | io_kiocb_to_cmd | poll.c | function parameter,return value |
| io_poll_table | poll.c | poll_table_struct, io_kiocb, int, int, bool, __poll_t | __io_queue_proc | poll.c | function parameter,local variable,return value |
| | | | io_poll_can_finish_inline | poll.c | function parameter,local variable,return value |
| | | | __io_arm_poll_handler | poll.c | function parameter,local variable,return value |
| | | | io_arm_poll_handler | poll.c | function parameter,local variable,return value |
| io_ring_ctx_rings | register.c | io_rings, io_uring_sqe, io_mapped_region, io_mapped_region | io_register_free_rings | register.c | local variable,return value |
| | | | io_register_resize_rings | register.c | local variable,return value |
| io_rsrc_update | rsrc.c | file, u64, u32, u32 | io_kiocb_to_cmd | rsrc.c | function parameter,return value |
| io_rw | rw.c | kiocb, u64, u32, rwf_t | io_alloc_cache_free | io_uring.c | function parameter |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_complete_rw_iopoll | rw.c | function parameter,return value |
| | | | io_iov_compat_buffer_select_prep | rw.c | function parameter,return value |
| | | | io_kiocb_to_cmd | rw.c | function parameter,return value |
| | | | io_rw_recycle | rw.c | function parameter,return value |
| | | | io_rw_alloc_async | rw.c | function parameter,return value |
| | | | io_prep_rw_pi | rw.c | function parameter,return value |
| | | | io_rw_should_reissue | rw.c | function parameter,return value |
| | | | io_rw_done | rw.c | function parameter,return value |
| | | | loop_rw_iter | rw.c | function parameter,return value |
| | | | io_rw_should_retry | rw.c | function parameter,return value |
| | | | io_iter_do_read | rw.c | function parameter,return value |
| | | | io_rw_init_file | rw.c | function parameter,return value |
| | | | io_rw_fail | rw.c | function parameter,return value |
| | | | io_rw_cache_free | rw.c | function parameter,return value |
| | | | io_rw_fail | rw.h | struct reference |
| | | | io_rw_cache_free | rw.h | struct reference |
| io_splice | splice.c | file, loff_t, loff_t, u64, int, uint, io_rsrc_node | io_eopnotsupp_prep | opdef.c | return value |
| | | | __io_splice_prep | splice.c | return value |
| | | | io_kiocb_to_cmd | splice.c | function parameter,return value |
| | | | io_splice_cleanup | splice.c | return value |
| | | | io_splice_get_file | splice.c | return value |
| | | | io_splice_prep | splice.c | return value |
| | | | io_splice | splice.c | return value |
| | | | io_splice_cleanup | splice.h | struct reference |
| | | | io_splice_prep | splice.h | struct reference |
| | | | io_splice | splice.h | struct reference |
| io_statx | statx.c | file, int, uint, uint, filename, statx | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_statx_prep | statx.c | return value |
| | | | io_kiocb_to_cmd | statx.c | function parameter,return value |
| | | | io_statx | statx.c | return value |
| | | | io_statx_cleanup | statx.c | return value |
| | | | io_statx_prep | statx.h | struct reference |
| | | | io_statx | statx.h | struct reference |
| | | | io_statx_cleanup | statx.h | struct reference |
| io_sync | sync.c | file, loff_t, loff_t, int, int | __io_sync_cancel | cancel.c | return value |
| | | | io_sync_cancel | cancel.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_sync_cancel | register.c | return value |
| | | | io_kiocb_to_cmd | sync.c | function parameter,return value |
| | | | io_sync_file_range | sync.c | return value |
| | | | io_sync_cancel | cancel.h | struct reference |
| | | | io_sync_file_range | sync.h | struct reference |
| io_timeout | timeout.c | file, u32, u32, u32, list_head, io_kiocb, io_kiocb | io_timeout_cancel | cancel.c | return value |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_kiocb_to_cmd | timeout.c | function parameter,return value |
| | | | io_timeout_finish | timeout.c | function parameter,return value |
| | | | io_timeout_fn | timeout.c | function parameter,return value |
| | | | io_timeout_complete | timeout.c | function parameter,return value |
| | | | io_flush_timeouts | timeout.c | function parameter,return value |
| | | | io_req_set_res | timeout.c | function parameter,return value |
| | | | io_timeout_extract | timeout.c | function parameter,return value |
| | | | io_timeout_cancel | timeout.c | function parameter,return value |
| | | | io_timeout_get_clock | timeout.c | function parameter,return value |
| | | | io_timeout_update | timeout.c | function parameter,return value |
| | | | io_timeout_remove_prep | timeout.c | function parameter,return value |
| | | | io_timeout_remove | timeout.c | function parameter,return value |
| | | | __io_timeout_prep | timeout.c | function parameter,return value |
| | | | io_timeout_prep | timeout.c | function parameter,return value |
| | | | io_timeout | timeout.c | function parameter,return value |
| | | | io_kill_timeouts | timeout.c | function parameter,return value |
| | | | io_timeout_cancel | timeout.h | struct reference |
| | | | io_timeout_prep | timeout.h | struct reference |
| | | | io_timeout | timeout.h | struct reference |
| | | | io_timeout_remove_prep | timeout.h | struct reference |
| | | | io_timeout_remove | timeout.h | struct reference |
| io_timeout_rem | timeout.c | file, u64, timespec64, u32, bool | io_timeout_update | timeout.c | struct reference |
| | | | io_timeout_remove_prep | timeout.c | struct reference |
| | | | io_translate_timeout_mode | timeout.c | struct reference |
| | | | io_timeout_remove | timeout.c | struct reference |
| io_ftrunc | truncate.c | file, loff_t | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_ftruncate_prep | truncate.c | return value |
| | | | io_kiocb_to_cmd | truncate.c | function parameter,return value |
| | | | io_ftruncate | truncate.c | return value |
| | | | io_ftruncate_prep | truncate.h | struct reference |
| | | | io_ftruncate | truncate.h | struct reference |
| io_waitid | waitid.c | file, int, pid_t, int, atomic_t, wait_queue_head, siginfo, waitid_info | io_waitid_cancel | cancel.c | return value |
| | | | io_waitid_remove_all | io_uring.c | struct reference |
| | | | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_waitid_cb | waitid.c | function parameter,return value |
| | | | io_waitid_free | waitid.c | function parameter,return value |
| | | | io_waitid_compat_copy_si | waitid.c | function parameter,return value |
| | | | io_waitid_copy_si | waitid.c | function parameter,return value |
| | | | io_kiocb_to_cmd | waitid.c | function parameter,return value |
| | | | io_waitid_finish | waitid.c | function parameter,return value |
| | | | io_waitid_complete | waitid.c | function parameter,return value |
| | | | __io_waitid_cancel | waitid.c | function parameter,return value |
| | | | io_waitid_cancel | waitid.c | function parameter,return value |
| | | | io_waitid_remove_all | waitid.c | function parameter,return value |
| | | | io_waitid_drop_issue_ref | waitid.c | function parameter,return value |
| | | | io_waitid_wait | waitid.c | function parameter,return value |
| | | | io_waitid_prep | waitid.c | function parameter,return value |
| | | | io_waitid | waitid.c | function parameter,return value |
| | | | io_waitid_prep | waitid.h | struct reference |
| | | | io_waitid | waitid.h | struct reference |
| | | | io_waitid_cancel | waitid.h | struct reference |
| | | | io_waitid_remove_all | waitid.h | struct reference |
| io_xattr | xattr.c | file, kernel_xattr_ctx, filename | io_eopnotsupp_prep | opdef.c | return value |
| | | | io_xattr_cleanup | xattr.c | return value |
| | | | io_kiocb_to_cmd | xattr.c | function parameter,return value |
| | | | io_xattr_finish | xattr.c | return value |
| | | | io_xattr_cleanup | xattr.h | struct reference |
| io_cancel_data | cancel.h | io_ring_ctx, u64, file, u8, u32, int | io_cancel_req_match | cancel.c | function parameter,local variable,return value |
| | | | io_async_cancel_one | cancel.c | function parameter,local variable,return value |
| | | | io_try_cancel | cancel.c | function parameter,local variable,return value |
| | | | __io_async_cancel | cancel.c | function parameter,local variable,return value |
| | | | io_kiocb_to_cmd | cancel.c | function parameter,local variable,return value |
| | | | __io_sync_cancel | cancel.c | function parameter,local variable,return value |
| | | | io_futex_cancel | futex.c | function parameter,return value |
| | | | __io_poll_cancel | poll.c | function parameter,local variable,return value |
| | | | io_poll_cancel | poll.c | function parameter,local variable,return value |
| | | | io_kiocb_to_cmd | poll.c | function parameter,local variable,return value |
| | | | io_timeout_cancel | timeout.c | function parameter,local variable,return value |
| | | | io_waitid_cancel | waitid.c | function parameter,return value |
| | | | io_try_cancel | cancel.h | function parameter,return value |
| | | | io_cancel_req_match | cancel.h | function parameter,return value |
| | | | io_futex_cancel | futex.h | function parameter,return value |
| | | | io_poll_remove | poll.h | function parameter,return value |
| | | | io_poll_cancel | poll.h | function parameter,return value |
| | | | io_flush_timeouts | timeout.h | function parameter,return value |
| | | | io_timeout_cancel | timeout.h | function parameter,return value |
| | | | io_waitid_cancel | waitid.h | function parameter,return value |
| io_wait_queue | io_uring.h | wait_queue_entry, io_ring_ctx, unsigned, unsigned, unsigned, int, ktime_t, ktime_t, hrtimer, ktime_t, bool | io_cqring_schedule_timeout | io_uring.c | function parameter,local variable,return value |
| | | | __io_cqring_wait_schedule | io_uring.c | function parameter,local variable,return value |
| | | | io_cqring_wait_schedule | io_uring.c | function parameter,local variable,return value |
| | | | io_cqring_wait | io_uring.c | function parameter,local variable,return value |
| | | | io_napi_busy_loop_should_end | napi.c | function parameter,return value |
| | | | io_napi_blocking_busy_loop | napi.c | function parameter,return value |
| | | | __io_napi_busy_loop | napi.c | function parameter,return value |
| | | | io_should_wake | io_uring.h | function parameter,return value |
| | | | __io_napi_busy_loop | napi.h | function parameter,return value |
| | | | io_napi_busy_loop | napi.h | function parameter,return value |
| io_wq_hash | io-wq.h | refcount_t, unsigned, wait_queue_head | io_wq_hash_work | io-wq.c | return value |
| | | | io_wq_hash_wake | io-wq.c | return value |
| | | | io_wq_put_hash | io-wq.h | function parameter,return value |
| | | | io_wq_hash_work | io-wq.h | function parameter,return value |
| io_wq_data | io-wq.h | io_wq_hash, task_struct, io_wq_work_fn, free_work_fn | io_wq_create | io-wq.c | function parameter,return value |
| | | | io_wq_create | io-wq.h | function parameter,return value |
| io_buffer_list | kbuf.h | list_head, io_uring_buf_ring, __u16, __u16, __u16, __u16, __u16, __u16, io_mapped_region | io_buffer_get_list | kbuf.c | function parameter,return value |
| | | | io_buffer_add_list | kbuf.c | function parameter,return value |
| | | | io_kbuf_recycle_legacy | kbuf.c | function parameter,return value |
| | | | io_provided_buffers_select | kbuf.c | function parameter,return value |
| | | | io_ring_buffers_peek | kbuf.c | function parameter,return value |
| | | | io_buffers_select | kbuf.c | function parameter,return value |
| | | | io_buffers_peek | kbuf.c | function parameter,return value |
| | | | __io_remove_buffers | kbuf.c | function parameter,return value |
| | | | io_put_bl | kbuf.c | function parameter,return value |
| | | | io_destroy_buffers | kbuf.c | function parameter,return value |
| | | | io_destroy_bl | kbuf.c | function parameter,return value |
| | | | io_kiocb_to_cmd | kbuf.c | function parameter,return value |
| | | | io_add_buffers | kbuf.c | function parameter,return value |
| | | | io_register_pbuf_ring | kbuf.c | function parameter,return value |
| | | | io_unregister_pbuf_ring | kbuf.c | function parameter,return value |
| | | | io_register_pbuf_status | kbuf.c | function parameter,return value |
| | | | io_kbuf_commit | kbuf.h | return value |
| | | | __io_put_kbuf_ring | kbuf.h | return value |
| io_buffer | kbuf.h | list_head, __u64, __u32, __u16, __u16 | __io_put_kbuf | kbuf.c | return value |
| | | | __io_put_kbuf_list | kbuf.c | function parameter,return value |
| | | | io_buffer_select | kbuf.c | return value |
| | | | io_refill_buffer_cache | kbuf.c | return value |
| | | | io_buffers_select | net.c | return value |
| | | | io_buffer_select | net.c | return value |
| | | | io_buffers_peek | net.c | return value |
| | | | io_buffer_validate | rsrc.c | return value |
| | | | io_buffer_unmap | rsrc.c | return value |
| | | | io_buffer_account_pin | rsrc.c | return value |
| | | | io_buffer_select | rw.c | return value |
| | | | io_buffer_select | kbuf.h | struct reference |
| | | | io_buffers_select | kbuf.h | struct reference |
| | | | io_buffers_peek | kbuf.h | struct reference |
| | | | __io_put_kbuf_list | kbuf.h | function parameter |
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
