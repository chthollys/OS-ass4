## Name : Jason Januardy
## NIM  : 1313623035
# Task 2: Dependency Injection

Source | Libary | Function utilized | Time Used
-------|--------|--------------| ------------------
alloc_cache.h | /include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | /include/linux/kasan.h | kasan_mempool_poison_object | 1
| | arch/x86/include/asm/string_64.h| memset | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | alloc_cache.h | io_cache_alloc_new | 1
| | linux/mm/slub.c | kfree | 1
| filetable.h | include/linux/printk.h | WARN_ON_ONCE | 2
| | arch/x86/include/asm/bitops.h | test_bit | 2
| | arch/x86/include/asm/bitops.h | set_bit | 2
| | filetable.h | io_file_get_flags | 1
| io_uring.h | include/linux/compiler.h | READ_ONCE | 3
| | include/linux/atomic/atomic-instrumented.h | atomic_read | 1
| | include/linux/lockdep.h | lockdep_assert | 2
| | include/linux/sched.h  | in_task | 1
| | include/linux/lockdep.h | lockdep_assert_held | 7
| | include/linux/percpu-refcount.h | percpu_ref_is_dying | 1
| | io_uring.h | __io_req_task_work_add | 1
| | io_uring.h | __io_submit_flush_completion | 1
| | io_uring.h | io_lockdep_assert_cq_locked | 1
| | include/linux/compiler.h | unlikely | 8
| | io_uring.h | io_cqe_cache_refill | 1
| | io_uring.h | io_get_cqe_overflow | 1
| | io_uring.h | io_get_cqe | 1
| | arch/x86/include/asm/string_64.h | memcpy | 2
| | arch/x86/include/asm/string_64.h | memset | 1
| | include/trace/events/io_uring.h | trace_io_uring_complete_enabled | 1
| | include/trace/events/io_uring.h | trace_io_uring_complete | 1
| | io_uring.c | io_cache_alloc | 1
| | include/linux/printk.h | WARN_ON_ONCE | 1
| | linux/mm/slub.c | kmalloc | 1
| | fs/file.h | fput | 1
| | include/linux/mutex.h | mutex_unlock | 1
| | include/linux/mutex.h | mutex_lock | 1
| | include/linux/compiler.h | smp_store_release | 1
| | include/linux/workqueue.h | wq_has_sleeper | 2
| | include/linux/wait.h | __wake_up | 2
| | include/linux/poll.h | poll_to_key | 2
| | include/linux/kernel.h | min | 1
| | include/linux/sched.h | test_thread_flag | 2
| | include/linux/sched/signal.h | clear_notify_signal | 1
| | include/linux/sched.h | __set_current_state | 3
| | include/linux/sched/signal.h | resume_user_mode_work | 1
| | io_uring.c | tctx_task_work_run | 1
| | include/linux/task_work.h | task_work_pending | 2
| | include/linux/task_work.h | task_work_run | 1
| | include/linux/llist.h | llist_empty | 2
| | io_uring.h | io_local_work_pending | 2
| | include/linux/compiler.h | __must_hold | 1
| | include/linux/workqueue.h | wq_list_add_tail | 1
| | io_uring.c | __io_commit_cqring_flush | 1
| | io_uring.c | io_task_refs_refill | 1
| | include/linux/kernel.h | container_of | 1
| | include/linux/workqueue.h | wq_stack_extract | 1
| | io_uring.h | io_req_cache_empty | 1
| | io_uring.c | __io_alloc_req_refill | 1
| | io_uring.h | io_extract_req | 1
| | include/linux/compiler.h | likely | 2
| | io_uring.h | io_req_set_res | 1
| | io_uring.c | io_req_task_complete | 1
| | io_uring.h | io_req_task_work_add | 1
| | io_uring.h | file_can_poll | 1
| | include/linux/ktime.h | ktime_get | 1
| | include/linux/ktime.h | ktime_get_with_offset | 1
| io-wq.h | include/linux/refcount.h | refcount_dec_and_test | 1
| | linux/mm/slub.c | kfree | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_read | 1
| | include/linux/sched.h  | in_task | 1
| | kbuf.c | io_kbuf_recycle_legacy | 1
| | kbuf.c | io_kbuf_recycle_ring | 2
| | include/linux/compiler.h | unlikely | 2
| | include/linux/printk.h | WARN_ON_ONCE | 1
| | kbuf.c | io_kbuf_commit | 1
| | kbuf.h | __io_put_kbuf | 2
| | kbuf.h | __io_put_kbufs | 2
| napi.h | include/linux/list.h | list_empty | 1
| | napi.h | io_napi | 1
| | napi.h | __io_napi_busy_loop | 1
| | include/linux/compiler.h | READ_ONCE | 2
| | socket.c | sock_from_file | 1
| | napi.c | __io_napi_add_id | 1
| notif.h | io_uring.c | io_kiocb_to_cmd | 1
| | include/linux/compiler.h | __must_hold | 1
| | notif.h | io_notif_to_data | 2
| | notif.c | io_tx_ubuf_complete | 1
| | io_uring.c | __io_account_mem | 1
| poll.h | include/linux/atomic/atomic-instrumented.h | atomic_inc | 2
| refs.h | include/linux/atomic/atomic-instrumented.h | atomic_read | 1
| | include/linux/printk.h | WARN_ON_ONCE | 4
| | include/linux/atomic/atomic-instrumented.h | atomic_rinc_not_zero | 1
| | include/linux/compiler.h | likely | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_dec_and_test | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_dec | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_set | 1
| | refs.h | __io_req_set_refcount | 1
| rsrc.h | include/linux/compiler.h | array_index_nospec | 1
| | include/linux/lockdep.h | lockdep_assert_held | 1
| | rcrc.h | io_free_rsrc_node | 1
| | rsrc.h | io_put_rsrc_node | 3
| | rsrc.h | io_req_assign_rsrc_node | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_long_sub | 1
| slist.h | include/linux/compiler.h | WRITE_ONCE | 3
| | slist.h | __wq_list_splice | 1
| | slist.h | wq_list_cut | 1
| | include/linux/kernel.h | container_of | 1
| tctx.h | include/linux/compiler.h | likely | 1
| | tctx.c | __io_uring_add_tctx_node_from_submit | 1
| timeout.h | timeout.c | __io_disarm_linked_timeout | 1