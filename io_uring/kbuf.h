// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_KBUF_H
#define IOU_KBUF_H

#include <uapi/linux/io_uring.h>
#include <linux/io_uring_types.h>

enum {
	/* ring mapped provided buffers */
	IOBL_BUF_RING	= 1,
	/* buffers are consumed incrementally rather than always fully */
	IOBL_INC	= 2,
};

struct io_buffer_list {
	/*
	 * If ->buf_nr_pages is set, then buf_pages/buf_ring are used. If not,
	 * then these are classic provided buffers and ->buf_list is used.
	 */
	union {
		struct list_head buf_list;
		struct io_uring_buf_ring *buf_ring;
	};
	__u16 bgid;

	/* below is for ring provided buffers */
	__u16 buf_nr_pages;
	__u16 nr_entries;
	__u16 head;
	__u16 mask;

	__u16 flags;

	struct io_mapped_region region;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

enum {
	/* can alloc a bigger vec */
	KBUF_MODE_EXPAND	= 1,
	/* if bigger vec allocated, free old one */
	KBUF_MODE_FREE		= 2,
};

struct buf_sel_arg {
	struct iovec *iovs;
	size_t out_len;
	size_t max_len;
	unsigned short nr_iovs;
	unsigned short mode;
};

// Selects a user buffer for a request and returns pointer to user-space buffer
void __user *io_buffer_select(struct io_kiocb *req, size_t *len,
			      unsigned int issue_flags);

// Selects multiple buffers for a request and populates the iovs array
int io_buffers_select(struct io_kiocb *req, struct buf_sel_arg *arg,
		      unsigned int issue_flags);

// Peeks at buffers without selecting them for a request
int io_buffers_peek(struct io_kiocb *req, struct buf_sel_arg *arg);

// Destroys and cleans up all buffers associated with a context
void io_destroy_buffers(struct io_ring_ctx *ctx);

// Prepares to remove buffers from a buffer group
int io_remove_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Removes buffers from a buffer group as specified in the request
int io_remove_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Prepares submission queue entry for buffer provision
int io_provide_buffers_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Provides buffers to the kernel for future use by io_uring operations
int io_provide_buffers(struct io_kiocb *req, unsigned int issue_flags);

// Registers a provided buffer ring with the io_uring context
int io_register_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

// Unregisters a previously registered buffer ring from the io_uring context
int io_unregister_pbuf_ring(struct io_ring_ctx *ctx, void __user *arg);

// Registers buffer status information with the io_uring context
int io_register_pbuf_status(struct io_ring_ctx *ctx, void __user *arg);

// Recycles legacy buffer using the legacy mechanism
bool io_kbuf_recycle_legacy(struct io_kiocb *req, unsigned issue_flags);

// Drops legacy kernel buffer associated with a request
void io_kbuf_drop_legacy(struct io_kiocb *req);

// Puts back multiple kernel buffers and handles the accounting
unsigned int __io_put_kbufs(struct io_kiocb *req, int len, int nbufs);

// Commits buffer usage to a buffer list with length and count information
bool io_kbuf_commit(struct io_kiocb *req,
		    struct io_buffer_list *bl, int len, int nr);

// Gets a mapped region for a provided buffer with specified buffer group ID
struct io_mapped_region *io_pbuf_get_region(struct io_ring_ctx *ctx,
					    unsigned int bgid);

// Recycles buffer rings by clearing flags and preserving buffer state
static inline bool io_kbuf_recycle_ring(struct io_kiocb *req)
{
	/*
	 * We don't need to recycle for REQ_F_BUFFER_RING, we can just clear
	 * the flag and hence ensure that bl->head doesn't get incremented.
	 * If the tail has already been incremented, hang on to it.
	 * The exception is partial io, that case we should increment bl->head
	 * to monopolize the buffer.
	 */
	if (req->buf_list) {
		req->buf_index = req->buf_list->bgid;
		req->flags &= ~(REQ_F_BUFFER_RING|REQ_F_BUFFERS_COMMIT);
		return true;
	}
	return false;
}

// Checks if buffer selection is needed for the request
static inline bool io_do_buffer_select(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_BUFFER_SELECT))
		return false;
	return !(req->flags & (REQ_F_BUFFER_SELECTED|REQ_F_BUFFER_RING));
}

// Handles recycling of buffers based on request flags and buffer type
static inline bool io_kbuf_recycle(struct io_kiocb *req, unsigned issue_flags)
{
	if (req->flags & REQ_F_BL_NO_RECYCLE)
		return false;
	if (req->flags & REQ_F_BUFFER_SELECTED)
		return io_kbuf_recycle_legacy(req, issue_flags);
	if (req->flags & REQ_F_BUFFER_RING)
		return io_kbuf_recycle_ring(req);
	return false;
}

// Puts back a single kernel buffer after use and updates buffer state
static inline unsigned int io_put_kbuf(struct io_kiocb *req, int len,
				       unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, 1);
}

// Puts back multiple kernel buffers after use and updates buffer state
static inline unsigned int io_put_kbufs(struct io_kiocb *req, int len,
					int nbufs, unsigned issue_flags)
{
	if (!(req->flags & (REQ_F_BUFFER_RING | REQ_F_BUFFER_SELECTED)))
		return 0;
	return __io_put_kbufs(req, len, nbufs);
}
#endif
