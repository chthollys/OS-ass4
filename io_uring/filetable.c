// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/nospec.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "rsrc.h"
#include "filetable.h"

/*
 * find an available slot in the file table bitmap starting from the allocation hint.
 * wraps around to the beginning of the allowed allocation range if no free slot is found.
 * returns the index of the free slot or -ENFILE if no slots are available.
 */
static int io_file_bitmap_get(struct io_ring_ctx *ctx)
{
	struct io_file_table *table = &ctx->file_table;
	unsigned long nr = ctx->file_alloc_end;
	int ret;

	if (!table->bitmap)
		return -ENFILE;

	do {
		ret = find_next_zero_bit(table->bitmap, nr, table->alloc_hint);
		if (ret != nr)
			return ret;

		if (table->alloc_hint == ctx->file_alloc_start)
			break;
		nr = table->alloc_hint;
		table->alloc_hint = ctx->file_alloc_start;
	} while (1);

	return -ENFILE;
}

/*
 * allocate file tables for an io_uring context, including the resource data array
 * and bitmap used to track fixed files. returns true on success, false on failure.
 */
bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table,
			  unsigned nr_files)
{
	if (io_rsrc_data_alloc(&table->data, nr_files))
		return false;
	table->bitmap = bitmap_zalloc(nr_files, GFP_KERNEL_ACCOUNT);
	if (table->bitmap)
		return true;
	io_rsrc_data_free(ctx, &table->data);
	return false;
}

/*
 * free resources used by file tables, including the resource data array
 * and bitmap. ensures all allocated memory is released.
 */
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table)
{
	io_rsrc_data_free(ctx, &table->data);
	bitmap_free(table->bitmap);
	table->bitmap = NULL;
}

/*
 * install a file in a specified slot in the fixed file table. rejects io_uring
 * files to prevent reference cycles. the uring_lock must be held when calling.
 * returns 0 on success or a negative error code on failure.
 */
static int io_install_fixed_file(struct io_ring_ctx *ctx, struct file *file,
				 u32 slot_index)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_rsrc_node *node;

	if (io_is_uring_fops(file))
		return -EBADF;
	if (!ctx->file_table.data.nr)
		return -ENXIO;
	if (slot_index >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_alloc(ctx, IORING_RSRC_FILE);
	if (!node)
		return -ENOMEM;

	if (!io_reset_rsrc_node(ctx, &ctx->file_table.data, slot_index))
		io_file_bitmap_set(&ctx->file_table, slot_index);

	ctx->file_table.data.nodes[slot_index] = node;
	io_fixed_file_set(node, file);
	return 0;
}

/*
 * install a file in the fixed file table, handling both user-specified slots
 * and automatic slot allocation. adjusts the slot index as needed before installation.
 * returns the allocated slot number or a negative error code on failure.
 */
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
			  unsigned int file_slot)
{
	bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
	int ret;

	if (alloc_slot) {
		ret = io_file_bitmap_get(ctx);
		if (unlikely(ret < 0))
			return ret;
		file_slot = ret;
	} else {
		file_slot--;
	}

	ret = io_install_fixed_file(ctx, file, file_slot);
	if (!ret && alloc_slot)
		ret = file_slot;
	return ret;
}
/*
 * Note when io_fixed_fd_install() returns error value, it will ensure
 * fput() is called correspondingly.
 */

/*
 * install a file in the fixed file table with locking. ensures proper
 * management of file reference counts on error. returns the allocated
 * slot number or a negative error code on failure.
 */
int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot)
{
	struct io_ring_ctx *ctx = req->ctx;
	int ret;

	io_ring_submit_lock(ctx, issue_flags);
	ret = __io_fixed_fd_install(ctx, file, file_slot);
	io_ring_submit_unlock(ctx, issue_flags);

	if (unlikely(ret < 0))
		fput(file);
	return ret;
}

/*
 * remove a file from the fixed file table at the specified slot index.
 * releases the file reference through io_reset_rsrc_node. returns 0 on
 * success or a negative error code on failure.
 */
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset)
{
	struct io_rsrc_node *node;

	if (unlikely(!ctx->file_table.data.nr))
		return -ENXIO;
	if (offset >= ctx->file_table.data.nr)
		return -EINVAL;

	node = io_rsrc_node_lookup(&ctx->file_table.data, offset);
	if (!node)
		return -EBADF;
	io_reset_rsrc_node(ctx, &ctx->file_table.data, offset);
	io_file_bitmap_clear(&ctx->file_table, offset);
	return 0;
}

/*
 * register a range for file slot allocations, restricting automatic
 * allocations to occur only within the specified range. returns 0 on
 * success or a negative error code on failure.
 */
int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg)
{
	struct io_uring_file_index_range range;
	u32 end;

	if (copy_from_user(&range, arg, sizeof(range)))
		return -EFAULT;
	if (check_add_overflow(range.off, range.len, &end))
		return -EOVERFLOW;
	if (range.resv || end > ctx->file_table.data.nr)
		return -EINVAL;

	io_file_table_set_alloc_range(ctx, range.off, range.len);
	return 0;
}

