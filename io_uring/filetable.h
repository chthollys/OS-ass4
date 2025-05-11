// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);

int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset);

int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);

io_req_flags_t io_file_get_flags(struct file *file);

/*
 * clears a specific bit in the file table bitmap and updates the allocation hint.
 * ensures the bit being cleared was previously set.
 */
static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}

/*
 * sets a specific bit in the file table bitmap and updates the allocation hint.
 * ensures the bit being set was previously cleared.
 */
static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));
	__set_bit(bit, table->bitmap);
	table->alloc_hint = bit + 1;
}

/**
 * File flag bits stored in the node->file_ptr's upper bits
 * @FFS_NOWAIT: Indicates file operations support non-blocking mode (NOWAIT)
 * @FFS_ISREG: Indicates the file is a regular file (supports optimized operations)
 * @FFS_MASK: Mask to extract the file pointer from node->file_ptr
 */
#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

/*
 * extracts capability flags from the resource node's file pointer.
 * shifts the flags to align with the request flag bit positions.
 */
static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{
	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

/*
 * retrieves the file pointer from the resource node by masking out flags.
 * ensures only the actual file pointer is returned.
 */
static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}

/*
 * stores a file pointer and its associated capability flags in a resource node.
 * flags are extracted from the file and packed into the high bits of the file_ptr field.
 */
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

/*
 * sets the allocation range for the file table in the io_ring context.
 * updates the allocation hint to the start of the specified range.
 */
static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif

