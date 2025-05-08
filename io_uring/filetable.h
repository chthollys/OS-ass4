// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

/**
 * This module implements a file table for io_uring, which manages pre-registered files.
 * Pre-registered files are files that have been registered with io_uring and can be
 * referenced directly using their index in future operations, avoiding the need for
 * repetitive file lookups during I/O operations.
 *
 * The file table consists of:
 * - A bitmap to track used/free file slots
 * - A range of available file slots (file_alloc_start to file_alloc_end)
 * - Resources for file references with associated flags
 *
 * The flags stored with file pointers (FFS_NOWAIT, FFS_ISREG) provide optimization
 * information that allows io_uring to make decisions without reexamining the file
 * properties on each operation.
 */

/**
 * struct io_file_table - Maintains the state of registered files
 * @bitmap: Bitmap indicating which slots are in use
 * @files: Array of resource nodes containing file pointers and flags
 * @alloc_hint: Position hint for the next allocation search
 *
 * This structure tracks pre-registered files that can be referenced by index
 * in io_uring operations, enabling faster access without repeated permission checks
 * or file lookups.
 */

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

static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}

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

static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{

	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}

static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}

/**
 * io_fixed_file_set() - Store a file pointer with associated capability flags
 * @node: Resource node where the file reference will be stored
 * @file: File pointer to store
 *
 * Stores both the file pointer and its capability flags in the resource node.
 * The capability flags (NOWAIT, ISREG) are extracted from the file and packed
 * into the high bits of the file_ptr field, allowing io_uring to make quick
 * decisions about how to handle I/O for this file without re-examining its
 * properties on each operation.
 */
static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}

static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}

#endif

