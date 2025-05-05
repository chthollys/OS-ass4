// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

/*
 * Unregisters the eventfd associated with the I/O ring context.
 */
int io_eventfd_unregister(struct io_ring_ctx *ctx);
/*
 * Unregisters a personality identified by its ID from the I/O ring context.
 */
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);
/*
 * Retrieves the file associated with a given file descriptor in the I/O ring.
 */
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif
