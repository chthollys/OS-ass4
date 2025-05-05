// SPDX-License-Identifier: GPL-2.0

/**
 * Closes a fixed file descriptor within the IO ring context, handling the offset and flags.
 * This function ensures the proper cleanup of file descriptors that are part of the fixed file descriptor table.
 */
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
		     unsigned int offset);

/**
 * Prepares the io_kiocb request for the `openat` system call, based on the provided submission queue entry.
 * Sets up the necessary fields in the request to execute the openat operation.
 */
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * Executes the `openat` system call within the context of the IO ring, using the prepared io_kiocb request.
 * Handles the opening of a file and returns the result of the operation.
 */
int io_openat(struct io_kiocb *req, unsigned int issue_flags);
/**
 * Cleans up the io_kiocb request after the `openat` operation completes.
 * Frees resources or resets states related to the `openat` operation in the request.
 */
void io_open_cleanup(struct io_kiocb *req);

/**
 * Prepares the io_kiocb request for the `openat2` system call, based on the provided submission queue entry.
 * Sets up the necessary fields to perform the openat2 operation with additional flags or options.
 */
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * Executes the `openat2` system call within the IO ring context, handling the file opening operation with additional flags.
 * Completes the operation and returns the result of opening the file with the specified options.
 */
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

/**
 * Prepares the io_kiocb request for the `close` system call, based on the submission queue entry.
 * Sets up the necessary fields to close a file descriptor.
 */
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * Executes the `close` system call within the IO ring context, ensuring that the provided file descriptor is closed.
 * Completes the close operation and returns the result.
 */
int io_close(struct io_kiocb *req, unsigned int issue_flags);

/**
 * Prepares the io_kiocb request for installing a fixed file descriptor within the IO ring context.
 * Configures the request to properly install the fixed descriptor with the provided submission queue entry.
 */
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/**
 * Installs a fixed file descriptor into the IO ring context, using the prepared io_kiocb request.
 * Handles the insertion of a fixed descriptor into the context, ensuring correct state management.
 */
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);
