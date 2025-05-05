// SPDX-License-Identifier: GPL-2.0

// Prepares the io_statx command by extracting and validating parameters from the submission queue entry (sqe).
int io_statx_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes the io_statx command by calling the do_statx function and setting the result in the request.
int io_statx(struct io_kiocb *req, unsigned int issue_flags);

// Cleans up resources allocated during the io_statx command, such as releasing the filename.
void io_statx_cleanup(struct io_kiocb *req);
