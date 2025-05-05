// SPDX-License-Identifier: GPL-2.0

// Function to prepare a file truncation request. Validates the input and sets up the request structure.
int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Function to execute a file truncation request. Performs the truncation and sets the result in the request structure.
int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
