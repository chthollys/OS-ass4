// SPDX-License-Identifier: GPL-2.0

// Synchronizes a message ring based on the provided submission queue entry
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);
// Prepares a message ring request from the submission queue entry
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Processes a message ring request with the specified issue flags
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);
// Performs cleanup operations for a message ring request
void io_msg_ring_cleanup(struct io_kiocb *req);
