// SPDX-License-Identifier: GPL-2.0

// Prepares the io_kiocb request for sync_file_range operation
int io_sfr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes the sync_file_range operation and sets the result in the request
int io_sync_file_range(struct io_kiocb *req, unsigned int issue_flags);

// Prepares the io_kiocb request for fsync operation
int io_fsync_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes the fsync operation and sets the result in the request
int io_fsync(struct io_kiocb *req, unsigned int issue_flags);

// Executes the fallocate operation and sets the result in the request
int io_fallocate(struct io_kiocb *req, unsigned int issue_flags);

// Prepares the io_kiocb request for fallocate operation
int io_fallocate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
