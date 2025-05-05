// SPDX-License-Identifier: GPL-2.0

// Cleans up resources allocated for an io_kiocb request related to xattr operations.
void io_xattr_cleanup(struct io_kiocb *req);

// Prepares an io_kiocb request for a setxattr operation on a file descriptor (public interface).
int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes a setxattr operation on a file descriptor.
int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepares an io_kiocb request for a setxattr operation on a file path.
int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes a setxattr operation on a file path.
int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepares an io_kiocb request for a getxattr operation on a file descriptor (public interface).
int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes a getxattr operation on a file descriptor.
int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);

// Prepares an io_kiocb request for a getxattr operation on a file path.
int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Executes a getxattr operation on a file path.
int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
