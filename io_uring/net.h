// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

struct io_async_msghdr {
#if defined(CONFIG_NET)
	struct iou_vec				vec;

	struct_group(clear,
		int				namelen;
		struct iovec			fast_iov;
		__kernel_size_t			controllen;
		__kernel_size_t			payloadlen;
		struct sockaddr __user		*uaddr;
		struct msghdr			msg;
		struct sockaddr_storage		addr;
	);
#else
	struct_group(clear);
#endif
};

#if defined(CONFIG_NET)

// Prepares a socket shutdown request from the provided SQE.
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket shutdown operation with the specified flags.
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

// Cleans up resources associated with sendmsg/recvmsg operations.
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);
// Prepares a socket message send request from the provided SQE.
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket message send operation with the specified flags.
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

// Performs a socket send operation with the specified flags.
int io_send(struct io_kiocb *req, unsigned int issue_flags);

// Prepares a socket message receive request from the provided SQE.
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket message receive operation with the specified flags.
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);
// Performs a socket receive operation with the specified flags.
int io_recv(struct io_kiocb *req, unsigned int issue_flags);

// Handles failure cases for send/receive operations.
void io_sendrecv_fail(struct io_kiocb *req);

// Prepares a socket accept request from the provided SQE.
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket accept operation with the specified flags.
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

// Prepares a socket creation request from the provided SQE.
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket creation operation with the specified flags.
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

// Prepares a socket connect request from the provided SQE.
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket connect operation with the specified flags.
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

// Performs a zero-copy socket send operation with the specified flags.
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);
// Performs a zero-copy socket message send operation with the specified flags.
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);
// Prepares a zero-copy socket send request from the provided SQE.
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Cleans up resources associated with zero-copy send operations.
void io_send_zc_cleanup(struct io_kiocb *req);

// Prepares a socket bind request from the provided SQE.
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket bind operation with the specified flags.
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

// Prepares a socket listen request from the provided SQE.
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
// Executes a socket listen operation with the specified flags.
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

// Frees network message cache entries.
void io_netmsg_cache_free(const void *entry);
#else
// Empty implementation for network message cache free when CONFIG_NET is not defined.
static inline void io_netmsg_cache_free(const void *entry)
{
}
#endif
