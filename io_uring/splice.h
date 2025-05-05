// SPDX-License-Identifier: GPL-2.0

/*
 * Prepare TEE operation - validate SQE fields and setup request structure
 * for duplicating pipe content without consuming it.
 */
int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

 /*
  * Execute TEE operation - duplicate data between pipes without removing
  * it from source pipe. Handles async/sync execution paths.
  */
int io_tee(struct io_kiocb *req, unsigned int issue_flags);

 /*
  * Cleanup splice resources - releases pipe references and any allocated
  * resources after splice operation completes or fails.
  */
void io_splice_cleanup(struct io_kiocb *req);
 
 /*
  * Prepare splice operation - validate SQE fields, setup request structure
  * for moving data between pipe/file descriptors.
  */
int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*
* Execute splice operation - move data between pipe/file descriptors.
* Manages pipe locking, partial operations, and async/sync execution.
*/
int io_splice(struct io_kiocb *req, unsigned int issue_flags);
