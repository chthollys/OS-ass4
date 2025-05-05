#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

#define __wq_list_for_each(pos, head)				\
	for (pos = (head)->first; pos; pos = (pos)->next)

#define wq_list_for_each(pos, prv, head)			\
	for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

#define wq_list_for_each_resume(pos, prv)			\
	for (; pos; prv = pos, pos = (pos)->next)

#define wq_list_empty(list)	(READ_ONCE((list)->first) == NULL)

#define INIT_WQ_LIST(list)	do {				\
	(list)->first = NULL;					\
} while (0)

/* Insert node after specified position, updating next pointers accordingly */
static inline void wq_list_add_after(struct io_wq_work_node *node,
				     struct io_wq_work_node *pos,
				     struct io_wq_work_list *list)
{
	struct io_wq_work_node *next = pos->next;

	pos->next = node;
	node->next = next;
	if (!next)
		list->last = node;
}

/* Append node to end of list, updating first/last pointers if needed */
static inline void wq_list_add_tail(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = NULL;
	if (!list->first) {
		list->last = node;
		WRITE_ONCE(list->first, node);
	} else {
		list->last->next = node;
		list->last = node;
	}
}

/* Prepend node to beginning of list, updating first pointer */
static inline void wq_list_add_head(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = list->first;
	if (!node->next)
		list->last = node;
	WRITE_ONCE(list->first, node);
}

/* Split list after specified node, properly handling first/last pointers */
static inline void wq_list_cut(struct io_wq_work_list *list,
			       struct io_wq_work_node *last,
			       struct io_wq_work_node *prev)
{
	/* first in the list, if prev==NULL */
	if (!prev)
		WRITE_ONCE(list->first, last->next);
	else
		prev->next = last->next;

	if (last == list->last)
		list->last = prev;
	last->next = NULL;
}

/* Internal splice implementation that joins two lists and clears source list */
static inline void __wq_list_splice(struct io_wq_work_list *list,
				    struct io_wq_work_node *to)
{
	list->last->next = to->next;
	to->next = list->first;
	INIT_WQ_LIST(list);
}

/* Public splice function that checks for empty list before splicing */
static inline bool wq_list_splice(struct io_wq_work_list *list,
				  struct io_wq_work_node *to)
{
	if (!wq_list_empty(list)) {
		__wq_list_splice(list, to);
		return true;
	}
	return false;
}

/* Stack push operation - adds node at head of stack */
static inline void wq_stack_add_head(struct io_wq_work_node *node,
				     struct io_wq_work_node *stack)
{
	node->next = stack->next;
	stack->next = node;
}

/* Remove node from list using cut operation */
static inline void wq_list_del(struct io_wq_work_list *list,
			       struct io_wq_work_node *node,
			       struct io_wq_work_node *prev)
{
	wq_list_cut(list, node, prev);
}

/* Stack pop operation - extracts and returns next node from stack */
static inline
struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
	struct io_wq_work_node *node = stack->next;

	stack->next = node->next;
	return node;
}

/* Get next work item by following list.next pointer and container_of */
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
	if (!work->list.next)
		return NULL;

	return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H
