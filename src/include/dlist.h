
/*================================================

*	File Name 		:	dlist.h
*	Creation Date 	:	09-15-2011
*	Last Modified 	:	Sun 18 Sep 2011 01:07:31 PM PDT
* 	Created By		:	Raghavendra Thodime (thodime@yahoo.com)
*   	copyrights owned by Raghavendra Thodime			
=================================================*/
#ifndef __DLIST_H__
#define __DLIST_H__

#include <inttypes.h>
#include <sys/types.h>

#define ELEM_OFFSET(st, elem) ((long) (&(((st*) 0)->elem)))

typedef struct dlist_link dlist_link_t;
struct dlist_link {
        dlist_link_t *prev;
        dlist_link_t *next;
};

typedef struct dlist_safe {
        dlist_link_t *head; //circular list
        uint32_t link_offset;
    uint32_t num_elem;
} dlist_t;

#define DLIST_INIT(list, offset) \
        do { \
                (list)->head = NULL; (list)->link_offset=offset; (list)->num_elem = 0; \
        } while(0);

#define DLINK_DATA(list, ptr) ((void *) ((char *) (ptr) - (list)->link_offset))
#define DLIST_PTR(list, data) ((dlist_link_t *) ((char *) (data) + (list)->link_offset))

#define DLIST_HEAD(list) (((list)->head) ? DLINK_DATA(list, (list)->head) : NULL)
#define DLIST_TAIL(list) (((list)->head) ? DLINK_DATA(list, (list)->head->prev) : NULL)
#define DLIST_NEXT(list, data) DLINK_DATA(list, DLIST_PTR(list, data)->next)
#define DLIST_PREV(list, data) DLINK_DATA(list, DLIST_PTR(list, data)->prev)
#define DLIST_LEN(list) ((list)->num_elem)

#define DLIST_INSERT(list, data) \
        do { \
                dlist_link_t *_node = DLIST_PTR(list, data); \
                if((list)->head) { _node->next = (list)->head; _node->prev = (list)->head->prev; \
                        (list)->head->prev->next = _node; (list)->head->prev = _node; \
                } else { \
                        _node->next = _node->prev = _node; \
                        (list)->head = _node; \
                } \
        ++(list)->num_elem; \
        } while(0);

#define DLIST_INSERT_AFTER(list, data, after) \
		do { \
			dlist_link_t *_node = DLIST_PTR(list, data); \
			dlist_link_t *anode= DLIST_PTR(list, after); \
			anode->next->prev = _node; _node->next = anode->next; \
			anode->next = _node; _node->prev = anode; \
			++(list)->num_elem; \
		} while(0);

#define DLIST_UPDATE_HEAD(list, data) (list)->head = DLIST_PTR(list, data)

#define DLIST_REMOVE(list, data) \
        do { \
                dlist_link_t *_node = DLIST_PTR(list, data); \
                if ((list)->head == (list)->head->prev) { \
                        if ((list)->head != _node) break; \
                        (list)->head = NULL; \
                } else { \
                        if ((list)->head == _node) (list)->head = _node->next; \
                        _node->prev->next = _node->next; _node->next->prev = _node->prev; \
                } \
        --(list)->num_elem; \
        } while(0);

#endif


