/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "win32/def.h"

#ifndef _SW_DATASTRUCT_H_
#define _SW_DATASTRUCT_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 默认swArray->pages指针数组的长度为SW_ARRAY_PAGE_MAX,也就是最多可以管理(SW_ARRAY_PAGE_MAX*page_size)个元素
 */
#define SW_ARRAY_PAGE_MAX      1024

typedef struct _swArray
{
    void **pages;

    /**
     * 页的数量
     */
    uint16_t page_num;

    /**
     * 每页的数据元素个数
     */
    uint16_t page_size;

    /**
     * 数据元素的尺寸
     */
    uint32_t item_size;

    /**
     * 数据个数
     */
    uint32_t item_num;
    uint32_t offset;
} swArray;

swArray *swArray_create(int page_size, size_t item_size);
void swArray_free(swArray *array);
void *swArray_fetch(swArray *array, uint32_t n);
int swArray_store(swArray *array, uint32_t n, void *data);
void *swArray_alloc(swArray *array, uint32_t n);
int swArray_append(swArray *array, void *data);
int swArray_extend(swArray *array);
void swArray_clear(swArray *array);

/*
 * hahs map
 */

#define swHashMap_each_reset(hmap)    (hmap->iterator = NULL)
typedef void (*swHashMap_dtor)(void *data);

typedef struct
{
    struct swHashMap_node *root;
    struct swHashMap_node *iterator;
    swHashMap_dtor dtor;
} swHashMap;

swHashMap* swHashMap_create(uint32_t bucket_num, swHashMap_dtor dtor);
void swHashMap_free(swHashMap *hmap);

int swHashMap_add(swHashMap *hmap, char *key, uint16_t key_len, void *data);
void swHashMap_add_int(swHashMap *hmap, uint64_t key, void *data);
void* swHashMap_find(swHashMap *hmap, char *key, uint16_t key_len);
void* swHashMap_find_int(swHashMap *hmap, uint64_t key);
void swHashMap_update_int(swHashMap *hmap, uint64_t key, void *data);
int swHashMap_update(swHashMap *hmap, char *key, uint16_t key_len, void *data);
int swHashMap_del(swHashMap *hmap, char *key, uint16_t key_len);
int swHashMap_del_int(swHashMap *hmap, uint64_t key);
int swHashMap_move(swHashMap *hmap, char *old_key, uint16_t old_key_len, char *new_key, uint16_t new_key_len);
int swHashMap_move_int(swHashMap *hmap, uint64_t old_key, uint64_t new_key);
void* swHashMap_each(swHashMap* hmap, char **key);
void* swHashMap_each_int(swHashMap* hmap, uint64_t *key);

/*
 * heap ,min heap/max heap
 */

enum swHeap_type
{
    SW_MIN_HEAP,
    SW_MAX_HEAP,
};

typedef struct swHeap_node
{
    uint64_t priority;
    uint32_t position;
    void *data;
} swHeap_node;

typedef struct _swHeap
{
    uint32_t num;
    uint32_t size;
    uint8_t type;
    swHeap_node **nodes;
} swHeap;

swHeap *swHeap_create(size_t n, uint8_t type);
void swHeap_free(swHeap *heap);
uint32_t swHeap_size(swHeap *heap);
swHeap_node* swHeap_push(swHeap *heap, uint64_t priority, void *data);
void *swHeap_pop(swHeap *heap);
void swHeap_change_priority(swHeap *heap, uint64_t new_priority, void* ptr);
int swHeap_remove(swHeap *heap, swHeap_node *node);
void *swHeap_peek(swHeap *heap);
void swHeap_print(swHeap *heap);

static inline swHeap_node *swHeap_top(swHeap *heap)
{
    return heap->num == 1? NULL:heap->nodes[1];
}

/*
 * list
 */
typedef void (*swDestructor)(void *data);

typedef struct _swLinkedList_node
{
    struct _swLinkedList_node *prev;
    struct _swLinkedList_node *next;
    uint64_t priority;
    void *data;
} swLinkedList_node;

typedef struct
{
    uint32_t num;
    uint8_t type;
    swLinkedList_node *head;
    swLinkedList_node *tail;
    swDestructor dtor;
} swLinkedList;

swLinkedList* swLinkedList_create(uint8_t type, swDestructor dtor);
swLinkedList_node* swLinkedList_append(swLinkedList *ll, void *data,uint64_t priority);
void swLinkedList_remove_node(swLinkedList *ll, swLinkedList_node *remove_node);
swLinkedList_node* swLinkedList_get_tail_node(swLinkedList* ll);
swLinkedList_node* swLinkedList_get_head_node(swLinkedList* ll);
int swLinkedList_prepend(swLinkedList *ll, void *data);
int swLinkedList_empty(swLinkedList *ll);
void* swLinkedList_pop(swLinkedList *ll);
void* swLinkedList_shift(swLinkedList *ll);
void swLinkedList_free(swLinkedList *ll);


/*
 * rb tree
 */

typedef struct swRbtree_node_s
{
	uint32_t key;
	void *value;
	struct swRbtree_node_s *left;
	struct swRbtree_node_s *right;
	struct swRbtree_node_s *parent;
	char color;
}swRbtree_node;

typedef struct swRbtree_s
{
	swRbtree_node *root;
	swRbtree_node *sentinel;
}swRbtree;

#define swRbtree_red(node)               ((node)->color = 1)
#define swRbtree_black(node)             ((node)->color = 0)
#define swRbtree_is_red(node)            ((node)->color)
#define swRbtree_is_black(node)          (!swRbtree_is_red(node))
#define swRbtree_copy_color(n1, n2)      (n1->color = n2->color)

#define swRbtree_sentinel_init(node)      swRbtree_black(node)

swRbtree* swRbtree_create();
void swRbtree_free(swRbtree*);
void swRbtree_insert(swRbtree *tree, uint32_t key, void *value);
void swRbtree_delete(swRbtree *tree, uint32_t key);
void *swRbtree_find(swRbtree *tree, uint32_t key);

static inline swRbtree_node *swRbtree_min(swRbtree_node *node, swRbtree_node *sentinel)
{
	while (node->left != sentinel)
	{
		node = node->left;
	}

	return node;
}

#ifdef SW_USE_RINGQUEUE_TS
#include "atomic.h"
#endif
typedef struct _swRingQueue
{
#ifdef SW_USE_RINGQUEUE_TS
	void **data;
	char *flags;
	// 0：push ready 1: push now
	// 2：pop ready; 3: pop now
	uint size;
	uint num;
	uint head;
	uint tail;
#else
	int head; /* 头部，出队列方向*/
	int tail; /* 尾部，入队列方向*/
	int tag; /* 为空还是为满的标志位*/
	int size; /* 队列总尺寸 */
	void **data; /* 队列空间 */
#endif
} swRingQueue;

int swRingQueue_init(swRingQueue *queue, int buffer_size);
int swRingQueue_push(swRingQueue *queue, void *);
int swRingQueue_pop(swRingQueue *queue, void **);

#ifdef SW_USE_RINGQUEUE_TS
#define swRingQueue_count(q) (q->num)
#else
void swRingQueue_free(swRingQueue *queue);
#define swRingQueue_empty(q) ( (q->head == q->tail) && (q->tag == 0))
#define swRingQueue_full(q) ( (q->head == q->tail) && (q->tag == 1))
#endif

//------------------------------String--------------------------------
#define swoole_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define swoole_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)
#define swString_length(s)	   (s->length)
#define swString_ptr(s) 	   (s->str)

typedef struct _swString
{
    size_t length;
    size_t size;
    off_t offset;
    char *str;
}swString;

size_t swoole_utf8_length(u_char *p, size_t n);
size_t swoole_utf8_length(u_char *p, size_t n);

static sw_inline size_t swoole_size_align(size_t size, int pagesize)
{
    return size + (pagesize - (size % pagesize));
}

static sw_inline void swString_clear(swString *str)
{
    str->length = 0;
    str->offset = 0;
}

swString *swString_new(size_t size);
swString *swString_dup(const char *src_str, int length);
swString *swString_dup2(swString *src);

void swString_print(swString *str);
void swString_free(swString *str);
int swString_append(swString *str, swString *append_str);
int swString_append_ptr(swString *str, char *append_str, int length);

int swString_write(swString *str, off_t offset, swString *write_str);
int swString_write_ptr(swString *str, off_t offset, char *write_str, int length);

int swString_extend(swString *str, size_t new_size);

uint32_t swoole_utf8_decode(u_char **p, size_t n);
size_t swoole_utf8_length(u_char *p, size_t n);

#ifdef __cplusplus
}
#endif

#endif
