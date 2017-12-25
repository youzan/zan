/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#ifndef _ZAN_MEMORY_H_
#define _ZAN_MEMORY_H_

#include <stdlib.h>
#include "swAtomic.h"

#ifdef __cplusplus
extern "C" {
#endif

void* malloc_debug(const char* file,int line,const char* func,int __size);
void free_debug(const char* file,int line,const char* func,void* ptr);

#ifdef ZAN_MALLOC_DEBUG
#define sw_malloc(__size)      malloc_debug(__FILE__, __LINE__,__func__,__size)
#define sw_free(ptr)           if(ptr){free_debug(__FILE__, __LINE__,__func__,ptr);ptr=NULL;}
#else
#define sw_malloc              malloc
#define sw_free(ptr)           if(ptr){free(ptr);ptr=NULL;}
#endif

#define sw_calloc              calloc
#define sw_realloc             realloc

#if defined(SW_USE_JEMALLOC) || defined(SW_USE_TCMALLOC)
#define sw_strdup_free(str)
#else
#define sw_strdup_free(str)     free(str)
#endif


//-------------------memory manager-------------------------
typedef struct _swMemoryPool
{
    void *object;
    void* (*alloc)(struct _swMemoryPool *pool, uint32_t size);
    void (*free)(struct _swMemoryPool *pool, void *ptr);
    void (*destroy)(struct _swMemoryPool *pool);

}swMemoryPool;

typedef struct _swFixedPool_slice
{
    uint8_t lock;
    struct _swFixedPool_slice *next;
    struct _swFixedPool_slice *pre;
    char data[0];

} swFixedPool_slice;

typedef struct _swFixedPool
{
    void *memory;
    size_t size;

    swFixedPool_slice *head;
    swFixedPool_slice *tail;

    /**
     * total memory size
     */
    uint32_t slice_num;

    /**
     * memory usage
     */
    uint32_t slice_use;

    /**
     * Fixed slice size, not include the memory used by swFixedPool_slice
     */
    uint32_t slice_size;

    /**
     * use shared memory
     */
    uint8_t shared;

} swFixedPool;
/**
 * FixedPool, random alloc/free fixed size memory
 */
swMemoryPool* swFixedPool_new(uint32_t slice_num, uint32_t slice_size, uint8_t shared);
swMemoryPool* swFixedPool_new2(uint32_t slice_size, void *memory, size_t size);
swMemoryPool* swMalloc_new();

/**
 * RingBuffer, In order for malloc / free
 */
typedef struct
{
    uint8_t shared;
    uint8_t status;
    uint32_t size;
    uint32_t alloc_offset;
    uint32_t collect_offset;
    uint32_t alloc_count;
    sw_atomic_t free_count;
    void *memory;
} swRingBuffer;

typedef struct
{
    uint16_t lock;
    uint16_t index;
    uint32_t length;
    char data[0];
} swRingBuffer_item;

swMemoryPool *swRingBuffer_new(uint32_t size, uint8_t shared);


#ifdef __cplusplus
}
#endif

#endif //_ZAN_MEMORY_H_
