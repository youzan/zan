/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/


#ifndef _SW_MEMORY_POOL_H_
#define _SW_MEMORY_POOL_H_

#include "swoole.h"
#include "swLock.h"
#include "swAtomic.h"


#ifdef __cplusplus
extern "C" {
#endif

void* malloc_debug(const char* file,int line,const char* func,int __size);
void free_debug(const char* file,int line,const char* func,void* ptr);

#ifdef SW_MALLOC_DEBUG
#define sw_malloc(__size)      malloc_debug(__FILE__, __LINE__,__func__,__size)
#define sw_free(ptr)           if(ptr){free_debug(__FILE__, __LINE__,__func__,ptr);ptr=NULL;}
#else
#define sw_malloc  		       malloc
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

/**
 * Global memory, the program life cycle only malloc / free one time
 */
typedef struct _swMemoryGlobal
{
    int size;  //总容量
    void *mem; //剩余内存的指针
    int offset; //内存分配游标
    char shared;
    int pagesize;
    swLock lock; //锁
    void *root_page;
    void *cur_page;
} swMemoryGlobal;

swMemoryPool* swMemoryGlobal_new(int pagesize, char shared);

void swFixedPool_debug(swMemoryPool *pool);

/**
 * alloc shared memory
 */
void* sw_shm_malloc(size_t size);
void sw_shm_free(void *ptr);
void* sw_shm_calloc(size_t num, size_t _size);
void* sw_shm_realloc(void *ptr, size_t new_size);

#define SW_SHM_MMAP_FILE_LEN  64

typedef struct _swShareMemory_mmap
{
    int size;
    char mapfile[SW_SHM_MMAP_FILE_LEN];
    int tmpfd;
    int key;
    int shmid;
    void *mem;
} swShareMemory;

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile);
void *swShareMemory_sysv_create(swShareMemory *object, int size, int key);
int swShareMemory_sysv_free(swShareMemory *object, int rm);
int swShareMemory_mmap_free(swShareMemory *object);

#ifdef __cplusplus
}
#endif

#endif
