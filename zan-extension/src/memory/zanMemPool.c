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

#include "zanMemory/zanMemory.h"
#include "zanLog.h"

static void* swMalloc_alloc(swMemoryPool *pool, uint32_t size);
static void swMalloc_free(swMemoryPool *pool, void *ptr);
static void swMalloc_destroy(swMemoryPool *pool);

void* malloc_debug(const char* file,int line,const char* func,int __size)
{
    void *ptr = malloc(__size);
    swDebug("malloc debug %s,%d,%s malloc %p",file,line,func,ptr);
    return ptr;
}

void free_debug(const char* file,int line,const char* func,void* ptr)
{
    free(ptr);
    swDebug("free debug %s,%d,%s free %p",file,line,func,ptr);
}

swMemoryPool* swMalloc_new()
{
    swMemoryPool *pool = sw_malloc(sizeof(swMemoryPool));
    if (pool == NULL)
    {
        swSysError("mallc() failed.");
        return NULL;
    }
    pool->alloc = swMalloc_alloc;
    pool->free = swMalloc_free;
    pool->destroy = swMalloc_destroy;
    return pool;
}

static void* swMalloc_alloc(swMemoryPool *pool, uint32_t size)
{
    return sw_malloc(size);
}

static void swMalloc_free(swMemoryPool *pool, void *ptr)
{
    sw_free(ptr);
}

static void swMalloc_destroy(swMemoryPool *pool)
{
    sw_free(pool);
}
