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

#include "zanIpc.h"
#include "zanLog.h"
#include "zanMemory/zanShmPool.h"


#define ZAN_SHM_PAGE_SIZE  256

static void *zanShmGlobal_alloc(zanShmPool *pool, uint32_t size);
static void zanShmGlobal_destroy(zanShmPool *pool);
static void *zanShmGlobal_new_page(zanShmGlobal *gShm);

zanShmPool* zanShmGlobal_new(int pagesize, char shared)
{
    zanShmGlobal gShm, *gm_ptr = NULL;
    assert(pagesize >= ZAN_SHM_PAGE_SIZE);

    bzero(&gShm, sizeof(zanShmGlobal));
    gShm.shared   = shared;
    gShm.pagesize = pagesize;
    void *first_page = zanShmGlobal_new_page(&gShm);
    if (first_page == NULL)
    {
        zanError("zanShmGlobal_new_page failed");
        return NULL;
    }
    //分配内存需要加锁
    if (zanLock_create(&gShm.lock, ZAN_MUTEX, 1) < 0)
    {
        zanError("zanLock_create failed");
        return NULL;
    }
    //root
    gShm.root_page = first_page;
    gShm.cur_page  = first_page;

    gm_ptr = (zanShmGlobal *) gShm.mem;
    gShm.offset += sizeof(zanShmGlobal);

    zanShmPool *pShmPool = (zanShmPool *) (gShm.mem + gShm.offset);
    gShm.offset += sizeof(zanShmPool);

    pShmPool->object  = gm_ptr;
    pShmPool->alloc   = zanShmGlobal_alloc;
    pShmPool->destroy = zanShmGlobal_destroy;
    memcpy(gm_ptr, &gShm, sizeof(zanShmGlobal));
    return pShmPool;
}

/**
 * 使用前8个字节保存next指针
 */
static void* zanShmGlobal_new_page(zanShmGlobal *gShm)
{
    void *page = (gShm->shared == 1) ? zan_shm_malloc(gShm->pagesize) : zan_malloc(gShm->pagesize);
    if (page == NULL)
    {
        zanError("malloc failed, gShm->shared=%d", gShm->shared);
        return NULL;
    }

    bzero(page, gShm->pagesize);
    ((void **)page)[0] = NULL;       //将next设置为NULL

    gShm->offset = 0;
    gShm->size = gShm->pagesize - sizeof(void*);
    gShm->mem  = page + sizeof(void*);
    return page;
}

static void *zanShmGlobal_alloc(zanShmPool *pool, uint32_t size)
{
    zanShmGlobal *gm = (zanShmGlobal *)pool->object;
    gm->lock.lock(&gm->lock);
    if (size > gm->pagesize)
    {
        zanWarn("alloc %d bytes not allow. Max size=%d", size, gm->pagesize);
        return NULL;
    }

    if (gm->offset + size > gm->size)
    {
        //没有足够的内存,再次申请
        zanDebug("new page: size=%d|offset=%d|alloc=%d", gm->size, gm->offset, size);
        void *page = zanShmGlobal_new_page(gm);
        if (page == NULL)
        {
            zanError("zanShmGlobal_new_page error.");
            return NULL;
        }
        //将next指向新申请的内存块
        ((void **) gm->cur_page)[0] = page;
        gm->cur_page = page;
    }

    void *mem = gm->mem + gm->offset;
    gm->offset += size;
    gm->lock.unlock(&gm->lock);
    return mem;
}

static void zanShmGlobal_destroy(zanShmPool *pool)
{
    zanShmGlobal *gShm = (zanShmGlobal *)pool->object;
    void *page = gShm->root_page;
    void *next = ((void **)page)[0];
    while(next != NULL)
    {
        next = ((void **)next)[0];
        zan_shm_free(page);
        zanTrace("zan_shm_free free=%p", next);
    }
}

