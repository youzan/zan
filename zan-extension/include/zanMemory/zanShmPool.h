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

#ifndef _ZAN_SHM_POOL_H_
#define _ZAN_SHM_POOL_H_

#include "zanMemory/zanMemory.h"
#include "zanLock.h"

#ifdef __cplusplus
extern "C" {
#endif

//==========================================================================
typedef struct _zanShmPool
{
    void *object;
    void* (*alloc)(struct _zanShmPool *pool, uint32_t size);
    void (*destroy)(struct _zanShmPool *pool);
}zanShmPool;

/**
 * Global share memory, the program life cycle only malloc / free one time
 */
typedef struct _zanShmGlobal
{
    int     size;      //总容量
    void    *mem;      //剩余内存的指针
    int     offset;    //内存分配游标
    char    shared;
    int     pagesize;
    zanLock lock;
    void *root_page;
    void *cur_page;
} zanShmGlobal;

//typedef zanMemPool zanShmPool;

zanShmPool* zanShmGlobal_new(int pagesize, char shared);

#ifdef __cplusplus
}
#endif

#endif  //_ZAN_SHM_POOL_H_

