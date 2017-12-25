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

void* zan_shm_malloc(size_t size)
{
    zanShareMemory object;

    size += sizeof(zanShareMemory);               //zanShareMemory 对象保存在整个内存块的头部
    void *mem = zanShm_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        zanError("zanShm_mmap_create failed.");
        return NULL;
    }
    memcpy(mem, &object, sizeof(zanShareMemory)); //zanShareMemory 对象保存在整个内存块的头部

    return mem + sizeof(zanShareMemory);
}

void* zan_shm_calloc(size_t num, size_t _size)
{
    zanShareMemory object;

    int size = sizeof(zanShareMemory) + (num * _size);
    void *mem = zanShm_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        zanError("zanShm_mmap_create failed.");
        return NULL;
    }

    memcpy(mem, &object, sizeof(zanShareMemory));  //zanShareMemory 对象保存在整个内存块的头部
    void *ret_mem = mem + sizeof(zanShareMemory);

    bzero(ret_mem, size - sizeof(zanShareMemory)); //calloc需要初始化
    return ret_mem;
}

void zan_shm_free(void *ptr)
{
    //取整块内存的起始地址, 然后释放
    //ptr 指向内存块起始地址偏移 sizeof(zanShareMemory) 的位置
    //zanShareMemory 对象存储在整块内存的头部
    zanShareMemory *object = (zanShareMemory *)(ptr - sizeof(zanShareMemory));
    zanShm_mmap_free(object);
}

void* zan_shm_realloc(void *ptr, size_t new_size)
{
    zanShareMemory *object = (zanShareMemory *)(ptr - sizeof(zanShareMemory));
    if (object->size >= new_size)
    {
        zanError("error: new_size=%d is less than oldsize=%d", (int)new_size, object->size);
        return ptr;
    }

    void *new_ptr = zan_shm_malloc(new_size);
    if(!new_ptr)
    {
        zanError("zan_shm_malloc failed, new_size=%d", (int)new_size);
        return ptr;
    }
    memcpy(new_ptr, ptr, object->size);
    zan_shm_free(ptr);

    return new_ptr;
}

void *zanShm_mmap_create(zanShareMemory *object, int size, char *mapfile)
{
    if (!object || size <= 0)
    {
        zanError("object is null or size=%d is invalid", size);
        return NULL;
    }

    bzero(object, sizeof(zanShareMemory));
    int flag = MAP_SHARED;
    int tmpfd = -1;

#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else
    mapfile = (!mapfile)? "/dev/zero":mapfile;
    strncpy(object->mapfile, mapfile, ZAN_FILE_NAME_LEN);

    tmpfd = open(mapfile, O_RDWR);
    if(-1 == tmpfd)
    {
        zanSysError("open failed, errno=%d:%s", errno, strerror(errno));
        return NULL;
    }
    object->tmpfd = tmpfd;
#endif
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (MAP_FAILED == mem)
#else
    if (!mem)
#endif
    {
        zanSysError("mmap failed, errno=%d:%s", errno, strerror(errno));
        return NULL;
    }

    object->size = size;
    object->mem  = mem;
    return mem;
}

int zanShm_mmap_free(zanShareMemory *object)
{
    int ret = 0;
    if (!object)
    {
        zanError("object is null");
        return ZAN_ERR;
    }

    ret = munmap(object->mem, object->size);
    if (-1 == ret)
    {
        zanSysError("munmap failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}
