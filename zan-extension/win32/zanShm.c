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
#include "zanGlobalVar.h"
#include <Windows.h>

void* zan_shm_malloc(size_t size)
{
    zanShareMemory object;
    void *mem;

    size += sizeof(zanShareMemory);               //zanShareMemory 对象保存在整个内存块的头部
    mem = zanShm_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        zanError("zanShm_mmap_create failed.");
        return NULL;
    }
    memcpy(mem, &object, sizeof(zanShareMemory)); //zanShareMemory 对象保存在整个内存块的头部

    return ((char *)mem) + sizeof(zanShareMemory);
}

void* zan_shm_calloc(size_t num, size_t _size)
{
    zanShareMemory object;

    int size = sizeof(zanShareMemory) + (num * _size);
    void *mem = zanShm_mmap_create(&object, size, NULL);
    void *ret_mem;
    if (mem == NULL)
    {
        zanError("zanShm_mmap_create failed.");
        return NULL;
    }

    memcpy(mem, &object, sizeof(zanShareMemory));  //zanShareMemory 对象保存在整个内存块的头部
    ret_mem = ((char *)mem) + sizeof(zanShareMemory);

    bzero(ret_mem, size - sizeof(zanShareMemory)); //calloc需要初始化
    return ret_mem;
}

void zan_shm_free(void *ptr)
{
    //取整块内存的起始地址, 然后释放
    //ptr 指向内存块起始地址偏移 sizeof(zanShareMemory) 的位置
    //zanShareMemory 对象存储在整块内存的头部
    zanShareMemory *object = (zanShareMemory *)(((char *)ptr) - sizeof(zanShareMemory));
    zanShm_mmap_free(object);
}

void* zan_shm_realloc(void *ptr, size_t new_size)
{
    zanShareMemory *object = (zanShareMemory *)(((char *)ptr) - sizeof(zanShareMemory));
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

    HANDLE hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE,
		NULL, PAGE_READWRITE, 0, size, NULL);

	if (hMapFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    object->mem = MapViewOfFile(
            hMapFile,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            size);
    CloseHandle(hMapFile);
    object->size = size;

    return object->mem;
}

int zanShm_mmap_free(zanShareMemory *object)
{
    int ret = 0;
    if (!object)
    {
        zanError("object is null");
        return ZAN_ERR;
    }

	return UnmapViewOfFile(object->mem) ? ZAN_OK : ZAN_ERR;
}
