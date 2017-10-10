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

#include <sys/shm.h>
#include "swMemory/memoryPool.h"
#include "zanLog.h"

void* sw_shm_malloc(size_t size)
{
    swShareMemory object;
    //object对象需要保存在头部
    size += sizeof(swShareMemory);
    void *mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }

    memcpy(mem, &object, sizeof(swShareMemory));
    return mem + sizeof(swShareMemory);
}

void* sw_shm_calloc(size_t num, size_t _size)
{
    swShareMemory object;
    //object对象需要保存在头部
    int size = sizeof(swShareMemory) + (num * _size);
    void *mem = swShareMemory_mmap_create(&object, size, NULL);
    if (mem == NULL)
    {
        return NULL;
    }

    memcpy(mem, &object, sizeof(swShareMemory));
    void *ret_mem = mem + sizeof(swShareMemory);
    //calloc需要初始化
    bzero(ret_mem, size - sizeof(swShareMemory));
    return ret_mem;
}

void sw_shm_free(void *ptr)
{
    //object对象在头部，如果释放了错误的对象可能会发生段错误
    swShareMemory *object = ptr - sizeof(swShareMemory);
    swShareMemory_mmap_free(object);
}

void* sw_shm_realloc(void *ptr, size_t new_size)
{
    swShareMemory *object = ptr - sizeof(swShareMemory);
    if (object->size >= new_size){
        return ptr;
    }

    void *new_ptr = sw_shm_malloc(new_size);
    if(new_ptr==NULL)
    {
        return NULL;
    }

    memcpy(new_ptr, ptr, object->size);
    sw_shm_free(ptr);
    return new_ptr;
}

void *swShareMemory_mmap_create(swShareMemory *object, int size, char *mapfile)
{
    if (!object || size <= 0){
        return NULL;
    }

    bzero(object, sizeof(swShareMemory));
    int flag = MAP_SHARED;
    int tmpfd = -1;
#ifdef MAP_ANONYMOUS
    flag |= MAP_ANONYMOUS;
#else

    mapfile = (!mapfile)? "/dev/zero":mapfile;
    strncpy(object->mapfile, mapfile, SW_SHM_MMAP_FILE_LEN);

    tmpfd = open(mapfile, O_RDWR);
    if(tmpfd < 0)
    {
        return NULL;
    }

    object->tmpfd = tmpfd;
#endif

    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, flag, tmpfd, 0);
#ifdef MAP_FAILED
    if (mem == MAP_FAILED)
#else
    if (!mem)
#endif
    {
        zanError("mmap failed.");
        return NULL;
    }
    else
    {
        object->size = size;
        object->mem = mem;
        return mem;
    }
}

int swShareMemory_mmap_free(swShareMemory *object)
{
    return munmap(object->mem, object->size);
}

void *swShareMemory_sysv_create(swShareMemory *object, int size, int key)
{
    if (!object || size <= 0){
        return NULL;
    }

    bzero(object, sizeof(swShareMemory));
    key = (key == 0)? IPC_PRIVATE:key;

    //SHM_R | SHM_W |
    int shmid = -1;
    if ((shmid = shmget(key, size, IPC_CREAT)) < 0)
    {
        zanError("shmget() failed.");
        return NULL;
    }

    void *mem = shmat(shmid, NULL, 0);
    if ((intptr_t)mem < 0)
    {
        zanError("shmat() failed.");
        return NULL;
    }
    else
    {
        object->key = key;
        object->shmid = shmid;
        object->size = size;
        object->mem = mem;
        return mem;
    }
}

int swShareMemory_sysv_free(swShareMemory *object, int rm)
{
    if (!object){
        return -1;
    }

    int ret = shmdt(object->mem);
    if (rm)
    {
        shmctl(object->shmid, IPC_RMID, NULL);
    }

    return ret;
}
