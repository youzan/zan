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

#ifndef ZAN_IPC_H_
#define ZAN_IPC_H_


#ifndef PHP_WIN32
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include "zanMemory/zanMemory.h"
#endif

#include "zanLock.h"
#include "swReactor.h"

#ifdef __cplusplus
extern "C" {
#endif

//==========================zanCond=============================================
typedef struct _zanCond
{
    zanLock lock;
#ifdef PHP_WIN32
    HANDLE cond;
#else
    pthread_cond_t cond;
#endif

    int (*wait)(struct _zanCond *object);
    int (*timewait)(struct _zanCond *object, long, long);
    int (*notify)(struct _zanCond *object);
    int (*broadcast)(struct _zanCond *object);
    void (*free)(struct _zanCond *object);
} zanCond;

int zanCond_create(zanCond *cond);


//=======================zanPipe================================================
enum ZAN_PIPE_TYPE
{
    ZAN_PIPE = 0,
    ZAN_UNSOCK = 1,
};

enum zanWorkerPipeType
{
    ZAN_PIPE_WORKER   = 0,
    ZAN_PIPE_MASTER   = 1,
    ZAN_PIPE_NONBLOCK = 2,
};

typedef struct _zanPipeFd
{
    int fds[2];
}zanPipeFd;

typedef struct _zanPipe
{
    void *object;
    int is_nonblock;
    enum ZAN_PIPE_TYPE pipe_type;

    int (*read)(struct _zanPipe *, void *buffer, int length);
    int (*write)(struct _zanPipe *, void *buffer, int length);
    int (*getFd)(struct _zanPipe *, int isWriteFd);
    int (*close)(struct _zanPipe *);
}zanPipe;

int zanPipe_create(zanPipe *pPipe, enum ZAN_PIPE_TYPE pipe_type, int isNonBlock, int protocpl);

//=======================zanMsg=================================================
enum zanIPCMode
{
    ZAN_IPC_UNSOCK   = 1,
    ZAN_IPC_MSGQUEUE = 2,
    ZAN_IPC_QUEUE_PREEMPTIVE = 3,
};

#ifdef PHP_WIN32
typedef unsigned int key_t;
#endif

typedef struct _zanQueue_Data
{
    long mtype;
    char mdata[sizeof(swEventData)];
}zanQueue_Data;

typedef struct _zanMsgQueue
{
    int is_nonblock;
    int msg_id;
    int ipc_wait;
    uint8_t deleted;

    int (*pop)(struct _zanMsgQueue *, zanQueue_Data *buffer, int length);
    int (*push)(struct _zanMsgQueue *, zanQueue_Data *buffer, int length);
    int (*stat)(struct _zanMsgQueue *, int *queue_num, int *queue_bytes);
    int (*close)(struct _zanMsgQueue *);
} zanMsgQueue;

int zanMsgQueue_create(zanMsgQueue *pMq, int wait, key_t msg_key);
int zanMsgQueue_stat(zanMsgQueue *pMq, int *queue_num, int *queue_bytes);

//=======================zanShm=================================================
//share memory
void* zan_shm_malloc(size_t size);
void zan_shm_free(void *ptr);
void* zan_shm_calloc(size_t num, size_t _size);
void* zan_shm_realloc(void *ptr, size_t new_size);

#define ZAN_FILE_NAME_LEN  64

typedef struct _zanShm_mmap
{
    int size;
    char mapfile[ZAN_FILE_NAME_LEN];
    int tmpfd;
    int key;
    int shmid;
    void *mem;
}zanShareMemory;

void *zanShm_mmap_create(zanShareMemory *object, int size, char *mapfile);
int zanShm_mmap_free(zanShareMemory *object);

#ifdef __cplusplus
}
#endif

#endif //ZAN_IPC_H_
