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
#ifndef _SW_PIPE_H_
#define _SW_PIPE_H_

#include "swoole.h"
#include "swLock.h"
#include "swReactor.h"

#ifdef __cplusplus
extern "C" {
#endif

enum swIPCMode
{
	SW_IPC_UNSOCK   = 1,
	SW_IPC_MSGQUEUE = 2,
	SW_IPC_CHANNEL  = 3,
};

enum swTaskIPCMode
{
    SW_TASK_IPC_UNIXSOCK    = 1,
    SW_TASK_IPC_MSGQUEUE    = 2,
    SW_TASK_IPC_PREEMPTIVE  = 3,
};

enum swWorkerPipeType
{
    SW_PIPE_WORKER     = 0,
    SW_PIPE_MASTER     = 1,
    SW_PIPE_NONBLOCK   = 2,
};

//------------------Msg Queue--------------------

typedef struct _swQueue_Data
{
    long mtype; /* type of received/sent message */
    char mdata[sizeof(swEventData)]; /* text of the message */
} swQueue_data;

typedef struct _swMsgQueue
{
    int blocking;
    int msg_id;
    int ipc_wait;
    uint8_t deleted;
    long type;
} swMsgQueue;

int swMsgQueue_create(swMsgQueue *q, int wait, key_t msg_key, long type);
void swMsgQueue_free(swMsgQueue *p);

int swMsgQueue_push(swMsgQueue *p, swQueue_data *in, int data_length);
int swMsgQueue_pop(swMsgQueue *p, swQueue_data *out, int buffer_length);
int swMsgQueue_stat(swMsgQueue *q, int *queue_num, int *queue_bytes);


/*
 *  pipe
 */
typedef struct _swPipe
{
    void *object;
    int blocking;
    double timeout;

    int (*read)(struct _swPipe *, void *recv, int length);
    int (*write)(struct _swPipe *, void *send, int length);
    int (*getFd)(struct _swPipe *, int isWriteFd);
    int (*close)(struct _swPipe *);
}swPipe;

int swPipeBase_create(swPipe *p, int blocking);
int swPipeBase_close(swPipe *p);

#ifdef HAVE_EVENTFD
int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout);
int swPipeEventfd_close(swPipe *p);
#endif

int swPipeUnsock_create(swPipe *p, int blocking, int protocol);
int swPipeUnsock_close(swPipe *p);

static inline int swPipeNotify_auto(swPipe *p, int blocking, int semaphore)
{
#ifdef HAVE_EVENTFD
    return swPipeEventfd_create(p, blocking, semaphore, 0);
#else
    return swPipeBase_create(p, blocking);
#endif
}

//-----------------------------Channel---------------------------
enum SW_CHANNEL_FLAGS
{
    SW_CHAN_LOCK     = 1u << 1,
    SW_CHAN_NOTIFY   = 1u << 2,
    SW_CHAN_SHM      = 1u << 3,
};

typedef struct _swChannel
{
	int head;    //头部，出队列方向
	int tail;    //尾部，入队列方向
	int size;    //队列总尺寸
	char head_tag;
	char tail_tag;
	int num;
	int flag;
	int maxlen;
	void *mem;   //内存块
	swLock lock;
	swPipe notify_fd;
} swChannel;

swChannel* swChannel_create(int size, int maxlen, int flag);
void swChannel_free(swChannel *object);

int swChannel_push(swChannel *object, void *in, int data_length);
int swChannel_pop(swChannel *object, void *out, int buffer_length);
int swChannel_wait(swChannel *object);
int swChannel_notify(swChannel *object);
int swChannel_push_withLock(swChannel *object, void *in, int data_length);
int swChannel_pop_withLock(swChannel *object, void *out, int buffer_length);

#ifdef __cplusplus
}
#endif

#endif
