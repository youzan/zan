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

#ifndef _ZAN_ZANFACTORY_H_
#define _ZAN_ZANFACTORY_H_

#include "swoole.h"
#include "zanThread.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * -----------------------------------Factory--------------------------------------------
 */
enum zanDispatchMode
{
    ZAN_DISPATCH_ROUND  = 1,      //轮循模式
    ZAN_DISPATCH_FDMOD  = 2,      //固定模式，根据连接的文件描述符分配worker
    ZAN_DISPATCH_QUEUE  = 3,      //抢占模式
    ZAN_DISPATCH_IPMOD  = 4,      //对 client IP 取模，分配给一个固定 worker
    //ZAN_DISPATCH_UIDMOD = 5,      //UID 分配
};

typedef struct
{
    long target_worker_id;
    swEventData data;
} swDispatchData;

typedef struct _swSendData
{
    swDataHead info;
    /**
     * for big package
     */
    uint32_t length;
    char *data;
} swSendData;


typedef struct _zanFactory
{
    int (*start)(struct _zanFactory *);
    int (*shutdown)(struct _zanFactory *);
    int (*dispatch)(struct _zanFactory *, swDispatchData *);
    int (*finish)(struct _zanFactory *, swSendData *);
    int (*notify)(struct _zanFactory *, swDataHead *);
    int (*end)(struct _zanFactory *, int session_id);
} zanFactory;

int zanFactory_create(zanFactory *factory);

/*----------------------------Thread Pool-------------------------------*/
enum swThread_type
{
    SW_THREAD_MASTER = 1,
    SW_THREAD_REACTOR = 2,
    SW_THREAD_WORKER = 3,
    SW_THREAD_UDP = 4,
    SW_THREAD_UNIX_DGRAM = 5,
    SW_THREAD_HEARTBEAT = 6,
};

typedef struct _swThread swThread;
typedef struct _swThreadPool swThreadPool;

typedef struct _swThreadParam
{
    void *object;
    int pti;
} swThreadParam;

struct _swThreadPool
{
    zanCond cond;
    swThread *threads;
    swThreadParam *params;

    void *ptr1;
    void *ptr2;

#ifdef SW_THREADPOOL_USE_CHANNEL
    swChannel *chan;
#else
    swRingQueue queue;
#endif

    int thread_num;
    int shutdown;
    sw_atomic_t task_num;

    void (*onStart)(struct _swThreadPool *pool, int id);
    void (*onStop)(struct _swThreadPool *pool, int id);
    int (*onTask)(struct _swThreadPool *pool, void *task, int task_len);

};

struct _swThread
{
    zan_thread_t tid;
    int id;
    swThreadPool *pool;
};

int swThreadPool_create(swThreadPool *pool, int max_num);
int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len);
int swThreadPool_run(swThreadPool *pool);
int swThreadPool_free(swThreadPool *pool);


#ifdef __cplusplus
}
#endif

#endif   //_ZAN_ZANFACTORY_H_
