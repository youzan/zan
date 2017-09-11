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
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/
#ifndef _ZAN_WORKERS_H_
#define _ZAN_WORKERS_H_

#include "zanSystem.h"
#include "zanIpc.h"
#include "zanFactory.h"

#ifdef __cplusplus
extern "C" {
#endif

///TODO:::进程数据结构及操作

enum zanWorker_status
{
    ZAN_WORKER_BUSY = 1,
    ZAN_WORKER_IDLE = 2,
    ZAN_WORKER_DEL  = 3,
};

enum zanResponseType
{
    ZAN_RESPONSE_SMALL = 0,
    ZAN_RESPONSE_BIG   = 1,
};

enum zanTaskType
{
    ZAN_TASK_TMPFILE    = 1,  //tmp file
    ZAN_TASK_SERIALIZE  = 2,  //php serialize
    ZAN_TASK_NONBLOCK   = 4,  //task
};

enum zanProcessType
{
    ZAN_PROCESS_UNKNOWN    = 0,
    ZAN_PROCESS_MASTER     = 1,
    ZAN_PROCESS_WORKER     = 2,
    ZAN_PROCESS_TASKWORKER = 3,
    ZAN_PROCESS_USERWORKER = 4,
    ZAN_PROCESS_NETWORKER  = 5,
};

#define is_unknown_process()  (ServerG.process_type == ZAN_PROCESS_UNKNOWN)
#define is_master()           (ServerG.process_type == ZAN_PROCESS_MASTER)
#define is_networker()        (ServerG.process_type == ZAN_PROCESS_NETWORKER)
#define is_worker()           (ServerG.process_type == ZAN_PROCESS_WORKER)
#define is_taskworker()       (ServerG.process_type == ZAN_PROCESS_TASKWORKER)
#define is_userworker()       (ServerG.process_type == ZAN_PROCESS_USERWORKER)


typedef struct _zanProcessPool zanProcessPool;

typedef struct _zanWorker
{
    uint8_t   process_type;
    zan_pid_t worker_pid;
    uint32_t  worker_id;
    pthread_t worker_tid;

    uint8_t   redirect_stdout;       //redirect stdout to pipe_master
    uint8_t   redirect_stdin;        //redirect stdin to pipe_worker
    uint8_t   redirect_stderr;       //redirect stderr to pipe_worker

    //worker status, IDLE or BUSY
    uint8_t   status;
    uint8_t   deleted;
    uint8_t   deny_request;

    //worker
    uint32_t  request_num;

    //task_worker
    //uint8_t      ipc_mode;
    //zanMsgQueue *queue;
    sw_atomic_t  tasking_num;

    ///
    zanLock lock;

    int pipe;
    int pipe_master;
    int pipe_worker;

    void *send_shm;

    zanPipe        *pipe_object;
    zanProcessPool *pool;

    void *ptr2;
} zanWorker;

typedef struct _zanUserWorker_node
{
    struct _zanUserWorker_node *next, *prev;
    zanWorker *worker;
} zanUserWorker_node;

/*---------------------init and free worker struct-----------------------*/
///TODO:::: delete or replace
int zanWorker_init(zanWorker *worker);
void zanWorker_free(zanWorker *worker);

//networker<--->worker<--->task_worker
int zanWorker_send2worker(zanWorker *dst_worker, void *buf, int n, int flag);
int zanWorker_send2reactor(swEventData *ev_data, size_t sendn, int fd);

////////////////////////////////////////////////////////////////////////////////
//worker pool
struct _zanProcessPool
{
    uint16_t     start_id;         //worker->id = start_id + index
    zan_atomic_t round_id;

    //taskworker
    zanMsgQueue *queue;
    swHashMap   *map;

    zanWorker   *workers;
    zanPipe     *pipes;

    int (*onTask)(struct _zanProcessPool *pool, swEventData *task);

    void (*onWorkerStart)(struct _zanProcessPool *pool, zanWorker *worker);
    void (*onWorkerStop)(struct _zanProcessPool *pool, zanWorker *worker);

    int (*main_loop)(struct _zanProcessPool *pool, zanWorker *worker);
    int (*onWorkerNotFound)(struct _zanProcessPool *pool, pid_t pid);
};

//create and start child workers
int zan_start_worker_processes(void);

/*----------------------------Process Pool-------------------------------*/
int zan_processpool_create(zanProcessPool *pool, int process_type);
void zan_processpool_shutdown(zanProcessPool *pool);

//
void zan_stats_set_worker_status(zanWorker *worker, int status);
void zan_worker_clean_pipe(void);

static inline zanWorker* zan_pool_get_worker(zanProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}


#ifdef __cplusplus
}
#endif

#endif  //_ZAN_WORKERS_H_

