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
#ifndef _SW_FACTORY_H_
#define _SW_FACTORY_H_

#include "swoole.h"
#include "swPipe.h"
#include "swMemory/memoryPool.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * -----------------------------------Factory--------------------------------------------
 */
enum swFactory_dispatch_mode
{
    SW_DISPATCH_ROUND = 1,
    SW_DISPATCH_FDMOD = 2,
    SW_DISPATCH_QUEUE = 3,
    SW_DISPATCH_IPMOD = 4,
    SW_DISPATCH_UIDMOD = 5,
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

typedef struct _swFactory
{
    void *object;
    void *ptr; //server object
    int last_from_id;

    swReactor *reactor; //reserve for reactor

    int (*start)(struct _swFactory *);
    int (*shutdown)(struct _swFactory *);
    int (*dispatch)(struct _swFactory *, swDispatchData *);
    int (*finish)(struct _swFactory *, swSendData *);
    int (*notify)(struct _swFactory *, swDataHead *);    //send a event notify
    int (*end)(struct _swFactory *, int fd);
}swFactory;


typedef struct _swFactoryProcess
{
    swPipe *pipes;
} swFactoryProcess;

typedef struct _swRequest
{
    int fd;
    uint8_t type;
    uint8_t status;
    void *object;
} swRequest;

typedef struct _swWorker swWorker;
typedef struct _swProcessPool	swProcessPool;

struct _swWorker
{
	/**
	 * worker process
	 */
	pid_t pid;

	/**
	 * worker thread
	 */
	pthread_t tid;

	swProcessPool *pool;
	swMemoryPool *pool_output;
	swMsgQueue *queue;

	/**
	 * redirect stdout to pipe_master
	 */
	uint8_t redirect_stdout;

	/**
     * redirect stdin to pipe_worker
     */
    uint8_t redirect_stdin;

    /**
     * redirect stderr to pipe_worker
     */
    uint8_t redirect_stderr;

	/**
	 * worker status, IDLE or BUSY
	 */
    uint8_t status;
    uint8_t type;
    uint8_t ipc_mode;

    uint8_t deleted;
    uint8_t child_process;

    /*
     * deny_request
     */
    uint8_t deny_request;

    /**
     * tasking num
     */
    sw_atomic_t tasking_num;

	/**
	 * worker id
	 */
	uint32_t id;

	swLock lock;

	void *send_shm;

	swPipe *pipe_object;

	int pipe_master;
	int pipe_worker;

	int pipe;
	void *ptr;
	void *ptr2;
};

typedef struct _swUserWorker_node
{
    struct _swUserWorker_node *next, *prev;
    swWorker *worker;
}swUserWorker_node;

typedef struct
{
    uint16_t num;
} swUserWorker;

struct _swProcessPool
{
    /**
     * reloading
     */
    uint8_t reloading;
    uint8_t reload_flag;
    uint8_t dispatch_mode;

    /**
     * process type
     */
    uint8_t type;

    /**
     * worker->id = start_id + i
     */
    uint16_t start_id;

    /**
     * use message queue IPC
     */
    uint8_t use_msgqueue;
    /**
     * message queue key
     */
    key_t msgqueue_key;

    int worker_num;
    int max_request;

    int (*onTask)(struct _swProcessPool *pool, swEventData *task);

    void (*onWorkerStart)(struct _swProcessPool *pool, int worker_id);
    void (*onWorkerStop)(struct _swProcessPool *pool, int worker_id);

    int (*main_loop)(struct _swProcessPool *pool, swWorker *worker);
    int (*onWorkerNotFound)(struct _swProcessPool *pool, pid_t pid);

    sw_atomic_t round_id;
    sw_atomic_t run_worker_num;

    swWorker *workers;
    swPipe *pipes;
    swHashMap *map;
    swReactor *reactor;
    swMsgQueue *queue;

    void *ptr;
    void *ptr2;

};

int swFactory_create(swFactory *factory);

int swFactory_finish(swFactory *factory, swSendData *_send);
int swFactory_notify(swFactory *factory, swDataHead *event);
int swFactory_end(swFactory *factory, int fd);
int swFactory_check_callback(swFactory *factory);

int swFactoryProcess_create(swFactory *factory, int worker_num);
int swFactoryThread_create(swFactory *factory, int writer_num);

//========================================================================
typedef swFactory zanFactory;
int zanFactory_create(zanFactory *factory);

/*----------------------------Process Pool-------------------------------*/
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int nopipe);
int swProcessPool_wait(swProcessPool *pool);
int swProcessPool_start(swProcessPool *pool);
void swProcessPool_shutdown(swProcessPool *pool);
pid_t swProcessPool_spawn(swWorker *worker);
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *worker_id);
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id);
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker);
int swProcessPool_del_worker(swProcessPool *pool, swWorker *worker);

static sw_inline swWorker* swProcessPool_get_worker(swProcessPool *pool, int worker_id)
{
    return &(pool->workers[worker_id - pool->start_id]);
}

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
//    pthread_mutex_t mutex;
//    pthread_cond_t cond;
    swCond cond;
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
    pthread_t tid;
    int id;
    swThreadPool *pool;
};

int swThreadPool_create(swThreadPool *pool, int max_num);
int swThreadPool_dispatch(swThreadPool *pool, void *task, int task_len);
int swThreadPool_run(swThreadPool *pool);
int swThreadPool_free(swThreadPool *pool);

//////////////////////////////////////////////////////////////

typedef struct _swReactorThread
{
    pthread_t thread_id;
    swReactor reactor;
    swUdpFd *udp_addrs;
    swMemoryPool *buffer_input;
#ifdef SW_USE_RINGBUFFER
    int *pipe_read_list;
#endif
    swLock lock;
    int c_udp_fd;
} swReactorThread;

#ifdef __cplusplus
}
#endif
#endif
