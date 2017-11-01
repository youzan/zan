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

#include "swWork.h"
#include "swFactory.h"
#include "swServer.h"
#include "swBaseOperator.h"

#include <stdlib.h>
#include <time.h>
#include "zanGlobalDef.h"
#include "zanWorkers.h"
#include "zanLog.h"
#include "zanProcess.h"

//TODO::: task_worker resource

int zan_pool_alloc_taskworker(zanProcessPool *pool);
int zan_pool_taskworker_init(zanProcessPool *pool);
int zan_spawn_task_process(zanProcessPool *pool);

static int  zan_taskworker_process_loop(zanProcessPool *pool, zanWorker *worker);
static void zan_processpool_free(zanProcessPool *pool);
static void zan_taskworker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zan_taskworker_onStop(zanProcessPool *pool, zanWorker *worker);

//int zanProcessPool_create(zanProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int create_pipe)
int zan_pool_alloc_taskworker(zanProcessPool *pool)
{
    int   index        = 0;
    int   create_pipe  = 1;
    key_t msgqueue_key = 0;
    int   worker_num   = ServerG.servSet.task_worker_num;

    if (ZAN_IPC_MSGQUEUE == ServerG.servSet.task_ipc_mode)
    {
        msgqueue_key = ServerG.servSet.message_queue_key;
        create_pipe = 0;
    }

    pool->workers = zan_shm_calloc(worker_num, sizeof(zanWorker));
    if (pool->workers == NULL)
    {
        zanError("zan_shm_calloc failed.");
        return ZAN_ERR;
    }

    pool->map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pool->map == NULL)
    {
        zanError("swHashMap_create failed.");
        //SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
        zan_shm_free(pool->workers);
        return ZAN_ERR;
    }

    if (msgqueue_key > 0)
    {
        pool->queue = (zanMsgQueue *)zan_malloc(sizeof(zanMsgQueue));
        if (pool->queue == NULL)
        {
            swHashMap_free(pool->map);
            zan_shm_free(pool->workers);
            zanError("malloc[2] failed.");
            return ZAN_ERR;
        }
        else if (zanMsgQueue_create(pool->queue, 1, msgqueue_key, 1) < 0)
        {
            zan_free(pool->queue);
            swHashMap_free(pool->map);
            zan_shm_free(pool->workers);
            return ZAN_ERR;
        }
    }
    else
    {
        pool->pipes = zan_calloc(worker_num, sizeof(zanPipe));
        if (pool->pipes == NULL)
        {
            zan_free(pool->pipes);
            swHashMap_free(pool->map);
            zan_shm_free(pool->workers);
            zanError("zan_calloc failed.");
            return ZAN_ERR;
        }

        zanPipe *pipe = NULL;
        for (index = 0; index < worker_num; index++)
        {
            pipe = &pool->pipes[index];
            if (zanPipe_create(pipe, ZAN_UNSOCK, 0, SOCK_DGRAM) < 0)
            {
                zan_free(pool->pipes);
                swHashMap_free(pool->map);
                zan_shm_free(pool->workers);
                return ZAN_ERR;
            }

            pool->workers[index].pipe_master = pipe->getFd(pipe, ZAN_PIPE_MASTER);
            pool->workers[index].pipe_worker = pipe->getFd(pipe, ZAN_PIPE_WORKER);
            pool->workers[index].pipe_object = pipe;
        }
    }

    //init every task_worker
    for (index = 0; index < worker_num; index++)
    {
        if (zan_worker_init((&pool->workers[index])) < 0)
        {
            zanError("create taskworker failed.");
            return ZAN_ERR;
        }
        if (create_pipe)
        {
            ///TODO:::
            //zanServer_store_pipe_fd(ServerG.serv, worker->pipe_object);
        }
    }

    pool->main_loop = zan_taskworker_process_loop;
    return ZAN_OK;
}

static inline int zan_pool_schedule_worker(zanProcessPool *pool)
{
    int index            = 0;
    int target_worker_id = 0;
    int run_worker_num   = ServerG.servSet.task_worker_num;

    if (ZAN_IPC_MSGQUEUE == ServerG.servSet.task_ipc_mode)
    {
        return 0;
    }

    for (index = 0; index < run_worker_num + 1; index++)
    {
        target_worker_id = zan_atomic_fetch_add(&pool->round_id, 1) % run_worker_num;
        if (pool->workers[target_worker_id].status == ZAN_WORKER_IDLE)
        {
            break;
        }

        //如果循环一遍无空闲 worker，则随机取一个 worker
        srand((unsigned)time(NULL));
        target_worker_id = rand() % run_worker_num;
    }

    return target_worker_id;
}

//dispatch data to task_worker
int zan_pool_dispatch_to_taskworker(zanProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    zanWorker *worker = NULL;
    if (*dst_worker_id < 0)
    {
        *dst_worker_id = zan_pool_schedule_worker(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = zan_pool_get_worker(pool, *dst_worker_id);
    int sendn = sizeof(data->info) + data->info.len;

    int ret = zan_worker_send2worker(worker, data, sendn, ZAN_PIPE_MASTER | ZAN_PIPE_NONBLOCK);
    if (ret < 0)
    {
        zanWarn("worker send %d bytes to taskworker#%d failed.", sendn, *dst_worker_id);
    }
    else
    {
        sw_stats_incr(&worker->tasking_num);
    }

    return ret;
}


void zan_processpool_shutdown(zanProcessPool *pool)
{
#if 0
    int index  = 0;
    int status = 0;
    zanWorker *worker = NULL;
    ServerG.running = 0;

    for (index = 0; index < pool->run_worker_num; index++)
    {
        worker = &pool->workers[index];
        if (swKill(worker->pid, SIGTERM) < 0)
        {
            zanError("kill(%d) failed.", worker->pid);
            continue;
        }
        if (swWaitpid(worker->pid, &status, 0) < 0)
        {
            zanError("waitpid(%d) failed.", worker->pid);
        }
    }
#endif
    zan_processpool_free(pool);
}

//task_worker look
static int zan_taskworker_process_loop(zanProcessPool *pool, zanWorker *worker)
{
    struct
    {
        long mtype;
        swEventData buf;
    } out;

    int task_n = 0;
    int worker_task_always = 0;

    if (ServerG.servSet.task_max_request < 1)
    {
        task_n = 1;
        worker_task_always = 1;
    }
    else
    {
        task_n = ServerG.servSet.task_max_request;
    }

    //Use from_fd save the task_worker->id
    out.buf.info.from_fd = worker->worker_id;
    out.mtype = (ServerG.servSet.task_ipc_mode == ZAN_IPC_MSGQUEUE)? 0: worker->worker_id + 1;
    int n = 0;
    while (SwooleG.running > 0 && task_n > 0)
    {
        zanWarn("task_worker loop: worker_id=%d, process_type=%d, pid=%d", worker->worker_id, ServerG.process_type, ServerG.process_pid);
        if (ZAN_IPC_MSGQUEUE == ServerG.servSet.task_ipc_mode)
        {
            n = pool->queue->pop(pool->queue, (zanQueue_Data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                zanError("[Worker#%d] msgrcv() failed.", worker->worker_id);
            }
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                zanError("[Worker#%d] read(%d) failed.", worker->worker_id, worker->pipe_worker);
                sleep(3);
            }
        }

        if (n < 0)
        {
            if (errno == EINTR && ServerG.signal_alarm)
            {
                swTimer_select(&ServerG.timer);
            }
            continue;
        }

        sw_stats_set_worker_status(ServerWG.worker, ZAN_WORKER_BUSY);
        int ret = pool->onTask(pool, &out.buf);
        sw_stats_set_worker_status(ServerWG.worker, ZAN_WORKER_IDLE);

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
    }

    return ZAN_OK;
}

static void zan_processpool_free(zanProcessPool *pool)
{
    zanPipe *_pipe = NULL;

    if (ZAN_IPC_UNSOCK == ServerG.servSet.task_ipc_mode)
    {
        int index = 0;
        for (index = 0; index < ServerG.servSet.worker_num; index++)
        {
            _pipe = &pool->pipes[index];
            _pipe->close(_pipe);
        }
        zan_free(pool->pipes);
    }
    else
    {
        pool->queue->close(pool->queue);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }
}

int zan_pool_taskworker_init(zanProcessPool *pool)
{
    ////TODO:::
    //pool->onTask         = swTaskWorker_onTask;
    pool->onWorkerStart  = zan_taskworker_onStart;
    pool->onWorkerStop   = zan_taskworker_onStop;
    pool->start_id       = ServerG.servSet.worker_num;

    char *tmp_dir = swoole_dirname(ServerG.servSet.task_tmpdir);
    if (access(tmp_dir, R_OK) < 0 && swoole_mkdir_recursive(tmp_dir) < 0)
    {
        zanWarn("create task tmp dir failed.");
        return ZAN_ERR;
    }
    return ZAN_OK;
}


int zan_spawn_task_process(zanProcessPool *pool)
{
    int index  = 0;
    for (index = 0; index < ServerG.servSet.task_worker_num; index++)
    {
        zanWorker *worker = &(pool->workers[index]);
        worker->pool         = pool;
        worker->worker_id    = pool->start_id + index;
        worker->process_type = ZAN_PROCESS_TASKWORKER;

        zan_pid_t pid = fork();
        if (0 == pid)
        {
            pool->onWorkerStart(pool, worker);
            //zanWarn("task_worker loop: worker_id=%d, start_id=%d", worker->worker_id, pool->start_id);
            int ret_code = pool->main_loop(pool, worker);
            pool->onWorkerStop(pool, worker);
            exit(ret_code);
        }
        else if (pid < 0)
        {
            zanError("fork failed.");
            return ZAN_ERR;
        }
        else
        {
            //remove old process
            if (worker->worker_pid)
            {
                swHashMap_del_int(pool->map, worker->worker_pid);
            }
            worker->deleted = 0;
            worker->worker_pid = pid;
            //insert new process
            swHashMap_add_int(pool->map, pid, worker);
            return ZAN_OK;
        }
    }
    return ZAN_OK;
}

static void zan_taskworker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;

    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_WORKER;
    ServerWG.worker_id   = worker->worker_id;

    //
    if (serv->onWorkerStart)
    {
        zanWarn("taskworker: call user worker onStart function");
        serv->onWorkerStart(serv, worker->worker_id);
    }
}

static void zan_taskworker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;
    if (serv->onWorkerStop)
    {
        zanWarn("taskworker: call user worker onStop function");
        serv->onWorkerStop(serv, worker->worker_id);
    }
    zan_worker_free(worker);
}
