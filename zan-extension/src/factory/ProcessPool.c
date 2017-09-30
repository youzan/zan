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

#include "swWork.h"
#include "swFactory.h"
#include "swServer.h"
#include "swBaseOperator.h"
#include "swLog.h"

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker);
static void swProcessPool_free(swProcessPool *pool);

/**
 * Process manager
 */
int swProcessPool_create(swProcessPool *pool, int worker_num, int max_request, key_t msgqueue_key, int create_pipe)
{
    if (!pool)
    {
        return SW_ERR;
    }

    bzero(pool, sizeof(swProcessPool));
    pool->worker_num = worker_num;
    pool->max_request = max_request;

    if (msgqueue_key > 0)
    {
        pool->use_msgqueue = 1;
        pool->msgqueue_key = msgqueue_key;
    }

    pool->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, worker_num * sizeof(swWorker));
    if (pool->workers == NULL)
    {
        swSysError("malloc[1] failed.");
        return SW_ERR;
    }

    pool->map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pool->map == NULL)
    {
        SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
        return SW_ERR;
    }

    pool->queue = sw_malloc(sizeof(swMsgQueue));
    if (pool->queue == NULL)
    {
        swHashMap_free(pool->map);
        SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
        swSysError("malloc[2] failed.");
        return SW_ERR;
    }


    if (pool->use_msgqueue)
    {
        if (swMsgQueue_create(pool->queue, 1, pool->msgqueue_key, 1) < 0)
        {
            sw_free(pool->queue);
            swHashMap_free(pool->map);
            SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
            return SW_ERR;
        }
    }
    else if (create_pipe)
    {
        pool->pipes = sw_calloc(worker_num, sizeof(swPipe));
        if (pool->pipes == NULL)
        {
            sw_free(pool->pipes);
            sw_free(pool->queue);
            swHashMap_free(pool->map);
            SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
            swFatalError("malloc[2] failed.");
            return SW_ERR;
        }

        int index = 0;
        swPipe *pipe = NULL;
        for (index = 0; index < worker_num; index++)
        {
            pipe = &pool->pipes[index];
            if (swPipeUnsock_create(pipe, 1, SOCK_DGRAM) < 0)
            {
                sw_free(pool->pipes);
                sw_free(pool->queue);
                swHashMap_free(pool->map);
                SwooleG.memory_pool->free(SwooleG.memory_pool,pool->workers);
                return SW_ERR;
            }

            pool->workers[index].pipe_master = pipe->getFd(pipe, SW_PIPE_MASTER);
            pool->workers[index].pipe_worker = pipe->getFd(pipe, SW_PIPE_WORKER);
            pool->workers[index].pipe_object = pipe;
        }
    }

    pool->main_loop = swProcessPool_worker_loop;
    return SW_OK;
}

/**
 * start workers
 */
int swProcessPool_start(swProcessPool *pool)
{
    int index;
    for (index = 0; index < pool->worker_num; index++)
    {
        pool->workers[index].pool = pool;
        pool->workers[index].id = pool->start_id + index;
        pool->workers[index].type = pool->type;

        if (swProcessPool_spawn(&(pool->workers[index])) < 0)
        {
            return SW_ERR;
        }
    }

    return SW_OK;
}

static sw_inline int swProcessPool_schedule(swProcessPool *pool)
{
    if (pool->dispatch_mode == SW_DISPATCH_QUEUE)
    {
        return 0;
    }

    int index = 0, target_worker_id = 0;
    int run_worker_num = pool->run_worker_num;

    for (index = 0; index < run_worker_num + 1; index++)
    {
        target_worker_id = sw_atomic_fetch_add(&pool->round_id, 1) % run_worker_num;
        if (pool->workers[target_worker_id].status == SW_WORKER_IDLE)
        {
            break;
        }
    }

    return target_worker_id;
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    swWorker *worker = 0;

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = swProcessPool_get_worker(pool, *dst_worker_id);

    int sendn = sizeof(data->info) + data->info.len;
    int ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER | SW_PIPE_NONBLOCK);

    if (ret < 0)
    {
        swNotice("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
    }
    else
    {
        sw_stats_incr(&worker->tasking_num);
    }

    return ret;
}

/**
 * dispatch data to worker
 */
int swProcessPool_dispatch_blocking(swProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    swWorker *worker = 0;

    if (*dst_worker_id < 0)
    {
        *dst_worker_id = swProcessPool_schedule(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = swProcessPool_get_worker(pool, *dst_worker_id);

    int sendn = sizeof(data->info) + data->info.len;
    int ret = swWorker_send2worker(worker, data, sendn, SW_PIPE_MASTER);

    if (ret < 0)
    {
        swNotice("send %d bytes to worker#%d failed.", sendn, *dst_worker_id);
    }
    else
    {
        sw_stats_incr(&worker->tasking_num);
    }

    return ret;
}

void swProcessPool_shutdown(swProcessPool *pool)
{
    int index = 0, status = 0;
    swWorker *worker = NULL;
    SwooleG.running = 0;

    for (index = 0; index < pool->run_worker_num; index++)
    {
        worker = &pool->workers[index];
        if (swKill(worker->pid, SIGTERM) < 0)
        {
            swSysError("kill(%d) failed.", worker->pid);
            continue;
        }
        if (swWaitpid(worker->pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", worker->pid);
        }
    }

    swProcessPool_free(pool);
}

pid_t swProcessPool_spawn(swWorker *worker)
{
    pid_t pid = fork();
    swProcessPool *pool = worker->pool;

    switch (pid)
    {
    //child
    case 0:
        {
            if (pool->onWorkerStart != NULL)
            {
                pool->onWorkerStart(pool, worker->id);
            }

            /**
             * Process main loop
             */
            int ret_code = pool->main_loop(pool, worker);
            /**
             * Process stop
             */
            if (pool->onWorkerStop != NULL)
            {
                pool->onWorkerStop(pool, worker->id);
            }
            exit(ret_code);
            break;
        }
    case -1:
        swSysError("fork failed.");
        break;
        //parent
    default:
        //remove old process
        if (worker->pid)
        {
            swHashMap_del_int(pool->map, worker->pid);
        }
        worker->deleted = 0;
        worker->pid = pid;
        //insert new process
        swHashMap_add_int(pool->map, pid, worker);
        break;
    }
    return pid;
}

static int swProcessPool_worker_loop(swProcessPool *pool, swWorker *worker)
{
    struct
    {
        long mtype;
        swEventData buf;
    } out;

    int task_n = 0, worker_task_always = 0;

    if (pool->max_request < 1)
    {
        task_n = 1;
        worker_task_always = 1;
    }
    else
    {
        task_n = pool->max_request;
    }

    /**
     * Use from_fd save the task_worker->id
     */
    out.buf.info.from_fd = worker->id;
    out.mtype = (pool->dispatch_mode == SW_DISPATCH_QUEUE)? 0: worker->id + 1;
    int n = 0;
    while (SwooleG.running > 0 && task_n > 0)
    {
        /**
         * fetch task
         */
        if (pool->use_msgqueue)
        {
            n = swMsgQueue_pop(pool->queue, (swQueue_data *) &out, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] msgrcv() failed.", worker->id);
            }
        }
        else
        {
            n = read(worker->pipe_worker, &out.buf, sizeof(out.buf));
            if (n < 0 && errno != EINTR)
            {
                swSysError("[Worker#%d] read(%d) failed.", worker->id, worker->pipe_worker);
            }
        }

        /**
         * timer
         */
        if (n < 0)
        {
            if (errno == EINTR && SwooleG.signal_alarm)
            {
                swTimer_select(&SwooleG.timer);
            }

            continue;
        }

        /**
         * do task
         */
        sw_stats_set_worker_status(SwooleWG.worker, SW_WORKER_BUSY);
        int ret = pool->onTask(pool, &out.buf);
        sw_stats_set_worker_status(SwooleWG.worker, SW_WORKER_IDLE);

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
    }

    return SW_OK;
}

/**
 * add a worker to pool
 */
int swProcessPool_add_worker(swProcessPool *pool, swWorker *worker)
{
    swHashMap_add_int(pool->map, worker->pid, worker);
    return SW_OK;
}

int swProcessPool_wait(swProcessPool *pool)
{
    int pid = -1, new_pid = -1;
    int reload_worker_i = 0;
    int status = -1;

    swWorker *reload_workers = sw_calloc(pool->worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("[manager] malloc[reload_workers] fail.\n");
        return SW_ERR;
    }

    while (SwooleG.running)
    {
        pid = swWaitpid(-1,&status,0);
        if (pid < 0)
        {
            if (pool->reloading == 0)
            {
                swTrace("[Manager] wait failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if (pool->reload_flag == 0)
            {
                swTrace("[Manager] reload workers.");
                memcpy(reload_workers, pool->workers, sizeof(swWorker) * pool->worker_num);
                pool->reload_flag = 1;
                goto reload_worker;
            }
            else if (SwooleG.running == 0)
            {
                break;
            }
        }
        swTrace("[Manager] worker stop.pid=%d", pid);
        if (SwooleG.running == 1)
        {
            swWorker *exit_worker = swHashMap_find_int(pool->map, pid);
            if (exit_worker == NULL)
            {
                if (pool->onWorkerNotFound)
                {
                    pool->onWorkerNotFound(pool, pid);
                }
                else
                {
                    swWarn("[Manager]unknow worker[pid=%d]", pid);
                }
                continue;
            }
            if (!WIFEXITED(status))
            {
                swError("worker#%d abnormal exit, status=%d, signal=%d", exit_worker->id, WEXITSTATUS(status),  WTERMSIG(status));
            }
            new_pid = swProcessPool_spawn(exit_worker);
            if (new_pid < 0)
            {
                swSysError("Fork worker process failed");
                return SW_ERR;
            }
            swHashMap_del_int(pool->map, pid);
        }
        //reload worker
        reload_worker:
        if (pool->reloading == 1)
        {
            //reload finish
            if (reload_worker_i >= pool->worker_num)
            {
                pool->reloading = 0;
                reload_worker_i = 0;
                continue;
            }

            if (swKill(reload_workers[reload_worker_i].pid, SIGTERM) < 0)
            {
                swSysError("[Manager]kill(%d) failed.", reload_workers[reload_worker_i].pid);
                continue;
            }
            reload_worker_i++;
        }
    }

    return SW_OK;
}

static void swProcessPool_free(swProcessPool *pool)
{
    swPipe *_pipe = NULL;

    if (!pool->use_msgqueue)
    {
        int index = 0;
        for (index = 0; index < pool->worker_num; index++)
        {
            _pipe = &pool->pipes[index];
            _pipe->close(_pipe);
        }

        sw_free(pool->pipes);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }
}

