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
#include "list.h"

#include "zanWorkers.h"
#include "zanLog.h"
#include "zanProcess.h"
#include "zanGlobalDef.h"

extern int zan_pool_alloc_taskworker(zanProcessPool *pool);
extern int zan_pool_alloc_worker(zanProcessPool *pool);
extern int zan_pool_alloc_networker(zanProcessPool *pool);

extern int zan_pool_worker_init(zanProcessPool *pool);
extern int zan_pool_taskworker_init(zanProcessPool *pool);
extern int zan_pool_networker_init(zanProcessPool *pool);

extern int zan_spawn_worker_process(zanProcessPool *);
extern int zan_spawn_task_process(zanProcessPool *);
extern int zan_spawn_net_process(zanProcessPool *);

static int zan_alloc_workers_rsc(void);
static int zan_spawn_user_process(void);
static int zan_alloc_userworker_process(void);
static int zan_spawn_child_process(void);

int zan_start_worker_processes(void)
{
    //alloc resource for all workes
    if (ZAN_OK != zan_alloc_workers_rsc())
    {
        zanError("zan_alloc_worker_rsc failed");
        return ZAN_ERR;
    }

    if (ZAN_OK != zan_spawn_child_process())
    {
        zanError("spawn child process failed");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zan_alloc_workers_rsc(void)
{
    zanServerSet *servSet = &(ServerG.servSet);

    if (ZAN_OK != zan_processpool_create(&ServerGS->event_workers, ZAN_PROCESS_WORKER))
    {
        zanError("zan_processpool_create worker failed");
        return ZAN_ERR;
    }

    if (ZAN_OK != zan_processpool_create(&ServerGS->task_workers, ZAN_PROCESS_TASKWORKER))
    {
        zanError("zan_processpool_create taskworker failed");
        return ZAN_ERR;
    }

    if (ZAN_OK != zan_alloc_userworker_process())
    {
        zanError("zan_alloc_userworker_process failed");
        return ZAN_ERR;
    }

    if (ZAN_OK != zan_processpool_create(&ServerGS->net_workers, ZAN_PROCESS_NETWORKER))
    {
        zanError("zan_processpool_create networker failed");
        return ZAN_ERR;
    }

    //Alloc shared memory for worker stats
    ServerStatsG->workers_state = zan_shm_calloc(servSet->worker_num +
                                  servSet->task_worker_num + servSet->net_worker_num, sizeof(zanWorkerStats));

    if (!ServerStatsG->workers_state)
    {
        zanError("gmalloc[SwooleStats->workers_state] failed");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

int zan_processpool_create(zanProcessPool *pool, int process_type)
{
    bzero(pool, sizeof(zanProcessPool));
    if (ZAN_PROCESS_WORKER == process_type)
    {
        if (ZAN_OK != zan_pool_alloc_worker(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zan_pool_worker_init(pool))
        {
            zanError("init worker pool failed.");
            return ZAN_ERR;
        }
    }
    else if (ZAN_PROCESS_TASKWORKER == process_type && ServerG.servSet.task_worker_num > 0)
    {
        if (ZAN_OK != zan_pool_alloc_taskworker(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zan_pool_taskworker_init(pool))
        {
            zanError("init taskworker pool failed.");
            return ZAN_ERR;
        }
    }
    else if (ZAN_PROCESS_NETWORKER == process_type)
    {
        if (ZAN_OK != zan_pool_alloc_networker(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zan_pool_networker_init(pool))
        {
            zanError("init networker pool failed.");
            return ZAN_ERR;
        }
    }
    else
    {
        zanError("unknown process_type=%d", process_type);
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zan_spawn_child_process(void)
{
    //fork workes
    if (ZAN_OK != zan_spawn_worker_process(&ServerGS->event_workers))
    {
        zanError("zan_spawn_worker_process failed");
        return ZAN_ERR;
    }

#if 0
    //fork task_workes
    if (ZAN_OK != zan_spawn_task_process(&ServerGS->task_workers))
    {
        zanError("zan_spawn_task_process failed");
        return ZAN_ERR;
    }

    //fork user workes
    if (ZAN_OK != zan_spawn_user_process())
    {
        zanError("zan_spawn_user_process failed");
        return ZAN_ERR;
    }
#endif

    //fork net_workes
    if (ZAN_OK != zan_spawn_net_process(&ServerGS->net_workers))
    {
        zanError("zan_spawn_net_process failed");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zan_alloc_userworker_process(void)
{
    zanServer *serv = (zanServer *)ServerG.serv;
    if (NULL == serv->user_worker_list)
    {
        return ZAN_OK;
    }

    int index = 0;
    serv->user_workers = (zanWorker **)zan_calloc(serv->user_worker_num, sizeof(zanWorker *));
    if (NULL == serv->user_workers)
    {
        zanError("calloc userworker failed， user_worker_num=%d.", serv->user_worker_num);
        return ZAN_ERR;
    }

    zanUserWorker_node *user_worker = NULL;
    LL_FOREACH(serv->user_worker_list, user_worker)
    {
        if (zanWorker_init(user_worker->worker) < 0)
        {
            zanError("init userworker failed, index=%d, user_worker_num=%d.", index, serv->user_worker_num);
            return ZAN_ERR;
        }
        serv->user_workers[index] = user_worker->worker;
        index++;
    }
    return ZAN_OK;
}

//fork user workes
static int zan_spawn_user_process(void)
{
    int index = 0;
    zan_pid_t  pid = 0;
    zanServer *serv       = (zanServer *)ServerG.serv;
    zanServerSet *servSet = &ServerG.servSet;
    if (NULL == serv->user_worker_list)
    {
        return ZAN_OK;
    }

    zanUserWorker_node *user_worker = NULL;
    LL_FOREACH(serv->user_worker_list, user_worker)
    {
        zanWorker *worker    = user_worker->worker;
        worker->process_type = ZAN_PROCESS_USERWORKER;
        worker->worker_id    = servSet->worker_num + servSet->task_worker_num +
                               servSet->net_worker_num + index++;

        //store the pipe object
        if (worker->pipe_object)
        {
            ///TODO:::
            /////zanServer_store_pipe_fd(serv, worker->pipe_object);
        }

        pid = zan_fork();
        if (pid < 0)
        {
            zanError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)
        {
            ServerG.process_pid  = zan_getpid();
            ServerG.process_type = ZAN_PROCESS_USERWORKER;
            ServerWG.worker_id = worker->worker_id;
            serv->onUserWorkerStart(serv, worker);
            exit(0);
        }
        else
        {
            if (worker->worker_pid)
            {
                swHashMap_del_int(serv->user_worker_map, worker->worker_pid);
            }
            worker->worker_pid = pid;
            swHashMap_add_int(serv->user_worker_map, pid, worker);
            return ZAN_OK;
        }
    }
    return ZAN_OK;
}

///TODO::: wait and respawn child process
int zan_master_process_loop(zanServer *serv)
{
    int status = 0;
    zan_pid_t pid = -1;

    if (serv->onStart)
    {
        //zanWarn("call server onStart");
        serv->onStart(serv);
    }


    while (ServerG.running > 0)
    {
        zanDebug("ServerG.running=%d, process_type=%d, master_pid=%d", ServerG.running, ServerG.process_type, ServerGS->master_pid);
        pid = zan_wait(&status);
        if (pid < 0)
        {
            zanWarn("wait error, pid=%d", pid);
            sleep(3);
            continue;
        }
        zanDebug("wait success, child pid=%d exit, status=%d", pid, status);
    }

    return ZAN_ERR;
}
