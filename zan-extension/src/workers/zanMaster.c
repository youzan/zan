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

#include "zanWorkers.h"
#include "zanLog.h"
#include "zanProcess.h"

static int zan_alloc_worker_rsc(zanFactory *);
static int zan_spawn_worker_process(zanFactory *);
int zan_spawn_task_process(zanFactory *factory);
int zan_spawn_net_process(zanFactory *factory);

int zanWorkers_start(zanFactory *factory)
{
    //Alloc shared memory for worker stats
    ServerStatsG->workers = ServerG.g_shm_pool->alloc(ServerG.g_shm_pool,
                            (ServerG.serverSet.worker_num + ServerG.serverSet.task_worker_num) * sizeof(zanWorkerStats));
    if (!ServerStatsG->workers)
    {
        zanError("gmalloc[SwooleStats->workers] failed");
        return ZAN_ERR;
    }

    //alloc resource for all workes
    if (ZAN_OK != zan_alloc_worker_rsc(factory))
    {
        zanError("zan_alloc_worker_rsc failed");
        return ZAN_ERR;
    }

    //fork workes
    if (ZAN_OK != zan_spawn_worker_process(factory))
    {
        zanError("zan_spawn_worker_process failed");
        return ZAN_ERR;
    }

    //fork task_workes
    if (ZAN_OK != zan_spawn_task_process(factory))
    {
        zanError("zan_spawn_task_process failed");
        return ZAN_ERR;
    }

#if 0
    //fork user workes
    if (ZAN_OK != zan_spawn_user_process(factory))
    {
        zanError("zan_spawn_user_process failed");
        return ZAN_ERR;
    }
#endif

    //fork net_workes
    if (ZAN_OK != zan_spawn_net_process(factory))
    {
        zanError("zan_spawn_net_process failed");
        return ZAN_ERR;
    }


    return SW_OK;
}

static int zan_alloc_worker_rsc(zanFactory *factory)
{
    return ZAN_OK;
}

static int zan_spawn_worker_process(zanFactory *factory)
{
    int index = 0;
    zan_pid_t pid = 0;
    //zanServer *serv = factory->ptr;

    for (index = 0; index < ServerG.serverSet.worker_num; index++)
    {
        pid = zan_fork();
        if (pid < 0)
        {
            zanError("zan_fork failed, pid=%d, Error:%s:%d", pid, strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)  //worker child processor
        {
            int ret = zanWorker_loop(factory, index);
            exit(ret);
        }
        else
        {
            zanTrace("zan_fork child process, pid=%d", pid);
            //serv->workers[index].pid = pid;
        }
    }
    return ZAN_OK;
}

int zan_spawn_task_process(zanFactory *factory)
{
    int index = 0;
    zan_pid_t pid = 0;
    //zanServer *serv = factory->ptr;

    for (index = 0; index < ServerG.serverSet.task_worker_num; index++)
    {
        pid = zan_fork();
        if (pid < 0)
        {
            zanError("zan_fork failed, pid=%d, Error:%s:%d", pid, strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)  //worker child processor
        {
            int ret = zanTaskWorker_loop(factory, index + ServerG.serverSet.worker_num);
            exit(ret);
        }
        else
        {
            zanTrace("zan_fork child process, pid=%d", pid);
            //serv->workers[index].pid = pid;
        }
    }
    return ZAN_OK;
}

//fork user workes
int zan_spawn_net_process(zanFactory *factory)
{
    zan_pid_t pid = zan_fork();
    if (pid < 0)
    {
        zanError("zan_fork failed, pid=%d, Error:%s:%d", pid, strerror(errno), errno);
        return ZAN_ERR;
    }
    else if (pid == 0)  //worker child processor
    {
        //TODO:::worker_id...
        int ret = zanNetWorker_start(factory, ServerG.serverSet.worker_num + ServerG.serverSet.task_worker_num);
        exit(ret);
    }
    else
    {
        zanTrace("zan_fork child process, pid=%d", pid);
        //serv->workers[index].pid = pid;
    }
    return ZAN_OK;
}

///TODO:::
//wait child process
int zanMaster_loop(zanServer *serv)
{
    int status = 0;
    zan_pid_t pid = -1;
    while (ServerG.running > 0)
    {
        zanWarn("ServerG.running = %d", ServerG.running);
        pid = zan_wait(&status);
        if (pid < 0)
        {
            zanWarn("wait error, pid=%d", pid);
            continue;
        }
        zanWarn("wait success, child pid=%d exit.", pid);
    }

    return ZAN_ERR;
}
