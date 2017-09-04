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
#include "swExecutor.h"

#include "zanGlobalDef.h"
#include "zanWorkers.h"
#include "zanLog.h"
#include "zanProcess.h"
#include "zanConnection.h"

int zan_pool_alloc_networker(zanProcessPool *pool);
int zan_pool_networker_init(zanProcessPool *pool);
int zan_spawn_net_process(zanProcessPool *pool);

static int zan_networker_process_loop(zanWorker *worker);
static void zan_networker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zan_networker_onStop(zanProcessPool *pool, zanWorker *worker);

int zan_pool_alloc_networker(zanProcessPool *pool)
{
    int index = 0;
    zanServerSet *servSet = &(ServerG.servSet);

    //alloc networkers
    pool->workers = (zanWorker *)zan_shm_calloc(servSet->net_worker_num, sizeof(zanWorker));
    if (!pool->workers)
    {
        zanError("alloc net_workers failed");
        return ZAN_ERR;
    }

    pool->pipes = (zanPipe *)zan_calloc(servSet->net_worker_num, sizeof(zanPipe));
    if (pool->pipes == NULL)
    {
        zan_shm_free(pool->workers);
        zanError("calloc pool->pipe for worker failed.");
        return ZAN_ERR;
    }

    zanPipe *pipe = NULL;
    for (index = 0; index < servSet->net_worker_num; index++)
    {
        zanWorker *worker = &(pool->workers[index]);
        if (zan_worker_init(worker) < 0)
        {
            zan_shm_free(pool->workers);
            zan_free(pool->pipes);
            zanWarn("zan_worker_init failed.");
            return ZAN_ERR;
        }

        pipe = &pool->pipes[index];
        if (zanPipe_create(pipe, ZAN_UNSOCK, 1, SOCK_DGRAM) < 0)
        {
            zan_shm_free(pool->workers);
            zan_free(pool->pipes);
            zanWarn("create pipe for worker failed.");
            return ZAN_ERR;
        }
        worker->pipe_master = pipe->getFd(pipe, ZAN_PIPE_MASTER);
        worker->pipe_worker = pipe->getFd(pipe, ZAN_PIPE_WORKER);
        worker->pipe_object = pipe;
        //swServer_store_pipe_fd(serv, worker->pipe_object);
    }

    return ZAN_OK;
}

int zan_spawn_net_process(zanProcessPool *pool)
{
    int        index = 0;
    zan_pid_t  pid   = 0;

    for (index = 0; index < ServerG.servSet.net_worker_num; index++)
    {
        zanWorker *worker    = &(pool->workers[index]);
        worker->pool         = pool;
        worker->worker_id    = pool->start_id + index;
        worker->process_type = ZAN_PROCESS_NETWORKER;
        //zanWarn("fork networker process, index=%d, worker_id=%d", index, worker->worker_id);

        pid = zan_fork();
        if (pid < 0)
        {
            zanError("zan_fork failed, pid=%d, Error:%s:%d", pid, strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)  //worker child processor
        {
            pool->onWorkerStart(pool, worker);
            int ret = zan_networker_process_loop(worker);
            pool->onWorkerStop(pool, worker);
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

int zan_pool_networker_init(zanProcessPool *pool)
{
    ////TODO:::
    pool->onWorkerStart  = zan_networker_onStart;
    pool->onWorkerStop   = zan_networker_onStop;
    pool->start_id       = ServerG.servSet.worker_num + ServerG.servSet.task_worker_num;

    return ZAN_OK;
}

static void zan_networker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_NETWORKER;


    ///TODO:::
    //zanWarn("networker onStart....");
}

static void zan_networker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    ///TODO:::
    zanWarn("networker onStop....");
}


int zan_networker_process_loop(zanWorker *worker)
{
    zanServer *serv = ServerG.serv;

    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_NETWORKER;

    //worker_id
    ServerWG.worker_id     = worker->worker_id;
    ServerWG.request_count = 0;

    swReactor *main_reactor = (swReactor *)zan_malloc(sizeof(swReactor));
    if (swReactor_init(main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        zanError("networker, main_reactor create error");
        return ZAN_ERR;
    }
    ServerG.main_reactor = main_reactor;

    ///TODO:::
    //swServer_store_listen_socket(serv);

    //main_reactor accept/recv/send....
    main_reactor->thread = 1;
    main_reactor->socket_list = serv->connection_list;
    main_reactor->disable_accept = 0;
    main_reactor->enable_accept = zan_net_enableAccept;

    main_reactor->id  = worker->worker_id;
    main_reactor->ptr = serv;
    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, zan_net_onAccept);

    if (serv->onStart)
    {
        zanWarn("call server onStart");
        serv->onStart(serv);
    }

    zanWarn("networker loop in: worker_id=%d, process_type=%d, pid=%d", worker->worker_id, ServerG.process_type, ServerG.process_pid);

    struct timeval tmo;
    tmo.tv_sec  = 1;
    tmo.tv_usec = 0;
    return main_reactor->wait(main_reactor, &tmo);

#if 0
    ///Test:::
    while (1)
    {
        zanWarn("loop test, process_type=%d,process_pid=%d, worker_id=%d", ServerG.process_type, ServerG.process_pid, worker->worker_id);
        sleep(3);
    }

    return ZAN_ERR;
#endif
}
