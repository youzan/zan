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

#include "list.h"
#include "swSignal.h"
#include "swBaseOperator.h"

#include "zanServer.h"
#include "zanWorkers.h"
#include "zanLog.h"
#include "zanGlobalDef.h"

extern int zanPool_worker_alloc(zanProcessPool *pool);
extern int zanPool_taskworker_alloc(zanProcessPool *pool);
extern int zanPool_networker_alloc(zanProcessPool *pool);

extern int zanPool_worker_init(zanProcessPool *pool);
extern int zanPool_taskworker_init(zanProcessPool *pool);
extern int zanPool_networker_init(zanProcessPool *pool);

extern int zan_spawn_worker_process(zanProcessPool *);
extern int zan_spawn_task_process(zanProcessPool *);
extern int zan_spawn_net_process(zanProcessPool *);

static int zan_alloc_workers_rsc(void);
static int zan_spawn_child_process(void);
static int zan_spawn_user_process(void);
static int zan_alloc_userworker_process(void);

//new functions
static void zanMaster_signalhandle(int sig);
int zanworker_freeprocess(int *reloadworker_index, zanWorker *reload_workers, int reload_num);
int zanMaster_waituserworker(zanProcessPool *pool, zan_pid_t pid);
zan_pid_t zanMaster_spawnuserworker(zanServer *serv, zanWorker* worker);
static void zanMaster_checkexitstatus(zanServer *serv, int worker_id, zan_pid_t pid, int status);
zan_pid_t zanrelaod_worker(int *index, int status, int worker_type, zanServer *serv, int *pid, zanProcessPool *reload_worker);

typedef struct
{
    uint8_t reloading;
    uint8_t reload_event_worker;
    uint8_t reload_task_worker;

} zanMasterProcess;

//工作进程是否reload参数
static zanMasterProcess MasterProcess;

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

    //Alloc shared memory for worker stats  //+ servSet->net_worker_num
    ServerStatsG->workers_state = zan_shm_calloc(servSet->worker_num + servSet->task_worker_num, sizeof(zanWorkerStats));
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
        if (ZAN_OK != zanPool_worker_alloc(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zanPool_worker_init(pool))
        {
            zanError("init worker pool failed.");
            return ZAN_ERR;
        }
    }
    else if (ZAN_PROCESS_TASKWORKER == process_type)
    {
        if (ServerG.servSet.task_worker_num <= 0)
        {
            return ZAN_OK;
        }

        if (ZAN_OK != zanPool_taskworker_alloc(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zanPool_taskworker_init(pool))
        {
            zanError("init taskworker pool failed.");
            return ZAN_ERR;
        }
    }
    else if (ZAN_PROCESS_NETWORKER == process_type)
    {
        if (ZAN_OK != zanPool_networker_alloc(pool))
        {
            zanError("alloc taskworker resource failed.");
            return ZAN_ERR;
        }

        if (ZAN_OK != zanPool_networker_init(pool))
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
    serv->user_workers = (zanWorker **)sw_calloc(serv->user_worker_num, sizeof(zanWorker *));
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

        pid = fork();
        if (pid < 0)
        {
            zanError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)
        {
            ServerG.process_pid  = getpid();
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

zan_pid_t zanrelaod_worker(int *index, int status, int worker_type, zanServer *serv, int *pid, zanProcessPool *reload_worker)
{
    if(serv == NULL)
    {
        zanWarn("server is null, can not reload process");
        return ZAN_ERR;
    }

    int worker_sum = 0;
    zan_pid_t new_pid = -1;

    switch(worker_type)
    {
        //worker
        case ZAN_PROCESS_WORKER:
            worker_sum = ServerG.servSet.worker_num;
            break;
        //task_worker
        case ZAN_PROCESS_TASKWORKER:
            worker_sum = ServerG.servSet.worker_num + ServerG.servSet.task_worker_num;
            break;
        //net_worker
        case ZAN_PROCESS_NETWORKER:
            worker_sum = ServerG.servSet.worker_num + ServerG.servSet.task_worker_num + ServerG.servSet.net_worker_num;
            break;
        default:
            zanWarn("not the corrent type,can not reload");
            return ZAN_ERR;
    }

    int i = *index;
    if((*pid > 0) && (i < worker_sum))
    {

        for(; i < worker_sum; ++i)
        {
            if(*pid != reload_worker->workers[i-reload_worker->start_id].worker_pid)
            {
                continue;
            }
            else
            {
                zan_stats_incr(status == 0 ? &ServerStatsG->worker_normal_exit
                              : &ServerStatsG->worker_abnormal_exit);
                zanMaster_checkexitstatus(serv, i, *pid, status);
                *pid = -1;
                while (1)
                {

                    if((reload_worker->workers[i-reload_worker->start_id].deleted) == 1)
                    {
                        reload_worker->workers[i-reload_worker->start_id].deleted = 0;
                        reload_worker->workers[i-reload_worker->start_id].worker_pid = -1;

                        break;
                    }

                    if(worker_type == ZAN_PROCESS_WORKER)
                    {
                        new_pid = zanMaster_spawnworker(reload_worker, &(reload_worker->workers[i-reload_worker->start_id]));
                        zanDebug("new_worker_pid=%d", new_pid);
                    }
                    else if(worker_type == ZAN_PROCESS_TASKWORKER)
                    {
                        new_pid = zanTaskWorker_spawn(&(reload_worker->workers[i-reload_worker->start_id]));
                        zanDebug("new_task_worker_pid=%d", new_pid);
                    }
                    else
                    {
                        new_pid = zanNetWorker_spawn(&(reload_worker->workers[i-reload_worker->start_id]));
                        zanDebug("new_net_worker_pid=%d", new_pid);
                    }

                    if (new_pid < 0)
                    {
                        usleep(100000);
                        continue;
                    }
                    else
                    {
                        reload_worker->workers[i-reload_worker->start_id].worker_pid = new_pid;
                        break;
                    }
                }
            }
        }
        *index = i;
    }

    return new_pid;
}

///TODO::: wait and respawn child process
int zan_master_process_loop(zanServer *serv)
{
    int status = 0;
    zan_pid_t pid = -1;
    zan_pid_t new_pid = -1;
    int index = 0;

    int reloadworker_index = 0;
    int result = -1;

    ServerG.use_signalfd = 0;
    ServerG.use_timerfd = 0;

    memset(&MasterProcess, 0, sizeof(MasterProcess));

    if (serv->onStart)
    {
        //zanWarn("call server onStart");
        serv->onStart(serv);
    }

    //init reload worker
    unsigned int reloadworker_num = ServerG.servSet.worker_num + ServerG.servSet.task_worker_num + ServerG.servSet.net_worker_num;
    if(reloadworker_num == 0)
    {
        zanError("No worker running");
        return ZAN_ERR;
    }
    zanWorker *reload_workers = sw_calloc(reloadworker_num, sizeof(zanWorker));
    if(NULL == reload_workers)
    {
        zanError("malloc[reload_workers] failed");
        return ZAN_ERR;
    }

    //for reload
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, zanMaster_signalhandle);
    swSignal_add(SIGINT, zanMaster_signalhandle);
    swSignal_add(SIGQUIT, zanMaster_signalhandle);
    swSignal_add(SIGUSR1, zanMaster_signalhandle);
    swSignal_add(SIGUSR2, zanMaster_signalhandle);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, zanMaster_signalhandle);
#endif

    if(ServerG.main_reactor != NULL)
    {
        ServerG.main_reactor = NULL;
    }

    while (ServerG.running > 0)
    {
        pid = -1;
        status = 0;
        pid = wait(&status);
        zanDebug("ServerG.running=%d, process_type=%d, master_pid=%d,pid=%d", ServerG.running, ServerG.process_type, ServerGS->master_pid, pid);
        if (pid < 0)
        {
            zanDebug("wait error, pid=%d", pid);
            if (MasterProcess.reloading == 0)
            {
                zanTrace("wait() failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if(MasterProcess.reload_event_worker == 1)
            {
                zanDebug("Server is reloading event_worker now.");
                memset(reload_workers, 0, sizeof(zanWorker)*reloadworker_num);
                memcpy(reload_workers, ServerGS->event_workers.workers, sizeof(zanWorker) * ServerG.servSet.worker_num);
                reloadworker_num = ServerG.servSet.worker_num;
                if (ServerG.servSet.task_worker_num > 0)
                {
                    memcpy(reload_workers + ServerG.servSet.worker_num, ServerGS->task_workers.workers, sizeof(zanWorker) * ServerG.servSet.task_worker_num);
                    reloadworker_num += ServerG.servSet.task_worker_num;
                }
                reloadworker_index = 0;
            }
            else if(MasterProcess.reload_task_worker == 1)
            {
                zanDebug("Server is reloading task_worker now.");
                memset(reload_workers, 0, sizeof(zanWorker)*reloadworker_num);
                if (ServerG.servSet.task_worker_num == 0)
                {
                    zanWarn("cannot reload workers, because server no have task workers.");
                    continue;
                }

                memcpy(reload_workers, ServerGS->task_workers.workers, sizeof(zanWorker) * ServerG.servSet.task_worker_num);
                reloadworker_num = ServerG.servSet.task_worker_num;
                reloadworker_index = 0;
            }
            else
            {
                zanWarn("signal is not right");
                break;
            }
        }

        else if((pid > 0) && (ServerG.running == 1))
        {
            index = 0;
            new_pid = zanrelaod_worker(&index, status, ZAN_PROCESS_WORKER, serv, &pid, &(ServerGS->event_workers));
            //reload task_worker
            if(pid > 0)
            {
                new_pid = zanrelaod_worker(&index, status, ZAN_PROCESS_TASKWORKER, serv, &pid, &(ServerGS->task_workers));
            }
            //reload net_worker
            if(pid > 0)
            {
                new_pid = zanrelaod_worker(&index, status, ZAN_PROCESS_NETWORKER, serv, &pid, &(ServerGS->net_workers));
            }

            if(serv->user_worker_map != NULL)
            {
                zanMaster_waituserworker(&(ServerGS->event_workers), pid);
            }
        }
        else
        {
            zanWarn("server is not running");
            break;
        }
        //zanDebug("wait success, child pid=%d exit, status=%d", pid, status);
        if((MasterProcess.reload_event_worker == 1 )|| (MasterProcess.reload_task_worker == 1))
        {
            result = zanworker_freeprocess(&reloadworker_index, reload_workers, reloadworker_num);
            if(result < 0)
            {
                zanWarn("kill workers failed");
            }
        }
    }

    sw_free(reload_workers);

    //kill all child process
    if(ServerG.servSet.worker_num > 0)
    {
        zan_worker_shutdown(&ServerGS->event_workers);
    }

    //kill and wait task process
    if (ServerG.servSet.task_worker_num > 0)
    {
        zan_processpool_shutdown(&ServerGS->task_workers);
    }

    //kill and wait net process
    if(ServerG.servSet.net_worker_num > 0)
    {
        zan_networker_shutdown(&ServerGS->net_workers);
    }

    if (serv->user_worker_map)
    {
        zanWorker* user_worker = NULL;
        uint64_t key = 0;

        //kill user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //has hmap empty
            if (user_worker == NULL)
            {
                break;
            }
            swKill(user_worker->worker_pid, SIGTERM);
        }
        //wait user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //hashmap empty
            if (user_worker == NULL)
            {
                break;
            }
            if (swWaitpid(user_worker->worker_pid, &status, 0) < 0)
            {
                zanSysError("waitpid(%d) failed.", user_worker->worker_pid);
            }
        }
    }

    return ZAN_ERR;
}

int zanworker_freeprocess(int *reloadworker_index, zanWorker *reload_workers, int reload_num)
{
    if(reload_workers == NULL)
    {
        zanWarn("reload workers is null");
        return ZAN_ERR;
    }

    int index = *reloadworker_index;

    if(MasterProcess.reloading == 1)
    {
        if(index >= reload_num)
        {
            MasterProcess.reloading = 0;
            index = 0;
            *reloadworker_index = index;
            MasterProcess.reload_event_worker = 0;
            MasterProcess.reload_task_worker = 0;
            return ZAN_OK;
        }

        zanDebug("start kill workers, id: %d, pid: %d.", index, reload_workers[index].worker_pid);
        int result = swKill(reload_workers[index].worker_pid, SIGTERM);
        if (result < 0)
        {
            zanSysError("kill(%d, SIGTERM) failed.", reload_workers[index].worker_pid);
            return ZAN_ERR;
        }
        ++index;
        *reloadworker_index = index;
        ServerStatsG->last_reload = time(NULL);
    }
    else
    {
        zanWarn("do not reload worker");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static void zanMaster_signalhandle(int sig)
{
    switch (sig)
    {
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
            ServerG.running = 0;
            break;
        case SIGUSR1:
            if (MasterProcess.reloading == 0)
            {
                MasterProcess.reloading = 1;
                MasterProcess.reload_event_worker = 1;
            }
            break;
        case SIGUSR2:
            if (MasterProcess.reloading == 0)
            {
                MasterProcess.reloading = 1;
                MasterProcess.reload_task_worker = 1;
            }
            break;
        default:
#ifdef SIGRTMIN
            if (sig == SIGRTMIN)
            {
                zanServer_reopen_log_file(ServerG.serv);
            }
#endif
            break;
    }
    return;
}

static void zanMaster_checkexitstatus(zanServer *serv, int worker_id, zan_pid_t pid, int status)
{
    if (status != 0)
    {
        zanWarn("worker#%d[pid#%ld] abnormal exit, exited=%d, status=%d, wifsignaled=%d, signal=%d", worker_id, (long)pid,WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
        if (serv->onWorkerError != NULL)
        {
            serv->onWorkerError(serv, worker_id, pid, WEXITSTATUS(status), WTERMSIG(status));
        }
    }

    return;
}

int zanMaster_waituserworker(zanProcessPool *pool, zan_pid_t pid)
{
    zanServer *serv = ServerG.serv;
    zanWorker *exit_worker = swHashMap_find_int(serv->user_worker_map, pid);
    if (exit_worker != NULL)
    {
        return zanMaster_spawnuserworker(serv, exit_worker);
    }
    else
    {
        return ZAN_ERR;
    }
}

zan_pid_t zanMaster_spawnuserworker(zanServer *serv, zanWorker* worker)
{
    zan_pid_t pid = fork();
    if (pid < 0)
    {
        zanError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return ZAN_ERR;
    }
    //child
    else if (pid == 0)
    {
        serv->onUserWorkerStart(serv, worker);
        exit(0);
    }
    //parent
    else
    {
        if (worker->worker_pid)
        {
            swHashMap_del_int(serv->user_worker_map, worker->worker_pid);
        }
        worker->worker_pid = pid;
        swHashMap_add_int(serv->user_worker_map, pid, worker);
        return pid;
    }
}
