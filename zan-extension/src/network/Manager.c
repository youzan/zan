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



#include "list.h"
#include "swLog.h"
#include "swWork.h"
#include "swSignal.h"
#include "swExecutor.h"
#include "swBaseOperator.h"

#include <sys/wait.h>

typedef struct
{
    uint8_t reloading;
    uint8_t reload_event_worker;
    uint8_t reload_task_worker;

} swManagerProcess;

static int swManager_loop_async(swFactory *factory);
static int swManager_loop_sync(swFactory *factory);
static void swManager_signal_handle(int sig);
static pid_t swManager_spawn_worker(swFactory *factory, int worker_id);
static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status);

static swManagerProcess ManagerProcess;

//create worker child proccess
int swManager_start(swFactory *factory)
{
    swFactoryProcess *object = factory->object;
    swServer *serv = factory->ptr;

    object->pipes = sw_calloc(serv->worker_num, sizeof(swPipe));
    if (object->pipes == NULL)
    {
        swError("malloc[worker_pipes] failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }

    //worker进程的pipes
    int index = 0;
    for (index = 0; index < serv->worker_num; index++)
    {
        if (swPipeUnsock_create(&object->pipes[index], 1, SOCK_DGRAM) < 0)
        {
            return SW_ERR;
        }
        serv->workers[index].pipe_master = object->pipes[index].getFd(&object->pipes[index], SW_PIPE_MASTER);
        serv->workers[index].pipe_worker = object->pipes[index].getFd(&object->pipes[index], SW_PIPE_WORKER);
        serv->workers[index].pipe_object = &object->pipes[index];
        swServer_store_pipe_fd(serv, serv->workers[index].pipe_object);
    }

    if (SwooleG.task_worker_num > 0)
    {
        key_t key = 0;
        int create_pipe = 1;

        if (SwooleG.task_ipc_mode > SW_TASK_IPC_UNIXSOCK)
        {
            key = serv->message_queue_key;
            create_pipe = 0;
        }

        if (swProcessPool_create(&SwooleGS->task_workers, SwooleG.task_worker_num, SwooleG.task_max_request, key, create_pipe) < 0)
        {
            swError("[Master] create task_workers failed.");
            return SW_ERR;
        }

        swProcessPool *pool = &SwooleGS->task_workers;
        swTaskWorker_init(pool);

        swWorker *worker = NULL;
        for (index = 0; index < SwooleG.task_worker_num; index++)
        {
            worker = &pool->workers[index];
            if (swWorker_create(worker) < 0)
            {
                return SW_ERR;
            }
            if (SwooleG.task_ipc_mode == SW_IPC_UNSOCK)
            {
                swServer_store_pipe_fd(SwooleG.serv, worker->pipe_object);
            }
        }
    }

    //User Worker Process
    if (serv->user_worker_num > 0)
    {
        serv->user_workers = sw_calloc(serv->user_worker_num, sizeof(swWorker *));
        swUserWorker_node *user_worker;
        index = 0;
        LL_FOREACH(serv->user_worker_list, user_worker)
        {
            if (swWorker_create(user_worker->worker) < 0)
            {
                return SW_ERR;
            }
            serv->user_workers[index++] = user_worker->worker;
        }
    }

    pid_t pid = fork();
    switch (pid)
    {
    //创建manager进程
    case 0:
        //wait master process
        SW_START_SLEEP;
        if (SwooleGS->start == 0)
        {
            return SW_OK;
        }
        swServer_close_listen_port(serv);
        /**
         * create worker process
         */
        for (index = 0; index < serv->worker_num; index++)
        {
            //close(worker_pipes[i].pipes[0]);
            pid = swManager_spawn_worker(factory, index);
            if (pid < 0)
            {
                swError("fork() failed.");
                return SW_ERR;
            }
            else
            {
                serv->workers[index].pid = pid;
            }
        }

        /**
         * create task worker process
         */
        if (SwooleG.task_worker_num > 0)
        {
            swProcessPool_start(&SwooleGS->task_workers);
        }

        /**
         * create user worker process
         */
        if (serv->user_worker_list)
        {
            swUserWorker_node *user_worker;
            LL_FOREACH(serv->user_worker_list, user_worker)
            {
                /**
                 * store the pipe object
                 */
                if (user_worker->worker->pipe_object)
                {
                    swServer_store_pipe_fd(serv, user_worker->worker->pipe_object);
                }
                swManager_spawn_user_worker(serv, user_worker->worker);
            }
        }

        //标识为管理进程
        SwooleG.process_type = SW_PROCESS_MANAGER;
        SwooleG.pid = getpid();

        int ret = (serv->reload_async)? swManager_loop_async(factory):swManager_loop_sync(factory);
        exit(ret);
        break;

        //master process
    case -1:
		swError("fork() failed.");
		return SW_ERR;
    default:
        SwooleGS->manager_pid = pid;
        break;
    }

    return SW_OK;
}

static void swManager_check_exit_status(swServer *serv, int worker_id, pid_t pid, int status)
{
    if (status != 0)
    {
        swWarn("worker#%d[pid#%ld] abnormal exit, exited=%d, status=%d, wifsignaled=%d, signal=%d", worker_id, (long)pid,WIFEXITED(status), WEXITSTATUS(status), WIFSIGNALED(status), WTERMSIG(status));
        if (serv->onWorkerError != NULL)
        {
            serv->onWorkerError(serv, worker_id, pid, WEXITSTATUS(status), WTERMSIG(status));
        }
    }
}

static int swManager_loop_async(swFactory *factory)
{
    //hashMap 存储oid_pid ->new_pid的映射
    swHashMap *pidMap = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (pidMap == NULL)
    {
        swError("swHashMap_create failed");
        return SW_ERR;
    }

    SwooleG.use_signalfd = 0;
    SwooleG.use_timerfd = 0;

    memset(&ManagerProcess, 0, sizeof(ManagerProcess));

    swServer *serv = factory->ptr;
    if (serv->onManagerStart)
    {
        serv->onManagerStart(serv);
    }

    int reload_worker_num = serv->worker_num + SwooleG.task_worker_num;
    swWorker *reload_workers = sw_calloc(reload_worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    //for reload
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, swManager_signal_handle);
    swSignal_add(SIGUSR1, swManager_signal_handle);
    swSignal_add(SIGUSR2, swManager_signal_handle);
    //swSignal_add(SIGINT, swManager_signal_handle);

    SwooleG.main_reactor = NULL;
    pid_t pid = -1;
    pid_t new_pid = -1;
    int status = -1;
    int index = 0;
    while (SwooleG.running > 0)
    {
        pid = wait(&status);
        if (pid < 0)
        {
            //pid < 0 代表manager进程收到reload信号量，将进程组复制到reload进程组，fork新的进程组
            if (ManagerProcess.reloading == 0)
            {
                swTrace("wait() failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if (ManagerProcess.reload_event_worker == 1)
            {
                swWarn("worker is reloading now.");
                memcpy(reload_workers, serv->workers, sizeof(swWorker) * serv->worker_num);
                reload_worker_num = serv->worker_num;

                if (SwooleG.task_worker_num > 0)
                {
                    memcpy(reload_workers + serv->worker_num, SwooleGS->task_workers.workers,
                            sizeof(swWorker) * SwooleG.task_worker_num);
                    reload_worker_num += SwooleG.task_worker_num;
                }

                ManagerProcess.reload_event_worker = 0;
                goto kill_workers;
            }
            else if (ManagerProcess.reload_task_worker == 1)
            {
                swWarn("task is reloading now.");
                if (SwooleG.task_worker_num == 0)
                {
                    swWarn("cannot reload workers, because server no have task workers.");
                    continue;
                }
                memcpy(reload_workers, SwooleGS->task_workers.workers, sizeof(swWorker) * SwooleG.task_worker_num);
                reload_worker_num = SwooleG.task_worker_num;

                ManagerProcess.reload_task_worker = 0;
                goto kill_workers;
            }            
        }

        if (SwooleG.running == 1)
        {
            /* 回收worker */
            for (index = 0; index < serv->worker_num; index++)
            {
                //compare PID
                if (pid != serv->workers[index].pid)
                {
                    continue;
                }
                else
                {
                    swManager_check_exit_status(serv, index, pid, status);

                    //pid ->new pid
                    new_pid = (pid_t)(long) swHashMap_find_int(pidMap, pid);
                    swWarn(" now the worker pid is %d", new_pid);
                    serv->workers[index].pid = new_pid;
                }
            }

            if (pid > 0)
            {
                swWarn(" pid %d is not in the workers need to exit", pid);
                swWorker *exit_worker = NULL;
                //task worker
                if (SwooleGS->task_workers.map)
                {
                    exit_worker = swHashMap_find_int(SwooleGS->task_workers.map, pid);
                    if (exit_worker != NULL)
                    {
                        swManager_check_exit_status(serv, exit_worker->id, pid, status);
                        if (exit_worker->deleted == 1)  //主动回收不重启
                        {
                            exit_worker->deleted = 0;
                        }
                        else
                        {
                            swProcessPool_spawn(exit_worker);
                        }
                    }
                }
                //user process
                if (serv->user_worker_map != NULL)
                {
                    swManager_wait_user_worker(&SwooleGS->event_workers, pid);
                }
            }
        }

kill_workers:
        if (ManagerProcess.reloading == 1)
        {
            for (index = 0; index < serv->worker_num; index++)
            {
                /* 先fork新的 再kill老的*/
                while (1)
                {
                    new_pid = swManager_spawn_worker(factory, index);
                    if (new_pid < 0)
                    {
                        usleep(100000);
                        continue;
                    }
                    else
                    {
                        swHashMap_add_int(pidMap, reload_workers[index].pid, (void*) &new_pid);
                        swWarn(" add pidMap new_pid is %d old pid is %d", new_pid, reload_workers[index].pid);
                        break;
                    }
                }
                
                swWarn("start kill workers, id: %d, pid: %d.", index, reload_workers[index].pid);
                if (swKill(reload_workers[index].pid, SIGUSR1) < 0)
                {
                    swSysError("kill(%d, SIGTERM) failed.", reload_workers[index].pid);
                }  
            }

            ManagerProcess.reloading = 0;
        }
    } 

    sw_free(reload_workers);

    //kill all child process
    for (index = 0; index < serv->worker_num; index++)
    {
        swTrace("[Manager]kill worker processor");
        swKill(serv->workers[index].pid, SIGTERM);
    }

    //wait child process
    for (index = 0; index < serv->worker_num; index++)
    {
        if (swWaitpid(serv->workers[index].pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", serv->workers[index].pid);
        }
    }

    //kill and wait task process
    if (SwooleG.task_worker_num > 0)
    {
        swProcessPool_shutdown(&SwooleGS->task_workers);
    }

    if (serv->user_worker_map)
    {
        swWorker* user_worker = NULL;
        uint64_t key = 0;

        //kill user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //hashmap empty
            if (user_worker == NULL)
            {
                break;
            }
            swKill(user_worker->pid, SIGTERM);
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
            if (swWaitpid(user_worker->pid, &status, 0) < 0)
            {
                swSysError("waitpid(%d) failed.", serv->workers[index].pid);
            }
        }
    }

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }

    return SW_OK;   
}

static int swManager_loop_sync(swFactory *factory)
{
    SwooleG.use_signalfd = 0;
    SwooleG.use_timerfd = 0;

    memset(&ManagerProcess, 0, sizeof(ManagerProcess));
    swServer *serv = factory->ptr;
    if (serv->onManagerStart)
    {
        serv->onManagerStart(serv);
    }

    int reload_worker_num = serv->worker_num + SwooleG.task_worker_num;
    swWorker *reload_workers = sw_calloc(reload_worker_num, sizeof(swWorker));
    if (reload_workers == NULL)
    {
        swError("malloc[reload_workers] failed");
        return SW_ERR;
    }

    //for reload
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGTERM, swManager_signal_handle);
    swSignal_add(SIGUSR1, swManager_signal_handle);
    swSignal_add(SIGUSR2, swManager_signal_handle);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swManager_signal_handle);
#endif
    //swSignal_add(SIGINT, swManager_signal_handle);

    SwooleG.main_reactor = NULL;
    int pid = -1;
    int new_pid = -1;
    int index = 0;
    int ret = -1;
    int status = -1,reload_worker_i = 0;
    while (SwooleG.running > 0)
    {
        pid = wait(&status);
        if (pid < 0)
        {
            if (ManagerProcess.reloading == 0)
            {
                swTrace("wait() failed. Error: %s [%d]", strerror(errno), errno);
            }
            else if (ManagerProcess.reload_event_worker == 1)
            {
                swWarn("Server is reloading event_worker now.");
                memcpy(reload_workers, serv->workers, sizeof(swWorker) * serv->worker_num);
                reload_worker_num = serv->worker_num;
                if (SwooleG.task_worker_num > 0)
                {
                    memcpy(reload_workers + serv->worker_num, SwooleGS->task_workers.workers,
                            sizeof(swWorker) * SwooleG.task_worker_num);
                    reload_worker_num += SwooleG.task_worker_num;
                }

                reload_worker_i = 0;
                ManagerProcess.reload_event_worker = 0;
                goto kill_worker;
            }
            else if (ManagerProcess.reload_task_worker == 1)
            {
                swWarn("Server is reloading task_worker now.");
                if (SwooleG.task_worker_num == 0)
                {
                    swWarn("cannot reload workers, because server no have task workers.");
                    continue;
                }

                memcpy(reload_workers, SwooleGS->task_workers.workers, sizeof(swWorker) * SwooleG.task_worker_num);
                reload_worker_num = SwooleG.task_worker_num;
                reload_worker_i = 0;
                ManagerProcess.reload_task_worker = 0;
                goto kill_worker;
            }
        }
        if (SwooleG.running == 1)
        {
            for (index = 0; index < serv->worker_num; index++)
            {
                //compare PID
                if (pid != serv->workers[index].pid)
                {
                    continue;
                }
                else
                {
                    swManager_check_exit_status(serv, index, pid, status);
                    pid = 0;
                    while (1)
                    {
                        new_pid = swManager_spawn_worker(factory, index);
                        if (new_pid < 0)
                        {
                            usleep(100000);
                            continue;
                        }
                        else
                        {
                            serv->workers[index].pid = new_pid;
                            break;
                        }
                    }
                }
            }

            if (pid > 0)
            {
                swWorker *exit_worker = NULL;
                //task worker
                if (SwooleGS->task_workers.map)
                {
                    exit_worker = swHashMap_find_int(SwooleGS->task_workers.map, pid);
                    if (exit_worker != NULL)
                    {
                        swManager_check_exit_status(serv, exit_worker->id, pid, status);
                        if (exit_worker->deleted == 1)  //主动回收不重启
                        {
                            exit_worker->deleted = 0;
                        }
                        else
                        {
                            swProcessPool_spawn(exit_worker);
                        }
                    }
                }
                //user process
                if (serv->user_worker_map != NULL)
                {
                    swManager_wait_user_worker(&SwooleGS->event_workers, pid);
                }
            }
        }
        //reload worker
kill_worker:
        if (ManagerProcess.reloading == 1)
        {
            //reload finish
            if (reload_worker_i >= reload_worker_num)
            {
                ManagerProcess.reloading = 0;
                reload_worker_i = 0;
                continue;
            }
            swWarn("start kill workers, id: %d, pid: %d.", reload_worker_i, reload_workers[reload_worker_i].pid);
            ret = swKill(reload_workers[reload_worker_i].pid, SIGTERM);
            if (ret < 0)
            {
                swSysError("kill(%d, SIGTERM) failed.", reload_workers[reload_worker_i].pid);
            }
            reload_worker_i++;
        }
    }

    sw_free(reload_workers);

    //kill all child process
    for (index = 0; index < serv->worker_num; index++)
    {
        swTrace("[Manager]kill worker processor");
        kill(serv->workers[index].pid, SIGTERM);
    }

    //wait child process
    for (index = 0; index < serv->worker_num; index++)
    {
        if (swWaitpid(serv->workers[index].pid, &status, 0) < 0)
        {
            swSysError("waitpid(%d) failed.", serv->workers[index].pid);
        }
    }

    //kill and wait task process
    if (SwooleG.task_worker_num > 0)
    {
        swProcessPool_shutdown(&SwooleGS->task_workers);
    }

    if (serv->user_worker_map)
    {
        swWorker* user_worker = NULL;
        uint64_t key = 0;

        //kill user process
        while (1)
        {
            user_worker = swHashMap_each_int(serv->user_worker_map, &key);
            //hashmap empty
            if (user_worker == NULL)
            {
                break;
            }
            swKill(user_worker->pid, SIGTERM);
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
            if (swWaitpid(user_worker->pid, &status, 0) < 0)
            {
                swSysError("waitpid(%d) failed.", serv->workers[index].pid);
            }
        }
    }

    if (serv->onManagerStop)
    {
        serv->onManagerStop(serv);
    }

    return SW_OK;
}

static pid_t swManager_spawn_worker(swFactory *factory, int worker_id)
{
    pid_t pid = fork();
    //fork() failed
    if (pid < 0)
    {
        swError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
    	int ret = swWorker_loop(factory, worker_id);
        exit(ret);
    }
    //parent,add to writer
    else
    {
        return pid;
    }
}

static void swManager_signal_handle(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        SwooleG.running = 0;
        break;
        /**
         * reload all workers
         */
    case SIGUSR1:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_event_worker = 1;
        }
        break;
        /**
         * only reload task workers
         */
    case SIGUSR2:
        if (ManagerProcess.reloading == 0)
        {
            ManagerProcess.reloading = 1;
            ManagerProcess.reload_task_worker = 1;
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

int swManager_wait_user_worker(swProcessPool *pool, pid_t pid)
{
    swServer *serv = SwooleG.serv;
    swWorker *exit_worker = swHashMap_find_int(serv->user_worker_map, pid);
    if (exit_worker != NULL)
    {
        return swManager_spawn_user_worker(serv, exit_worker);
    }
    else
    {
        return SW_ERR;
    }
}

pid_t swManager_spawn_user_worker(swServer *serv, swWorker* worker)
{
    pid_t pid = fork();
    if (pid < 0)
    {
    	swError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return SW_ERR;
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
        if (worker->pid)
        {
            swHashMap_del_int(serv->user_worker_map, worker->pid);
        }
        worker->pid = pid;
        swHashMap_add_int(serv->user_worker_map, pid, worker);
        return pid;
    }
}
