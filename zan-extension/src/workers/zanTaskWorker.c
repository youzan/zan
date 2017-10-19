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

#include "swBaseOperator.h"
#include "swSignal.h"
#include "swSendfile.h"

#include "zanGlobalDef.h"
#include "zanServer.h"
#include "zanWorkers.h"
#include "zanLog.h"

static swEventData *current_task;

int zan_spawn_task_process(zanProcessPool *pool);

int zanPool_taskworker_alloc(zanProcessPool *pool);
int zanPool_taskworker_init(zanProcessPool *pool);
void zanTaskWorker_signal_handler(int signo);
static void zanTaskWorker_signal_init(void);
static void zanPool_taskworker_free(zanProcessPool *pool);

static void zanTaskworker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zanTaskworker_onStop(zanProcessPool *pool, zanWorker *worker);
static int zanTaskworker_onTask(zanProcessPool *pool, swEventData *task);
static int zanTaskworker_loop(zanProcessPool *pool, zanWorker *worker);

int zanPool_taskworker_alloc(zanProcessPool *pool)
{
    int   index        = 0;
    int   create_pipe  = 1;
    key_t msgqueue_key = 0;
    zanServerSet *servSet = &ServerG.servSet;

    if (ZAN_IPC_MSGQUEUE == servSet->task_ipc_mode)
    {
        if (servSet->message_queue_key == 0)
        {
            char path_buf[128] = {0};
            char *path_ptr = getcwd(path_buf, 128);
            servSet->message_queue_key = ftok(path_ptr, 1);
        }

        msgqueue_key = servSet->message_queue_key;
        create_pipe = 0;
    }

    int worker_num = servSet->task_worker_num;
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
        zan_shm_free(pool->workers);
        return ZAN_ERR;
    }

    if (msgqueue_key > 0)
    {
        pool->queue = (zanMsgQueue *)sw_malloc(sizeof(zanMsgQueue));
        if (pool->queue == NULL)
        {
            swHashMap_free(pool->map);
            zan_shm_free(pool->workers);
            zanError("malloc[2] failed.");
            return ZAN_ERR;
        }
        else if (zanMsgQueue_create(pool->queue, 1, msgqueue_key, 1) < 0)
        {
            sw_free(pool->queue);
            swHashMap_free(pool->map);
            zan_shm_free(pool->workers);
            return ZAN_ERR;
        }
    }
    else
    {
        pool->pipes = sw_calloc(worker_num, sizeof(zanPipe));
        if (pool->pipes == NULL)
        {
            sw_free(pool->pipes);
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
                sw_free(pool->pipes);
                swHashMap_free(pool->map);
                zan_shm_free(pool->workers);
                return ZAN_ERR;
            }

            pool->workers[index].pipe_worker = pipe->getFd(pipe, ZAN_PIPE_WORKER);
            pool->workers[index].pipe_master = pipe->getFd(pipe, ZAN_PIPE_MASTER);
            pool->workers[index].pipe_object = pipe;
        }
    }

    //init every task_worker
    for (index = 0; index < worker_num; index++)
    {
        if (zanWorker_init((&pool->workers[index])) < 0)
        {
            zanError("create taskworker failed.");
            return ZAN_ERR;
        }
    }

    return ZAN_OK;
}

//TODO:::
static void zanPool_taskworker_free(zanProcessPool *pool)
{
    int index = 0;
    zanPipe *_pipe = NULL;

    if (ZAN_IPC_UNSOCK == ServerG.servSet.task_ipc_mode)
    {
        for (index = 0; index < ServerG.servSet.task_worker_num; index++)
        {
            _pipe = &pool->pipes[index];
            _pipe->close(_pipe);
        }
        sw_free(pool->pipes);
    }
    else
    {
        pool->queue->close(pool->queue);
        sw_free(pool->queue);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }

#if 0
    for (index = 0; index < ServerG.servSet.task_worker_num; ++index)
    {
        //zanWorker_free(&pool->workers[index]);
    }
#endif

    zan_shm_free(pool->workers);
}

void zan_processpool_shutdown(zanProcessPool *pool)
{
    int index  = 0;
    int status = 0;
    zanWorker *worker = NULL;
    ServerG.running = 0;

    for (index = 0; index < ServerG.servSet.task_worker_num; ++index)
    {
        worker = &pool->workers[index];
        if(worker->worker_pid == -1)
        {
            zanWarn("this worker is delete,worker_id=%d", worker->worker_id);
            continue;
        }

        if (swKill(worker->worker_pid, SIGTERM) < 0)
        {
            zanError("kill(%d) failed.", worker->worker_pid);
            continue;
        }
        if (swWaitpid(worker->worker_pid, &status, 0) < 0)
        {
            zanError("waitpid(%d) failed.", worker->worker_pid);
        }
    }
    zanPool_taskworker_free(pool);
}

//task_worker look
static int zanTaskworker_loop(zanProcessPool *pool, zanWorker *worker)
{
    ServerG.process_pid  = getpid();
    ServerG.process_type = ZAN_PROCESS_TASKWORKER;
    ServerWG.worker_id   = worker->worker_id;

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

    pool->onWorkerStart(pool, worker);
    zanDebug("task_worker loop in: worker_id=%d, process_type=%d, pipe_worker=%d, pipe_master=%d",
             worker->worker_id, ServerG.process_type, worker->pipe_worker, worker->pipe_master);

    //Use from_fd save the task_worker->id
    int n = 0;
    out.buf.info.from_fd = worker->worker_id;
    out.mtype = (ServerG.servSet.task_ipc_mode == ZAN_IPC_MSGQUEUE)? 0: worker->worker_id + 1;

    while (ServerG.running > 0 && task_n > 0)
    {
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

        zan_stats_set_worker_status(worker, ZAN_WORKER_BUSY);
        zan_stats_incr(&ServerStatsG->tasking_num);
        zan_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].request_count);
        zan_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].total_request_count);
        int ret = pool->onTask(pool, &out.buf);
        zan_stats_set_worker_status(worker, ZAN_WORKER_IDLE);

        if (ret >= 0 && !worker_task_always)
        {
            task_n--;
        }
    }

    pool->onWorkerStop(pool, worker);

    return ZAN_OK;
}

int zanPool_taskworker_init(zanProcessPool *pool)
{
    pool->onWorkerStart  = zanTaskworker_onStart;
    pool->onWorkerStop   = zanTaskworker_onStop;
    pool->onTask         = zanTaskworker_onTask;
    pool->main_loop      = zanTaskworker_loop;
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
    uint32_t index  = 0;
    for (index = 0; index < ServerG.servSet.task_worker_num; index++)
    {
        zanWorker *worker = &(pool->workers[index]);
        worker->pool         = pool;
        worker->worker_id    = pool->start_id + index;
        worker->process_type = ZAN_PROCESS_TASKWORKER;

        zan_pid_t pid = fork();
        if (0 == pid)
        {
            int ret_code = pool->main_loop(pool, worker);
            exit(ret_code);
        }
        else if (pid < 0)
        {
            zanError("fork failed.");
            return ZAN_ERR;
        }
        else
        {
            zanTrace("fork worker child process, pid=%d", pid);

            //remove old process
            if (worker->worker_pid)
            {
                swHashMap_del_int(pool->map, worker->worker_pid);
            }
            worker->deleted = 0;
            worker->worker_pid = pid;
            //insert new process
            swHashMap_add_int(pool->map, pid, worker);
        }
    }
    return ZAN_OK;
}

static void zanTaskWorker_signal_init(void)
{
    swSignal_set(SIGHUP, NULL, 1, 0);
    swSignal_set(SIGPIPE, NULL, 1, 0);
    swSignal_set(SIGUSR1, NULL, 1, 0);
    swSignal_set(SIGUSR2, NULL, 1, 0);
    swSignal_set(SIGTERM, zanTaskWorker_signal_handler, 1, 0);
    swSignal_set(SIGINT, zanTaskWorker_signal_handler, 1, 0);
    swSignal_set(SIGQUIT, zanTaskWorker_signal_handler, 1, 0);
    swSignal_set(SIGALRM, swSystemTimer_signal_handler, 1, 0);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, zanTaskWorker_signal_handler, 1, 0);
#endif
}

void zanTaskWorker_signal_handler(int signo)
{
    switch (signo)
    {
        case SIGTERM:
        case SIGINT:
        case SIGQUIT:
            //zanWarn("signal SIGTERM coming");
            if (ServerG.main_reactor)
            {
                ServerG.main_reactor->running = 0;
            }
            else
            {
                ServerG.running = 0;
            }
            break;
        case SIGALRM:
            zanWarn("signal SIGALRM coming");
            swSystemTimer_signal_handler(SIGALRM);
            break;
        /**
         * for test
    */
        case SIGVTALRM:
            zanWarn("signal SIGVTALRM coming");
            break;
        case SIGUSR1:
            zanWarn("signal SIGUSR1 coming");
            if (ServerG.main_reactor)
            {
                //获取当前进程运行进程的信息
                uint32_t worker_id = ServerWG.worker_id;
                zanWorker worker = ServerGS->task_workers.workers[worker_id];
                zanWarn("the worker %d get the signo", worker.worker_pid);
                ServerWG.reload = 1;
                ServerWG.reload_count = 0;

                //删掉read管道
                swConnection *socket = swReactor_get(ServerG.main_reactor, worker.pipe_worker);
                if (socket->events & SW_EVENT_WRITE)
                {
                    socket->events &= (~SW_EVENT_READ);
                    if (ServerG.main_reactor->set(ServerG.main_reactor, worker.pipe_worker, socket->fdtype | socket->events) < 0)
                    {
                        zanSysError("reactor->set(%d, SW_EVENT_READ) failed.", worker.pipe_worker);
                    }
                }
                else
                {
                    if (ServerG.main_reactor->del(ServerG.main_reactor, worker.pipe_worker) < 0)
                    {
                        zanSysError("reactor->del(%d) failed.", worker.pipe_worker);
                    }
                }
            }
            else
            {
                ServerG.running = 0;
            }
            break;
        case SIGUSR2:
            zanWarn("signal SIGUSR2 coming.");
            break;
        default:
#ifdef SIGRTMIN
            if (signo == SIGRTMIN)
            {
                swServer_reopen_log_file(ServerG.serv);
            }
            else
#endif
            {
                zanWarn("recv other signal: %d.", signo);
            }
            break;
    }
}

static void zanTaskworker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;
    ServerG.main_reactor = NULL;
    ServerG.use_timerfd = 0;
    ServerG.use_timer_pipe = 0;

    int worker_id = worker->worker_id;
    ServerStatsG->workers_state[worker_id].start_time = time(NULL);
    ServerStatsG->workers_state[worker_id].request_count = 0;
    zan_stats_incr(&ServerStatsG->workers_state[worker_id].start_count);
    zan_stats_set_worker_status(worker, ZAN_WORKER_IDLE);

    zanTaskWorker_signal_init();
    if (serv->onWorkerStart)
    {
        //zanDebug("taskworker: call worker onStart, worker_id=%d, process_type=%d", worker->worker_id, worker->process_type);
        serv->onWorkerStart(serv, worker_id);
    }
}

static void zanTaskworker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;
    if (serv->onWorkerStop)
    {
        zanDebug("taskworker: call taskworker onStop, worker_id=%d, process_type=%d", worker->worker_id, worker->process_type);
        serv->onWorkerStop(serv, worker->worker_id);
    }
    ///TODO
    zanWorker_free(worker);
}

int zanTaskworker_onTask(zanProcessPool *pool, swEventData *task)
{
    int ret = ZAN_OK;
    zanServer *serv = ServerG.serv;
    zanDebug("taskworker onTask in: type=%d, task_id=%d, src_worker_id=%d, dst_worker_id=%d, cur_worker_id=%d",
             task->info.type, task->info.fd, task->info.from_id, task->info.worker_id, ServerWG.worker_id);

    current_task = task;
    if (task->info.type == SW_EVENT_PIPE_MESSAGE)
    {
        serv->onPipeMessage(serv, task);
    }
    else
    {
        ret = serv->onTask(serv, task);
    }
    return ret;
}

//Send the task result to worker
int zanTaskworker_finish(char *data, int data_len, int flags)
{
    zanDebug("data=%s, flags=%d, worker_id=%d, type=%d", data, flags, ServerWG.worker_id, ServerG.process_type);

    zanServer *serv = ServerG.serv;
    if (ServerG.servSet.task_worker_num < 1)
    {
        zanWarn("cannot use task/finish, because no set task_worker_num.");
        return ZAN_ERR;
    }

    uint16_t source_worker_id = current_task->info.from_id;
    zanWorker *worker = zanServer_get_worker(serv, source_worker_id);

    int ret = 0;
    swEventData buf;
    //for swoole_server_task
    if (swTask_type(current_task) & ZAN_TASK_NONBLOCK)
    {
        buf.info.type = SW_EVENT_FINISH;
        buf.info.fd = current_task->info.fd;
        swTask_type(&buf) = flags;

        //write to file
        if (data_len >= SW_IPC_MAX_SIZE - sizeof(buf.info))
        {
            if (swTaskWorker_large_pack(&buf, data, data_len) < 0 )
            {
                zanWarn("large task pack failed()");
                return SW_ERR;
            }
        }
        else
        {
            memcpy(buf.data, data, data_len);
            buf.info.len = data_len;
        }

        ret = zanWorker_send2worker(worker, &buf, sizeof(buf.info) + buf.info.len, ZAN_PIPE_MASTER);
    }
    else
    {
        zanError("error task type=%d, flags=%d, cur_worker_id=%d", swTask_type(current_task), flags, ServerWG.worker_id);
    }

    if (ret < 0)
    {
        zanError("TaskWorker: send result to worker failed.");
    }
    return ret;
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
        target_worker_id = sw_atomic_fetch_add(&pool->round_id, 1) % run_worker_num;
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
int zanPool_dispatch_to_taskworker(zanProcessPool *pool, swEventData *data, int *dst_worker_id)
{
    zanWorker *worker = NULL;
    if (*dst_worker_id < 0)
    {
        *dst_worker_id = zan_pool_schedule_worker(pool);
    }

    *dst_worker_id += pool->start_id;
    worker = zan_pool_get_worker(pool, *dst_worker_id);
    data->info.worker_id = *dst_worker_id;
    int sendn = sizeof(data->info) + data->info.len;

    zanDebug("dst_worker_id=%d, src_worker_type=%d, src_worker_id=%d, sendn=%d", *dst_worker_id, worker->process_type, ServerWG.worker_id, sendn);
    int ret = zanWorker_send2worker(worker, data, sendn, ZAN_PIPE_MASTER | ZAN_PIPE_NONBLOCK);
    if (ret < 0)
    {
        zanWarn("worker send %d bytes to taskworker#%d failed.", sendn, *dst_worker_id);
    }

    return ret;
}

zan_pid_t zanTaskWorker_spawn(zanWorker *worker)
{
    pid_t pid = fork();
    zanProcessPool *pool = worker->pool;

    switch (pid)
    {
        //child
        case 0:
        {
            if(zanWorker_init(worker) < 0)
            {
                zanError("init worker failed");
                return ZAN_ERR;
            }

            int ret_code = pool->main_loop(pool, worker);
            exit(ret_code);
        }
            break;
        case -1:
            zanSysError("fork failed.");
            break;
        //parent
        default:
            //remove old process
            if (worker->worker_pid)
            {
                swHashMap_del_int(pool->map, worker->worker_pid);
            }
            worker->deleted = 0;
            worker->worker_pid = pid;
            //insert new process
            swHashMap_add_int(pool->map, pid, worker);
            break;
    }
    return pid;
}

int zanTaskWorker_largepack(swEventData *task, void *data, int data_len)
{
    swPackage_task pkg;
    bzero(&pkg, sizeof(pkg));

    memcpy(pkg.tmpfile, ServerG.servSet.task_tmpdir, ServerG.servSet.task_tmpdir_len);

    //create temp file
    int tmp_fd = swoole_tmpfile(pkg.tmpfile);
    if (tmp_fd < 0)
    {
        return ZAN_ERR;
    }

    //write to file
    if (swoole_sync_writefile(tmp_fd, data, data_len) <= 0)
    {
        zanWarn("write to tmpfile failed.");
        return ZAN_ERR;
    }

    task->info.len = sizeof(swPackage_task);
    //use tmp file
    swTask_type(task) |= ZAN_TASK_TMPFILE;

    pkg.length = data_len;
    memcpy(task->data, &pkg, sizeof(swPackage_task));
    close(tmp_fd);
    return ZAN_OK;
}
