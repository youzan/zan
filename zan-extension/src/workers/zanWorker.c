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


#include "zanGlobalDef.h"
#include "zanSystem.h"
#include "zanWorkers.h"
#include "zanServer.h"
#include "zanLog.h"

int zan_pool_alloc_worker(zanProcessPool *pool);
int zan_pool_worker_init(zanProcessPool *pool);
int zan_spawn_net_process(zanProcessPool *pool);

static int zan_worker_onPipeReceive(swReactor *reactor, swEvent *event);
static void zan_worker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zan_worker_onStop(zanProcessPool *pool, zanWorker *worker);
static int zan_worker_onTask(zanFactory *factory, swEventData *task);
static int zan_worker_process_loop(zanWorker *worker);

int zan_worker_init(zanWorker *worker)
{
    if (!worker)
    {
        zanError("worker is null.");
        return ZAN_ERR;
    }

    worker->send_shm = sw_shm_malloc(ServerG.servSet.buffer_output_size);
    if (worker->send_shm == NULL)
    {
        zanError("malloc for worker->send_shm failed.");
        return ZAN_ERR;
    }
    zanLock_create(&worker->lock, ZAN_MUTEX, 1);
    return ZAN_OK;
}

void zan_worker_free(zanWorker *worker)
{
    if (worker->send_shm)
    {
        zan_shm_free(worker->send_shm);
    }
    worker->lock.free(&worker->lock);
}

int zan_pool_alloc_worker(zanProcessPool *pool)
{
    int index = 0;
    //zanServer    *serv    = (zanServer *)ServerG.serv;
    zanServerSet *servSet = &(ServerG.servSet);

    //alloc workers...
    pool->workers = zan_shm_calloc(servSet->worker_num, sizeof(zanWorker));
    if (!pool->workers)
    {
        zanError("alloc event_workers failed");
        return ZAN_ERR;
    }

    pool->pipes = (zanPipe *)zan_calloc(servSet->worker_num, sizeof(zanPipe));
    if (pool->pipes == NULL)
    {
        zanWarn("calloc pool->pipe for worker failed.");
        zan_shm_free(pool->workers);
        return ZAN_ERR;
    }

    zanPipe *pipe = NULL;
    for (index = 0; index < servSet->worker_num; index++)
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

int zan_worker_process_loop(zanWorker *worker)
{
    //
    ServerG.main_reactor = (swReactor *)zan_malloc(sizeof(swReactor));
    if (swReactor_init(ServerG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        zanError("[Worker] create worker_reactor failed.");
        return SW_ERR;
    }

    int pipe_worker = worker->pipe_worker;
    zan_set_nonblocking(pipe_worker, 1);

    ServerG.main_reactor->id  = worker->worker_id;
    ServerG.main_reactor->ptr = ServerG.serv;
    ServerG.main_reactor->add(ServerG.main_reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_PIPE, zan_worker_onPipeReceive);
    ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_PIPE | SW_FD_WRITE, swReactor_onWrite);

    zanProcessPool *pool = worker->pool;
    pool->onWorkerStart(pool, worker);
    zan_stats_set_worker_status(worker, ZAN_WORKER_IDLE);

    zanWarn("worker loop in: worker_id=%d, process_type=%d, pid=%d", worker->worker_id, ServerG.process_type, ServerG.process_pid);

    int ret = ServerG.main_reactor->wait(ServerG.main_reactor, NULL);
    zanWarn("worker wait return, ret=%d", ret);

    //clear pipe buffer
    zan_worker_clean_pipe();

    //worker shutdown
    pool->onWorkerStop(pool, worker);
    return ret;
}

int zan_spawn_worker_process(zanProcessPool *pool)
{
    int index       = 0;
    zan_pid_t pid   = 0;

    for (index = 0; index < ServerG.servSet.worker_num; index++)
    {
        zanWorker *worker    = &(pool->workers[index]);
        worker->pool         = pool;
        worker->worker_id    = index + pool->start_id;
        worker->process_type = ZAN_PROCESS_WORKER;

        pid = zan_fork();
        if (pid < 0)
        {
            zanError("zan_fork failed, pid=%d, Error:%s:%d", pid, strerror(errno), errno);
            return ZAN_ERR;
        }
        else if (pid == 0)  //worker child processor
        {
            int ret = zan_worker_process_loop(worker);
            exit(ret);
        }
        else
        {
            worker->worker_pid = pid;
            zanTrace("zan_fork child process, pid=%d", pid);
        }
    }
    return ZAN_OK;
}

int zan_pool_worker_init(zanProcessPool *pool)
{

    //pool->onTask         = swTaskWorker_onTask;
    pool->onWorkerStart  = zan_worker_onStart;
    pool->onWorkerStop   = zan_worker_onStop;
    pool->start_id       = 0;

#if 0
    zanServer *serv = ServerG.serv;
    int buffer_input_size = (serv->listen_list->open_eof_check ||
                             serv->listen_list->open_length_check ||
                             serv->listen_list->open_http_protocol)?
                            serv->listen_list->protocol.package_max_length:
                            SW_BUFFER_SIZE_BIG;


    ///TODO:::
    int buffer_num = /*serv->reactor_num + */ serv->dgram_port_num;
    ServerWG.buffer_input = zan_malloc(sizeof(swString*) * buffer_num);
    if (!SwooleWG.buffer_input)
    {
        zanError("malloc for ServerWG.buffer_input failed.");
        return ZAN_ERR;
    }

    int index = 0;
    for (index = 0; index < buffer_num; index++)
    {
        ServerWG.buffer_input[index] = swString_new(buffer_input_size);
        if (!ServerWG.buffer_input[index])
        {
            zanError("buffer_input init failed.");
            return ZAN_ERR;
        }
    }

    if (ServerG.servSet.max_request < 1)
    {
        ServerWG.run_always = 1;
    }
    else
    {
        ServerWG.max_request = ServerG.servSet.max_request;
        if (ServerWG.max_request > 10)
        {
            ServerWG.max_request += random()%100;
        }
    }
#endif
    return ZAN_OK;
}

//receive data from reactor
static int zan_worker_onPipeReceive(swReactor *reactor, swEvent *event)
{
    swEventData task;
    zanServer  *serv    = ServerG.serv;
    zanFactory *factory = &serv->factory;
    int ret = 0;

read_from_pipe:
    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        zanWarn("read from fd=%d, info.type=%d", event->fd, task.info.type);

        ///TODO:::
        ret = zan_worker_onTask(factory, &task);
#ifndef SW_WORKER_RECV_AGAIN
        //Big package
        if (task.info.type == SW_EVENT_PACKAGE_START)
#endif
        {
            //no data
            if (ret < 0 && errno == EAGAIN)
            {
                return ZAN_OK;
            }
            else if (ret > 0)
            {
                goto read_from_pipe;
            }
        }
        return ret;
    }
    return ZAN_ERR;
}

static void zan_worker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    zanServer    *serv    = ServerG.serv;
    zanServerSet *servSet = &(ServerG.servSet);

    ServerG.process_pid    = zan_getpid();
    ServerG.process_type   = ZAN_PROCESS_WORKER;
    ServerWG.worker_id     = worker->worker_id;
    ServerWG.request_count = 0;

    ServerStatsG->workers_state[ServerWG.worker_id].request_count = 0;
    sw_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].start_count);
    ServerStatsG->workers_state[worker->worker_id].first_start_time = time(NULL);

    //signal init
    //swWorker_signal_init();

    /// 设置cpu 亲和性
    ///swoole_cpu_setAffinity(ServerWG.worker_id, serv);

    //TODO::: init

    //TODO:::
    int index = 0;
    swConnection *pipe_socket = NULL;
    for (index = 0; index < servSet->worker_num + servSet->task_worker_num; index++)
    {
        worker = zanServer_get_worker(serv, index);
        pipe_socket = swReactor_get(ServerG.main_reactor, worker->pipe_master);
        pipe_socket->buffer_size = servSet->pipe_buffer_size;
        pipe_socket = swReactor_get(ServerG.main_reactor, worker->pipe_worker);
        pipe_socket->buffer_size = servSet->pipe_buffer_size;
    }

    //
    if (serv->onWorkerStart)
    {
        zanWarn("worker: call user worker onStart function");
        serv->onWorkerStart(serv, worker->worker_id);
    }
}

static void zan_worker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;
    if (serv->onWorkerStop)
    {
        zanWarn("worker: call user worker onStop function");
        serv->onWorkerStop(serv, worker->worker_id);
    }
    zan_worker_free(worker);
}

void zan_worker_clean_pipe(void)
{
    int index = 0;
    zanWorker    *worker  = NULL;
    zanServerSet *servSet = &(ServerG.servSet);

    for (index = 0; index < servSet->worker_num + servSet->task_worker_num; index++)
    {
        worker = zanServer_get_worker(ServerG.serv, index);
        if (ServerG.main_reactor)
        {
            if (worker->pipe_worker)
            {
                //TODO:::
                swReactor_wait_write_buffer(ServerG.main_reactor, worker->pipe_worker);
            }
            if (worker->pipe_master)
            {
                //TODO:::
                swReactor_wait_write_buffer(ServerG.main_reactor, worker->pipe_master);
            }
        }
    }
}

int zan_worker_onTask(zanFactory *factory, swEventData *task)
{
    zanServer     *serv    = ServerG.serv;
    swString      *package = NULL;
    //swDgramPacket *header  = NULL;

#ifdef SW_USE_OPENSSL
    /////swConnection *conn = NULL;
#endif

    zanWarn("worker_onTask: fd=%d, from_id=%d, info.type=%d", task->info.fd, task->info.from_id, task->info.type);

    zanWorker *worker = &ServerGS->event_workers.workers[ServerWG.worker_id];
    zan_stats_set_worker_status(worker, ZAN_WORKER_BUSY);
    switch (task->info.type)
    {
        //no buffer
        case SW_EVENT_TCP:
        //ringbuffer shm package
        case SW_EVENT_PACKAGE:
#if 0
            ///TODO:::
            //discard data
            if (swWorker_discard_data(serv, task) == SW_TRUE)
            {
                break;
            }
#endif
///do_task:
            {
                serv->onReceive(serv, task);
                ServerWG.request_count++;
                sw_stats_incr(&ServerStatsG->request_count);
                sw_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].total_request_count);
                sw_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].request_count);
            }
            if (task->info.type == SW_EVENT_PACKAGE_END)
            {
                package->length = 0;
            }
            break;
        ///TODO:::
            //.....
        default:
            zanWarn("[Worker] error event[type=%d], worker_id=%d", (int )task->info.type, ServerWG.worker_id);
            break;
    }

    //worker idle
    zan_stats_set_worker_status(worker, ZAN_WORKER_IDLE);

    //maximum number of requests, process will exit.
    if (!ServerWG.run_always && ServerWG.request_count >= ServerWG.max_request)
    {
        ServerG.running = 0;
        ServerG.main_reactor->running = 0;
    }
    return ZAN_OK;
}

int zan_worker_send2worker(zanWorker *dst_worker, void *buf, int lenght, int flag)
{
    int pipefd = (flag & SW_PIPE_MASTER) ? dst_worker->pipe_master : dst_worker->pipe_worker;
    if (ZAN_IPC_MSGQUEUE == ServerG.servSet.task_ipc_mode)
    {
        struct
        {
            long mtype;
            swEventData buf;
        } msg;

        msg.mtype = dst_worker->worker_id + 1;
        memcpy(&msg.buf, buf, lenght);

        zanMsgQueue *queue = dst_worker->pool->queue;
        return queue->push(queue, (zanQueue_Data *) &msg, lenght);
    }

    int ret = 0;
    if ((flag & ZAN_PIPE_NONBLOCK) && ServerG.main_reactor)
    {
        return ServerG.main_reactor->write(ServerG.main_reactor, pipefd, buf, lenght);
    }
    else
    {
        //TODO:::delete
        //ret = swSocket_write_blocking(pipefd, buf, n);
    }

    return ret;
}

void zan_stats_set_worker_status(zanWorker *worker, int status)
{
    ServerStatsG->lock.lock(&ServerStatsG->lock);
    worker->status = status;
    if (status == ZAN_WORKER_BUSY)
    {
        if (is_worker())
        {
            sw_stats_incr(&ServerStatsG->active_worker);
            if (ServerStatsG->active_worker > ServerStatsG->max_active_worker)
            {
                ServerStatsG->max_active_worker = ServerStatsG->active_worker;
            }
        }
        else if (is_taskworker())
        {
            sw_stats_incr(&SwooleStats->active_task_worker);
            if (ServerStatsG->active_task_worker > ServerStatsG->max_active_task_worker)
            {
                ServerStatsG->max_active_task_worker = ServerStatsG->active_task_worker;
            }
        }
    }
    else if (status == ZAN_WORKER_IDLE)
    {
        if (is_worker() && ServerStatsG->active_worker > 0)
        {
            sw_stats_decr(&ServerStatsG->active_worker);
        }
        else if (is_taskworker() && ServerStatsG->active_task_worker > 0)
        {
            sw_stats_decr(&ServerStatsG->active_task_worker);
        }
    }
    else
    {
        zanWarn("Set worker status failed, unknow worker[%d] status[%d]", worker->worker_id, status);
    }
    ServerStatsG->lock.unlock(&ServerStatsG->lock);
}
