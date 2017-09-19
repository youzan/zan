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
#include "swStats.h"

#include "zanGlobalDef.h"
#include "zanSystem.h"
#include "zanWorkers.h"
#include "zanServer.h"
#include "zanSocket.h"
#include "zanLog.h"

int zan_spawn_net_process(zanProcessPool *pool);

int zanPool_worker_alloc(zanProcessPool *pool);
int zanPool_worker_init(zanProcessPool *pool);

static void zanWorker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zanWorker_onStop(zanProcessPool *pool, zanWorker *worker);
static int zanWorker_onTask(zanFactory *factory, swEventData *task);
static int zanWorker_loop(zanProcessPool *pool, zanWorker *worker);
static int zanWorker_onPipeRead(swReactor *reactor, swEvent *event);

int zanWorker_init(zanWorker *worker)
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

void zanWorker_free(zanWorker *worker)
{
    if (worker->send_shm)
    {
        zan_shm_free(worker->send_shm);
    }
    worker->lock.free(&worker->lock);
}

int zanPool_worker_alloc(zanProcessPool *pool)
{
    int index = 0;
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
        if (zanWorker_init(worker) < 0)
        {
            zan_shm_free(pool->workers);
            zan_free(pool->pipes);
            zanWarn("zanWorker_init failed.");
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

int zan_spawn_worker_process(zanProcessPool *pool)
{
    uint32_t index  = 0;
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
            int ret_code = pool->main_loop(pool, worker);
            exit(ret_code);
        }
        else
        {
            worker->worker_pid = pid;
            zanTrace("zan_fork worker child process, pid=%d", pid);
        }
    }
    return ZAN_OK;
}

int zanPool_worker_init(zanProcessPool *pool)
{
    pool->onWorkerStart  = zanWorker_onStart;
    pool->onWorkerStop   = zanWorker_onStop;

    pool->main_loop      = zanWorker_loop;
    pool->start_id       = 0;

    return ZAN_OK;
}

//receive data from networker or taskworker
static int zanWorker_onPipeRead(swReactor *reactor, swEvent *event)
{
    swEventData task;
    zanServer  *serv    = ServerG.serv;
    zanFactory *factory = &serv->factory;
    int ret = 0;

read_from_pipe:
    if (read(event->fd, &task, sizeof(task)) > 0)
    {
        zanDebug("read from pipe_worker=%d, info.type=%d", event->fd, task.info.type);

        ret = zanWorker_onTask(factory, &task);
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

static void zanWorker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;

    if (ServerG.servSet.max_request < 1)
    {
        ServerWG.run_always = 1;
    }
    else
    {
        ServerWG.max_request = ServerG.servSet.max_request;
        if (ServerWG.max_request > 100)
        {
            ServerWG.max_request += random()%100;
        }
    }
    ServerWG.request_count = 0;

    ServerStatsG->workers_state[ServerWG.worker_id].request_count = 0;
    sw_stats_incr(&ServerStatsG->workers_state[ServerWG.worker_id].start_count);

    ///TODO:::
    ServerStatsG->workers_state[worker->worker_id].first_start_time = time(NULL);

    //signal init
    //swWorker_signal_init();

    /// 设置cpu 亲和性
    ///swoole_cpu_setAffinity(ServerWG.worker_id, serv);

    if (serv->onWorkerStart)
    {
        //zanWarn("worker: call worker onStart, worker_id=%d, process_type=%d", worker->worker_id, worker->process_type);
        serv->onWorkerStart(serv, worker->worker_id);
    }
}

///TODO:::
static void zanWorker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    zanServer *serv = ServerG.serv;
    if (serv->onWorkerStop)
    {
        //zanWarn("worker: call user worker onStop, worker_id=%d, process_type=%d", worker->worker_id, worker->process_type);
        serv->onWorkerStop(serv, worker->worker_id);
    }

    ServerG.main_reactor->free(ServerG.main_reactor);
    zan_free(ServerG.main_reactor);
    zanWorker_free(worker);
}

int zanWorker_loop(zanProcessPool *pool, zanWorker *worker)
{
    ServerG.process_pid    = zan_getpid();
    ServerG.process_type   = ZAN_PROCESS_WORKER;
    ServerWG.worker_id     = worker->worker_id;

    swReactor *reactor = (swReactor *)zan_malloc(sizeof(swReactor));
    ServerG.main_reactor = reactor;
    if (swReactor_init(ServerG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        zanError("[Worker] create worker_reactor failed.");
        return ZAN_ERR;;
    }

    int pipe_worker = worker->pipe_worker;
    zan_set_nonblocking(pipe_worker, 1);

    reactor->id  = worker->worker_id;
    reactor->ptr = ServerG.serv;
    reactor->add(reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, zanWorker_onPipeRead);

    ///TODO:: 什么场景触发???
    ///reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactor_onWrite);  ////????

    //zan_stats_set_worker_status(worker, ZAN_WORKER_IDLE);

    //TODO:::
    int index = 0;
    swConnection *pipe_socket = NULL;
    zanServer *serv = ServerG.serv;
    zanServerSet *servSet = &ServerG.servSet;
    for (index = 0; index < servSet->worker_num + servSet->task_worker_num; index++)
    {
        zanWorker *worker_tmp = zanServer_get_worker(serv, index);
        pipe_socket = swReactor_get(ServerG.main_reactor, worker_tmp->pipe_master);
        pipe_socket->buffer_size = servSet->pipe_buffer_size;
        pipe_socket = swReactor_get(ServerG.main_reactor, worker_tmp->pipe_worker);
        pipe_socket->buffer_size = servSet->pipe_buffer_size;
    }

    pool->onWorkerStart(pool, worker);
    zanWarn("worker loop in: worker_id=%d, process_type=%d, pid=%d, reactor->add pipe_worker=%d, event=%d, pipe_master=%d",
            worker->worker_id, ServerG.process_type, ServerG.process_pid, worker->pipe_worker, SW_FD_PIPE | SW_EVENT_READ, worker->pipe_master);

    int ret = ServerG.main_reactor->wait(ServerG.main_reactor, NULL);
    zanWarn("worker wait return, ret=%d", ret);

    pool->onWorkerStop(pool, worker);

    //clear pipe buffer
    zanWorker_clean_pipe();

    return ret;
}

static int zanWorker_onTask(zanFactory *factory, swEventData *task)
{
    zanServer     *serv    = ServerG.serv;
    swString      *package = NULL;

#ifdef SW_USE_OPENSSL
    swConnection *conn = NULL;
#endif

    zanWorker *worker = zanServer_get_worker(serv, ServerWG.worker_id);
    zan_stats_set_worker_status(worker, ZAN_WORKER_BUSY);

    zanDebug("worker_onTask: fd=%d, from_id=%d, info.type=%d", task->info.fd, task->info.from_id, task->info.type);
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

        case SW_EVENT_CONNECT:
#ifdef SW_USE_OPENSSL
            //SSL client certificate
            if (task->info.len > 0)
            {
                conn = zanServer_verify_connection(serv, task->info.fd);
                conn->ssl_client_cert.str = strndup(task->data, task->info.len);
                conn->ssl_client_cert.size = conn->ssl_client_cert.length = task->info.len;
            }
#endif
            if (serv->onConnect)
            {
                serv->onConnect(serv, &task->info);
            }
            break;

        case SW_EVENT_CLOSE:
#ifdef SW_USE_OPENSSL
            conn = zanServer_verify_connection(serv, task->info.fd);
            if (conn && conn->ssl_client_cert.length)
            {
                free(conn->ssl_client_cert.str);
                bzero(&conn->ssl_client_cert, sizeof(conn->ssl_client_cert.str));
            }
#endif
            factory->end(factory, task->info.fd);
            break;

        case SW_EVENT_FINISH:
            serv->onFinish(serv, task);
            break;

        case SW_EVENT_PIPE_MESSAGE:
            serv->onPipeMessage(serv, task);
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
        zanWarn("run_always=%d, request_count=%d, max_request=%d", ServerWG.run_always, ServerWG.request_count, ServerWG.max_request);
        ServerG.running = 0;
        ServerG.main_reactor->running = 0;
    }
    return ZAN_OK;
}

int zanWorker_send2worker(zanWorker *dst_worker, void *buf, int lenght, int flag)
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
        zanWarn("dst_worker_id=%d, dst_pipe_fd=%d", dst_worker->worker_id, pipefd);
        return ServerG.main_reactor->write(ServerG.main_reactor, pipefd, buf, lenght);
    }
    else
    {
        zanWarn("taskworker-->worker, serv->finish, dst_worker_id=%d, dst_pipe_fd=%d", dst_worker->worker_id, pipefd);
        ret = swSocket_write_blocking(pipefd, buf, lenght);
    }

    return ret;
}

//Send data to networker
int zanWorker_send2networker(swEventData *ev_data, size_t sendn, int session_id)
{
    int ret = -1;
    zanServer *serv = ServerG.serv;
    zanSession *session = zanServer_get_session(serv, session_id);
    zanWorker *worker = zanServer_get_worker(serv, session->networker_id);

    zanDebug("session_id=%d, sendn=%d, networker_id=%d", session_id, (int)sendn, session->networker_id);

    if (ServerG.main_reactor)
    {
        zanWarn("write to pipe_worker=%d, dst worker_id=%d, src_worker_id=%d", worker->pipe_master, worker->worker_id, ServerWG.worker_id);
        ret = ServerG.main_reactor->write(ServerG.main_reactor, worker->pipe_master, ev_data, sendn);
    }
    else
    {
        zanWarn("write to pipe_master=%d, dst worker_id=%d, src worker_id=%d", worker->pipe_master, worker->worker_id, ServerWG.worker_id);
        ret = swSocket_write_blocking(worker->pipe_master, ev_data, sendn);
    }

    return ret;
}

void zanWorker_clean_pipe(void)
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
            sw_stats_incr(&ServerStatsG->active_task_worker);
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

//根据ID fork指定的worker
zan_pid_t zanMaster_spawnworker(zanProcessPool *pool, zanWorker *worker)
{
    zan_pid_t pid = fork();
    //fork() failed
    if (pid < 0)
    {
        zanError("Fork Worker failed. Error: %s [%d]", strerror(errno), errno);
        return ZAN_ERR;
    }
    //worker child processor
    else if (pid == 0)
    {
    	int ret = zanWorker_loop(pool, worker);
        exit(ret);
    }
    //parent,add to writer
    else
    {
        return pid;
    }
}
