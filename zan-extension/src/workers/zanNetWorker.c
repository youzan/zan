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
#include "swWork.h"
#include "swStats.h"

#include "swProtocol/http.h"

#include "zanServer.h"
#include "zanGlobalDef.h"
#include "zanSocket.h"
#include "zanWorkers.h"
#include "zanProcess.h"
#include "zanConnection.h"
#include "zanLog.h"

int zanPool_networker_alloc(zanProcessPool *pool);
int zanPool_networker_init(zanProcessPool *pool);

int zan_spawn_net_process(zanProcessPool *pool);

static int zanNetworker_loop(zanProcessPool *pool, zanWorker *worker);
static void zanNetworker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zanNetworker_onStop(zanProcessPool *pool, zanWorker *worker);

static int zanNetworker_tcp_setup(swReactor *reactor, zanServer *serv);
static int zanNetworker_onPipeReceive(swReactor *reactor, swEvent *event);
static int zanNetworker_onPipeWrite(swReactor *reactor, swEvent *event);
static int zanNetworker_onRead(swReactor *reactor, swEvent *event);
static int zanNetworker_onWrite(swReactor *reactor, swEvent *event);
static int zanNetworker_send(swSendData *_send);

static int swReactorThread_verify_ssl_state(swListenPort *port, swConnection *conn);

int zanPool_networker_alloc(zanProcessPool *pool)
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

int zan_spawn_net_process(zanProcessPool *pool)
{
    uint32_t   index = 0;
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
            int ret = pool->main_loop(pool, worker);
            exit(ret);
        }
        else
        {
            zanTrace("zan_fork child process, pid=%d", pid);
            worker->worker_pid = pid;
        }
    }
    return ZAN_OK;
}

int zanPool_networker_init(zanProcessPool *pool)
{
    pool->onWorkerStart  = zanNetworker_onStart;
    pool->onWorkerStop   = zanNetworker_onStop;
    pool->main_loop      = zanNetworker_loop;
    pool->start_id       = ServerG.servSet.worker_num + ServerG.servSet.task_worker_num;

    return ZAN_OK;
}

static void zanNetworker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    //zanWarn("networker onStart....");
}

static void zanNetworker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    ///TODO:::
    zanWarn("networker onStop, worker_id=%d, process_types=%d", worker->worker_id, worker->process_type);
}


int zanNetworker_loop(zanProcessPool *pool, zanWorker *worker)
{
    zanServer    *serv    = ServerG.serv;
    zanServerSet *servSet = &ServerG.servSet;

    ServerG.process_pid   = zan_getpid();
    ServerG.process_type  = ZAN_PROCESS_NETWORKER;
    ServerWG.worker_id    = worker->worker_id;

    int networker_index = zanServer_get_networker_index(worker->worker_id);

    swReactor *reactor = (swReactor *)zan_malloc(sizeof(swReactor));
    if (swReactor_init(reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        zanError("networker, main_reactor create error");
        return ZAN_ERR;
    }
    ServerG.main_reactor = reactor;

    //main_reactor accept/recv/send....
    reactor->ptr = serv;
    reactor->thread = 1;                  //TODO:::
    reactor->id  = worker->worker_id;     //=========networker_id
    reactor->disable_accept = 0;
    reactor->socket_list = serv->connection_list[networker_index];
    reactor->max_socket  = servSet->max_connection;
    reactor->enable_accept = zanReactor_enableAccept;

    zanServer_store_listen_socket(serv, worker->worker_id);

    //listen UDP

    //TCP
    if (ZAN_OK != zanNetworker_tcp_setup(reactor, serv))
    {
        zanWarn("reactor tcp setup failed.");
        return ZAN_ERR;
    }

    //for worker->networker
    int pipe_worker = worker->pipe_worker;
    zan_set_nonblocking(pipe_worker, 1);
    reactor->add(reactor, pipe_worker, SW_FD_PIPE | SW_EVENT_READ);
    reactor->setHandle(reactor, SW_FD_LISTEN | SW_EVENT_READ, zanReactor_onAccept);

    pool->onWorkerStart(pool, worker);
    zanDebug("networker loop in: worker_id=%d, process_type=%d, pid=%d, reactor->add pipe_worker=%d, pipe_master=%d",
              worker->worker_id, ServerG.process_type, ServerG.process_pid, pipe_worker, worker->pipe_master);

    struct timeval tmo = {1, 0};
    int ret = reactor->wait(reactor, &tmo);

    pool->onWorkerStop(pool, worker);
    reactor->free(reactor);

    zanWarn("networker loop out: wait return ret=%d, worker_id=%d, process_type=%d, pid=%d",
            ret, worker->worker_id, ServerG.process_type, ServerG.process_pid);

    return ret;
}

int zanNetworker_tcp_setup(swReactor *reactor, zanServer *serv)
{
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (!swSocket_is_dgram(ls->type))
        {
            swPort_set_protocol(ls);
            reactor->add(reactor, ls->sock, SW_FD_LISTEN | SW_EVENT_READ);
            zanDebug("networker, reactor->add sock=%d, event=%d", ls->sock, SW_FD_LISTEN | SW_EVENT_READ);
        }
    }

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    reactor->close = zanNetworker_close_connection;

    reactor->setHandle(reactor, SW_FD_CLOSE| SW_EVENT_READ, zanNetworker_onClose);      ///???
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, zanNetworker_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, zanNetworker_onPipeWrite);

    //reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, zanNetworker_onRead);
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, zanNetworker_onWrite);

    return ZAN_OK;
}

//receive data from worker process pipe
static int zanNetworker_onPipeReceive(swReactor *reactor, swEvent *ev)
{
    int n;
    swEventData resp;
    swSendData _send;

    swPackage_response pkg_resp;
    zanWorker *worker;

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, &resp, sizeof(resp));
        if (n > 0)
        {
            memcpy(&_send.info, &resp.info, sizeof(resp.info));
            if (_send.info.type == SW_EVENT_DENY_REQUEST) {
                int target_worker_id = _send.info.worker_id;
                ServerGS->event_workers.workers[target_worker_id].deny_request = 1;
                zanTrace("[Master] set worker exit.[work_id=%d]", target_worker_id);
                return ZAN_OK;
            } else if(_send.info.type == SW_EVENT_DENY_EXIT) {
                int target_worker_id = _send.info.worker_id;
                ServerGS->event_workers.workers[target_worker_id].deny_request = 0;
                zanTrace("[Master] set worker idle.[work_id=%d]", target_worker_id);
                return ZAN_OK;
            }

            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                zanWarn("small response, from_fd=%d, from_worker_id=%d, pipe_fd=%d", _send.info.from_fd, _send.info.worker_id, ev->fd);
                _send.data = resp.data;
                _send.length = resp.info.len;
                zanNetworker_send(&_send);
            }
            else
            {
                zanWarn("big response, from_fd=%d, from_worker_id=%d, pipe_fd=%d", _send.info.from_fd, _send.info.worker_id, ev->fd);
                memcpy(&pkg_resp, resp.data, sizeof(pkg_resp));
                worker = zanServer_get_worker(ServerG.serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.length = pkg_resp.length;

                zanNetworker_send(&_send);
                worker->lock.unlock(&worker->lock);
            }
        }
        else if (errno == EAGAIN)
        {
            zanTrace("read(worker_pipe) return EAGAIN, n=%d, errno:%d:%s.", n, errno, strerror(errno));
            return ZAN_OK;
        }
        else
        {
            zanError("read(worker_pipe) failed, n=%d, errno:%d:%s", n, errno, strerror(errno));
            return ZAN_ERR;
        }
    }

    return ZAN_OK;
}

//[Networker] worker pipe can write.
static int zanNetworker_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret = 0;
    int networker_index = zanServer_get_networker_index(ev->from_id);

    swBuffer_trunk *trunk = NULL;
    swEventData *send_data = NULL;
    swConnection *conn = NULL;

    zanServer *serv = ServerG.serv;
    swBuffer *buffer = serv->connection_list[networker_index][ev->fd].in_buffer;
    swLock *lock = serv->connection_list[networker_index][ev->fd].object;

    zanWarn("onPipeWrite in, worker_id=%d, fd=%d, from_id=%d, type=%d", ServerWG.worker_id, ev->fd, ev->from_id, ev->type);

    //lock thread
    lock->lock(lock);

    while (!swBuffer_empty(buffer))
    {
        trunk = swBuffer_get_trunk(buffer);
        send_data = trunk->store.ptr;

        //server active close, discard data.
        if (swEventData_is_stream(send_data->info.type))
        {
            //send_data->info.fd is session_id
            conn = zanServer_verify_connection(serv, send_data->info.fd);
            if (conn == NULL || conn->closed)
            {
                if (conn && conn->closed)
                {
                    zanTrace("Session#%d is closed by server.", send_data->info.fd);
                }
                swBuffer_pop_trunk(buffer, trunk);
                continue;
            }
        }

        ret = write(ev->fd, trunk->store.ptr, trunk->length);
        if (ret < 0)
        {
            //release lock
            lock->unlock(lock);
#ifdef HAVE_KQUEUE
            return (errno == EAGAIN || errno == ENOBUFS) ? SW_OK : SW_ERR;
#else
            return errno == EAGAIN ? SW_OK : SW_ERR;
#endif
        }
        else
        {
            swBuffer_pop_trunk(buffer, trunk);
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        zanWarn("=============================>>>TODO::::");
        ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        if (ret < 0)
        {
            zanError("reactor->set(%d) failed.", ev->fd);
        }
    }

    //release lock
    lock->unlock(lock);

    return SW_OK;
}

static int zanNetworker_onRead(swReactor *reactor, swEvent *event)
{
    zanWarn("onRead in, fd=%d, from_fd=%d", event->fd, event->socket->from_fd);

    if (event->socket->from_fd == 0)  //from_fd: listen socket fd
    {
        zanWarn("from_fd==0");
        return ZAN_OK;
    }

    zanServer *serv = ServerG.serv;
    swListenPort *port = zanServer_get_port(serv, event->from_id, event->fd);

#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(port, event->socket) < 0)
    {
        return zanNetworker_close_connection(reactor, event->fd);
    }
#endif

    event->socket->last_time = ServerGS->server_time;
    return port->onRead(reactor, port, event);
}

static int zanNetworker_onWrite(swReactor *reactor, swEvent *event)
{
    int ret;
    int fd = event->fd;
    int networker_id = event->from_id;
    zanServer *serv = ServerG.serv;

    swConnection *conn = zanServer_get_connection(serv, networker_id, fd);
    if (conn->active == 0)
    {
        zanWarn("conn->active == 0, fd=%d", fd);
        return ZAN_OK;
    }
    //notify worker process
    else if (conn->connect_notify)
    {
        zanDebug("notify worker connected, fd=%d", fd);
        zanServer_connection_ready(serv, fd, reactor->id);
        conn->connect_notify = 0;
        return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
    }
    else if (conn->close_notify)
    {
        swDataHead close_event;
        close_event.type = SW_EVENT_CLOSE;
        close_event.from_id = reactor->id;
        close_event.fd = fd;

        if (serv->factory.notify(&serv->factory, &close_event) < 0)
        {
            zanWarn("send notification [fd=%d] failed.", fd);
        }
        conn->close_notify = 0;
        return ZAN_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        zanDebug("to close the reactor fd");
        return zanNetworker_close_connection(reactor, fd);
    }

    swBuffer_trunk *chunk = NULL;
    while (!swBuffer_empty(conn->out_buffer))
    {
        chunk = swBuffer_get_trunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
close_fd:
            reactor->close(reactor, fd);
            return ZAN_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            ret = swConnection_onSendfile(conn, chunk);
        }
        else
        {
            ret = swConnection_buffer_send(conn);
        }

        if (ret < 0)
        {
            if (conn->close_wait)
            {
                goto close_fd;
            }
            else if (conn->send_wait)
            {
                return ZAN_OK;
            }
        }
    }

    if (conn->overflow && conn->out_buffer->length < ServerG.servSet.socket_buffer_size)
    {
        conn->overflow = 0;
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(conn->out_buffer))
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_READ);
    }
    return ZAN_OK;
}

int zanNetworker_onClose(swReactor *reactor, swEvent *event)
{
    zanServer *serv = ServerG.serv;
    swDataHead notify_ev;

    int fd = event->fd;
    int networker_id = event->from_id;

    bzero(&notify_ev, sizeof(notify_ev));
    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = zanServer_get_connection(ServerG.serv, networker_id, fd);
    if (conn == NULL || conn->active == 0)
    {
        zanWarn("conn==null or conn->active==0, conn=%p", conn);
        return ZAN_ERR;
    }
    else if (serv->disable_notify)
    {
        zanNetworker_close_connection(reactor, fd);
        return ZAN_OK;
    }
    else if (reactor->del(reactor, fd) == 0)
    {
        return ServerG.factory->notify(ServerG.factory, &notify_ev);
    }
    else
    {
        return ZAN_ERR;
    }
}

/**
 * send to client or append to out_buffer
 */
int zanNetworker_send(swSendData *_send)
{
    zanServer *serv = ServerG.serv;
    uint32_t session_id = _send->info.fd;
    void *_send_data = _send->data;
    uint32_t _send_length = _send->length;

    swConnection *conn = zanServer_verify_connection(serv, session_id);
    if (!conn)
    {
        zanTrace("send event:%d byte:%d  failed, session#%d does not exist.", _send->info.type, _send_length, session_id);
        return ZAN_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor = ServerG.main_reactor;

    //Reset send buffer, Immediately close the connection.
    if (_send->info.type == SW_EVENT_CLOSE && conn->close_reset)
    {
        goto close_fd;
    }

    if (swBuffer_empty(conn->out_buffer))
    {
        /**
         * close connection.
         */
        if (_send->info.type == SW_EVENT_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
        }
#ifdef SW_REACTOR_SYNC_SEND
        //Direct send
        if (_send->info.type != SW_EVENT_SENDFILE)
        {
            if (!conn->direct_send)
            {
                goto buffer_send;
            }

            int n;

        direct_send:
            n = swConnection_send(conn, _send_data, _send_length, 0);
            if (n == _send_length)
            {
                return SW_OK;
            }
            else if (n > 0)
            {
                _send_data += n;
                _send_length -= n;
                goto buffer_send;
            }
            else if (errno == EINTR)
            {
                goto direct_send;
            }
            else
            {
                goto buffer_send;
            }
        }
#endif
        //buffer send
        else
        {
#ifdef SW_REACTOR_SYNC_SEND
            buffer_send:
#endif
            if (!conn->out_buffer)
            {
                conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
                if (conn->out_buffer == NULL)
                {
                    return SW_ERR;
                }
            }
        }
    }

    swBuffer_trunk *trunk;
    //close connection
    if (_send->info.type == SW_EVENT_CLOSE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_CLOSE, 0);
        trunk->store.data.val1 = _send->info.type;
    }
    //sendfile to client
    else if (_send->info.type == SW_EVENT_SENDFILE)
    {
        swConnection_sendfile_async(conn, _send_data);
    }
    //send data
    else
    {
        //connection is closed
        if (conn->removed)
        {
            zanTrace("connection#%d is closed by client.", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (conn->out_buffer->length >= ServerG.servSet.buffer_output_size)
        {
            zanTrace("connection#%d output buffer overflow.", fd);
            conn->overflow = 1;
        }

        int _length = _send_length;
        void* _pos = _send_data;
        int _n;

        //buffer enQueue
        while (_length > 0)
        {
            _n = _length >= SW_BUFFER_SIZE_BIG ? SW_BUFFER_SIZE_BIG : _length;
            swBuffer_append(conn->out_buffer, _pos, _n);
            _pos += _n;
            _length -= _n;
        }
    }

    //listen EPOLLOUT event
    if (reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_WRITE | SW_EVENT_READ) < 0
            && (errno == EBADF || errno == ENOENT))
    {
        goto close_fd;
    }

    return ZAN_OK;
}

int zanNetworker_send2worker(void *data, int len, uint16_t target_worker_id)
{
    int ret = -1;
    zanServer *serv    = ServerG.serv;
    swReactor *reactor = ServerG.main_reactor;
    zanWorker *worker  = zanServer_get_worker(serv, target_worker_id);

    int networker_index = zanServer_get_networker_index(ServerWG.worker_id);

    if (serv->have_tcp_sock)
    {
        int pipe_fd = worker->pipe_master;
        swBuffer *buffer = serv->connection_list[networker_index][pipe_fd].in_buffer; ///TODO:::
        if (swBuffer_empty(buffer))
        {
            ret = write(pipe_fd, (void *) data, len);
#ifdef HAVE_KQUEUE
            if (ret < 0 && (errno == EAGAIN || errno == ENOBUFS))
#else
            if (ret < 0 && errno == EAGAIN)
#endif
            {
                if (reactor->set(reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
                {
                    zanError("reactor->set(%d, PIPE | READ | WRITE) failed.", pipe_fd);
                }
                zanWarn("write pipd_fd=%d, faild, append to buffer retry, errno=%d:%s.", pipe_fd, errno, strerror(errno));
                goto append_pipe_buffer;
            }
        }
        else
        {
append_pipe_buffer:
            zanWarn("append_pipe_buffer: length=%d, pipe_buffer_size=%d", buffer->length, ServerG.servSet.pipe_buffer_size);
            if (buffer->length > ServerG.servSet.pipe_buffer_size)
            {
                swYield();
                swSocket_wait(pipe_fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
            }
            if (swBuffer_append(buffer, data, len) < 0)
            {
                zanWarn("append to pipe_buffer failed.");
                ret = ZAN_ERR;
            }
            else
            {
                ret = ZAN_OK;
            }
        }
    }
    else
    {
        //udp????
        int pipe_fd = worker->pipe_master;
        ret = swSocket_write_blocking(pipe_fd, data, len);
    }

    return ret;
}

/**
 * close connection
 */
int zanNetworker_close_connection(swReactor *reactor, int fd)
{
    int networker_id = ServerWG.worker_id;
    int network_index = zanServer_get_networker_index(networker_id);
    zanServer *serv = ServerG.serv;

    swConnection *conn = zanServer_get_connection(serv, networker_id, fd);
    if (conn == NULL)
    {
        zanWarn("[Reactor]connection not found. fd=%d|networker_id=%d|maxfd=%d", fd, networker_id, zanServer_get_maxfd(serv, network_index));
        return ZAN_ERR;
    }

    if (!conn->removed)
    {
        zanWarn("conn->removed=%d, fd=%d, del reactor", conn->removed, fd);
        reactor->del(reactor, fd);
    }

    sw_stats_incr(&ServerStatsG->close_count);
    sw_stats_decr(&ServerStatsG->connection_count);

    zanDebug("Close Event.fd=%d|from=%d", fd, reactor->id);

    swListenPort *port = zanServer_get_port(serv, networker_id, fd);

    //clear output buffer
    if (port->open_eof_check || port->open_length_check || port->open_mqtt_protocol)
    {
        if (conn->object)
        {
            zanServer_free_connection_buffer(serv, networker_id, fd);
            conn->object = NULL;
        }
    }
    else if (port->open_http_protocol)
    {
        if (conn->object)
        {
            if (conn->http_upgrade)
            {
                zanServer_free_connection_buffer(serv, networker_id, fd);
                conn->websocket_status = 0;
            }
            else
            {
                swHttpRequest_free(conn);
            }
        }
    }

#ifdef SW_REACTOR_USE_SESSION
    zanSession *session = zanServer_get_session(serv, conn->session_id);
    session->accept_fd = 0;
#endif

    //reset maxfd, for connection_list
    if (fd == zanServer_get_maxfd(serv, network_index))
    {
        ServerGS->lock.lock(&ServerGS->lock);
        int find_max_fd = fd - 1;
        zanTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);

        //Find the new max_fd
        for (; serv->connection_list[network_index][find_max_fd].active == 0 && find_max_fd > zanServer_get_minfd(serv, network_index); find_max_fd--)
            ;
        zanServer_set_maxfd(serv, network_index, find_max_fd);
        ServerGS->lock.unlock(&ServerGS->lock);
    }

    return swReactor_close(reactor, fd);
}

#ifdef SW_USE_OPENSSL
static int swReactorThread_verify_ssl_state(swListenPort *port, swConnection *conn)
{
    if (conn->ssl_state == 0 && conn->ssl)
    {
        int ret = swSSL_accept(conn);
        if (ret == SW_READY)
        {
            if (port->ssl_client_cert_file)
            {
                swDispatchData task;
                ret = swSSL_get_client_certificate(conn->ssl, task.data.data, sizeof(task.data.data));
                if (ret < 0)
                {
                    goto no_client_cert;
                }
                else
                {
                    zanFactory *factory = ServerG.factory;
                    task.target_worker_id = -1;
                    task.data.info.fd = conn->fd;
                    task.data.info.type = SW_EVENT_CONNECT;
                    task.data.info.from_id = conn->from_id;
                    task.data.info.len = ret;
                    if (factory->dispatch(factory, &task) < 0)
                    {
                        return ZAN_OK;
                    }
                }
            }
no_client_cert:
            if (ServerG.serv->onConnect)
            {
                zanServer_connection_ready(ServerG.serv, conn->fd, conn->from_id);
            }
            return ZAN_OK;
        }
        else if (ret == SW_WAIT)
        {
            return ZAN_OK;
        }
        else
        {
            return ZAN_ERR;
        }
    }
    return ZAN_OK;
}
#endif
