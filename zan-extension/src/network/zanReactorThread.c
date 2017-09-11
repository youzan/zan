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

#include "swoole.h"
#include "list.h"
#include "swWork.h"
#include "swSignal.h"
#include "swServer.h"

#include "swBaseOperator.h"
#include "swProtocol/websocket.h"

#include "zanServer.h"
#include "zanFactory.h"
#include "zanExecutor.h"
#include "zanLog.h"

static int zanReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int zanReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);

static int zanReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int zanReactorThread_onWrite(swReactor *reactor, swEvent *ev);


/**
 * [ReactorThread] worker pipe can write.
 */
static int zanReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret = 0;

    swBuffer_trunk *trunk = NULL;
    swEventData *send_data = NULL;
    swConnection *conn = NULL;
    swServer *serv = reactor->ptr;
    swBuffer *buffer = serv->connection_list[ev->fd].in_buffer;
    swLock *lock = serv->connection_list[ev->fd].object;

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
            conn = swServer_connection_verify(serv, send_data->info.fd);
            if (conn == NULL || conn->closed)
            {
#ifdef SW_USE_RINGBUFFER
                swReactorThread *thread = swServer_get_thread(SwooleG.serv, SwooleTG.id);
                swPackage package;
                memcpy(&package, send_data->data, sizeof(package));
                thread->buffer_input->free(thread->buffer_input, package.data);
#endif
                if (conn && conn->closed)
                {
                    swNotice("Session#%d is closed by server.", send_data->info.fd);
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
        if (SwooleG.serv->connection_list[ev->fd].from_id == SwooleTG.id)
        {
            ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        }
        else
        {
            ret = reactor->del(reactor, ev->fd);
        }
        if (ret < 0)
        {
            swSysError("reactor->set(%d) failed.", ev->fd);
        }
    }

    //release lock
    lock->unlock(lock);

    return SW_OK;
}

/**
 * receive data from worker process pipe
 */
static int zanReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev)
{
    int n;
    swEventData resp;
    //swSendData _send;

    //swPackage_response pkg_resp;
    //zanWorker *worker;

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, &resp, sizeof(resp));
        zanWarn("read return, n=%d, errno=%d:%s", n, errno, strerror(errno));
#if 0
        if (n > 0)
        {
            memcpy(&_send.info, &resp.info, sizeof(resp.info));
            if (_send.info.type == SW_EVENT_DENY_REQUEST) {
                swServer* serv = SwooleG.serv;
                int target_worker_id = _send.info.worker_id;
                serv->workers[target_worker_id].deny_request = 1;
                swNotice("[Master] set worker exit.[work_id=%d]", target_worker_id);
                return SW_OK;
            } else if(_send.info.type == SW_EVENT_DENY_EXIT) {
                swServer* serv = SwooleG.serv;
                int target_worker_id = _send.info.worker_id;
                serv->workers[target_worker_id].deny_request = 0;
                swNotice("[Master] set worker idle.[work_id=%d]", target_worker_id);
                return SW_OK;
            }

            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                _send.data = resp.data;
                _send.length = resp.info.len;
                swReactorThread_send(&_send);
            }
            else
            {
                memcpy(&pkg_resp, resp.data, sizeof(pkg_resp));
                worker = swServer_get_worker(SwooleG.serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.length = pkg_resp.length;

                swReactorThread_send(&_send);
                worker->lock.unlock(&worker->lock);
            }
        }
        else if (errno == EAGAIN)
        {
            return SW_OK;
        }
        else
        {
            swSysError("read(worker_pipe) failed.");
            return SW_ERR;
        }
#endif
    }

    return SW_OK;
}

static int zanReactorThread_onRead(swReactor *reactor, swEvent *event)
{
    zanWarn("onRead in, fd=%d, from_fd=%d", event->fd, event->socket->from_fd);

    if (event->socket->from_fd == 0)
    {
        zanWarn("from_fd==0");
        return SW_OK;
    }

    zanServer *serv = ServerG.serv;
    swListenPort *port = zanServer_get_port(serv, event->fd);

#if 0
#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->fd);
    }
#endif
#endif

    event->socket->last_time = ServerGS->server_time;
    return port->onRead(reactor, port, event);
}

static int zanReactorThread_onWrite(swReactor *reactor, swEvent *event)
{
    int ret;
    int fd = event->fd;
    zanServer *serv = ServerG.serv;

    //zanDebug("onWrite in, fd=%d", event->fd);

    swConnection *conn = zanServer_get_connection(serv, fd);
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
            swWarn("send notification [fd=%d] failed.", fd);
        }
        conn->close_notify = 0;
        return SW_OK;
    }
    else if (serv->disable_notify && conn->close_force)
    {
        zanDebug("to close the reactor fd");
        //return swReactorThread_close(reactor, fd);
    }

    swBuffer_trunk *chunk = NULL;
    while (!swBuffer_empty(conn->out_buffer))
    {
        chunk = swBuffer_get_trunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            close_fd:
            reactor->close(reactor, fd);
            return SW_OK;
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
                return SW_OK;
            }
        }
    }

    if (conn->overflow && conn->out_buffer->length < SwooleG.socket_buffer_size)
    {
        conn->overflow = 0;
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(conn->out_buffer))
    {
        reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_READ);
    }
    return SW_OK;
}


/**
 * close connection
 */
int zanReactorThread_close(swReactor *reactor, int fd)
{
    zanServer *serv = ServerG.serv;
    swConnection *conn = zanServer_get_connection(serv, fd);
    if (conn == NULL)
    {
        zanWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
        return ZAN_ERR;
    }

    if (!conn->removed)
    {
        zanWarn("conn->removed=%d, fd=%d, del reactor", conn->removed, fd);
        reactor->del(reactor, fd);
    }

    sw_stats_incr(&ServerStatsG->close_count);
    sw_stats_decr(&ServerStatsG->connection_count);

    zanTrace("Close Event.fd=%d|from=%d", fd, reactor->id);

    swListenPort *port = zanServer_get_port(serv, fd);

    //clear output buffer
    if (port->open_eof_check || port->open_length_check || port->open_mqtt_protocol)
    {
        if (conn->object)
        {
            zanServer_free_buffer(serv, fd);
            conn->object = NULL;
        }
    }
    else if (port->open_http_protocol)
    {
        if (conn->object)
        {
            if (conn->http_upgrade)
            {
                zanServer_free_buffer(serv, fd);
                conn->websocket_status = 0;
            }
            else
            {
                swHttpRequest_free(conn);
            }
        }
    }

#ifdef SW_REACTOR_USE_SESSION
    swSession *session = zanServer_get_session(serv, conn->session_id);
    session->fd = 0;
#endif

    //reset maxfd, for connection_list
    if (fd == swServer_get_maxfd(serv))
    {
        ServerGS->lock.lock(&ServerGS->lock);
        int find_max_fd = fd - 1;
        zanTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);

        //Find the new max_fd
        for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--)
            ;
        swServer_set_maxfd(serv, find_max_fd);
        ServerGS->lock.unlock(&ServerGS->lock);
    }

    return swReactor_close(reactor, fd);
}

int zanReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    zanServer *serv = ServerG.serv;

    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = zanServer_get_connection(ServerG.serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        zanWarn("conn==null or conn->active==0, conn=%p", conn);
        return ZAN_ERR;
    }
    else if (serv->disable_notify)
    {
        zanReactorThread_close(reactor, fd);
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

int zanReactorThread_send2worker(void *data, int len, uint16_t target_worker_id)
{
    int ret = -1;
    zanServer *serv   = ServerG.serv;
    zanWorker *worker = zanServer_get_worker(serv, target_worker_id);

    swReactor *reactor = ServerG.main_reactor;

    zanDebug("send2worker in: worker_id=%d", target_worker_id);

    if (serv->have_tcp_sock)
    {
        int pipe_fd = worker->pipe_master;
        //int thread_id = serv->connection_list[pipe_fd].from_id;

        //swReactorThread *thread = swServer_get_thread(serv, thread_id);
        //swLock *lock = serv->connection_list[pipe_fd].object;

        //lock thread
        //lock->lock(lock);

        swBuffer *buffer = serv->connection_list[pipe_fd].in_buffer;
        if (swBuffer_empty(buffer))
        {
            ret = write(pipe_fd, (void *) data, len);
#ifdef HAVE_KQUEUE
            if (ret < 0 && (errno == EAGAIN || errno == ENOBUFS))
#else
            if (ret < 0 && errno == EAGAIN)
#endif
            {
                //if (thread->reactor.set(&thread->reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
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
                swWarn("append to pipe_buffer failed.");
                ret = ZAN_ERR;
            }
            else
            {
                ret = ZAN_OK;
            }
        }
        //release thread lock
        //lock->unlock(lock);
    }
    else
    {
        //udp????
        int pipe_fd = worker->pipe_master;
        ret = swSocket_write_blocking(pipe_fd, data, len);
    }

    return ret;
}


#if 0
/**
 * send to client or append to out_buffer
 */
int swReactorThread_send(swSendData *_send)
{
    swServer *serv = SwooleG.serv;
    uint32_t session_id = _send->info.fd;
    void *_send_data = _send->data;
    uint32_t _send_length = _send->length;

    swConnection *conn = swServer_connection_verify(serv, session_id);
    if (!conn)
    {
        if (_send->info.type == SW_EVENT_TCP)
        {
            swNotice("send %d byte failed, session#%d does not exist.", _send_length, session_id);
        }
        else
        {
            swNotice("send event$[%d] failed, session#%d does not exist.", _send->info.type, session_id);
        }

        return SW_ERR;
    }

    int fd = conn->fd;
    swReactor *reactor = (serv->factory_mode == SW_MODE_SINGLE)?
                         &(serv->reactor_threads[0].reactor):&(serv->reactor_threads[conn->from_id].reactor);

    /**
     * Reset send buffer, Immediately close the connection.
     */
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
            swNotice("connection#%d is closed by client.", fd);
            return SW_ERR;
        }
        //connection output buffer overflow
        if (conn->out_buffer->length >= serv->buffer_output_size)
        {
            swNotice("connection#%d output buffer overflow.", fd);
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

    return SW_OK;
}

int zanReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
{
    swFactory *factory = SwooleG.factory;
    swDispatchData task;
    memset(&task, 0, sizeof(task));

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;

    swTrace("send string package, size=%u bytes.", length);

#ifdef SW_USE_RINGBUFFER
    swServer *serv = SwooleG.serv;
    swReactorThread *thread = swServer_get_thread(serv, SwooleTG.id);
    int target_worker_id = swServer_worker_schedule(serv, conn->fd);

    swPackage package;
    package.length = length;
    package.data = swReactorThread_alloc(thread, package.length);

    task.data.info.type = SW_EVENT_PACKAGE;
    task.data.info.len = sizeof(package);
    task.target_worker_id = target_worker_id;

    //swoole_dump_bin(package.data, 's', buffer->length);
    memcpy(package.data, data, package.length);
    memcpy(task.data.data, &package, sizeof(package));

    //dispatch failed, free the memory.
    if (factory->dispatch(factory, &task) < 0)
    {
        thread->buffer_input->free(thread->buffer_input, package.data);
    }
    else
    {
        return SW_OK;
    }
#else

    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.target_worker_id = -1;

    /**
     * lock target
     */
    SwooleTG.factory_lock_target = 1;

    size_t send_n = length;
    size_t offset = 0;

    while (send_n > 0)
    {
        if (send_n > SW_BUFFER_SIZE)
        {
            task.data.info.len = SW_BUFFER_SIZE;
        }
        else
        {
            task.data.info.type = SW_EVENT_PACKAGE_END;
            task.data.info.len = send_n;
        }

        task.data.info.fd = conn->fd;
        memcpy(task.data.data, data + offset, task.data.info.len);

        send_n -= task.data.info.len;
        offset += task.data.info.len;

        swTrace("dispatch, type=%d|len=%d\n", task.data.info.type, task.data.info.len);

        if (factory->dispatch(factory, &task) < 0)
        {
            break;
        }
    }

    /**
     * unlock
     */
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;

#endif
    return SW_OK;
}
#endif

int zan_reactor_tcp_setup(swReactor *reactor, zanServer *serv)
{
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (!swSocket_is_dgram(ls->type))
        {
            swPort_set_protocol(ls);
            reactor->add(reactor, ls->sock, SW_FD_LISTEN | SW_EVENT_READ);
            zanWarn("networker, reactor->add sock=%d, event=%d", ls->sock, SW_FD_LISTEN | SW_EVENT_READ);
        }
    }

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    reactor->close = zanReactorThread_close;

    reactor->setHandle(reactor, SW_FD_CLOSE, zanReactorThread_onClose);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, zanReactorThread_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, zanReactorThread_onPipeWrite);

    //reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, zanReactorThread_onWrite);
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, zanReactorThread_onRead);

#if 0
    int index = 0, pipe_fd = -1;
    for (index = 0; index < serv->worker_num; index++)
    {
        if ((index % serv->reactor_num) == reactor_id)
        {
            pipe_fd = serv->workers[index].pipe_master;

            //for request
            swBuffer *buffer = swBuffer_new(sizeof(swEventData));
            if (!buffer)
            {
                swError("create buffer failed.");
                break;
            }
            serv->connection_list[pipe_fd].in_buffer = buffer;

            //for response
            swSetNonBlock(pipe_fd,1);
            reactor->add(reactor, pipe_fd, SW_FD_PIPE);

            /**
             * mapping reactor_id and worker pipe
             */
            serv->connection_list[pipe_fd].from_id = reactor_id;
            serv->connection_list[pipe_fd].fd = pipe_fd;
            serv->connection_list[pipe_fd].object = sw_malloc(sizeof(swLock));

            /**
             * create pipe lock
             */
            if (swMutex_create(serv->connection_list[pipe_fd].object, 0) < 0)
            {
                swError("create pipe mutex lock failed.");
                break;
            }
        }
    }
#endif

    return ZAN_OK;
}
