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


#include "swoole.h"
#include "list.h"
#include "swWork.h"
#include "swSignal.h"
#include "swServer.h"
#include "swBaseOperator.h"
#include "swProtocol/websocket.h"
#include "swFactory.h"
#include "swExecutor.h"

static int swUDPThread_start(swServer *serv);
static int swReactorThread_loop_dgram(swThreadParam *param);

static int swTCPThread_start(swServer *serv);
static int swReactorThread_loop_stream(swThreadParam *param);

static void swHeartbeatThread_loop(swThreadParam *param);

static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev);

static int swReactorThread_onRead(swReactor *reactor, swEvent *ev);
static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev);
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event);

static int swUDPThread_start(swServer *serv)
{
    swThreadParam *param = NULL;
    pthread_t thread_id;
    swListenPort *ls = NULL;
    int index = serv->reactor_num;

    LL_FOREACH(serv->listen_list, ls)
    {
        param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[ls->sock].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else
            {
                serv->connection_list[ls->sock].info.addr.inet_v6.sin6_port = htons(ls->port);
            }

            serv->connection_list[ls->sock].fd = ls->sock;
            serv->connection_list[ls->sock].socket_type = ls->type;
            serv->connection_list[ls->sock].object = ls;

            param->object = ls;
            param->pti = index++;

            if (pthread_create(&thread_id, NULL, (void * (*)(void *)) swReactorThread_loop_dgram, (void *) param) < 0)
            {
                swSysError("pthread_create[udp_listener] fail");
                return SW_ERR;
            }

            ls->thread_id = thread_id;
        }
    }

    return SW_OK;
}

/**
 * udp listener thread
 */
static int swReactorThread_loop_dgram(swThreadParam *param)
{
    swEvent event;
    swListenPort *ls = param->object;

    int fd = ls->sock;

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = param->pti;
    SwooleTG.type = SW_THREAD_UDP;

    swSignal_none();

    //blocking
    swSetNonBlock(fd,0);
    event.fd = fd;

    while (SwooleG.running == 1)
    {
        swReactorThread_onPackage(NULL, &event);
    }

    pthread_exit(0);
    return 0;
}

static int swTCPThread_start(swServer *serv)
{
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (!swSocket_is_dgram(ls->type))
        {
        	SwooleG.main_reactor->add(SwooleG.main_reactor, ls->sock, SW_FD_LISTEN);
        }
    }

#ifdef HAVE_PTHREAD_BARRIER
    //init thread barrier
    pthread_barrier_init(&serv->barrier, NULL, serv->reactor_num + 1);
#endif

    swThreadParam *param = NULL;
    swReactorThread *thread = NULL;
    pthread_t pidt;
    int index = 0;
    //create reactor thread
    for (index = 0; index < serv->reactor_num; index++)
    {
        thread = &(serv->reactor_threads[index]);
        param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
        if (param == NULL)
        {
            swError("malloc failed");
            return SW_ERR;
        }

        param->object = serv;
        param->pti = index;

        if (pthread_create(&pidt, NULL, (void * (*)(void *)) swReactorThread_loop_stream, (void *) param) < 0)
        {
            swError("pthread_create[tcp_reactor] failed. Error: %s[%d]", strerror(errno), errno);
        }
        else{
            thread->thread_id = pidt;
        }
    }
#ifdef HAVE_PTHREAD_BARRIER
    //wait reactor thread
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif

    return SW_OK;
}
/**
 * ReactorThread tcp reactor Loop
 */
static int swReactorThread_loop_stream(swThreadParam *param)
{
    swServer *serv = SwooleG.serv;
    int reactor_id = param->pti;

    SwooleTG.factory_lock_target = 0;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.id = reactor_id;
    SwooleTG.type = SW_THREAD_REACTOR;

    swReactorThread *thread = swServer_get_thread(serv, reactor_id);
    swReactor *reactor = &thread->reactor;

    swoole_cpu_setAffinity(reactor_id,serv);

    if (swReactor_init(reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        return SW_ERR;
    }

    swSignal_none();

    reactor->ptr = serv;
    reactor->id = reactor_id;
    reactor->thread = 1;
    reactor->socket_list = serv->connection_list;
    reactor->max_socket = serv->max_connection;

    reactor->onFinish = NULL;
    reactor->onTimeout = NULL;
    reactor->close = swReactorThread_close;

    reactor->setHandle(reactor, SW_FD_CLOSE, swReactorThread_onClose);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, swReactorThread_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, swReactorThread_onPipeWrite);

    //set protocol function point
    swReactorThread_set_protocol(serv, reactor);

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
#ifdef SW_USE_RINGBUFFER
        int j = 0;
        thread->pipe_read_list = sw_calloc(serv->reactor_pipe_num, sizeof(int));
        if (thread->pipe_read_list == NULL)
        {
            swSysError("thread->buffer_pipe create failed");
            return SW_ERR;
        }
#endif
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

#ifdef SW_USE_RINGBUFFER
                thread->pipe_read_list[j++] = pipe_fd;
#endif
            }
        }
    }

    //wait other thread
#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_wait(&serv->barrier);
#else
    SW_START_SLEEP;
#endif

    struct timeval tm={5,0};
    //main loop
    reactor->wait(reactor, &tm);
    //shutdown
    reactor->free(reactor);
    pthread_exit(0);
    return SW_OK;
}

static void swHeartbeatThread_start(swServer *serv)
{
    swThreadParam *param;
    pthread_t thread_id;
    param = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swThreadParam));
    if (param == NULL)
    {
        swError("heartbeat_param malloc fail\n");
        return;
    }

    param->object = serv;
    param->pti = 0;

    if (pthread_create(&thread_id, NULL, (void * (*)(void *)) swHeartbeatThread_loop, (void *) param) < 0)
    {
    	swSysError("pthread_create[hbcheck] fail.");
    }
    SwooleG.heartbeat_pidt = thread_id;
}

static void swHeartbeatThread_loop(swThreadParam *param)
{
    swSignal_none();

    swServer *serv = param->object;
    swDataHead notify_ev;
    swConnection *conn;
    swReactor *reactor;

    int fd;
    int serv_max_fd;
    int serv_min_fd;
    int checktime;

    SwooleTG.type = SW_THREAD_HEARTBEAT;

    bzero(&notify_ev, sizeof(notify_ev));
    notify_ev.type = SW_EVENT_CLOSE;

    while (SwooleG.running)
    {
        serv_max_fd = swServer_get_maxfd(serv);
        serv_min_fd = swServer_get_minfd(serv);

        checktime = (int) time(NULL) - serv->heartbeat_idle_time;

        //遍历到最大fd
        for (fd = serv_min_fd; fd <= serv_max_fd; fd++)
        {
            swTrace("check fd=%d", fd);
            conn = swServer_connection_get(serv, fd);

            if (conn != NULL && conn->active == 1 && conn->fdtype == SW_FD_TCP)
            {
                if (conn->protect || conn->last_time > checktime)
                {
                    continue;
                }

                notify_ev.fd = fd;
                notify_ev.from_id = conn->from_id;

                conn->close_force = 1;
                conn->close_notify = 1;
                conn->close_wait = 1;

                if (serv->factory_mode != SW_MODE_PROCESS)
                {
                    if (serv->factory_mode == SW_MODE_SINGLE)
                    {
                        reactor = SwooleG.main_reactor;
                    }
                    else
                    {
                        reactor = &serv->reactor_threads[conn->from_id].reactor;
                    }
                }
                else
                {
                    reactor = &serv->reactor_threads[conn->from_id].reactor;
                }
                //notify to reactor thread
                reactor->set(reactor, fd, SW_FD_TCP | SW_EVENT_WRITE);
            }
        }
        sleep(serv->heartbeat_check_interval);
    }
    pthread_exit(0);
}

#ifdef SW_USE_RINGBUFFER
static sw_inline void swReactorThread_yield(swReactorThread *thread)
{
    swEvent event;
    swServer *serv = SwooleG.serv;
    int i;
    for (i = 0; i < serv->reactor_pipe_num; i++)
    {
        event.fd = thread->pipe_read_list[i];
        swReactorThread_onPipeReceive(&thread->reactor, &event);
    }
    swYield();
}

static sw_inline void* swReactorThread_alloc(swReactorThread *thread, uint32_t size)
{
    void *ptr = NULL;
    int try_count = 0;

    while (1)
    {
        ptr = thread->buffer_input->alloc(thread->buffer_input, size);
        if (ptr == NULL)
        {
            if (try_count > SW_RINGBUFFER_WARNING)
            {
                swWarn("memory pool is full. Wait memory collect. alloc(%d)", size);
                usleep(1000);
                try_count = 0;
            }

            try_count++;
            swReactorThread_yield(thread);
            continue;
        }
        break;
    }
    //debug("%p\n", ptr);
    return ptr;
}
#endif

#ifdef SW_USE_OPENSSL
static sw_inline int swReactorThread_verify_ssl_state(swListenPort *port, swConnection *conn)
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
                    swFactory *factory = &SwooleG.serv->factory;
                    task.target_worker_id = -1;
                    task.data.info.fd = conn->fd;
                    task.data.info.type = SW_EVENT_CONNECT;
                    task.data.info.from_id = conn->from_id;
                    task.data.info.len = ret;
                    if (factory->dispatch(factory, &task) < 0)
                    {
                        return SW_OK;
                    }
                }
            }
            no_client_cert:
            if (SwooleG.serv->onConnect)
            {
                swServer_connection_ready(SwooleG.serv, conn->fd, conn->from_id);
            }
            return SW_OK;
        }
        else if (ret == SW_WAIT)
        {
            return SW_OK;
        }
        else
        {
            return SW_ERR;
        }
    }
    return SW_OK;
}
#endif

/**
 * for udp
 */
static int swReactorThread_onPackage(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    int ret = -1;

    swServer *serv = SwooleG.serv;
    swConnection *server_sock = &serv->connection_list[fd];
    swDispatchData task;
    swSocketAddress info;
    swDgramPacket pkt;
    swFactory *factory = &serv->factory;

    info.len = sizeof(info.addr);
    bzero(&task.data.info, sizeof(task.data.info));
    task.data.info.from_fd = fd;
    task.data.info.from_id = SwooleTG.id;

    int socket_type = server_sock->socket_type;
    switch(socket_type)
    {
    case SW_SOCK_UDP6:
        task.data.info.type = SW_EVENT_UDP6;
        break;
    case SW_SOCK_UNIX_DGRAM:
        task.data.info.type = SW_EVENT_UNIX_DGRAM;
        break;
    case SW_SOCK_UDP:
    default:
        task.data.info.type = SW_EVENT_UDP;
        break;
    }

    char packet[SW_BUFFER_SIZE_UDP] = {0};
    ret = recvfrom(fd, packet, SW_BUFFER_SIZE_UDP, 0, (struct sockaddr *) &info.addr, &info.len);
    if (ret > 0)
    {
        pkt.length = ret;

        //IPv4
        if (socket_type == SW_SOCK_UDP)
        {
            pkt.port = ntohs(info.addr.inet_v4.sin_port);
            pkt.addr.v4.s_addr = info.addr.inet_v4.sin_addr.s_addr;
            task.data.info.fd = pkt.addr.v4.s_addr;
        }
        //IPv6
        else if (socket_type == SW_SOCK_UDP6)
        {
            pkt.port = ntohs(info.addr.inet_v6.sin6_port);
            memcpy(&pkt.addr.v6, &info.addr.inet_v6.sin6_addr, sizeof(info.addr.inet_v6.sin6_addr));
            memcpy(&task.data.info.fd, &info.addr.inet_v6.sin6_addr, sizeof(task.data.info.fd));
        }
        //Unix Dgram
        else
        {
            pkt.addr.un.path_length = strlen(info.addr.un.sun_path) + 1;
            pkt.length += pkt.addr.un.path_length;
            pkt.port = 0;
            memcpy(&task.data.info.fd, info.addr.un.sun_path + pkt.addr.un.path_length - 6, sizeof(task.data.info.fd));
        }

        task.target_worker_id = -1;
        uint32_t header_size = sizeof(pkt);

        //dgram header
        memcpy(task.data.data, &pkt, sizeof(pkt));
        //unix dgram
        if (socket_type == SW_SOCK_UNIX_DGRAM )
        {
            header_size += pkt.addr.un.path_length;
            memcpy(task.data.data + sizeof(pkt), info.addr.un.sun_path, pkt.addr.un.path_length);
        }
        //dgram body
        if (pkt.length > SW_BUFFER_SIZE - sizeof(pkt))
        {
            task.data.info.len = SW_BUFFER_SIZE;
        }
        else
        {
            task.data.info.len = pkt.length + sizeof(pkt);
        }
        //dispatch packet header
        memcpy(task.data.data + header_size, packet, task.data.info.len - header_size);

        uint32_t send_n = pkt.length + header_size;
        uint32_t offset = 0;

        /**
         * lock target
         */
        SwooleTG.factory_lock_target = 1;

        if (factory->dispatch(factory, &task) < 0)
        {
            return SW_ERR;
        }

        send_n -= task.data.info.len;
        if (send_n == 0)
        {
            /**
             * unlock
             */
            SwooleTG.factory_target_worker = -1;
            SwooleTG.factory_lock_target = 0;
            return ret;
        }

        offset = SW_BUFFER_SIZE - header_size;
        while (send_n > 0)
        {
            task.data.info.len = send_n > SW_BUFFER_SIZE ? SW_BUFFER_SIZE : send_n;
            memcpy(task.data.data, packet + offset, task.data.info.len);
            send_n -= task.data.info.len;
            offset += task.data.info.len;

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
    }
    return ret;
}

/**
 * [ReactorThread] worker pipe can write.
 */
static int swReactorThread_onPipeWrite(swReactor *reactor, swEvent *ev)
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
static int swReactorThread_onPipeReceive(swReactor *reactor, swEvent *ev)
{
    int n;
    swEventData resp;
    swSendData _send;

    swPackage_response pkg_resp;
    swWorker *worker;

#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
        n = read(ev->fd, &resp, sizeof(resp));
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
    }

    return SW_OK;
}

static int swReactorThread_onRead(swReactor *reactor, swEvent *event)
{
	if (event->socket->from_fd == 0)
	{
		return SW_OK;
	}

    swServer *serv = reactor->ptr;
    swListenPort *port = swServer_get_port(serv, event->fd);

#ifdef SW_USE_OPENSSL
    if (swReactorThread_verify_ssl_state(port, event->socket) < 0)
    {
        return swReactorThread_close(reactor, event->fd);
    }
#endif
    event->socket->last_time = SwooleGS->now;
    return port->onRead(reactor, port, event);
}

static int swReactorThread_onWrite(swReactor *reactor, swEvent *ev)
{
    int ret;
    swServer *serv = SwooleG.serv;
    int fd = ev->fd;

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn->active == 0)
    {
        return SW_OK;
    }
    //notify worker process
    else if (conn->connect_notify)
    {
        swServer_connection_ready(serv, fd, reactor->id);
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
        return swReactorThread_close(reactor, fd);
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
int swReactorThread_close(swReactor *reactor, int fd)
{
    swServer *serv = SwooleG.serv;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (conn == NULL)
    {
        swWarn("[Reactor]connection not found. fd=%d|max_fd=%d", fd, swServer_get_maxfd(serv));
        return SW_ERR;
    }

    if (!conn->removed)
    {
    	reactor->del(reactor, fd);
    }

    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        assert(fd % serv->reactor_num == reactor->id);
        assert(fd % serv->reactor_num == SwooleTG.id);
    }

    sw_stats_incr(&SwooleStats->close_count);
    sw_stats_decr(&SwooleStats->connection_num);

    swTrace("Close Event.fd=%d|from=%d", fd, reactor->id);

    swListenPort *port = swServer_get_port(serv, fd);

    //clear output buffer
    if (port->open_eof_check || port->open_length_check || port->open_mqtt_protocol)
    {
        if (conn->object)
        {
            swServer_free_buffer(serv, fd);
            conn->object = NULL;
        }
    }
    else if (port->open_http_protocol)
    {
        if (conn->object)
        {
            if (conn->http_upgrade)
            {
                swServer_free_buffer(serv, fd);
                conn->websocket_status = 0;
            }
            else
            {
                swHttpRequest_free(conn);
            }
        }
    }

#ifdef SW_REACTOR_USE_SESSION
    swSession *session = swServer_get_session(serv, conn->session_id);
    session->fd = 0;
#endif

    /**
     * reset maxfd, for connection_list
     */
    if (fd == swServer_get_maxfd(serv))
    {
        SwooleGS->lock.lock(&SwooleGS->lock);
        int find_max_fd = fd - 1;
        swTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);
        /**
         * Find the new max_fd
         */
        for (; serv->connection_list[find_max_fd].active == 0 && find_max_fd > swServer_get_minfd(serv); find_max_fd--)
            ;
        swServer_set_maxfd(serv, find_max_fd);
        SwooleGS->lock.unlock(&SwooleGS->lock);
    }

    return swReactor_close(reactor, fd);
}

/**
 * close the connection
 */
int swReactorThread_onClose(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        return swReactorProcess_onClose(reactor, event);
    }

    int fd = event->fd;
    swDataHead notify_ev;
    bzero(&notify_ev, sizeof(notify_ev));

    assert(fd % serv->reactor_num == reactor->id);
    assert(fd % serv->reactor_num == SwooleTG.id);

    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;

    swConnection *conn = swServer_connection_get(SwooleG.serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        return SW_ERR;
    }
    else if (serv->disable_notify)
    {
        swReactorThread_close(reactor, fd);
        return SW_OK;
    }
    else if (reactor->del(reactor, fd) == 0)
    {
        return SwooleG.factory->notify(SwooleG.factory, &notify_ev);
    }
    else
    {
        return SW_ERR;
    }
}

int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id)
{
    swServer *serv = SwooleG.serv;

    int ret = -1;
    swWorker *worker = &(serv->workers[target_worker_id]);

    //reactor thread
    if (SwooleTG.type == SW_THREAD_REACTOR)
    {
        int pipe_fd = worker->pipe_master;
        int thread_id = serv->connection_list[pipe_fd].from_id;
        swReactorThread *thread = swServer_get_thread(serv, thread_id);
        swLock *lock = serv->connection_list[pipe_fd].object;

        //lock thread
        lock->lock(lock);

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
                if (thread->reactor.set(&thread->reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
                {
                    swSysError("reactor->set(%d, PIPE | READ | WRITE) failed.", pipe_fd);
                }
                goto append_pipe_buffer;
            }
        }
        else
        {
            append_pipe_buffer:
            if (buffer->length > serv->pipe_buffer_size)
            {
                swYield();
                swSocket_wait(pipe_fd, SW_SOCKET_OVERFLOW_WAIT, SW_EVENT_WRITE);
            }
            if (swBuffer_append(buffer, data, len) < 0)
            {
                swWarn("append to pipe_buffer failed.");
                ret = SW_ERR;
            }
            else
            {
                ret = SW_OK;
            }
        }
        //release thread lock
        lock->unlock(lock);
    }
    //master/udp thread
    else
    {
        int pipe_fd = worker->pipe_master;
        ret = swSocket_write_blocking(pipe_fd, data, len);
    }
    return ret;
}

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

void swReactorThread_set_protocol(swServer *serv, swReactor *reactor)
{
    //UDP Packet
    reactor->setHandle(reactor, SW_FD_UDP, swReactorThread_onPackage);
    //Write
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, swReactorThread_onWrite);
    //Read
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, swReactorThread_onRead);

    swListenPort *ls = NULL;
    //listen the all tcp port
    LL_FOREACH(serv->listen_list, ls)
    {
        if (!swSocket_is_dgram(ls->type))
        {
        	swPort_set_protocol(ls);
        }
    }
}

int swReactorThread_create(swServer *serv)
{

    ///init reactor thread pool
    serv->reactor_threads = SwooleG.memory_pool->alloc(SwooleG.memory_pool, (serv->reactor_num * sizeof(swReactorThread)));
    if (!serv->reactor_threads)
    {
        swError("calloc[reactor_threads] fail.alloc_size=%d", (int )(serv->reactor_num * sizeof(swReactorThread)));
        return SW_ERR;
    }

    /**
     * alloc the memory for connection_list
     */
    serv->connection_list = (serv->factory_mode == SW_MODE_PROCESS)?
                        sw_shm_calloc(serv->max_connection, sizeof(swConnection)):
                        sw_calloc(serv->max_connection, sizeof(swConnection));

    if (!serv->connection_list)
    {
        swError("calloc[1] failed");
        return SW_ERR;
    }

    //create factry object
    int ret = (serv->factory_mode == SW_MODE_THREAD)?
              swFactoryThread_create(&(serv->factory), serv->worker_num):
              ((serv->factory_mode == SW_MODE_PROCESS)? swFactoryProcess_create(&(serv->factory), serv->worker_num):
              swFactory_create(&(serv->factory)));

    if (ret < 0)
    {
        swError("create factory failed");
    }

    return ret < 0? SW_ERR:SW_OK;
}

/**
 * proxy模式
 * 在单独的n个线程中接受维持TCP连接
 */
int swReactorThread_start(swServer *serv)
{
    swReactor *main_reactor = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swReactor));
    if (swReactor_init(main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        swError("Reactor create error");
        return SW_ERR;
    }

    /**
    * master thread loop
    */
    SwooleTG.type = SW_THREAD_MASTER;
    SwooleTG.factory_target_worker = -1;
    SwooleTG.factory_lock_target = 0;
    SwooleTG.id = 0;
    SwooleTG.update_time = 1;

    SwooleG.main_reactor = main_reactor;
    SwooleG.pid = getpid();
    SwooleG.process_type = SW_PROCESS_MASTER;

    main_reactor->thread = 1;
    main_reactor->socket_list = serv->connection_list;
    main_reactor->disable_accept = 0;
    main_reactor->enable_accept = swServer_enable_accept;

#ifdef HAVE_SIGNALFD
    if (SwooleG.use_signalfd)
    {
        swSignalfd_setup(main_reactor);
    }
#endif

    swServer_store_listen_socket(serv);

    //listen UDP, 一个端口一个线程监听
    if (serv->have_udp_sock == 1 && swUDPThread_start(serv) < 0)
    {
        swError("udp thread start failed.");
        return SW_ERR;
    }

#ifdef HAVE_REUSEPORT
    SwooleG.reuse_port = 0;
#endif

    //listen TCP
    if (serv->have_tcp_sock == 1 && swTCPThread_start(serv) < 0)
    {
        swError("tcp thread start failed.");
        return SW_ERR;
    }

    /**
     * heartbeat thread
     */
    if (serv->heartbeat_check_interval >= 1 && serv->heartbeat_check_interval <= serv->heartbeat_idle_time)
    {
        swTrace("hb timer start, time: %d live time:%d", serv->heartbeat_check_interval, serv->heartbeat_idle_time);
        swHeartbeatThread_start(serv);
    }

    /**
     * set a special id
     */
    main_reactor->id = serv->reactor_num;
    main_reactor->ptr = serv;
    main_reactor->setHandle(main_reactor, SW_FD_LISTEN, swServer_master_onAccept);

    if (serv->onStart)
    {
        serv->onStart(serv);
    }

    struct timeval tmo;
    tmo.tv_sec = 1; //for seconds timer
    tmo.tv_usec = 0;
    return main_reactor->wait(main_reactor, &tmo);;
}

int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length)
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

void swReactorThread_free(swServer *serv)
{
    if (SwooleGS->start == 0)
    {
        return;
    }

    if (serv->have_tcp_sock == 1)
    {
    	int i = 0;
    	swReactorThread *thread = NULL;
        for (i = 0; i < serv->reactor_num; i++)
        {
            thread = &(serv->reactor_threads[i]);
            if (thread->reactor.running && thread->thread_id && pthread_cancel(thread->thread_id) != 0)
            {
            	swSysError("pthread_cancel(%ld) failed.",(long)thread->thread_id);
            }
            thread->reactor.running = 0;

            //wait thread
            if (thread->thread_id && pthread_join(thread->thread_id, NULL) != 0)
            {
                swSysError("pthread_join(%ld) failed.", (long)thread->thread_id);
            }

            //release the lock
            SwooleGS->lock.unlock(&SwooleGS->lock);
#ifdef SW_USE_RINGBUFFER
            thread->buffer_input->destroy(thread->buffer_input);
#endif
        }
    }

    if (serv->have_udp_sock == 1)
    {
        swListenPort *ls;
        LL_FOREACH(serv->listen_list, ls)
        {
            if (swSocket_is_dgram(ls->type))
            {
                if (ls->thread_id && pthread_cancel(ls->thread_id) != 0)
                {
                	swSysError("pthread_cancel(%ld) failed.",(long)ls->thread_id);
                }

                if (ls->thread_id && pthread_join(ls->thread_id, NULL) != 0)
                {
                	swSysError("pthread_join(%ld) failed.", (long)ls->thread_id);
                }
            }
        }
    }
}
