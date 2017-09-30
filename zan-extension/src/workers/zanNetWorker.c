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
#include "swSignal.h"
#include "swBaseOperator.h"
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
void zanNetWorker_signal_handler(int signo);

static int zanNetworker_loop(zanProcessPool *pool, zanWorker *worker);
static void zanNetworker_onStart(zanProcessPool *pool, zanWorker *worker);
static void zanNetworker_onStop(zanProcessPool *pool, zanWorker *worker);
static void zanNetWorker_signal_init(void);
static void zanPool_networker_free(zanProcessPool *pool);

static int zanNetworker_tcp_setup(swReactor *reactor, zanServer *serv);
static int zanNetworker_onPipeReceive(swReactor *reactor, swEvent *event);
static int zanNetworker_onPipeWrite(swReactor *reactor, swEvent *event);
static int zanNetworker_onRead(swReactor *reactor, swEvent *event);
static int zanNetworker_onWrite(swReactor *reactor, swEvent *event);
static int zanNetworker_send(swSendData *_send);

static int zanNetworker_udp_setup(zanServer *serv);
static int zanNetworker_dgram_loop(swThreadParam *param);
static int zanNetworker_onPacket(swReactor *reactor, swEvent *event);

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

static void zanNetWorker_signal_init(void)
{
    swSignal_set(SIGHUP, NULL, 1, 0);
    swSignal_set(SIGPIPE, NULL, 1, 0);
    swSignal_set(SIGUSR1, NULL, 1, 0);
    swSignal_set(SIGUSR2, NULL, 1, 0);
    swSignal_set(SIGTERM, zanNetWorker_signal_handler, 1, 0);
    swSignal_set(SIGALRM, swSystemTimer_signal_handler, 1, 0);
#ifdef SIGRTMIN
    swSignal_set(SIGRTMIN, zanNetWorker_signal_handler, 1, 0);
#endif
}

void zanNetWorker_signal_handler(int signo)
{
    switch (signo)
    {
		case SIGTERM:
			zanWarn("signal SIGTERM coming");
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
				zanWorker worker = ServerGS->net_workers.workers[worker_id];
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

static void zanNetworker_onStart(zanProcessPool *pool, zanWorker *worker)
{
    //zanWarn("networker onStart....");
	zanNetWorker_signal_init();
	return;
}

static void zanNetworker_onStop(zanProcessPool *pool, zanWorker *worker)
{
    ///TODO:::
    zanWarn("networker onStop, worker_id=%d, process_types=%d", worker->worker_id, worker->process_type);
	return;
}


static int zanNetworker_loop(zanProcessPool *pool, zanWorker *worker)
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
    if (serv->have_udp_sock == 1 && ZAN_OK != zanNetworker_udp_setup(serv))
    {
        zanWarn("reactor udp setup failed.");
        return ZAN_ERR;
    }

    //TCP
    if (serv->have_tcp_sock == 1 && ZAN_OK != zanNetworker_tcp_setup(reactor, serv))
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

    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_READ, zanNetworker_onPipeReceive);
    reactor->setHandle(reactor, SW_FD_PIPE | SW_EVENT_WRITE, zanNetworker_onPipeWrite);

    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_READ, zanNetworker_onRead);
    reactor->setHandle(reactor, SW_FD_TCP | SW_EVENT_WRITE, zanNetworker_onWrite);

    int pipe_fd = -1;
    swConnection *conn_pipe = NULL;
    for (int index = 0; index < ServerG.servSet.worker_num; index++)
    {
        zanWorker *worker = zanServer_get_worker(serv, index);
        pipe_fd   = worker->pipe_master;
        conn_pipe = zanServer_get_connection(serv, ServerWG.worker_id, pipe_fd);

        //for request
        swBuffer *buffer = swBuffer_new(sizeof(swEventData));
        if (!buffer)
        {
            zanError("create buffer failed.");
            return ZAN_ERR;
        }

        conn_pipe->in_buffer = buffer;
        conn_pipe->fd = pipe_fd;
        conn_pipe->from_id = reactor->id;
        conn_pipe->networker_id = ServerWG.worker_id;
        //conn_pipe->object = sw_malloc(sizeof(zanLock));

        zan_set_nonblocking(pipe_fd, 1);
        reactor->add(reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ);
    }

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
/*
#ifdef SW_REACTOR_RECV_AGAIN
    while (1)
#endif
    {
*/
    while (1)
    {
        n = read(ev->fd, &resp, sizeof(resp));
        if (n > 0)
        {
            memcpy(&_send.info, &resp.info, sizeof(resp.info));
            if (_send.info.type == SW_EVENT_DENY_REQUEST) {
                int target_worker_id = _send.info.worker_id;
                ServerGS->event_workers.workers[target_worker_id].deny_request = 1;
                zanTrace("set worker deny_request, [dst_work_id=%d]", target_worker_id);
                return ZAN_OK;
            } else if(_send.info.type == SW_EVENT_DENY_EXIT) {
                int target_worker_id = _send.info.worker_id;
                ServerGS->event_workers.workers[target_worker_id].deny_request = 0;
                zanTrace("set worker accept request, [work_id=%d]", target_worker_id);
                return ZAN_OK;
            }

            if (_send.info.from_fd == SW_RESPONSE_SMALL)
            {
                zanTrace("small response, data_type=%d, session_id=%d, from_worker_id=%d, pipe_fd=%d",
                          _send.info.from_fd, _send.info.fd, _send.info.worker_id, ev->fd);
                _send.data = resp.data;
                _send.length = resp.info.len;
                zanNetworker_send(&_send);
                return ZAN_OK;
            }
            else
            {
                zanTrace("big response, data_type=%d, session_id=%d, from_worker_id=%d, pipe_fd=%d",
                          _send.info.from_fd, _send.info.fd, _send.info.worker_id, ev->fd);
                memcpy(&pkg_resp, resp.data, sizeof(pkg_resp));
                worker = zanServer_get_worker(ServerG.serv, pkg_resp.worker_id);

                _send.data = worker->send_shm;
                _send.length = pkg_resp.length;

                zanNetworker_send(&_send);
                worker->lock.unlock(&worker->lock);
                return ZAN_OK;
            }
        }
        else if (errno == EAGAIN)
        {
            return ZAN_OK;
        }
        else if (errno == EINTR)
        {
            zanWarn("read(worker_pipe) EINTR, n=%d, errno:%d:%s", n, errno, strerror(errno));
            continue;
        }
        else
        {
            zanError("read(worker_pipe) failed, n=%d, errno:%d:%s", n, errno, strerror(errno));
            return ZAN_ERR;
        }
    }
}

//[Networker] worker pipe can write.
static int zanNetworker_onPipeWrite(swReactor *reactor, swEvent *ev)
{
    int ret = 0;
    zanServer *serv = ServerG.serv;
    int networker_id = ServerWG.worker_id;
    swConnection *conn = zanServer_get_connection(serv, networker_id, ev->fd);

    zanDebug("onPipeWrite: networker_id=%d, pipe_fd=%d, from_id=%d, type=%d", networker_id, ev->fd, ev->from_id, ev->type);

    swBuffer *buffer = conn->in_buffer;
    //while (!swBuffer_empty(buffer))
    if (!swBuffer_empty(buffer))
    {
        swBuffer_trunk *trunk  = swBuffer_get_trunk(buffer);
        swEventData *send_data = trunk->store.ptr;

        //server active close, discard data.
        if (swEventData_is_stream(send_data->info.type))
        {
            conn = zanServer_verify_connection(serv, send_data->info.fd);
            if (conn == NULL || conn->closed)
            {
                if (conn && conn->closed)
                {
                    zanTrace("Session#%d is closed by server.", send_data->info.fd);
                }
                swBuffer_pop_trunk(buffer, trunk);
                return ZAN_OK;
            }
        }

        while (1)
        {
            ret = write(ev->fd, trunk->store.ptr, trunk->length);
            if (ret < 0)
            {
#ifdef HAVE_KQUEUE
                if (errno == EAGAIN || errno == ENOBUFS)
#else
                if (errno == EAGAIN)
#endif
                {
                    return ZAN_OK;
                }
                else if (errno == EINTR)
                {
                    continue;
                }
                else
                {
                    zanError("write pipe_fd=%d failed, errno=%d:%s, ret=%d, data=%s", ev->fd, errno, strerror(errno), ret, send_data->data);
                    return ZAN_ERR;
                }
            }
            else
            {
                swBuffer_pop_trunk(buffer, trunk);
                break;
            }
        }
    }

    //remove EPOLLOUT event
    if (swBuffer_empty(buffer))
    {
        ret = reactor->set(reactor, ev->fd, SW_FD_PIPE | SW_EVENT_READ);
        if (ret < 0)
        {
            zanError("reactor->set(%d) failed, networker_id=%d, reactor_id=%d", ev->fd, networker_id, reactor->id);
        }
    }

    return ZAN_OK;
}

static int zanNetworker_onRead(swReactor *reactor, swEvent *event)
{
    zanDebug("onRead in, fd=%d, listen_socket=%d, event->type=%d", event->fd, event->socket->from_fd, event->type);
    if (event->socket->from_fd == 0)  //from_fd: listen socket fd
    {
        zanWarn("from_fd==0");
        return ZAN_OK;
    }

    zanServer *serv = ServerG.serv;
    swListenPort *port = zanServer_get_port(serv, ServerWG.worker_id, event->fd);

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
    int networker_id = ServerWG.worker_id;
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
        zanDebug("notify worker connected, fd=%d, networker_id=%d", fd, networker_id);
        swDataHead connect_event;
        connect_event.fd   = fd;
        connect_event.type = SW_EVENT_CONNECT;
        connect_event.from_id = reactor->id;
        connect_event.networker_id = networker_id;

        if (serv->factory.notify(&serv->factory, &connect_event) < 0)
        {
            zanWarn("send notification SW_EVENT_CONNECT, [fd=%d] failed, networker_id=%d.", fd, networker_id);
        }
        conn->connect_notify = 0;
        return reactor->set(reactor, fd, SW_EVENT_TCP | SW_EVENT_READ);
    }
    else if (conn->close_notify)
    {
        swDataHead close_event;
        close_event.fd   = fd;
        close_event.type = SW_EVENT_CLOSE;
        close_event.from_id = reactor->id;
        close_event.networker_id = networker_id;

        if (serv->factory.notify(&serv->factory, &close_event) < 0)
        {
            zanWarn("send notification SW_EVENT_CLOSE [fd=%d] failed, networker_id=%d.", fd, networker_id);
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
    //while (!swBuffer_empty(conn->out_buffer))
    if (!swBuffer_empty(conn->out_buffer))   ///TODO:::
    {
        chunk = swBuffer_get_trunk(conn->out_buffer);
        if (chunk->type == SW_CHUNK_CLOSE)
        {
            reactor->close(reactor, fd);
            swBuffer_pop_trunk(conn->out_buffer, chunk);
            return ZAN_OK;
        }
        else if (chunk->type == SW_CHUNK_SENDFILE)
        {
            zanWarn("-----------------test sendfile:");
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
                reactor->close(reactor, fd);
                return ZAN_OK;
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
    int networker_id = ServerWG.worker_id;

    bzero(&notify_ev, sizeof(notify_ev));
    notify_ev.from_id = reactor->id;
    notify_ev.fd = fd;
    notify_ev.type = SW_EVENT_CLOSE;
    notify_ev.networker_id = networker_id;

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
    uint32_t session_id   = _send->info.fd;
    uint32_t _send_length = _send->length;
    void      *_send_data = _send->data;

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
            return ZAN_OK;
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
                return ZAN_OK;
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
                    return ZAN_ERR;
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
            return ZAN_ERR;
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

int zanNetworker_send2worker(void *data, int len, uint16_t worker_id)
{
    int ret = ZAN_OK;
    zanServer *serv   = ServerG.serv;
    zanWorker *worker = zanServer_get_worker(serv, worker_id);
    int pipe_fd = worker->pipe_master;

    if (serv->have_udp_sock)
    {
        zanDebug("write to worker pipdfd=%d, len=%d", pipe_fd, len);
        return swSocket_write_blocking(pipe_fd, data, len);
    }

    int networker_id = ServerWG.worker_id;
    swConnection *conn_pipe = zanServer_get_connection(serv, networker_id, pipe_fd);

    swBuffer *buffer = conn_pipe->in_buffer;
    if (swBuffer_empty(buffer))
    {
        while (1)
        {
            ret = write(pipe_fd, (void *) data, len);
            if (ret > 0)
            {
                return ZAN_OK;
            }

#ifdef HAVE_KQUEUE
            if (errno == EAGAIN || errno == ENOBUFS)
#else
            if (errno == EAGAIN)
#endif
            {
                zanWarn("write pipd_fd=%d EAGAIN, append to buffer, errno=%d:%s.", pipe_fd, errno, strerror(errno));
                break;
            }
            else if (errno == EINTR)
            {
                zanDebug("write pipd_fd=%d EINTR, errno=%d:%s.", pipe_fd, errno, strerror(errno));
                continue;
            }
            else
            {
                zanError("write pipd_fd=%d failed, errno=%d:%s.", pipe_fd, errno, strerror(errno));
                return ZAN_ERR;
            }
        }
    }

    zanDebug("append_pipe_buffer: pipe_fd=%d, length=%d, pipe_buffer_size=%d", pipe_fd, buffer->length, ServerG.servSet.pipe_buffer_size);
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

    swReactor *reactor = ServerG.main_reactor;
    if (reactor->set(reactor, pipe_fd, SW_FD_PIPE | SW_EVENT_READ | SW_EVENT_WRITE) < 0)
    {
        zanError("reactor->set(%d, PIPE | READ | WRITE) failed.", pipe_fd);
        ret = ZAN_ERR;
    }

    return ret;
}

//close connection
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
        //zanTrace("set_maxfd=%d|close_fd=%d\n", find_max_fd, fd);

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
                    task.data.info.networker_id = conn->networker_id;
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
                zanServer_connection_ready(ServerG.serv, conn->fd, conn->from_id, conn->networker_id);
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

static int zanNetworker_udp_setup(zanServer *serv)
{
    pthread_t thread_id;
    swThreadParam *param = NULL;
    swListenPort *ls = NULL;
    int index = 0;
    int networker_index = zanServer_get_networker_index(ServerWG.worker_id);

    LL_FOREACH(serv->listen_list, ls)
    {
        param = ServerG.g_shm_pool->alloc(ServerG.g_shm_pool, sizeof(swThreadParam));

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[networker_index][ls->sock].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else
            {
                serv->connection_list[networker_index][ls->sock].info.addr.inet_v6.sin6_port = htons(ls->port);
            }

            serv->connection_list[networker_index][ls->sock].fd = ls->sock;
            serv->connection_list[networker_index][ls->sock].socket_type = ls->type;
            serv->connection_list[networker_index][ls->sock].object = ls;

            param->object = ls;
            param->pti = index++;

            if (pthread_create(&thread_id, NULL, (void * (*)(void *)) zanNetworker_dgram_loop, (void *) param) < 0)
            {
                zanError("pthread_create[udp_listener] fail");
                return ZAN_ERR;
            }

            ls->thread_id = thread_id;
        }
    }

    return ZAN_OK;
}

static int zanNetworker_dgram_loop(swThreadParam *param)
{
    swEvent event;
    swListenPort *ls = param->object;


    //ServerTG.factory_lock_target = 0;
    //ServerTG.factory_target_worker = -1;
    ServerTG.id = param->pti;
    ServerTG.type = SW_THREAD_UDP;

    //swSignal_none();

    //blocking
    int fd = ls->sock;
    zan_set_nonblocking(fd, 0);
    event.fd = fd;

    while (ServerG.running == 1)
    {
        zanNetworker_onPacket(NULL, &event);
    }

    pthread_exit(0);
    return 0;
}


/**
 * for udp
 */
static int zanNetworker_onPacket(swReactor *reactor, swEvent *event)
{
    int fd = event->fd;
    int ret = -1;
    int networker_index = zanServer_get_networker_index(ServerWG.worker_id);

    swDispatchData task;
    swSocketAddress info;
    swDgramPacket pkt;

    zanServer *serv = ServerG.serv;
    swConnection *server_sock = &serv->connection_list[networker_index][fd];
    zanFactory *factory = ServerG.factory;

    info.len = sizeof(info.addr);
    bzero(&task.data.info, sizeof(task.data.info));
    task.data.info.from_fd = fd;

    //.......
    task.data.info.from_id     = ServerTG.id;
    task.data.info.networker_id = ServerWG.worker_id;

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
        zanDebug("recvfrom ret=%d, type=%d, data=%s, errno=%d:%s", ret, socket_type, packet, errno, strerror(errno));
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

        if (factory->dispatch(factory, &task) < 0)
        {
            return ZAN_ERR;
        }

        send_n -= task.data.info.len;
        if (send_n == 0)
        {
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
    }
    return ret;
}

zan_pid_t zanNetWorker_spawn(zanWorker *worker)
{
    pid_t pid = fork();
    zanProcessPool *pool = worker->pool;

    switch (pid)
    {
        //child
        case 0:
        {
            if (pool->onWorkerStart != NULL)
            {
                pool->onWorkerStart(pool, worker);
            }

            int ret_code = pool->main_loop(pool, worker);

            if (pool->onWorkerStop != NULL)
            {
                pool->onWorkerStop(pool, worker);
            }
            exit(ret_code);
            break;
        }
        case -1:
            zanSysError("fork failed.");
            break;
        //parent
        default:
            //remove old process
            //if (worker->worker_pid)
            //{
            //    swHashMap_del_int(pool->map, worker->worker_pid);
            //}
            worker->deleted = 0;
            worker->worker_pid = pid;
            //insert new process
            //swHashMap_add_int(pool->map, pid, worker);
            break;
    }
    return pid;
}

static void zanPool_networker_free(zanProcessPool *pool)
{
    int index = 0;
    zanPipe *_pipe = NULL;

    if (ZAN_UNSOCK == pool->workers[0].pipe_object->pipe_type)
    {
        for (index = 0; index < ServerG.servSet.net_worker_num; index++)
        {
            _pipe = &pool->pipes[index];
            _pipe->close(_pipe);
        }
        zan_free(pool->pipes);
    }
    else
    {
        pool->queue->close(pool->queue);
        zan_free(pool->queue);
    }

    if (pool->map)
    {
        swHashMap_free(pool->map);
    }

    for (index = 0; index < ServerG.servSet.net_worker_num; index++)
    {
        //TODO:::???
        zanWorker_free(&pool->workers[index]);
    }
    zan_shm_free(pool->workers);
}

void zan_networker_shutdown(zanProcessPool *pool)
{
    int index  = 0;
    int status = 0;
    zanWorker *worker = NULL;
    ServerG.running = 0;

    for (index = 0; index < ServerG.servSet.net_worker_num; ++index)
    {
        worker = &pool->workers[index];
		if(worker->worker_pid == -1)
		{
			zanWarn("this net worker is delete,worker_id=%d", worker->worker_id);
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
    zanPool_networker_free(pool);
}
