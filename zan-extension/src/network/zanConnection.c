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
#include "swBaseOperator.h"
#include "swSocket.h"

#include "zanServer.h"
#include "zanGlobalDef.h"
#include "zanSocket.h"
#include "zanConnection.h"
#include "zanLog.h"

static void zanReactor_disableAccept(swReactor *reactor);
static swConnection* zanConnection_create(zanServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id);

void zanReactor_enableAccept(swReactor *reactor)
{
    swListenPort *ls = NULL;
    LL_FOREACH(ServerG.serv->listen_list, ls)
    {
        //UDP
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }
        reactor->add(reactor, ls->sock, SW_FD_LISTEN);
    }
}

static void zanReactor_disableAccept(swReactor *reactor)
{
    swListenPort *ls = NULL;

    LL_FOREACH(ServerG.serv->listen_list, ls)
    {
        //non udp
        if (!swSocket_is_dgram(ls->type))
        {
            reactor->del(reactor, ls->sock);
        }
    }
}

int zanReactor_onAccept(swReactor *reactor, swEvent *event)
{
    zanServer    *serv    = ServerG.serv;
    zanServerSet *servSet = &ServerG.servSet;

    int network_index = 0;
    int networker_id  = ServerWG.worker_id;
    socklen_t     client_addrlen = 0;
    swListenPort *listen_host    = NULL;
    swSocketAddress client_addr;

    client_addrlen = sizeof(client_addr);
    network_index  = zanServer_get_networker_index(networker_id);
    listen_host    = serv->connection_list[network_index][event->fd].object;

    int index = 0;
    for (index = 0; index < SW_ACCEPT_MAX_COUNT; index++)
    {
        int new_fd = 0;
        bzero(&client_addr, sizeof(swSocketAddress));

#ifdef HAVE_ACCEPT4
        new_fd = accept4(event->fd, (struct sockaddr*)&client_addr, &client_addrlen, SOCK_NONBLOCK|SOCK_CLOEXEC);
#else
        new_fd = accept(event->fd, (struct sockaddr*)&client_addr, &client_addrlen);
#endif

        if (new_fd < 0)
        {
            switch (errno)
            {
                case EAGAIN:
                    return ZAN_OK;
                case EINTR:
                    continue;
                default:
                    if (errno == EMFILE || errno == ENFILE)
                    {
                        zanWarn("accept failed 0, errno=%d:%s", errno, strerror(errno));
                        zanReactor_disableAccept(reactor);
                        reactor->disable_accept = 1;
                    }
                    zanWarn("accept failed, errno=%d:%s", errno, strerror(errno));
                    return ZAN_OK;
            }
        }
#ifndef HAVE_ACCEPT4
        else
        {
            zan_set_nonblocking(new_fd, 1);
        }
#endif

        uint32_t connection_num = zanServer_get_connection_num(serv);
        zanDebug("[NetWorker] Accept new connection. connection_num=%d|networker_id/reactor_id=%d|new_fd=%d", connection_num, reactor->id, new_fd);

        //TODO::: too many connection; max_connection/networker_num
        if (connection_num >= servSet->max_connection)
        {
            zanWarn("Too many connections [now: %d], max_connection=%d, close it.", new_fd, servSet->max_connection);
            close(new_fd);
            return ZAN_OK;
        }

        zanDebug("new_fd=%d, sockfd event->fd=%d, reactor->id=%d， networker_id=%d", new_fd, event->fd, reactor->id, networker_id);
        //add to connection_list
        swConnection *conn = zanConnection_create(serv, listen_host, new_fd, event->fd, reactor->id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        conn->socket_type = listen_host->type;

        zan_stats_incr(&ServerStatsG->accept_count);
        zan_stats_incr(&ServerStatsG->connection_num);

#ifdef SW_USE_OPENSSL
        if (listen_host->ssl)
        {
            if (swSSL_create(conn, listen_host->ssl_context, 0) < 0)
            {
                bzero(conn, sizeof(swConnection));
                close(new_fd);
                return SW_OK;
            }
        }
        else
        {
            conn->ssl = NULL;
        }
#endif

        //new_connection function must before reactor->add
        int events = SW_EVENT_READ;
        if (serv->onConnect && !listen_host->ssl)
        {
            zanDebug("new clinet connect, set connect_notify=1, new_fd=%d", new_fd);
            conn->connect_notify = 1;
            events |= SW_EVENT_WRITE;
        }

        if (reactor->add(reactor, new_fd, SW_FD_TCP | events) < 0)
        {
            zanError("networker, reactor->add new_fd=%d failed, events=%d", new_fd, SW_FD_TCP | events);
            bzero(conn, sizeof(swConnection));
            close(new_fd);
            return ZAN_OK;
        }
        //zanDebug("networker accept, reactor->add new_fd=%d, events=%d", new_fd, SW_FD_TCP | events);

#ifdef SW_ACCEPT_AGAIN
        continue;
#else
        break;
#endif
    }
    return ZAN_OK;
}

static swConnection* zanConnection_create(zanServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    int networker_id    = ServerWG.worker_id;
    int networker_index = zanServer_get_networker_index(networker_id);

    if (fd > zanServer_get_maxfd(serv, networker_index))
    {
        zanServer_set_maxfd(serv, networker_index, fd);
    }
    if (fd < zanServer_get_minfd(serv, networker_index) || 0 == zanServer_get_minfd(serv, networker_index))
    {
        zanServer_set_minfd(serv, networker_index, fd);
    }

    zanDebug("-------------minfd=%d, maxfd=%d", zanServer_get_minfd(serv, networker_index), zanServer_get_maxfd(serv, networker_index));
    swConnection* connection = zanServer_get_connection(serv, networker_id, fd);
    bzero(connection, sizeof(swConnection));

    connection->fd = fd;
    connection->active  = 1;
    connection->from_id = reactor_id;
    connection->from_fd = from_fd;                    //listen sockfd
    connection->networker_id = networker_id;
    connection->last_time    = ServerGS->server_time;
    connection->connect_time = ServerGS->server_time;

    if (ls->open_tcp_nodelay)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) < 0)
        {
            zanError("setsockopt(TCP_NODELAY) failed.");
        }
        else
        {
            connection->tcp_nodelay = 1;
        }
    }

#ifdef HAVE_TCP_NOPUSH
    //TCP NOPUSH
    if (ls->open_tcp_nopush)
    {
        connection->tcp_nopush = 1;
    }
#endif

#ifdef SW_REACTOR_SYNC_SEND
    if (!ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    uint32_t session_id = 1;
    zanSession *session = NULL;

    sw_spinlock(&ServerGS->spinlock);
    int index = 0;
    while (index++ < ServerG.servSet.max_connection)
    {
        session_id = ServerGS->session_round++;
        if (session_id == 0)
        {
            session_id = 1;
            ServerGS->session_round = 1;
        }
        zanDebug("session_id=%d, index=%d", session_id, index);
        session = zanServer_get_session(serv, session_id);

        if (session->accept_fd == 0)
        {
            session->accept_fd    = fd;
            session->session_id   = session_id;
            session->reactor_id   = reactor_id;
            session->networker_id = networker_id;
            break;
        }
    }

    sw_spinlock_release(&ServerGS->spinlock);
    connection->session_id = session_id;
#endif
    return connection;
}

int zanNetworker_dispatch(swConnection *conn, char *data, uint32_t length)
{
    zanFactory *factory = ServerG.factory;
    swDispatchData task;
    memset(&task, 0, sizeof(task));

    task.data.info.fd = conn->fd;
    task.data.info.from_id = conn->from_id;
    task.data.info.type = SW_EVENT_PACKAGE_START;
    task.data.info.networker_id = conn->networker_id;
    task.target_worker_id = -1;

    zanTrace("send string package, size=%u bytes.", length);

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

        zanTrace("dispatch, type=%d|len=%d\n", task.data.info.type, task.data.info.len);

        if (factory->dispatch(factory, &task) < 0)
        {
            break;
        }
    }

    return ZAN_OK;
}
