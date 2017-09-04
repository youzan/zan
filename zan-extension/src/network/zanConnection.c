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
#include "swSocket.h"
#include "swPort.h"
#include "swBaseOperator.h"

#include "zanServer.h"
#include "zanAtomic.h"
#include "zanGlobalDef.h"
#include "zanSocket.h"
#include "zanConnection.h"
#include "zanLog.h"

/////TODO:::Test.....

static void zan_net_disable_accept(swReactor *reactor);
//static swConnection* zan_connection_create(zanServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id);

void zan_net_enableAccept(swReactor *reactor)
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

static void zan_net_disable_accept(swReactor *reactor)
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

int zan_net_onAccept(swReactor *reactor, swEvent *event)
{
    zanServer    *serv    = ServerG.serv;
    zanServerSet *servSet = &ServerG.servSet;
    socklen_t     client_addrlen = 0;
    swListenPort *listen_host    = NULL;
    swSocketAddress client_addr;

    //swReactor *sub_reactor = NULL;
    client_addrlen = sizeof(client_addr);
    listen_host    = serv->connection_list[event->fd].object;

    //SW_ACCEPT_AGAIN
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
                        zan_net_disable_accept(reactor);
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

        //zanTrace("[NetWorker] Accept new connection. maxfd=%d|reactor_id=%d|new_fd=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= servSet->max_connection)
        {
            zanWarn("Too many connections [now: %d], close it.", new_fd);
            close(new_fd);
            return ZAN_OK;
        }
#if 0
        //add to connection_list
        int reactor_id = reactor->id;//new_fd % serv->reactor_num;
        swConnection *conn = zan_connection_create(serv, listen_host, new_fd, event->fd, reactor_id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        conn->socket_type = listen_host->type;

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
#endif

        //new_connection function must before reactor->add
        int events;
        if (serv->onConnect && !listen_host->ssl)
        {
            zanWarn("new clinet connect, notify to worker, new_fd=%d", new_fd);
            //conn->connect_notify = 1;
            events = ZAN_EVENT_WRITE;
        }
        else
        {
            events = ZAN_EVENT_READ;
        }

        if (reactor->add(reactor, new_fd, SW_FD_TCP | events) < 0)
        {
            zanError("reactor add new_fd=%d failed", new_fd);
            //bzero(conn, sizeof(swConnection));
            close(new_fd);
            return ZAN_OK;
        }

#ifdef SW_ACCEPT_AGAIN
        continue;
#else
        break;
#endif
    }
    return ZAN_OK;
}

#if 0
static swConnection* zan_connection_create(zanServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    swConnection* connection = NULL;

    sw_stats_incr(&ServerStatsG->accept_count);
    sw_stats_incr(&ServerStatsG->connection_count);

    if (fd > swServer_get_maxfd(serv))
    {
        //swServer_set_maxfd(serv, fd);
    }

    connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(swConnection));
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

    connection->fd = fd;
    connection->from_id = reactor_id;
    connection->from_fd = from_fd;
    connection->connect_time = ServerGS->now;
    connection->last_time    = ServerGS->now;
    connection->active = 1;

#ifdef SW_REACTOR_SYNC_SEND
    if (!ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    uint32_t session_id = 1;
    swSession *session = NULL;

    zan_spinlock(&ServerGS->spinlock);
    int index = 0;
    while (index++ < ServerG.servSet.max_connection)
    {
        session_id = ServerGS->session_round++;
        if (session_id == 0)
        {
            session_id = 1;
            ServerGS->session_round = 1;
        }
        session = zanServer_get_session(serv, session_id);

        if (session->fd == 0)
        {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->from_id;
            break;
        }
    }

    zan_spinlock_release(&ServerGS->spinlock);
    connection->session_id = session_id;
#endif
    return connection;
}
#endif
