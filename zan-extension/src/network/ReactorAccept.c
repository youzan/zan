
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
#include "swError.h"
#include "swLog.h"
#include "swExecutor.h"
#include "swConnection.h"
#include "swBaseOperator.h"

static void swServer_disable_accept(swReactor *reactor);
static swConnection* swConnection_create(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id);

static void swServer_disable_accept(swReactor *reactor)
{
    swListenPort *ls = NULL;

    LL_FOREACH(SwooleG.serv->listen_list, ls)
    {
        //non udp
        if (!swSocket_is_dgram(ls->type))
        {
        	reactor->del(reactor, ls->sock);
        }
    }
}

static swConnection* swConnection_create(swServer *serv, swListenPort *ls, int fd, int from_fd, int reactor_id)
{
    swConnection* connection = NULL;

    sw_stats_atom_incr(&SwooleStats->accept_count);
    sw_stats_atom_incr(&SwooleStats->connection_num);

    if (fd > swServer_get_maxfd(serv))
    {
        swServer_set_maxfd(serv, fd);
    }

    connection = &(serv->connection_list[fd]);
    bzero(connection, sizeof(swConnection));

    //TCP Nodelay
    if (ls->open_tcp_nodelay)
    {
        int sockopt = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sockopt, sizeof(sockopt)) < 0)
        {
            swSysError("setsockopt(TCP_NODELAY) failed.");
        }
        connection->tcp_nodelay = 1;
    }

#ifdef HAVE_TCP_NOPUSH
    //TCP NOPUSH
    if (ls->open_tcp_nopush)
    {
        connection->tcp_nopush = 1;
    }
#endif

    connection->fd = fd;
    connection->from_id = serv->factory_mode == SW_MODE_SINGLE ? SwooleWG.id : reactor_id;
    connection->from_fd = from_fd;
    connection->connect_time = connection->last_time = SwooleGS->now;
    connection->active = 1;

#ifdef SW_REACTOR_SYNC_SEND
    if (serv->factory_mode != SW_MODE_THREAD && !ls->ssl)
    {
        connection->direct_send = 1;
    }
#endif

#ifdef SW_REACTOR_USE_SESSION
    uint32_t session_id = 1;
    swSession *session = NULL;

    /// 可以优化，这样遍历的查不可取
    sw_spinlock(&SwooleGS->spinlock);
    int index = 0;
    //get session id
    while (index++ < serv->max_connection)
    {
        session_id = SwooleGS->session_round++;
        if (session_id == 0)
        {
            session_id = 1;
            SwooleGS->session_round = 1;
        }
        session = swServer_get_session(serv, session_id);

        //vacancy
        if (session->fd == 0)
        {
            session->fd = fd;
            session->id = session_id;
            session->reactor_id = connection->from_id;
            break;
        }
    }

    sw_spinlock_release(&SwooleGS->spinlock);
    connection->session_id = session_id;
#endif

    return connection;
}

void swServer_enable_accept(swReactor *reactor)
{
    swListenPort *ls = NULL;
    LL_FOREACH(SwooleG.serv->listen_list, ls)
    {
        //UDP
        if (swSocket_is_dgram(ls->type))
        {
            continue;
        }

        reactor->add(reactor, ls->sock, SW_FD_LISTEN);
    }
}

int swServer_master_onAccept(swReactor *reactor, swEvent *event)
{
    swServer *serv = reactor->ptr;
    swReactor *sub_reactor = NULL;
    swSocketAddress client_addr;
    socklen_t client_addrlen = sizeof(client_addr);
    swListenPort *listen_host = serv->connection_list[event->fd].object;

    int new_fd = 0, ret = -1;
    int index;

    //SW_ACCEPT_AGAIN
    for (index = 0; index < SW_ACCEPT_MAX_COUNT; index++)
    {
#ifdef HAVE_ACCEPT4
	new_fd = accept4(event->fd,(struct sockaddr*)&client_addr,&client_addrlen,SOCK_NONBLOCK|SOCK_CLOEXEC);
#else
        new_fd = accept(event->fd, (struct sockaddr *) &client_addr, &client_addrlen);
#endif
        if (new_fd < 0)
        {
            switch (errno)
            {
            case EAGAIN:
                return SW_OK;
            case EINTR:
                continue;
            default:
                if (errno == EMFILE || errno == ENFILE)
                {
                    swServer_disable_accept(reactor);
                    reactor->disable_accept = 1;
                }

                swSysError("accept failed.");
                return SW_OK;
            }
        }
#ifndef HAVE_ACCEPT4
        else
        {
            swSetNonBlock(new_fd,1);
        }
#endif

        swTrace("[Master] Accept new connection. maxfd=%d|reactor_id=%d|conn=%d", swServer_get_maxfd(serv), reactor->id, new_fd);

        //too many connection
        if (new_fd >= serv->max_connection)
        {
            swWarn("Too many connections [now: %d].", new_fd);
            close(new_fd);
            return SW_OK;
        }

        int reactor_id = (serv->factory_mode == SW_MODE_SINGLE)? 0:new_fd % serv->reactor_num;

        //add to connection_list
        swConnection *conn = swConnection_create(serv, listen_host, new_fd, event->fd, reactor_id);
        memcpy(&conn->info.addr, &client_addr, sizeof(client_addr));
        sub_reactor = &serv->reactor_threads[reactor_id].reactor;
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
        /*
         * [!!!] new_connection function must before reactor->add
         */
        if (serv->factory_mode == SW_MODE_PROCESS)
        {
            int events;
            if (serv->onConnect && !listen_host->ssl)
            {
                conn->connect_notify = 1;
                events = SW_EVENT_WRITE;
            }
            else
            {
                events = SW_EVENT_READ;
            }
            ret = sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | events);
        }
        else
        {
            ret = sub_reactor->add(sub_reactor, new_fd, SW_FD_TCP | SW_EVENT_READ);
            if (ret >= 0 && serv->onConnect && !listen_host->ssl)
            {
                swServer_connection_ready(serv, new_fd, reactor->id);
            }
        }

        if (ret < 0)
        {
            bzero(conn, sizeof(swConnection));
            close(new_fd);
            return SW_OK;
        }

#ifdef SW_ACCEPT_AGAIN
        continue;
#else
        break;
#endif
    }
    return SW_OK;
}
