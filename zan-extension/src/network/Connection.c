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
#include <sys/stat.h>

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#include "list.h"
#include "swError.h"
#include "swSendfile.h"
#include "swConnection.h"
#include "swBaseOperator.h"
#include "zanServer.h"
#include "zanLog.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL        0
#endif

typedef struct {
    char *filename;
    uint16_t name_len;
    int fd;
    off_t filesize;
    off_t offset;
} swTask_sendfile;

int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk)
{
    int ret;
    swTask_sendfile *task = chunk->store.ptr;

#ifdef HAVE_TCP_NOPUSH
    if (task->offset == 0 && conn->tcp_nopush)
    {
        /**
         * disable tcp_nodelay
         */
        if (conn->tcp_nodelay)
        {
            int tcp_nodelay = 0;
            if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                zanError("setsockopt(TCP_NODELAY) failed.");
            }
        }
        /**
         * enable tcp_nopush
         */
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            zanError("swSocket_tcp_nopush() failed.");
        }
    }
#endif

    int sendn = (task->filesize - task->offset > SW_SENDFILE_TRUNK) ?
                SW_SENDFILE_TRUNK : task->filesize - task->offset;

#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        ret = swSSL_sendfile(conn, task->fd, &task->offset, sendn);
    }
    else
#endif
    {
        ret = swoole_sendfile(conn->fd, task->fd, &task->offset, sendn);
    }
    zanTrace("ret=%d|task->offset=%lld|sendn=%d|filesize=%lld", ret, (long long int)(task->offset), sendn, (long long int)(task->filesize));

    if (ret <= 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            zanError("sendfile() failed.");
            swBuffer_pop_trunk(conn->out_buffer, chunk);
            return ZAN_OK;
        case SW_CLOSE:
            conn->close_wait = 1;
            return ZAN_ERR;
        default:
            break;
        }
    }

    //sendfile finish
    if (task->offset >= task->filesize)
    {
        swBuffer_pop_trunk(conn->out_buffer, chunk);

#ifdef HAVE_TCP_NOPUSH
        if (conn->tcp_nopush)
        {
            /**
             * disable tcp_nopush
             */
            if (swSocket_tcp_nopush(conn->fd, 0) == -1)
            {
                zanError("swSocket_tcp_nopush() failed.");
            }

            /**
             * enable tcp_nodelay
             */
            if (conn->tcp_nodelay)
            {
                int value = 1;
                if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &value, sizeof(int)) == -1)
                {
                    zanError("setsockopt(TCP_NODELAY) failed.");
                }
            }
        }
#endif
    }
    return ZAN_OK;
}

/**
 * send buffer to client
 */
int swConnection_buffer_send(swConnection *conn)
{
    int ret, sendn;

    swBuffer *buffer = conn->out_buffer;
    swBuffer_trunk *trunk = swBuffer_get_trunk(buffer);
    sendn = trunk->length - trunk->offset;

    if (sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
        return ZAN_OK;
    }

    ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
    if (ret < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            zanError("send to fd[%d] failed.", conn->fd);
            break;
        case SW_CLOSE:
            conn->close_wait = 1;
            return ZAN_ERR;
        case SW_WAIT:
            conn->send_wait = 1;
            return ZAN_ERR;
        default:
            break;
        }
        return ZAN_OK;
    }
    //trunk full send
    else if (ret == sendn || sendn == 0)
    {
        swBuffer_pop_trunk(buffer, trunk);
    }
    else
    {
        trunk->offset += ret;
    }
    return ZAN_OK;
}

int swConnection_get_ip(swConnection *conn,char* addip,int len)
{
    if (len < SW_IP_MAX_LENGTH || !addip){
        zanError("swConnnection get ip cache len %d must more than %d\n",len,SW_IP_MAX_LENGTH);
        return ZAN_ERR;
    }

    const char  *ipstr = NULL;
    bzero(addip,len);
    if (swSocket_is_NET(conn->socket_type))
    {
        ipstr = inet_ntop(AF_INET,&conn->info.addr.inet_v4.sin_addr,addip,len);
    }
    else if (swSocket_is_NET6(conn->socket_type)){
        ipstr = inet_ntop(AF_INET6, &conn->info.addr.inet_v6.sin6_addr,addip,len);
    }

    return (NULL == ipstr)? ZAN_ERR:ZAN_OK;
}

int swConnection_get_port(swConnection *conn)
{
    if (swSocket_is_NET(conn->socket_type))
    {
        return ntohs(conn->info.addr.inet_v4.sin_port);
    }
    else if (swSocket_is_NET6(conn->socket_type))
    {
        return ntohs(conn->info.addr.inet_v6.sin6_port);
    }

    return ZAN_ERR;
}

ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags)
{
#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        int ret = 0;
        int written = 0;

        while(written < __n)
        {
            ret = swSSL_recv(conn, __buf + written, __n - written);
            if (__flags & MSG_WAITALL)
            {
                if (ret <= 0)
                {
                    return ret;
                }
                else
                {
                    written += ret;
                }
            }
            else
            {
                return ret;
            }
        }

        return written;
    }
    else
    {
        return recv(conn->fd, __buf, __n, __flags);
    }
#else
    return recv(conn->fd, __buf, __n, __flags);
#endif
}

int swConnection_send(swConnection *conn, void *__buf, size_t __n, int __flags)
{
#ifdef SW_USE_OPENSSL
    if (conn->ssl)
    {
        return swSSL_send(conn, __buf, __n);
    }
    else
    {
        return send(conn->fd, __buf, __n, __flags);
    }
#else
    return send(conn->fd, __buf, __n, __flags);
#endif
}

void swConnection_sendfile_destructor(swBuffer_trunk *chunk)
{
    swTask_sendfile *task = chunk->store.ptr;
    close(task->fd);
    sw_free(task->filename);
    sw_free(task);
}

int swConnection_sendfile_async(swConnection *conn, char *filename)
{
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        zanError("open(%s) failed.",filename);
        return ZAN_ERR;
    }

    size_t filelen = get_filelen(file_fd);
    if (filelen <= 0)
    {
        close(file_fd);
        return ZAN_ERR;
    }

    swTask_sendfile *task = sw_malloc(sizeof(swTask_sendfile));
    if (task == NULL)
    {
        close(file_fd);
        zanFatalError("malloc for swTask_sendfile failed.");
        return ZAN_ERR;
    }

    bzero(task, sizeof(swTask_sendfile));
    task->filename = strdup(filename);
    task->fd = file_fd;
    task->filesize = filelen;

    swBuffer_trunk *chunk = swConnection_get_out_buffer(conn, SW_CHUNK_SENDFILE);
    if (!chunk)
    {
        zanError("get out_buffer trunk failed.");
        swBuffer_trunk error_chunk;
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return ZAN_ERR;
    }

    chunk->store.ptr = (void *) task;
    chunk->destroy = swConnection_sendfile_destructor;

    return ZAN_OK;
}

swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type)
{
    swBuffer_trunk *trunk;
    if (conn->out_buffer == NULL)
    {
        conn->out_buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (conn->out_buffer == NULL)
        {
            return NULL;
        }
    }
    if (type == SW_CHUNK_SENDFILE)
    {
        trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_SENDFILE, 0);
    }
    else
    {
        trunk = swBuffer_get_trunk(conn->out_buffer);
        if (trunk == NULL)
        {
            trunk = swBuffer_new_trunk(conn->out_buffer, SW_CHUNK_DATA, conn->out_buffer->trunk_size);
        }
    }
    return trunk;
}

int swConnection_error(int err)
{
    switch (err)
    {
        case EFAULT:
            abort();
            return SW_ERROR;
        case EBADF:
        case ECONNRESET:
#ifdef __CYGWIN__
        case ECONNABORTED:
#endif
        case EPIPE:
        case ENOTCONN:
        case ETIMEDOUT:
        case ECONNREFUSED:
        case ENETDOWN:
        case ENETUNREACH:
        case EHOSTDOWN:
        case EHOSTUNREACH:
        case SW_ERROR_SSL_BAD_CLIENT:
            return SW_CLOSE;
        case EAGAIN:
#ifdef HAVE_KQUEUE
        case ENOBUFS:
#endif
        case 0:
            return SW_WAIT;
        default:
            return SW_ERROR;
    }
}

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
