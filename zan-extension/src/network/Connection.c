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



#include "swServer.h"
#include "swSendfile.h"
#include "swConnection.h"
#include "swBaseOperator.h"
#include "swLog.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#include <sys/stat.h>

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
                swSysError("setsockopt(TCP_NODELAY) failed.");
            }
        }
        /**
         * enable tcp_nopush
         */
        if (swSocket_tcp_nopush(conn->fd, 1) == -1)
        {
            swSysError("swSocket_tcp_nopush() failed.");
        }
    }
#endif

    int sendn = (task->filesize - task->offset > SW_SENDFILE_TRUNK) ?
                SW_SENDFILE_TRUNK : task->filesize - task->offset;
    ret = swoole_sendfile(conn->fd, task->fd, &task->offset, sendn);
    swTrace("ret=%d|task->offset=%lld|sendn=%d|filesize=%lld", ret, (long long int)(task->offset), sendn, (long long int)(task->filesize));

    if (ret <= 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("sendfile() failed.");
            swBuffer_pop_trunk(conn->out_buffer, chunk);
            return SW_OK;
        case SW_CLOSE:
            conn->close_wait = 1;
            return SW_ERR;
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
                swSysError("swSocket_tcp_nopush() failed.");
            }

            /**
             * enable tcp_nodelay
             */
            if (conn->tcp_nodelay)
            {
                int value = 1;
                if (setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &value, sizeof(int)) == -1)
                {
                    swSysError("setsockopt(TCP_NODELAY) failed.");
                }
            }
        }
#endif
    }
    return SW_OK;
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
        return SW_OK;
    }

    ret = swConnection_send(conn, trunk->store.ptr + trunk->offset, sendn, 0);
    if (ret < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("send to fd[%d] failed.", conn->fd);
            break;
        case SW_CLOSE:
            conn->close_wait = 1;
            return SW_ERR;
        case SW_WAIT:
            conn->send_wait = 1;
            return SW_ERR;
        default:
            break;
        }
        return SW_OK;
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
    return SW_OK;
}

swString* swConnection_get_string_buffer(swConnection *conn)
{
    swString *buffer = conn->object;
    if (buffer == NULL)
    {
        return swString_new(SW_BUFFER_SIZE);
    }
    else
    {
        return buffer;
    }
}

int swConnection_get_ip(swConnection *conn,char* addip,int len)
{
    if (len < SW_IP_MAX_LENGTH || !addip){
        swError("swConnnection get ip cache len %d must more than %d\n",len,SW_IP_MAX_LENGTH);
        return SW_ERR;
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

    return (NULL == ipstr)? SW_ERR:SW_OK;
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

    return SW_ERR;
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

int swConnection_sendfile_sync(swConnection *conn, char *filename, double timeout)
{
    if (conn->closed)
    {
        return SW_ERR;
    }

    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    int sock = conn->fd;
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        swSysError("open(%s) failed.", filename);
        return SW_ERR;
    }

    int iret = SW_OK;
    int sendn = 0;
    off_t offset = 0;
    size_t file_size = get_filelen(file_fd);
    if (file_size <= 0)
    {
        goto end;
    }

    while (offset < file_size)
    {
        if (swSocket_wait(sock, timeout_ms, SW_EVENT_WRITE) < 0)
        {
            iret = SW_ERR;
            goto end;
        }
        else
        {
            sendn = (file_size - offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : file_size - offset;
            if (swoole_sendfile(sock, file_fd, &offset, sendn) <= 0)
            {
                iret = SW_ERR;
                swSysError("sendfile(%d, %s) failed.", sock, filename);
                goto end;
            }
        }
    }

end:
    close(file_fd);
    return iret;
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
        swSysError("open(%s) failed.",filename);
        return SW_ERR;
    }

    size_t filelen = get_filelen(file_fd);
    if (filelen <= 0)
    {
        close(file_fd);
        return SW_ERR;
    }

    swTask_sendfile *task = sw_malloc(sizeof(swTask_sendfile));
    if (task == NULL)
    {
        close(file_fd);
        swFatalError("malloc for swTask_sendfile failed.");
        return SW_ERR;
    }

    bzero(task, sizeof(swTask_sendfile));
    task->filename = strdup(filename);
    task->fd = file_fd;
    task->filesize = filelen;

    swBuffer_trunk *chunk = swConnection_get_out_buffer(conn, SW_CHUNK_SENDFILE);
    if (!chunk)
    {
        swError("get out_buffer trunk failed.");
        swBuffer_trunk error_chunk;
        error_chunk.store.ptr = task;
        swConnection_sendfile_destructor(&error_chunk);
        return SW_ERR;
    }

    chunk->store.ptr = (void *) task;
    chunk->destroy = swConnection_sendfile_destructor;

    return SW_OK;
}


void swConnection_clear_string_buffer(swConnection *conn)
{
    swString *buffer = conn->object;
    if (buffer != NULL)
    {
        swString_free(buffer);
        conn->object = NULL;
    }
}

#if 0
swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn)
{
    swBuffer_trunk *trunk = NULL;
    swBuffer *buffer;

    if (conn->in_buffer == NULL)
    {
        buffer = swBuffer_new(SW_BUFFER_SIZE);
        if (buffer == NULL)
        {
            return NULL;
        }
        //new trunk
        trunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, buffer->trunk_size);
        if (trunk == NULL)
        {
            sw_free(buffer);
            return NULL;
        }
        conn->in_buffer = buffer;
    }
    else
    {
        buffer = conn->in_buffer;
        trunk = buffer->tail;
        if (trunk == NULL || trunk->length == buffer->trunk_size)
        {
            trunk = swBuffer_new_trunk(buffer, SW_CHUNK_DATA, buffer->trunk_size);
        }
    }
    return trunk;
}
#endif

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
