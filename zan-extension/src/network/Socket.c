/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include <sys/poll.h>
#include <sys/ioctl.h>

#include "swoole.h"
#include "swSocket.h"
#include "swReactor.h"
#include "swSendfile.h"
#include "swConnection.h"
#include "zanMemory/zanMemory.h"
#include "swBaseOperator.h"

#include "zanLog.h"

/**
 * clear socket buffer.
 */
void swSocket_clean(int fd)
{
    char buf[2048] = {0};
    while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0);
}

/**
 * Wait socket can read or write.
 */
int swSocket_wait(int fd, int timeout_ms, int events)
{
    struct pollfd event;
    event.fd = fd;
    event.events = 0;

    if (events & SW_EVENT_READ)
    {
        event.events |= POLLIN;
    }
    if (events & SW_EVENT_WRITE)
    {
        event.events |= POLLOUT;
    }
    while (1)
    {
        int ret = poll(&event, 1, timeout_ms);
        if (ret == 0)
        {
            return ZAN_ERR;
        }
        else if (ret < 0 && errno != EINTR)
        {
            zanError("poll() failed.");
            return ZAN_ERR;
        }
        else
        {
            return ZAN_OK;
        }
    }
    return ZAN_OK;
}

int swWrite(int fd, void *buf, int count)
{
    int nwritten = 0, totlen = 0;
    while (totlen != count)
    {
        nwritten = write(fd, buf, count - totlen);
        if (nwritten == 0)
        {
            return totlen;
        }
        if (nwritten < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
#ifdef HAVE_KQUEUE
            else if (errno == EAGAIN || errno == ENOBUFS)
#else
            else if (errno == EAGAIN)
#endif
            {
                swYield();
                continue;
            }

            return ZAN_ERR;

        }

        totlen += nwritten;
        buf += nwritten;
    }

    return totlen;
}

void swSocket_ioctl_set_block(int sock, int nonblock)
{
    int ret = 0;
    do
    {
        ret = ioctl(sock, FIONBIO, &nonblock);
    }while (ret < 0 && errno == EINTR);

    if (ret < 0)
    {
        zanError("ioctl(%d, FIONBIO, %d) failed.", sock, nonblock);
    }
}

int swSocket_write_blocking(int __fd, void *__data, int __len)
{
    int n = 0;
    int written = 0;

    while (written < __len)
    {
        n = write(__fd, __data + written, __len - written);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
#ifdef HAVE_KQUEUE
            else if (errno == EAGAIN || errno == ENOBUFS)
#else
            else if (errno == EAGAIN)
#endif
            {
                if (swSocket_wait(__fd, SW_WORKER_WAIT_TIMEOUT, SW_EVENT_WRITE) >= 0)
                    continue;
            }
            else
            {
                zanError("write %d bytes failed.", __len);
                return ZAN_ERR;
            }
        }
        written += n;
    }

    return written;
}

int swSocket_udp_sendto(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len)
{
    struct sockaddr_in addr;
    bzero(&addr,sizeof(addr));

    int checkAddr = inet_pton(AF_INET,dst_ip, &(addr.sin_addr.s_addr));
    if (checkAddr != 1)
    {
        zanWarn("ip[%s] is invalid.", dst_ip);
        return ZAN_ERR;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);
    return swSocket_sendto_blocking(server_sock, data, len, 0, (struct sockaddr *) &addr, sizeof(addr));
}

int swSocket_udp_sendto6(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len)
{
    struct sockaddr_in6 addr;
    bzero(&addr, sizeof(addr));
    if (inet_pton(AF_INET6, dst_ip, &(addr.sin6_addr.s6_addr)) != 1)
    {
        zanWarn("ip[%s] is invalid.", dst_ip);
        return ZAN_ERR;
    }
    addr.sin6_port = (uint16_t) htons(dst_port);
    addr.sin6_family = AF_INET6;
    return swSocket_sendto_blocking(server_sock, data, len, 0, (struct sockaddr *) &addr, sizeof(addr));
}

int swSocket_sendto_blocking(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len)
{
    int n = 0;

    while (1)
    {
        n = sendto(fd, __buf, __n, flag, __addr, __addr_len);
        if (n >= 0)
        {
            break;
        }
        else
        {
            if (errno == EINTR)
            {
                continue;
            }
#ifdef HAVE_KQUEUE
            else if (errno == EAGAIN || errno == ENOBUFS)
#else
            else if (errno == EAGAIN)
#endif
            {
                swSocket_wait(fd, 1000, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                break;
            }
        }
    }

    return n;
}

int swSocket_sendfile_sync(int sock, char *filename, double timeout)
{
    int timeout_ms = timeout < 0 ? -1 : timeout * 1000;
    int file_fd = open(filename, O_RDONLY);
    if (file_fd < 0)
    {
        zanError("open(%s) failed.", filename);
        return ZAN_ERR;
    }

    size_t filelen = get_filelen(file_fd);
    if (filelen <= 0)
    {
        close(file_fd);
        return ZAN_ERR;
    }

    int n, sendn;
    off_t offset = 0;
    while (offset < filelen)
    {
        if (swSocket_wait(sock, timeout_ms, SW_EVENT_WRITE) < 0)
        {
            close(file_fd);
            return ZAN_ERR;
        }
        else
        {
            sendn = (filelen - offset > SW_SENDFILE_TRUNK) ? SW_SENDFILE_TRUNK : filelen - offset;
            n = swoole_sendfile(sock, file_fd, &offset, sendn);
            if (n <= 0)
            {
                close(file_fd);
                zanError("sendfile(%d, %s) failed.", sock, filename);
                return ZAN_ERR;
            }
            else
            {
                continue;
            }
        }
    }

    close(file_fd);
    return ZAN_OK;
}

int swSocket_create(int type,int *sockType,int* sockDomain)
{
    int _domain = -1;
    int _type = -1;

    switch (type)
    {
    case SW_SOCK_TCP:
        _domain = PF_INET;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_TCP6:
        _domain = PF_INET6;
        _type = SOCK_STREAM;
        break;
    case SW_SOCK_UDP:
        _domain = PF_INET;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UDP6:
        _domain = PF_INET6;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_DGRAM:
        _domain = PF_UNIX;
        _type = SOCK_DGRAM;
        break;
    case SW_SOCK_UNIX_STREAM:
        _domain = PF_UNIX;
        _type = SOCK_STREAM;
        break;
    default:
        zanError("unknown socket type [%d]", type);
        return ZAN_ERR;
    }

    int sockfd = socket(_domain, _type, 0);
    if (sockfd < 0)
    {
        zanError("socket() failed");
        return ZAN_ERR;
    }

    if (NULL != sockType) *sockType = _type;
    if (NULL != sockDomain) *sockDomain = _domain;

    return sockfd;
}

int swSocket_bind(int sock, int type, char *host, int port)
{
    int ret;

    struct sockaddr_in addr_in4;
    struct sockaddr_in6 addr_in6;
    struct sockaddr_un addr_un;

    //SO_REUSEADDR option
    int option = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(int)) < 0)
    {
        zanError("setsockopt(%d, SO_REUSEADDR) failed.", sock);
    }
    //unix socket
    if (type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM)
    {
        bzero(&addr_un, sizeof(addr_un));
        unlink(host);
        addr_un.sun_family = AF_UNIX;
        strcpy(addr_un.sun_path, host);
        ret = bind(sock, (struct sockaddr*) &addr_un, sizeof(addr_un));
    }
    //IPv6
    else if (type > SW_SOCK_UDP)
    {
        bzero(&addr_in6, sizeof(addr_in6));
        inet_pton(AF_INET6, host, &(addr_in6.sin6_addr));
        addr_in6.sin6_port = htons(port);
        addr_in6.sin6_family = AF_INET6;
        ret = bind(sock, (struct sockaddr *) &addr_in6, sizeof(addr_in6));
    }
    //IPv4
    else
    {
        bzero(&addr_in4, sizeof(addr_in4));
        inet_pton(AF_INET, host, &(addr_in4.sin_addr));
        addr_in4.sin_port = htons(port);
        addr_in4.sin_family = AF_INET;
        ret = bind(sock, (struct sockaddr *) &addr_in4, sizeof(addr_in4));
    }
    //bind failed
    if (ret < 0)
    {
        zanError("bind(%s:%d) failed.", host, port);
        return ZAN_ERR;
    }
    return ret;
}

int swSocket_set_buffer_size(int fd, int buffer_size)
{
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)))
    {
        zanError("setsockopt(SO_SNDBUF,fd=%d,size=%d) failed, errno=%d:%s", fd, buffer_size, errno, strerror(errno));
        return ZAN_ERR;
    }
    if (-1 == setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)))
    {
        zanError("setsockopt(SO_RCVBUF,fd=%d,size=%d) failed, errno=%d:%s", fd, buffer_size, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

int swSocket_set_timeout(int sock, double timeout)
{
    int ret;
    struct timeval timeo;
    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);
    ret = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        zanError("setsockopt(SO_SNDTIMEO) failed.");
        return ZAN_ERR;
    }
    ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeo, sizeof(timeo));
    if (ret < 0)
    {
        zanError("setsockopt(SO_RCVTIMEO) failed.");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

void swSocket_fcntl_set_option(int sock, int nonblock, int cloexec)
{
    int opts, ret;
    do
    {
        opts = fcntl(sock, F_GETFL);
    }
    while (opts < 0 && errno == EINTR);

    if (opts < 0)
    {
        zanError("fcntl(%d, GETFL) failed.", sock);
    }

    if (nonblock)
    {
        opts = opts | O_NONBLOCK;
    }
    else
    {
        opts = opts & ~O_NONBLOCK;
    }

    do
    {
        ret = fcntl(sock, F_SETFL, opts);
    }
    while (ret < 0 && errno == EINTR);

    if (ret < 0)
    {
        zanError("fcntl(%d, SETFL, opts) failed.", sock);
    }
#ifdef FD_CLOEXEC
    do
    {
        opts = fcntl(sock, F_GETFD);
    }
    while (opts < 0 && errno == EINTR);

    if (opts < 0)
    {
        zanError("fcntl(%d, GETFL) failed.", sock);
    }

    if (cloexec)
    {
        opts = opts | FD_CLOEXEC;
    }
    else
    {
        opts = opts & ~FD_CLOEXEC;
    }

    do
    {
        ret = fcntl(sock, F_SETFD, opts);
    }
    while (ret < 0 && errno == EINTR);

    if (ret < 0)
    {
        zanError("fcntl(%d, SETFD, opts) failed.", sock);
    }
#endif
}

int zan_set_nonblocking(int fd, int isNonblock)
{
    int opts, ret;
    opts = ret = 0;
    do
    {
        opts = fcntl(fd, F_GETFL);
    }while (-1 == opts && errno == EINTR);

    if (-1 == opts)
    {
        zanSysError("fcntl(%d, GETFL) failed.", fd);
        //opts = (isNonblock)? 0:1;
        return ZAN_ERR;
    }
    opts = (isNonblock)? (opts | O_NONBLOCK):(opts & ~O_NONBLOCK);

    do
    {
        ret = fcntl(fd, F_SETFL, opts);
    }while (-1 == ret && errno == EINTR);

    if (-1 == ret)
    {
        zanSysError("fcntl(%d, SETFL, opts) failed, errno=%d:%s.", fd, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

