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

#include "zanSocket.h"

///TODO:::socket 操作，设置，send 及 recv 相关操作；

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
        opts = (isNonblock)? 0:1;
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

int zan_socket_set_buffersize(int fd, int buffer_size)
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
