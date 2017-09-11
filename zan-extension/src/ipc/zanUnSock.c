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

#include "zanIpc.h"
#include "zanSocket.h"
#include "zanLog.h"

///TODO:::read or write argument

static int zanUnSock_read(zanPipe *pPipe, void *buffer, int length);
static int zanUnSock_write(zanPipe *pPipe, void *buffer, int length);
static int zanUnSock_getFd(zanPipe *pPipe, int isWriteFd);
static int zanUnSock_close(zanPipe *pPipe);

int zanUnSock_create(zanPipe *pPipe, int isNonBlock, int protocol);

int zanUnSock_create(zanPipe *pPipe, int isNonBlock, int protocol)
{
    if (!pPipe){
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)zan_malloc(sizeof(zanPipeFd));
    if (!object)
    {
        zanFatalError("malloc failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (socketpair(AF_UNIX, protocol, 0, object->fds) < 0)
    {
        zanSysError("socketpair failed, errno=%d:%s", errno, strerror(errno));
        zan_free(object);
        return ZAN_ERR;
    }

    //Nonblock
    if (isNonBlock) {
        zan_set_nonblocking(object->fds[0], 1);
        zan_set_nonblocking(object->fds[1], 1);
    }

    ///TODO:::
    int sbsize = ServerG.servSet.socket_buffer_size;
    zan_socket_set_buffersize(object->fds[0], sbsize);
    zan_socket_set_buffersize(object->fds[1], sbsize);

    pPipe->object      = object;
    pPipe->is_nonblock = isNonBlock;
    pPipe->pipe_type   = ZAN_UNSOCK;

    pPipe->read  = zanUnSock_read;
    pPipe->write = zanUnSock_write;
    pPipe->getFd = zanUnSock_getFd;
    pPipe->close = zanUnSock_close;

    return ZAN_OK;
}

static int zanUnSock_read(zanPipe *pPipe, void *buffer, int length)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return read(object->fds[0], buffer, length);
}

static int zanUnSock_write(zanPipe *pPipe, void *buffer, int length)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return write(object->fds[1], buffer, length);
}

static int zanUnSock_getFd(zanPipe *pPipe, int isWriteFd)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return (isWriteFd == 0) ? object->fds[0] : object->fds[1];
}

int zanUnSock_close(zanPipe *pPipe)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    int ret1 = close(object->fds[0]);
    int ret2 = close(object->fds[1]);
    zan_free(object);

    return 0 - ret1 - ret2;
}
