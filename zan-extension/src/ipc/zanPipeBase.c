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
#include "zanLog.h"

static int zanPipeBase_read(zanPipe *pPipe, void *buffer, int length);
static int zanPipeBase_write(zanPipe *pPipe, void *buffer, int length);
static int zanPipeBase_getFd(zanPipe *pPipe, int isWriteFd);
static int zanPipeBase_close(zanPipe *pPipe);

int zanPipeBase_create(zanPipe *pPipe, int isNonBlock);

int zanPipeBase_create(zanPipe *pPipe, int isNonBlock)
{
    if (!pPipe){
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)sw_malloc(sizeof(zanPipeFd));
    if (!object)
    {
        zanSysError("malloc fail, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (pipe(object->fds) < 0)
    {
        sw_free(object);
        zanSysError("pipe create fail, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (isNonBlock) {
        zan_set_nonblocking(object->fds[0], 1);
        zan_set_nonblocking(object->fds[1], 1);
    }

    pPipe->object      = (void *)object;
    pPipe->is_nonblock = isNonBlock;
    pPipe->pipe_type   = ZAN_PIPE;

    pPipe->read       = zanPipeBase_read;
    pPipe->write      = zanPipeBase_write;
    pPipe->getFd      = zanPipeBase_getFd;
    pPipe->close      = zanPipeBase_close;

    return ZAN_OK;
}

static int zanPipeBase_read(zanPipe *pPipe, void *buffer, int length)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return read(object->fds[0], buffer, length);
}

static int zanPipeBase_write(zanPipe *pPipe, void *buffer, int length)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return write(object->fds[1], buffer, length);
}

static int zanPipeBase_getFd(zanPipe *pPipe, int isWriteFd)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    return (isWriteFd == 0) ? object->fds[0] : object->fds[1];
}

int zanPipeBase_close(zanPipe *pPipe)
{
    if (!pPipe) {
        zanError("pPipe is null, error.");
        return ZAN_ERR;
    }

    zanPipeFd *object = (zanPipeFd *)pPipe->object;
    int ret1 = close(object->fds[0]);
    int ret2 = close(object->fds[1]);
    sw_free(object);
    return 0 - ret1 - ret2;
}
