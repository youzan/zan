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
#include "swPipe.h"
#include "swLog.h"
#include "swMemory/buffer.h"
#include "swGlobalVars.h"
#include <sys/ipc.h>
#include <sys/msg.h>

static int swPipeUnsock_read(swPipe *p, void *data, int length);
static int swPipeUnsock_write(swPipe *p, void *data, int length);
static int swPipeUnsock_getFd(swPipe *p, int isWriteFd);

typedef struct _swPipeUnsock
{
    int socks[2];
} swPipeUnsock;

int swPipeUnsock_create(swPipe *p, int blocking, int protocol)
{
    if (!p){
    	return SW_ERR;
    }

    swPipeUnsock *object = sw_malloc(sizeof(swPipeUnsock));
    if (object == NULL)
    {
        swFatalError("malloc() failed.");
        return SW_ERR;
    }

    if (socketpair(AF_UNIX, protocol, 0, object->socks) < 0)
    {
        swSysError("socketpair() failed.");
        sw_free(object);
        return SW_ERR;
    }
    else
    {
        //Nonblock
        if (!blocking)
        {
            swSetNonBlock(object->socks[0],1);
            swSetNonBlock(object->socks[1],1);
        }

        int sbsize = SwooleG.socket_buffer_size;
        swSocket_set_buffer_size(object->socks[0], sbsize);
        swSocket_set_buffer_size(object->socks[1], sbsize);

        p->blocking = blocking;
        p->object = object;
        p->read = swPipeUnsock_read;
        p->write = swPipeUnsock_write;
        p->getFd = swPipeUnsock_getFd;
        p->close = swPipeUnsock_close;
    }

    return SW_OK;
}

int swPipeUnsock_close(swPipe *p)
{
    swPipeUnsock *object = p->object;

    int ret1 = close(object->socks[0]);
    int ret2 = close(object->socks[1]);

    sw_free(object);

    return 0 - ret1 - ret2;
}

static int swPipeUnsock_read(swPipe *p, void *data, int length)
{
    return read(((swPipeUnsock *) p->object)->socks[0], data, length);
}

static int swPipeUnsock_write(swPipe *p, void *data, int length)
{
    return write(((swPipeUnsock *) p->object)->socks[1], data, length);
}

static int swPipeUnsock_getFd(swPipe *p, int isWriteFd)
{
    swPipeUnsock *this = p->object;
    return isWriteFd? this->socks[1] : this->socks[0];
}
