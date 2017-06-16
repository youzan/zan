/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
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

#include "swLog.h"
#include "swPipe.h"

static int swPipeBase_read(swPipe *p, void *data, int length);
static int swPipeBase_write(swPipe *p, void *data, int length);
static int swPipeBase_getFd(swPipe *p, int isWriteFd);

typedef struct _swPipeBase
{
    int pipes[2];
} swPipeBase;

int swPipeBase_create(swPipe *p, int blocking)
{
	if (!p){
		return SW_ERR;
	}

    swPipeBase *object = sw_malloc(sizeof(swPipeBase));
    if (object == NULL)
    {
        return SW_ERR;
    }

    if (pipe(object->pipes) < 0)
    {
    	sw_free(object);
        swWarn("pipe create fail. Error: %s[%d]", strerror(errno), errno);
        return SW_ERR;
    }

	swSetNonBlock(object->pipes[0],!blocking);
	swSetNonBlock(object->pipes[1],!blocking);
	p->blocking = blocking;
	p->timeout = -1;
	p->object = object;
	p->read = swPipeBase_read;
	p->write = swPipeBase_write;
	p->getFd = swPipeBase_getFd;
	p->close = swPipeBase_close;

    return SW_OK;
}

int swPipeBase_close(swPipe *p)
{
    swPipeBase *this = p->object;
    int ret1 = close(this->pipes[0]);
    int ret2 = close(this->pipes[1]);
    sw_free(this);
    return 0 - ret1 - ret2;
}

static int swPipeBase_read(swPipe *p, void *data, int length)
{
    swPipeBase *object = p->object;
    if (p->blocking && p->timeout > 0 && swSocket_wait(object->pipes[0], p->timeout * 1000, SW_EVENT_READ) < 0)
    {
        return SW_ERR;
    }

    return read(object->pipes[0], data, length);
}

static int swPipeBase_write(swPipe *p, void *data, int length)
{
    swPipeBase *this = p->object;
    return write(this->pipes[1], data, length);
}

static int swPipeBase_getFd(swPipe *p, int isWriteFd)
{
    swPipeBase *this = p->object;
    return (isWriteFd == 0) ? this->pipes[0] : this->pipes[1];
}

