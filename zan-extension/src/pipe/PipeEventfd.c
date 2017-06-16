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



#include "swoole.h"
#include "swPipe.h"
#include "swLog.h"
#include "swMemory/memoryPool.h"


#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>

static int swPipeEventfd_read(swPipe *p, void *data, int length);
static int swPipeEventfd_write(swPipe *p, void *data, int length);
static int swPipeEventfd_getFd(swPipe *p, int isWriteFd);

typedef struct _swPipeEventfd
{
    int event_fd;
} swPipeEventfd;

int swPipeEventfd_create(swPipe *p, int blocking, int semaphore, int timeout)
{
    swPipeEventfd *object = sw_malloc(sizeof(swPipeEventfd));
    if (object == NULL)
    {
        return SW_ERR;
    }

    int flag = EFD_NONBLOCK;
    if (blocking)
    {
    	p->timeout = (timeout > 0)? -1:timeout;
    	flag = (timeout > 0)? 0:flag;
    }

#ifdef EFD_SEMAPHORE
    flag |= (semaphore == 1)? EFD_SEMAPHORE:1;
#endif

    int efd = eventfd(0, flag);
    if (efd < 0)
    {
        swWarn("eventfd create failed. Error: %s[%d]", strerror(errno), errno);
        sw_free(object);
        return SW_ERR;
    }
    else
    {
        p->object = object;
        p->blocking = blocking;
        p->read = swPipeEventfd_read;
        p->write = swPipeEventfd_write;
        p->getFd = swPipeEventfd_getFd;
        p->close = swPipeEventfd_close;
        object->event_fd = efd;
    }

    return SW_OK;
}

int swPipeEventfd_close(swPipe *p)
{
    int ret = 0;
    ret = close(((swPipeEventfd *) (p->object))->event_fd);
    sw_free(p->object);
    return ret;
}

static int swPipeEventfd_read(swPipe *p, void *data, int length)
{
    swPipeEventfd *object = p->object;

    //eventfd not support socket timeout
    if (p->blocking && p->timeout > 0 && swSocket_wait(object->event_fd, p->timeout * 1000, SW_EVENT_READ) < 0)
    {
        return SW_ERR;
    }

    int ret = -1;
    while (1)
    {
        ret = read(object->event_fd, data, sizeof(uint64_t));
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }

        break;
    }

    return ret;
}

static int swPipeEventfd_write(swPipe *p, void *data, int length)
{
    swPipeEventfd *this = p->object;
    int ret = -1;
    while (1)
    {
        ret = write(this->event_fd, data, sizeof(uint64_t));
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }

        break;
    }

    return ret;
}

static int swPipeEventfd_getFd(swPipe *p, int isWriteFd)
{
    return ((swPipeEventfd *) (p->object))->event_fd;
}

#endif
