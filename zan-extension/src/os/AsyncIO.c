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


#include "swLog.h"
#include "swDNS.h"
#include "swReactor.h"
#include "swFactory.h"
#include "swAsyncIO.h"
#include "swGlobalVars.h"

swAsyncIO SwooleAIO;
swPipe swoole_aio_pipe;

static int swAioBase_init(int max_aio_events);

static void swAioBase_destroy();
static int swAioBase_read(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_write(int fd, void *inbuf, size_t size, off_t offset);
static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int swAioBase_onError(swReactor *reactor, swEvent *event);
static int swAioBase_onFinish(swReactor *reactor, swEvent *event);

static swThreadPool swAioBase_thread_pool;
static int swAioBase_pipe_read;
static int swAioBase_pipe_write;

int swAio_init(void)
{
    if (SwooleAIO.init)
    {
        swInfo("AIO has already been initialized");
        return SW_OK;
    }

    if (!SwooleG.main_reactor)
    {
        swError("No eventloop, cannot initialized");
        return SW_ERR;
    }

    if (swMutex_create(&SwooleAIO.wLock,0) < 0)
    {
		swError("create async lock error.");
		return SW_ERR;
    }

    int ret = swAioBase_init(SW_AIO_EVENT_NUM);

    SwooleAIO.init = 1;
    return ret;
}

void swAio_free(void)
{
    if (!SwooleAIO.init)
    {
        return;
    }

    SwooleAIO.init = 0;
    SwooleAIO.destroy();
}

/**
 * for test
 */
void swAio_callback_test(swAio_event *aio_event)
{
    swDebug("content=%s\n", (char *)aio_event->buf);
    swDebug("fd: %d, request_type: %s, offset: %lld, length: %llu\n", aio_event->fd,
            (aio_event == SW_AIO_READ) ? "READ" : "WRITE", (long long int)aio_event->offset, (long long unsigned)aio_event->nbytes);
    SwooleG.running = 0;
}

static int swAioBase_onFinish(swReactor *reactor, swEvent *event)
{
    swAio_event *events[SW_AIO_EVENT_NUM] = {0};
    int n = read(event->fd, events, sizeof(swAio_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        swSysError("read() failed.");
        return SW_ERR;
    }

    uint32_t bytes = sizeof(swAio_event*);
    int index = 0;
    for (index = 0; index < n /bytes ; index++)
    {
        SwooleAIO.callback(events[index]);
        SwooleAIO.task_num--;
        sw_free(events[index]);
    }

    return SW_OK;
}

static int swAioBase_onError(swReactor *reactor, swEvent *event)
{
	swError("asyncIO read pipe fd error,process will exit.");
	exit(1);
	return SW_OK;
}

static int swAioBase_init(int max_aio_events)
{
    if (swPipeBase_create(&swoole_aio_pipe, 0) < 0)
    {
        return SW_ERR;
    }

    if (SwooleAIO.thread_num <= 0)
    {
        SwooleAIO.thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    }

    if (swThreadPool_create(&swAioBase_thread_pool, SwooleAIO.thread_num) < 0)
    {
        return SW_ERR;
    }

    swAioBase_thread_pool.onTask = swAioBase_thread_onTask;
    swAioBase_pipe_read = swoole_aio_pipe.getFd(&swoole_aio_pipe, 0);
    swAioBase_pipe_write = swoole_aio_pipe.getFd(&swoole_aio_pipe, 1);

    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, swAioBase_onFinish);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor,SW_FD_AIO | SW_EVENT_ERROR,swAioBase_onError);

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, swAioBase_pipe_read);
    bzero(_socket,sizeof(swConnection));
    _socket->fd = swAioBase_pipe_read;

    SwooleG.main_reactor->add(SwooleG.main_reactor, swAioBase_pipe_read, SW_FD_AIO);

    if (swThreadPool_run(&swAioBase_thread_pool) < 0)
    {
        return SW_ERR;
    }

    SwooleAIO.callback = swAio_callback_test;
    SwooleAIO.destroy = swAioBase_destroy;
    SwooleAIO.read = swAioBase_read;
    SwooleAIO.write = swAioBase_write;

    return SW_OK;
}

int swAio_dns_lookup(int flags,void *hostname, void *ip_addr, size_t size)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
    	swFatalError("malloc failed.");
        return SW_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->buf = ip_addr;
    aio_ev->fd = flags;
    aio_ev->req = hostname;
    aio_ev->type = SW_AIO_DNS_LOOKUP;
    aio_ev->nbytes = size;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
    	sw_free(aio_ev);
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

static int swAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len)
{
    swAio_event *event = task;
    int ret = -1;

start_switch:
    switch(event->type)
    {
    case SW_AIO_WRITE:
        ret = (event->nbytes <= 0)? 0: pwrite(event->fd, event->buf, event->nbytes, event->offset);
        break;
    case SW_AIO_READ:
        ret = (event->nbytes <= 0)? 0: pread(event->fd, event->buf, event->nbytes, event->offset);
        break;
    case SW_AIO_DNS_LOOKUP:
		{
			char ipaddr[SW_IP_MAX_LENGTH] = {0};
			ret = swoole_gethostbyname(event->fd, event->buf,ipaddr,SW_IP_MAX_LENGTH);
			
			if (ret >= 0)
			{
				bzero(event->buf, event->nbytes);
				memcpy(event->buf, ipaddr, strnlen(ipaddr, SW_IP_MAX_LENGTH) + 1);
			}
			
		}
		break;
    default:
        swError("unknow aio task.");
        break;
    }

    event->ret = ret;
    if (ret < 0)
    {
        if (errno == EINTR || errno == EAGAIN)
        {
            goto start_switch;
        }
        else
        {
            event->error = errno;
        }
    }

    swTrace("aio_thread ok. ret=%d", ret);

    do
    {
    	SwooleAIO.wLock.lock(&SwooleAIO.wLock);
        ret = write(swAioBase_pipe_write, &task, sizeof(task));
        SwooleAIO.wLock.unlock(&SwooleAIO.wLock);
        if (ret < 0 && (errno == EAGAIN || errno == EINTR))
        {
        	 if (errno == EAGAIN)	swYield();
             continue;
        }

        break;
    } while(1);

    return SW_OK;
}

static int swAioBase_write(int fd, void *inbuf, size_t size, off_t offset)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        swFatalError("malloc failed.");
        return SW_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->fd = fd;
    aio_ev->buf = inbuf;
    aio_ev->type = SW_AIO_WRITE;
    aio_ev->nbytes = size;
    aio_ev->offset = offset;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

static int swAioBase_read(int fd, void *inbuf, size_t size, off_t offset)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
    	swFatalError("malloc failed.");
        return SW_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->fd = fd;
    aio_ev->buf = inbuf;
    aio_ev->type = SW_AIO_READ;
    aio_ev->nbytes = size;
    aio_ev->offset = offset;
    aio_ev->task_id = SwooleAIO.current_id++;

    if (swThreadPool_dispatch(&swAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
    	sw_free(aio_ev);
        return SW_ERR;
    }
    else
    {
        SwooleAIO.task_num++;
        return aio_ev->task_id;
    }
}

static void swAioBase_destroy()
{
    swThreadPool_free(&swAioBase_thread_pool);
}
