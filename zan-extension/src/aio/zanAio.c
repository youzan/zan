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

#include "swDNS.h"
#include "zanAsyncIo.h"

static zanAsyncIO ZanAIO;
static zanPipe zan_aio_pipe;
static swThreadPool zanAioBase_thread_pool;

static int zanAioBase_init(int max_aio_events);
static void zanAioBase_destroy();
static int zanAioBase_read(int fd, void *inbuf, size_t size, off_t offset);
static int zanAioBase_write(int fd, void *inbuf, size_t size, off_t offset);
static int zanAioBase_task(int fd, void *inbuf, size_t size, off_t offset, int task_type);
static int zanAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len);
static int zanAioBase_onError(swReactor *reactor, swEvent *event);
static int zanAioBase_onFinish(swReactor *reactor, swEvent *event);


int zanAio_init(void)
{
    if (ZanAIO.init)
    {
        zanWarn("ZanAIO has already been initialized");
        return ZAN_OK;
    }

    if (!SwooleG.main_reactor)
    {
        zanError("No eventloop, cannot init ZanAIO");
        return ZAN_ERR;
    }

    if (ZAN_OK != zanLock_create(&ZanAIO.mutexLock, ZAN_MUTEX, 0))
    {
        zanError("create async lock error.");
        return ZAN_ERR;
    }

    int ret = zanAioBase_init(SW_AIO_EVENT_NUM);
    ZanAIO.init = 1;
    return ret;
}

void zanAio_free(void)
{
    if (!ZanAIO.init)
    {
        zanWarn("ZanAIO not been initialized");
        return;
    }

    ZanAIO.init = 0;
    ZanAIO.mutexLock.free(&ZanAIO.mutexLock);
    ZanAIO.destroy();
}

static int zanAioBase_onFinish(swReactor *reactor, swEvent *event)
{
    swAio_event *events[SW_AIO_EVENT_NUM];
    int n = read(event->fd, events, sizeof(swAio_event*) * SW_AIO_EVENT_NUM);
    if (n < 0)
    {
        zanSysError("read() failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    uint32_t bytes = sizeof(swAio_event*);
    int index = 0;
    for (index = 0; index < n / bytes ; index++)
    {
        //zanWarn("zanAioBase_onFinish, index=%d, n=%d", index, n);
        ZanAIO.callback(events[index]);
        ZanAIO.task_num--;
        sw_free(events[index]);
    }
    return ZAN_OK;
}

static int zanAioBase_onError(swReactor *reactor, swEvent *event)
{
    zanError("asyncIO read pipe fd=%d error,process will exit.", event->fd);
    exit(1);
    return ZAN_ERR;
}

static int zanAioBase_init(int max_aio_events)
{
    int pipe_read_fd  = -1;
    if (ZAN_OK != zanPipe_create(&zan_aio_pipe, ZAN_PIPE, 0, 0))
    {
        zanError("zanPipe_create failed.");
        return ZAN_ERR;
    }

    if (ZanAIO.thread_num <= 0)
    {
        ZanAIO.thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    }

    if (swThreadPool_create(&zanAioBase_thread_pool, ZanAIO.thread_num) < 0)
    {
        zanError("swThreadPool_create failed.");
        return ZAN_ERR;
    }

    pipe_read_fd = zan_aio_pipe.getFd(&zan_aio_pipe, 0);
    SwooleG.main_reactor->add(SwooleG.main_reactor, pipe_read_fd, SW_FD_AIO);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor, SW_FD_AIO, zanAioBase_onFinish);
    SwooleG.main_reactor->setHandle(SwooleG.main_reactor,SW_FD_AIO | SW_EVENT_ERROR, zanAioBase_onError);

    zanAioBase_thread_pool.onTask = zanAioBase_thread_onTask;
    if (swThreadPool_run(&zanAioBase_thread_pool) < 0)
    {
        zanError("swThreadPool_run failed.");
        return ZAN_ERR;
    }

    ZanAIO.read     = zanAioBase_read;
    ZanAIO.write    = zanAioBase_write;
    ZanAIO.destroy  = zanAioBase_destroy;
    return ZAN_OK;
}

static int zanAioBase_thread_onTask(swThreadPool *pool, void *task, int task_len)
{
    int ret = -1;
    int pipe_write_fd  = -1;
    swAio_event *event = (swAio_event *)task;

start_switch:
    switch(event->type)
    {
    case SW_AIO_WRITE:
        //需要加锁吗?
        ret = (event->nbytes <= 0)? 0: pwrite(event->fd, event->buf, event->nbytes, event->offset);
        break;
    case SW_AIO_READ:
        //需要加锁吗?
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
        zanError("unknow aio task type=%d.", event->type);
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
            zanError("error: ret=%d, errno=%d:%s", ret, errno, strerror(errno));
            event->error = errno;
        }
    }

    //todo:::如果写管道失败怎么办?
    //无法执行回调，胶水层会有内存泄漏。。。
    pipe_write_fd = zan_aio_pipe.getFd(&zan_aio_pipe, 1);
    do
    {
        int ret1, ret2;
        ret1 = ret2 = -1;
        ret1 = ZanAIO.mutexLock.lock(&ZanAIO.mutexLock);
        ret = write(pipe_write_fd, &task, sizeof(task));
        ret2 = ZanAIO.mutexLock.unlock(&ZanAIO.mutexLock);
        if (ret < 0)
        {
            if (errno == EAGAIN)
            {
                swYield();
                continue;
            }
            else if(errno == EINTR)
            {
                continue;
            }
            else
            {
                zanWarn("sendto pipe_write_fd=%d failed. errno=%d:%s", pipe_write_fd, errno, strerror(errno));
            }
            continue;
        } else if (ret1 != ZAN_OK || ret2 != ZAN_OK) {
            zanError("error: ret1=%d, ret2=%d, errno=%d:%s", ret1, ret2, errno, strerror(errno));
        }
        break;
    } while(1);

    return ZAN_OK;
}

static int zanAioBase_read(int fd, void *inbuf, size_t size, off_t offset)
{
    return zanAioBase_task(fd, inbuf, size, offset, SW_AIO_READ);
}

static int zanAioBase_write(int fd, void *inbuf, size_t size, off_t offset)
{
    return zanAioBase_task(fd, inbuf, size, offset, SW_AIO_WRITE);
}

int zanAio_dns_lookup(int flags,void *dns_req, void *ip_addr, size_t size)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        zanFatalError("malloc failed.");
        return ZAN_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->buf     = ip_addr;
    aio_ev->fd      = flags;
    aio_ev->req     = dns_req;
    aio_ev->type    = SW_AIO_DNS_LOOKUP;
    aio_ev->nbytes  = size;
    aio_ev->task_id = ZanAIO.current_id++;

    if (SW_OK != swThreadPool_dispatch(&zanAioBase_thread_pool, aio_ev, sizeof(aio_ev)))
    {
        //何时释放 dns_req, ip_addr 呢?
        //胶水层的一些 zval 如何释放?
        zanError("swThreadPool_dispatch failed.");
        sw_free(aio_ev);
        return ZAN_ERR;
    }
    else
    {
        ZanAIO.task_num++;
        return aio_ev->task_id;
    }
}

static void zanAioBase_destroy()
{
    swThreadPool_free(&zanAioBase_thread_pool);
}

static int zanAioBase_task(int fd, void *inbuf, size_t size, off_t offset, int task_type)
{
    swAio_event *aio_ev = (swAio_event *) sw_malloc(sizeof(swAio_event));
    if (aio_ev == NULL)
    {
        zanFatalError("malloc failed, task_type=%d.", task_type);
        return ZAN_ERR;
    }

    if (NULL == inbuf)
    {
        zanError("inbuf is NULL, task_type=%d.", task_type);
        return ZAN_ERR;
    }

    bzero(aio_ev, sizeof(swAio_event));
    aio_ev->fd      = fd;
    aio_ev->buf     = inbuf;
    aio_ev->type    = (SW_AIO_READ == task_type) ? SW_AIO_READ : SW_AIO_WRITE;
    aio_ev->nbytes  = size;
    aio_ev->offset  = offset;
    aio_ev->task_id = ZanAIO.current_id++;

    if (swThreadPool_dispatch(&zanAioBase_thread_pool, aio_ev, sizeof(aio_ev)) < 0)
    {
        //这种场景如何释放 inbuf 呢?
        //胶水层的一些 zval 如何释放?
        zanError("swThreadPool_dispatch failed, task_type=%d.", task_type);
        sw_free(aio_ev);
        return ZAN_ERR;
    }
    else
    {
        ZanAIO.task_num++;
        return aio_ev->task_id;
    }
}

