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

#include "swWork.h"
#include "swServer.h"
#include "swFactory.h"
#include "swExecutor.h"
#include "swBaseOperator.h"

#include "zanIpc.h"
#include "zanLog.h"

typedef struct _zanNotify_data
{
    long target_worker_id;
    swDataHead _send;
} zanNotify_data;

//static __thread zanNotify_data zan_notify_data;

static int zanFactory_start(zanFactory *factory);
static int zanFactory_notify(zanFactory *factory, swDataHead *event);
static int zanFactory_dispatch(zanFactory *factory, swDispatchData *buf);
static int zanFactory_finish(zanFactory *factory, swSendData *data);
static int zanFactory_shutdown(zanFactory *factory);
static int zanFactory_end(zanFactory *factory, int fd);

///TODO:::factory 的功能，要将消息分发抽离吗???
/*
  1. 根据用户配置的 server 运行模式，启动不同的模式，暂时只支持多进程
     统一入口 start 接口，创建子进程及子进程资源

  2. 运行模式和消息分发是相关联的
     收到 client 的消息，net_worker 将消息分发给不同的 worker，分发机制可配置
     worker 发送消息给 client，finish 接口，将消息发送到 reactor，再发送到 client
     client connect、close，将消息通知给 worker

  3. 需要精简 factory 功能吗?
*/

int zanFactory_create(zanFactory *factory)
{
    if (!factory)
    {
        zanError("error, factory is null.");
        return ZAN_ERR;
    }

    //swFactoryProcess *object;
    //object = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swFactoryProcess));
    zanPipe *object = (zanPipe *)zan_malloc(sizeof(zanPipe));
    if (!object)
    {
        swFatalError("malloc[zanPipe*] failed, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    factory->object   = object;
    factory->start    = zanFactory_start;
    factory->end      = zanFactory_end;
    factory->notify   = zanFactory_notify;
    factory->finish   = zanFactory_finish;
    factory->shutdown = zanFactory_shutdown;
    factory->dispatch = zanFactory_dispatch;
    return ZAN_OK;
}

static int zanFactory_shutdown(zanFactory *factory)
{
    if (!factory)
    {
        zanError("factory is null");
        return ZAN_ERR;
    }

    /*
    if (swKill(SwooleGS->manager_pid, SIGTERM) < 0)
    {
        swSysError("kill(%d) failed.", SwooleGS->manager_pid);
    }

    int status = 0;
    if (swWaitpid(SwooleGS->manager_pid, &status, 0) < 0)
    {
        swSysError("waitpid(%d) failed.", SwooleGS->manager_pid);
    }
    */
    zanWarn("factory shutdown.");
    return ZAN_OK;
}

static int zanFactory_start(zanFactory *factory)
{
    if (!factory)
    {
        zanError("factory is null");
        return ZAN_ERR;
    }

    //根据 serv->factory_mode 走不同启动流程，创建子进程，暂且只支持多进程模式
    //swServer *serv = (swServer *)factory->ptr;
    //zanWarn("serv->factory_mode=%d", serv->factory_mode);
    /*if (zanWorkers_start(factory) < 0)
    {
        swError("zanWorkers_start failed.");
        return SW_ERR;
    }
    */

    //创建各个 worker 管理及通信需要的资源，然后依次 fork 进程
    //注：要保证 net_work 最后启动???? 如何保证
    //因为 net_worker 启动后就可以 accept client 连接

    //
    factory->finish = swFactory_finish;
    return ZAN_OK;
}

//close connection, and notify to worker.
//swReactorThread_onClose
static int zanFactory_notify(zanFactory *factory, swDataHead *ev)
{
    zanNotify_data notify_data;
    if (!factory || !ev)
    {
        zanError("factory=%p or ev=%p is null", factory, ev);
        return ZAN_ERR;
    }

    memcpy(&notify_data._send, ev, sizeof(swDataHead));
    notify_data._send.len = 0;
    notify_data.target_worker_id = -1;
    return factory->dispatch(factory, (swDispatchData *) &notify_data);
}

/**
 * [ReactorThread] dispatch request to worker
 */
static int zanFactory_dispatch(zanFactory *factory, swDispatchData *task)
{
    uint32_t schedule_key = 0;
    uint32_t send_len     = 0;
    uint16_t to_worker_id = -1;
    swServer *serv = SwooleG.serv;

    if (!factory || !task)
    {
        zanError("factory=%p or task=%p is null", factory, task);
        return ZAN_ERR;
    }

    //1. get target_worker_id
    if (task->target_worker_id < 0)
    {
        schedule_key = task->data.info.fd;
        to_worker_id = swServer_worker_schedule(serv, schedule_key);
    }
    else
    {
        to_worker_id = task->target_worker_id;
    }

    //2. send data to worker
    //todo:::
    if (swEventData_is_stream(task->data.info.type))
    {
        swConnection *conn = swServer_connection_get(serv, task->data.info.fd);
        if (conn == NULL || conn->active == 0)
        {
            swNotice("dispatch[type=%d] failed, connection#%d is not active.", task->data.info.type, task->data.info.fd);
            return SW_ERR;
        }
        //conn active close, discard data.
        if (conn->closed)
        {
            if (!(task->data.info.type == SW_EVENT_CLOSE && conn->close_force))
            {
                swNotice("dispatch[type=%d] failed, connection#%d[session_id=%d] is closed by server.",
                        task->data.info.type, task->data.info.fd, conn->session_id);
                return SW_OK;
            }
        }
        //converted fd to session_id
        task->data.info.fd = conn->session_id;
        task->data.info.from_fd = conn->from_fd;
    }

    send_len = sizeof(task->data.info) + task->data.info.len;
    return swReactorThread_send2worker((void *) &(task->data), send_len, to_worker_id);
}

//send data to client
static int zanFactory_finish(zanFactory *factory, swSendData *resp)
{
    int ret, sendn, fd;
    swServer *serv;

    if (!factory || !resp)
    {
        zanError("factory=%p or resp=%p is null", factory, resp);
        return ZAN_ERR;
    }

    //todo:::
    serv = factory->ptr;
    fd = resp->info.fd;
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        zanWarn("session#fd=%d does not exist.", fd);
        return ZAN_ERR;
    }
    else if ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        zanWarn("send %d byte failed, because session#fd=%d is closed.", _len, fd);
        return ZAN_ERR;
    }
    else if (conn->overflow)
    {
        zanWarn("send failed, session#fd=%d output buffer has been overflowed.", fd);
        return ZAN_ERR;
    }

    swEventData ev_data;
    memset(&ev_data, 0, sizeof(ev_data));
    ev_data.info.fd   = fd;
    ev_data.info.type = resp->info.type;
    swWorker *worker  = swServer_get_worker(serv, SwooleWG.id);

    /**
     * Big response, use shared memory
     */
    if (resp->length > 0)
    {
        if (worker->send_shm == NULL)
        {
            zanWarn("send failed, data is too big.");
            return ZAN_ERR;
        }

        swPackage_response response;

        worker->lock.lock(&worker->lock);
        response.length = resp->length;
        response.worker_id = SwooleWG.id;

        zanDebug("BigPackage, length=%d|worker_id=%d", response.length, response.worker_id);

        ev_data.info.from_fd = SW_RESPONSE_BIG;
        ev_data.info.len = sizeof(response);

        memcpy(ev_data.data, &response, sizeof(response));
        memcpy(worker->send_shm, resp->data, resp->length);
    }
    else
    {
        //copy data
        memcpy(ev_data.data, resp->data, resp->info.len);
        ev_data.info.len = resp->info.len;
        ev_data.info.from_fd = SW_RESPONSE_SMALL;
    }

    ev_data.info.from_id = conn->from_id;
    sendn = ev_data.info.len + sizeof(resp->info);
    zanTrace("[Worker] send: sendn=%d|type=%d|content=%s", sendn, resp->info.type, resp->data);

    ret = swWorker_send2reactor(&ev_data, sendn, fd);
    if (ret < 0)
    {
        zanError("sendto to reactor failed.");
    }

    return ret;
}

//关闭连接
//TODO:::
//1. server: close 接口
//2. SW_EVENT_CLOSE 事件
static int zanFactory_end(zanFactory *factory, int fd)
{
    swServer *serv = (swServer *)factory->ptr;
    swSendData _send;
    swDataHead info;

    bzero(&_send, sizeof(_send));
    _send.info.fd   = fd;
    _send.info.len  = 0;
    _send.info.type = SW_EVENT_CLOSE;

    //1. get and verify connection, then close the conn
    swConnection *conn = swWorker_get_connection(serv, fd);
    if (conn == NULL || conn->active == 0)
    {
        zanWarn("can not close. Connection[%d] not found.", _send.info.fd);
        return SW_ERR;
    }
    else if (conn->close_force)
    {
        goto do_close;
    }
    else if (conn->closing)
    {
        zanWarn("The connection[fd=%d] is closing.", fd);
        return ZAN_ERR;
    }
    else if (conn->closed)
    {
        zanWarn("The connection[fd=%d] is closed.", fd);
        return ZAN_ERR;
    }
    else
    {
        do_close:
        conn->closing = 1;
        if (serv->onClose != NULL)
        {
            info.fd = fd;
            info.from_id =  conn->from_id;
            info.from_fd =  conn->from_fd;
            serv->onClose(serv, &info);
        }
        conn->closing = 0;
        conn->closed = 1;
        return factory->finish(factory, &_send);
    }
}
