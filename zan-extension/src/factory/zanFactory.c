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

#include "zanGlobalDef.h"
#include "zanServer.h"
#include "zanWorkers.h"
#include "zanFactory.h"
#include "zanLog.h"

typedef struct _zanNotify_data
{
    long target_worker_id;
    swDataHead _send;
} zanNotify_data;

static int zanFactory_start(zanFactory *factory);
static int zanFactory_notify(zanFactory *factory, swDataHead *event);
static int zanFactory_dispatch(zanFactory *factory, swDispatchData *buf);
static int zanFactory_finish(zanFactory *factory, swSendData *data);
static int zanFactory_shutdown(zanFactory *factory);
static int zanFactory_end(zanFactory *factory, int fd);

int zanFactory_create(zanFactory *factory)
{
    if (!factory)
    {
        zanError("error, factory is null.");
        return ZAN_ERR;
    }

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

    ///TODO:::
    //....

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

    if (zan_start_worker_processes() < 0)
    {
        zanError("zan_start_worker_processes failed.");
        return ZAN_ERR;
    }

    ////TODO::::
    ////factory->finish = swFactory_finish;

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
    zanServer *serv = ServerG.serv;

    int fd = task->data.info.fd;
    send_len = sizeof(task->data.info) + task->data.info.len;

    //1. get target_worker_id
    if (task->target_worker_id < 0)
    {
        schedule_key = task->data.info.fd;
        to_worker_id = zanServer_worker_schedule(serv, schedule_key);
    }
    else
    {
        to_worker_id = task->target_worker_id;
    }

    //2. send data to worker
    //todo:::
    if (swEventData_is_stream(task->data.info.type))
    {
        swConnection *conn = zanServer_get_connection(serv, task->data.info.fd);
        if (conn == NULL || conn->active == 0)
        {
            zanWarn("dispatch[type=%d] failed, connection#%d is not active.", task->data.info.type, task->data.info.fd);
            return ZAN_ERR;
        }
        //conn active close, discard data.
        if (conn->closed)
        {
            if (!(task->data.info.type == SW_EVENT_CLOSE && conn->close_force))
            {
                zanWarn("dispatch[type=%d] failed, connection#%d[session_id=%d] is closed by server.",
                        task->data.info.type, task->data.info.fd, conn->session_id);
                return ZAN_OK;
            }
            else
            {
                ///TODO:::??????
                zanWarn("error: type=%d, fd=%d, session_id=%d", task->data.info.type, task->data.info.fd, conn->session_id);
                return ZAN_ERR;
            }
        }

        //converted fd to session_id
        task->data.info.fd = conn->session_id;
        task->data.info.from_fd = conn->from_fd;
        zanDebug("send2worker: fd=%d, session_id=%d, from_fd=%d, len=%d, worker_id=%d", fd, conn->session_id, conn->from_fd, send_len, to_worker_id);
    }

    return zanNetworker_send2worker((void *) &(task->data), send_len, to_worker_id);
}

//send data to client
static int zanFactory_finish(zanFactory *factory, swSendData *resp)
{
    int ret, sendn, session_id;
    zanServer *serv = (zanServer *)ServerG.serv;

    if (!factory || !resp)
    {
        zanError("factory=%p or resp=%p is null", factory, resp);
        return ZAN_ERR;
    }

    //todo:::
    session_id = resp->info.fd;
    swConnection *conn = zanServer_verify_connection(serv, session_id);
    if (!conn)
    {
        zanWarn("session#fd=%d does not exist.", session_id);
        return ZAN_ERR;
    }
    else if ((conn->closed || conn->removed) && resp->info.type != SW_EVENT_CLOSE)
    {
        int _len = resp->length > 0 ? resp->length : resp->info.len;
        zanWarn("send %d byte failed, because session#fd=%d is closed.", _len, session_id);
        return ZAN_ERR;
    }
    else if (conn->overflow)
    {
        zanWarn("send failed, session#fd=%d output buffer has been overflowed.", session_id);
        return ZAN_ERR;
    }

    swEventData ev_data;
    memset(&ev_data, 0, sizeof(ev_data));
    ev_data.info.fd   = session_id;
    ev_data.info.type = resp->info.type;

    ////TODO:::
    zanWorker *worker  = zanServer_get_worker(serv, ServerWG.worker_id);

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
        response.worker_id = ServerWG.worker_id;

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

    ret = zanWorker_send2networker(&ev_data, sendn, session_id);
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
    //zanServer *serv = (zanServer *)ServerG.serv;
    swSendData _send;
    //swDataHead info;

    bzero(&_send, sizeof(_send));
    _send.info.fd   = fd;
    _send.info.len  = 0;
    _send.info.type = SW_EVENT_CLOSE;

    zanDebug("for test, todo.........");
    return ZAN_OK;

#if 0
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
#endif
}
