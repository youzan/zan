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

static int zanCond_notify(zanCond *cond);
static int zanCond_broadcast(zanCond *cond);
static int zanCond_timewait(zanCond *cond, long sec, long nsec);
static int zanCond_wait(zanCond *cond);
static void zanCond_free(zanCond *cond);

extern int zanMutex_create(zanLock *lock, int use_in_process);

int zanCond_create(zanCond *cond)
{
    if (!cond)
    {
        zanError("cond is null");
        return ZAN_ERR;
    }

    if (0 != pthread_cond_init(&cond->cond, NULL))
    {
        zanSysError("pthread_cond_init fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (ZAN_OK != zanMutex_create(&cond->lock, 0))
    {
        zanError("zanMutex_create return error.");
        return ZAN_ERR;
    }

    cond->notify = zanCond_notify;
    cond->broadcast = zanCond_broadcast;
    cond->timewait = zanCond_timewait;
    cond->wait = zanCond_wait;
    cond->free = zanCond_free;

    return ZAN_OK;
}

static int zanCond_notify(zanCond *cond)
{
    int err = 0;
    if (!cond)
    {
        zanError("cond is null");
        return ZAN_ERR;
    }

    err = pthread_cond_signal(&cond->cond);
    if (0 != err)
    {
        zanError("pthread_cond_signal return err=%d, errno=%d:%s", err, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanCond_broadcast(zanCond *cond)
{
    int err = 0;
    if (!cond)
    {
        zanError("cond is null");
        return ZAN_ERR;
    }

    err = pthread_cond_broadcast(&cond->cond);
    if (0 != err)
    {
        zanError("pthread_cond_broadcast return err=%d, errno=%d:%s", err, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanCond_timewait(zanCond *cond, long sec, long nsec)
{
    int err = 0;
    if (!cond)
    {
        zanError("cond is null");
        return ZAN_ERR;
    }

    struct timespec timeo;

    timeo.tv_sec = sec;
    timeo.tv_nsec = nsec;

    err = pthread_cond_timedwait(&cond->cond, &cond->lock.object.mutex._lock, &timeo);
    if (0 != err)
    {
        zanError("pthread_cond_timedwait return err=%d, errno=%d:%s", err, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanCond_wait(zanCond *cond)
{
    int err = 0;
    if (!cond)
    {
        zanError("cond is null");
        return ZAN_ERR;
    }

    err = pthread_cond_wait(&cond->cond, &cond->lock.object.mutex._lock);
    if (0 != err)
    {
        zanError("pthread_cond_wait return err=%d, errno=%d:%s", err, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static void zanCond_free(zanCond *cond)
{
    int err = 0;
    if (!cond)
    {
        zanError("cond is null");
        return;
    }

    err = pthread_cond_destroy(&cond->cond);
    if (err != 0)
    {
        zanError("pthread_cond_destroy fail，err=%d, errno=%d:%s", err, errno, strerror(errno));
    }
    cond->lock.free(&cond->lock);
}
