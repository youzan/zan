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

#include "zanLock.h"
#include "zanLog.h"

static int zanMutex_lock(zanLock *lock);
static int zanMutex_unlock(zanLock *lock);
static int zanMutex_trylock(zanLock *lock);
static int zanMutex_free(zanLock *lock);

int zanMutex_create(zanLock *lock, int use_in_process);

int zanMutex_create(zanLock *lock, int use_in_process)
{
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    bzero(lock, sizeof(zanLock));

    pthread_mutexattr_init(&lock->object.mutex.attr);
    if (use_in_process && pthread_mutexattr_setpshared(&lock->object.mutex.attr, PTHREAD_PROCESS_SHARED) < 0)
    {
        zanSysError("pthread_mutexattr_setpshared fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }


    if (pthread_mutex_init(&lock->object.mutex._lock, &lock->object.mutex.attr) < 0)
    {
        zanSysError("pthread_mutex_init fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    lock->lock_type = ZAN_MUTEX;
    lock->lock = zanMutex_lock;
    lock->unlock = zanMutex_unlock;
    lock->trylock = zanMutex_trylock;
    lock->free = zanMutex_free;
    return ZAN_OK;
}

static int zanMutex_lock(zanLock *lock)
{
    int ret = 0;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_mutex_lock(&lock->object.mutex._lock);
    if (0 != ret) {
        zanError("pthread_mutex_lock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanMutex_unlock(zanLock *lock)
{
    int ret = 0;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_mutex_unlock(&lock->object.mutex._lock);
    if (0 != ret) {
        zanError("pthread_mutex_unlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanMutex_trylock(zanLock *lock)
{
    int ret = 0;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_mutex_trylock(&lock->object.mutex._lock);
    if (0 != ret) {
        zanError("pthread_mutex_trylock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

#ifdef HAVE_MUTEX_TIMEDLOCK
int zanMutex_lockwait(zanLock *lock, int timeout_msec)
{
    int ret = 0;
    struct timespec timeo;

    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    timeo.tv_sec = timeout_msec / 1000;
    timeo.tv_nsec = (timeout_msec - timeo.tv_sec * 1000) * 1000 * 1000;

    //return pthread_mutex_timedlock(&lock->object.mutex._lock, &timeo);
    ret = pthread_mutex_timedlock(&lock->object.mutex._lock, &timeo);
    if (0 != ret) {
        zanError("pthread_mutex_timedlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}
#else
int zanMutex_lockwait(zanLock *lock, int timeout_msec)
{
    int sub = 1;
    int sleep_ms = 1000;

    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    if (timeout_msec > 100)
    {
        sub = 10;
        sleep_ms = 10000;
    }

    while( timeout_msec > 0)
    {
        if (pthread_mutex_trylock(&lock->object.mutex._lock) != 0)
        {
            usleep(sleep_ms);
            timeout_msec -= sub;
        }
        else
        {
            return ZAN_OK;
        }
    }
    return ETIMEDOUT;
}
#endif

static int zanMutex_free(zanLock *lock)
{
    int ret = 0;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_mutex_destroy(&lock->object.mutex._lock);
    if (0 != ret) {
        zanError("pthread_mutex_destroy return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

