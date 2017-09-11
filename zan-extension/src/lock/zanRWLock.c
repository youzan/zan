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

#ifdef HAVE_RWLOCK
static int zanRWLock_lock_rd(zanLock *lock);
static int zanRWLock_lock_rw(zanLock *lock);
static int zanRWLock_unlock(zanLock *lock);
static int zanRWLock_trylock_rw(zanLock *lock);
static int zanRWLock_trylock_rd(zanLock *lock);
static int zanRWLock_free(zanLock *lock);

int zanRWLock_create(zanLock *lock, int use_in_process);

int zanRWLock_create(zanLock *lock, int use_in_process)
{
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    bzero(lock, sizeof(zanLock));

    if (use_in_process && pthread_rwlockattr_setpshared(&lock->object.rwlock.attr, PTHREAD_PROCESS_SHARED) < 0)
    {
        zanSysError("pthread_rwlockattr_setpshared fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (pthread_rwlock_init(&lock->object.rwlock._lock, &lock->object.rwlock.attr) < 0)
    {
        zanSysError("pthread_rwlockattr_setpshared fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    lock->lock_type = ZAN_RWLOCK;
    lock->lock_rd = zanRWLock_lock_rd;
    lock->lock = zanRWLock_lock_rw;
    lock->unlock = zanRWLock_unlock;
    lock->trylock = zanRWLock_trylock_rw;
    lock->trylock_rd = zanRWLock_trylock_rd;
    lock->free = zanRWLock_free;
    return ZAN_OK;
}

static int zanRWLock_lock_rd(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_rdlock(&lock->object.rwlock._lock);
    ret = pthread_rwlock_rdlock(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_rdlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanRWLock_lock_rw(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_wrlock(&lock->object.rwlock._lock);
    ret = pthread_rwlock_wrlock(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_wrlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanRWLock_unlock(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_unlock(&lock->object.rwlock._lock);
    ret = pthread_rwlock_unlock(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_unlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanRWLock_trylock_rd(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_tryrdlock(&lock->object.rwlock._lock);
    ret = pthread_rwlock_tryrdlock(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_unlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanRWLock_trylock_rw(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_trywrlock(&lock->object.rwlock._lock);
    ret = pthread_rwlock_trywrlock(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_trywrlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanRWLock_free(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //return pthread_rwlock_destroy(&lock->object.rwlock._lock);
    ret = pthread_rwlock_destroy(&lock->object.rwlock._lock);
    if (0 != ret) {
        zanError("pthread_rwlock_destroy return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

#endif
