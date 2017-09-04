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

#ifdef HAVE_SPINLOCK
static int zanSpinLock_lock(zanLock *lock);
static int zanSpinLock_unlock(zanLock *lock);
static int zanSpinLock_trylock(zanLock *lock);
static int zanSpinLock_free(zanLock *lock);

int zanSpinLock_create(zanLock *object, int spin);

int zanSpinLock_create(zanLock *lock, int use_in_process)
{
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    bzero(lock, sizeof(zanLock));
    if (pthread_spin_init(&lock->object.spinlock.lock_t, use_in_process) < 0)
    {
        zanSysError("pthread_spin_init fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    lock->lock_type = ZAN_SPINLOCK;
    lock->lock = zanSpinLock_lock;
    lock->unlock = zanSpinLock_unlock;
    lock->trylock = zanSpinLock_trylock;
    lock->free = zanSpinLock_free;
    return ZAN_OK;
}

static int zanSpinLock_lock(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_spin_lock(&lock->object.spinlock.lock_t);
    if (0 != ret) {
        zanError("pthread_spin_lock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanSpinLock_unlock(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = zanSpinLock_unlock(&lock->object.spinlock.lock_t);
    if (0 != ret) {
        zanError("zanSpinLock_unlock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanSpinLock_trylock(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_spin_trylock(&lock->object.spinlock.lock_t);
    if (0 != ret) {
        zanError("pthread_spin_trylock return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanSpinLock_free(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = pthread_spin_destroy(&lock->object.spinlock.lock_t);
    if (0 != ret) {
        zanError("pthread_spin_destroy return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

#endif
