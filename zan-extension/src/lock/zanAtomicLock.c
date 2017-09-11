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

//#include "zanBaseOperator.h"
#include "swBaseOperator.h"    ///todo:replace
#include "zanLock.h"
#include "zanLog.h"

static int zanAtomicLock_lock(zanLock *lock);
static int zanAtomicLock_unlock(zanLock *lock);
static int zanAtomicLock_trylock(zanLock *lock);

int zanAtomicLock_create(zanLock *object, int spin);

int zanAtomicLock_create(zanLock *lock, int spin)
{
    if (!lock){
        zanError("lock is null.");
        return ZAN_ERR;
    }

    bzero(lock, sizeof(zanLock));

    lock->lock_type = ZAN_ATOMLOCK;
    lock->object.atomlock.spin = spin;
    lock->lock    = zanAtomicLock_lock;
    lock->unlock  = zanAtomicLock_unlock;
    lock->trylock = zanAtomicLock_trylock;
    return ZAN_OK;
}

static int zanAtomicLock_lock(zanLock *lock)
{
    if (!lock){
        zanError("lock is null.");
        return ZAN_ERR;
    }

    zan_spinlock(&lock->object.atomlock.lock_t);
    return ZAN_OK;
}

static int zanAtomicLock_unlock(zanLock *lock)
{
    if (!lock){
        zanError("lock is null.");
        return ZAN_ERR;
    }

    lock->object.atomlock.lock_t = 0;
    return ZAN_OK;
}

static int zanAtomicLock_trylock(zanLock *lock)
{
    if (!lock){
        zanError("lock is null.");
        return ZAN_ERR;
    }

    zan_atomic_t *atomic = &lock->object.atomlock.lock_t;
    return (*(atomic) == 0 && zan_atomic_cmp_set(atomic, 0, 1));
}
