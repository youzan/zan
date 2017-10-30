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

//=============================used for zanLock_create==========================
extern int zanMutex_create(zanLock *lock, int use_in_process);
#ifdef HAVE_RWLOCK
extern int zanRWLock_create(zanLock *lock, int use_in_process);
#endif
#ifdef HAVE_SPINLOCK
extern int zanSpinLock_create(zanLock *object, int spin);
#endif
extern int zanFileLock_create(zanLock *lock, int fd);
extern int zanSem_create(zanLock *lock, key_t key);
extern int zanAtomicLock_create(zanLock *object, int spin);

int zanLock_create(zanLock *lock, enum ZAN_LOCK_TYPE lock_type, int lock_arg)
{
    if (lock_type == ZAN_RWLOCK) {
#ifdef HAVE_RWLOCK
        return zanRWLock_create(lock, lock_arg);
#endif
        zanFatalError("ZAN_RWLOCK lock_type not support, exit.");
        return ZAN_ERR;
#ifndef PHP_WIN32
    } else if (lock_type == ZAN_FILELOCK) {
        return zanFileLock_create(lock, lock_arg);
#endif
    } else if (lock_type == ZAN_MUTEX) {
        return zanMutex_create(lock, lock_arg);
    } else if (lock_type == ZAN_SEM) {
        return zanSem_create(lock, lock_arg);
    } else if (lock_type == ZAN_SPINLOCK) {
#ifdef HAVE_SPINLOCK
        return zanSpinLock_create(lock, lock_arg);
#endif
        zanFatalError("ZAN_SPINLOCK lock_type not support, exit.");
        return ZAN_ERR;
    } else if (lock_type == ZAN_ATOMLOCK) {
        return zanAtomicLock_create(lock, lock_arg);
    } else {
        zanFatalError("lock_type=%d not support, exit.", lock_type);
        return ZAN_ERR;
    }
}
