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

static int zanFileLock_lock_rd(zanLock *lock);
static int zanFileLock_lock_rw(zanLock *lock);
static int zanFileLock_unlock(zanLock *lock);
static int zanFileLock_trylock_rw(zanLock *lock);
static int zanFileLock_trylock_rd(zanLock *lock);
static int zanFileLock_free(zanLock *lock);


int zanFileLock_create(zanLock *lock, int fd);

int zanFileLock_create(zanLock *lock, int fd)
{
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    bzero(lock, sizeof(zanLock));

    lock->lock_type = ZAN_FILELOCK;
    lock->object.filelock.fd = fd;
    lock->lock_rd = zanFileLock_lock_rd;
    lock->lock = zanFileLock_lock_rw;
    lock->trylock_rd = zanFileLock_trylock_rd;
    lock->trylock = zanFileLock_trylock_rw;
    lock->unlock = zanFileLock_unlock;
    lock->free = zanFileLock_free;
    return 0;
}

static int zanFileLock_lock_rd(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    lock->object.filelock.lock_t.l_type = F_RDLCK;

    ret = fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
    if (-1 == ret) {
        zanError("fcntl return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}

static int zanFileLock_lock_rw(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    lock->object.filelock.lock_t.l_type = F_WRLCK;
    ret = fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
    if (-1 == ret) {
        zanError("fcntl return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}

static int zanFileLock_unlock(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    lock->object.filelock.lock_t.l_type = F_UNLCK;
    ret = fcntl(lock->object.filelock.fd, F_SETLKW, &lock->object.filelock);
    if (-1 == ret) {
        zanError("fcntl return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}

static int zanFileLock_trylock_rw(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    lock->object.filelock.lock_t.l_type = F_WRLCK;
    ret = fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
    if (-1 == ret) {
        zanError("fcntl return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}

static int zanFileLock_trylock_rd(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    lock->object.filelock.lock_t.l_type = F_RDLCK;
    ret = fcntl(lock->object.filelock.fd, F_SETLK, &lock->object.filelock);
    if (-1 == ret) {
        zanError("fcntl return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}

static int zanFileLock_free(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = close(lock->object.filelock.fd);
    if (-1 == ret) {
        zanError("close return error, errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}
