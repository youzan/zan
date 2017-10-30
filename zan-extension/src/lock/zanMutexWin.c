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

/**
 * Only for windows platform
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

    // set mutex name (Mutex:{PID}:{idx})
    static int idx = 0;
    sprintf(lock->object.mutex.name, "Mutex:%d:%d", GetCurrentProcessId(), idx++);

    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd,TRUE,NULL,FALSE);
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = use_in_process ? TRUE : FALSE;

    lock->object.mutex._lock = CreateMutex(&sa, FALSE, lock->object.mutex.name);
    if (!lock->object.mutex._lock) {
        zanSysError("CreateMutex fail，errno=%d", GetLastError());
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
    DWORD dwRet;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    dwRet = WaitForSingleObject(lock->object.mutex._lock, INFINITE);
    if (WAIT_OBJECT_0 != dwRet) {
        zanError("WaitForSingleObject return ret=%d, errno=%d", dwRet, GetLastError())
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanMutex_unlock(zanLock *lock)
{
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    if (!ReleaseMutex(lock->object.mutex._lock)) {
        zanError("ReleaseMutex fail, errno=%d", GetLastError());
    }
    return ZAN_OK;
}

static int zanMutex_trylock(zanLock *lock)
{
    DWORD dwRet;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    dwRet = WaitForSingleObject(lock->object.mutex._lock, 0);
    if (WAIT_TIMEOUT != dwRet) {
        zanError("WaitForSingleObject trylock return ret=%d, errno=%d", dwRet, GetLastError());
        return ZAN_ERR;
    }
    return ZAN_OK;
}

int zanMutex_lockwait(zanLock *lock, int timeout_msec)
{
    DWORD dwRet;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }

    dwRet = WaitForSingleObject(lock->object.mutex._lock, timeout_msec);
    switch (dwRet) {
        case WAIT_ABANDONED:
            zanWarn("WaitForSingleObject return WAIT_ABANDONED");
            return ZAN_OK;
        case WAIT_OBJECT_0:
            return ZAN_OK;
        case WAIT_TIMEOUT:
            return ZAN_ERR;
        case WAIT_FAILED:
            zanError("WaitForSingleObject return WAIT_FAILED");
            return ZAN_ERR;
        default:
            zanError("WaitForSingleObject return unknow:%d", dwRet);
    }
    return ZAN_ERR;
}

static int zanMutex_free(zanLock *lock)
{
    int ret = 0;
    if (!lock)
    {
        zanError("lock is null");
        return ZAN_ERR;
    }
    CloseHandle(lock->object.mutex._lock);
    return ZAN_OK;
}

