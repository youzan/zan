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

#include <sys/sem.h>
#include "zanLock.h"
#include "zanLog.h"

static int zanSem_lock(zanLock *lock);
static int zanSem_unlock(zanLock *lock);
static int zanSem_free(zanLock *lock);

int zanSem_create(zanLock *lock, key_t key);

int zanSem_create(zanLock *lock, key_t key)
{
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    //assert(key != 0);
    if (key == 0){
        zanError("key==0.");
        return ZAN_ERR;
    }

    int semid = semget(key, 1, IPC_CREAT | 0666);
    if (semid < 0)
    {
        zanSysError("semget fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    if (semctl(semid, 0, SETVAL, 1) < 0)
    {
        zanSysError("semget(SETVAL) fail，errno=%d:%s", errno, strerror(errno));
        return ZAN_ERR;
    }

    lock->lock_type = ZAN_SEM;
    lock->object.sem.semid = semid;

    lock->lock = zanSem_lock;
    lock->unlock = zanSem_unlock;
    lock->free = zanSem_free;

    return ZAN_OK;
}

static int zanSem_unlock(zanLock *lock)
{
    int ret = 0;
    struct sembuf sem;

    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = 1;

    ret = semop(lock->object.sem.semid, &sem, 1);
    if (0 != ret) {
        zanError("semop(SEM_UNDO,op=1) return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanSem_lock(zanLock *lock)
{
    int ret = 0;
    struct sembuf sem;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    sem.sem_flg = SEM_UNDO;
    sem.sem_num = 0;
    sem.sem_op = -1;

    ret = semop(lock->object.sem.semid, &sem, 1);
    if (0 != ret) {
        zanError("semop(SEM_UNDO,op=-1) return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static int zanSem_free(zanLock *lock)
{
    int ret = 0;
    if (!lock){
        zanError("lock is null");
        return ZAN_ERR;
    }

    ret = semctl(lock->object.sem.semid, 0, IPC_RMID);
    if (-1 == ret) {
        zanError("semctl(IPC_RMID) return ret=%d, errno=%d:%s", ret, errno, strerror(errno));
        return ZAN_ERR;
    }
    return ret;
}
