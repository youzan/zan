
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


#ifndef _ZAN_ZANLOCK_H_
#define _ZAN_ZANLOCK_H_

#include "swoole.h"
#include "swAtomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PHP_WIN32
#include <pthread.h>
#include <fcntl.h>
#endif

//===============================zanLock========================================
enum ZAN_LOCK_TYPE
{
    ZAN_RWLOCK = 1,
#define ZAN_RWLOCK ZAN_RWLOCK
    ZAN_FILELOCK = 2,
#define ZAN_FILELOCK ZAN_FILELOCK
    ZAN_MUTEX = 3,
#define ZAN_MUTEX ZAN_MUTEX
    ZAN_SEM = 4,
#define ZAN_SEM ZAN_SEM
    ZAN_SPINLOCK = 5,
#define ZAN_SPINLOCK ZAN_SPINLOCK
    ZAN_ATOMLOCK = 6,
#define ZAN_ATOMLOCK ZAN_ATOMLOCK
};

#ifdef PHP_WIN32

typedef struct _zanMutex
{
    HANDLE _lock;
    char name[32];
} zanMutex;

#else
typedef struct _zanFileLock
{
    struct flock lock_t;
    int fd;
} zanFileLock;

typedef struct _zanMutex
{
    pthread_mutex_t _lock;
    pthread_mutexattr_t attr;
} zanMutex;
#endif

#ifdef HAVE_RWLOCK
typedef struct _zanRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} zanRWLock;
#endif

#ifdef HAVE_SPINLOCK
typedef struct _zanSpinLock
{
    pthread_spinlock_t lock_t;
} zanSpinLock;
#endif

typedef struct _zanAtomicLock
{
    sw_atomic_t lock_t;
    uint32_t spin;
} zanAtomicLock;

typedef struct _zanSem
{
    key_t key;
    int semid;
} zanSem;

typedef struct _zanLock
{
    enum ZAN_LOCK_TYPE lock_type;

    union
    {
        zanMutex mutex;
#ifdef HAVE_RWLOCK
        zanRWLock rwlock;
#endif
#ifdef HAVE_SPINLOCK
        zanSpinLock spinlock;
#endif
#ifndef PHP_WIN32
        zanFileLock filelock;
#endif
        zanSem sem;
        zanAtomicLock atomlock;
    } object;

    //operation function
    int (*lock_rd)(struct _zanLock *);
    int (*lock)(struct _zanLock *);
    int (*unlock)(struct _zanLock *);
    int (*trylock_rd)(struct _zanLock *);
    int (*trylock)(struct _zanLock *);
    int (*free)(struct _zanLock *);
}zanLock;


//========================zanLock_create========================================
/*
 * lock_type: type of lock
 * lock_arg:
 *           lock_type = ZAN_RWLOCK,   lock_arg: use_in_process
 *           lock_type = ZAN_FILELOCK, lock_arg: fd
 *           lock_type = ZAN_MUTEX,    lock_arg: use_in_process
 *           lock_type = ZAN_SEM,      lock_arg: key
 *           lock_type = ZAN_SPINLOCK, lock_arg: spin
 *           lock_type = ZAN_ATOMLOCK, lock_arg: spin
 */
int zanLock_create(zanLock *lock, enum ZAN_LOCK_TYPE lock_type, int lock_arg);


#ifdef __cplusplus
}
#endif

#endif  //_ZAN_LOCK_H_
