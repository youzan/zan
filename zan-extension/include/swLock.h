/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group                                    |
  +----------------------------------------------------------------------+
  | This source file is subject to version 2.0 of the Apache license,    |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
  | If you did not receive a copy of the Apache2.0 license and are unable|
  | to obtain it through the world-wide-web, please send a note to       |
  | zan@zanphp.io so we can mail you a copy immediately.                 |
  +----------------------------------------------------------------------+
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/


#ifndef SW_LOCK_H_
#define SW_LOCK_H_

#include "swoole.h"
#include "swAtomic.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <fcntl.h>

//------------------Lock--------------------------------------
enum SW_LOCKS
{
    SW_RWLOCK = 1,
#define SW_RWLOCK SW_RWLOCK
    SW_FILELOCK = 2,
#define SW_FILELOCK SW_FILELOCK
    SW_MUTEX = 3,
#define SW_MUTEX SW_MUTEX
    SW_SEM = 4,
#define SW_SEM SW_SEM
    SW_SPINLOCK = 5,
#define SW_SPINLOCK SW_SPINLOCK
    SW_ATOMLOCK = 6,
#define SW_ATOMLOCK SW_ATOMLOCK
};

//File Lock
typedef struct _swFileLock
{
    struct flock lock_t;
    int fd;
} swFileLock;

//Mutex Lock
typedef struct _swMutex
{
    pthread_mutex_t _lock;
    pthread_mutexattr_t attr;
} swMutex;

//R/W Lock
#ifdef HAVE_RWLOCK
typedef struct _swRWLock
{
    pthread_rwlock_t _lock;
    pthread_rwlockattr_t attr;

} swRWLock;
#endif

//Spin Lock
#ifdef HAVE_SPINLOCK
typedef struct _swSpinLock
{
    pthread_spinlock_t lock_t;
} swSpinLock;
#endif

//Atomic Lock
typedef struct _swAtomicLock
{
    sw_atomic_t lock_t;
    uint32_t spin;
} swAtomicLock;

//Sem
typedef struct _swSem
{
    key_t key;
    int semid;
} swSem;

//encapsulation of all kinds of locks and sem
//containing type,lock object and op functions
typedef struct _swLock
{   
    // determined by SW_LOCKS  
    int type;
    // all kinds of locks and sem
    union
    {
        swMutex mutex;
#ifdef HAVE_RWLOCK
        swRWLock rwlock;
#endif
#ifdef HAVE_SPINLOCK
        swSpinLock spinlock;
#endif
        swFileLock filelock;
        swSem sem;
        swAtomicLock atomlock;
    } object;

    //operation function
    int (*lock_rd)(struct _swLock *);
    int (*lock)(struct _swLock *);
    int (*unlock)(struct _swLock *);
    int (*trylock_rd)(struct _swLock *);
    int (*trylock)(struct _swLock *);
    int (*free)(struct _swLock *);
}swLock;

//Thread Condition
typedef struct _swCond
{
    swLock lock;
    pthread_cond_t cond;

    int (*wait)(struct _swCond *object);
    int (*timewait)(struct _swCond *object, long, long);
    int (*notify)(struct _swCond *object);
    int (*broadcast)(struct _swCond *object);
    void (*free)(struct _swCond *object);
} swCond;

#ifdef HAVE_RWLOCK
int swRWLock_create(swLock *lock, int use_in_process);
#endif

int swSem_create(swLock *lock, key_t key);

int swMutex_create(swLock *lock, int use_in_process);
int swMutex_lockwait(swLock *lock, int timeout_msec);
int swFileLock_create(swLock *lock, int fd);

#ifdef HAVE_SPINLOCK
int swSpinLock_create(swLock *object, int spin);
#endif

int swAtomicLock_create(swLock *object, int spin);

int swCond_create(swCond *cond);

#ifdef __cplusplus
}
#endif

#endif
