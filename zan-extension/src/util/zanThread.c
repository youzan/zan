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

#include "zanThread.h"


#if (__linux__)

zan_tid_t zan_get_thread_tid(void)
{
    return syscall(SYS_gettid);
}

#elif (__FreeBSD__) && (__FreeBSD_version >= 900031)

#include <pthread_np.h>
zan_tid_t zan_get_thread_tid(void)
{
    return pthread_getthreadid_np();
}

#elif (__MACH__)
/*
 * MacOSX thread has two thread ids:
 *
 * 1) MacOSX 10.6 (Snow Leoprad) has pthread_threadid_np() returning
 *    an uint64_t value, which is obtained using the __thread_selfid()
 *    syscall.  It is a number above 300,000.
 */
zan_tid_t zan_get_thread_tid(void)
{
    uint64_t  tid;

    (void) pthread_threadid_np(NULL, &tid);
    return tid;
}

/*
 * 2) Kernel thread mach_port_t returned by pthread_mach_thread_np().
 *    It is a number in range 100-100,000.
 * return pthread_mach_thread_np(pthread_self());
 */
#else

zan_tid_t zan_get_thread_tid(void)
{
    return (uint64_t) (uintptr_t) pthread_self();
}

#endif


