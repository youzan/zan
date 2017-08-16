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

#include "zanProcess.h"
#include <errno.h>

///TODO:::
///要进行什么样的封装？跨平台吗?
///

#ifdef XXXX
    ///......
#endif

zan_pid_t zan_fork()
{
    return fork();
}

zan_pid_t zan_wait(int *status)
{
    return wait(status);
}

void zan_exit(int status)
{
    exit(status);
}

int zan_setuid(zan_uid_t uid)
{
    return setuid(uid);
}

int zan_waitpid(zan_pid_t pid, int *status, int options)
{
    int ret;
    do
    {
        ret = waitpid(pid, status, options);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while(1);

    return ret;
}

int zan_kill(zan_pid_t pid, int sig)
{
    int ret = -1;
    do
    {
        ret = kill(pid, sig);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while (1);

    return ret;
}
