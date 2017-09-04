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

#include "stdlib.h"
#include "string.h"
#include "zanSystem.h"

//todo::: 跨平台
//错误处理

zan_pid_t zan_getpid(void)
{
    return getpid();
}

zan_pid_t zan_getppid(void)
{
    return getppid();
}

long zan_sysconf(int name)
{
    return sysconf(name);
}

int zan_uname(struct utsname *buf)
{
    return uname(buf);
}

int zan_getrlimit(int resource, struct rlimit *rlim)
{
    return getrlimit(resource, rlim);
}

