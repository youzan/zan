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
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#ifndef _ZAN_SYSTEM_H_
#define _ZAN_SYSTEM_H_

#include <sys/resource.h>
#include <sys/utsname.h>
#include "zanProcess.h"

#ifdef __cplusplus
extern "C" {
#endif

//todo::跨平台

#define  NGX_OK          0
#define  NGX_ERROR      -1
#define NGX_SETPROCTITLE_PAD       '\0'

typedef int                 ngx_int_t;
typedef unsigned int        ngx_uint_t;

zan_pid_t zan_getpid(void);
zan_pid_t zan_getppid(void);
long zan_sysconf(int name);
int zan_uname(struct utsname *buf);
int zan_getrlimit(int resource, struct rlimit *rlim);

#ifdef __cplusplus
}
#endif


#endif
