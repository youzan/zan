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

#ifndef _ZAN_PROCESS_H_
#define _ZAN_PROCESS_H_

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

///TODO:::
///这些要封装成什么形式？？？

typedef pid_t zan_pid_t;
typedef uid_t zan_uid_t;

zan_pid_t zan_fork();

zan_pid_t zan_wait(int *status);

void zan_exit(int status);

int zan_setuid(zan_uid_t uid);

int zan_waitpid(zan_pid_t pid, int *status, int options);

int zan_kill(zan_pid_t pid, int sig);






/*
waitpid

setuid

exec

exit

kill

getenv

setenv

///////////////////////////////////////////
CreateProcess()             fork()
CreateProcessAsUser()       setuid()
                            exec()

TerminateProcess()          kill()

SetThreadpriority()         Setpriority()
GetThreadPriority()         getPriority()

GetCurrentProcessID()       getpid()

Exitprocess()               exit()

Waitforsingleobject()       waitpid()
Waitformultipleobject()     sys v semaphores
GetExitCodeProcess()        XXX

GetEnvironmentVariable      getenv()
SetEnvironmentVariable      setenv()
*/

#ifdef __cplusplus
}
#endif

#endif
