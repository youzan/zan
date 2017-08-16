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
#ifndef _ZAN_SOCKET_H_
#define _ZAN_SOCKET_H_

#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include "swoole.h"
#include "zanLog.h"

#ifdef __cplusplus
extern "C" {
#endif

///TODO::: 包装一些 socket 的接口
///具体接口形式应该是什么样的？封装哪些接口?

//make socket, send, recv 之类的？


int zan_nonblocking(int fd, int isNonBlock);
int zanSocket_set_buffer_size(int fd, int buffer_size);

#ifdef __cplusplus
}
#endif

#endif
