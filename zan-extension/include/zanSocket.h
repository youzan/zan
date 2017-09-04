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

///TODO:::

enum zanSocketType
{
    ZAN_SOCK_UNKNOW       =  0,
    ZAN_SOCK_TCP          =  1,
    ZAN_SOCK_UDP          =  2,
    ZAN_SOCK_TCP6         =  3,
    ZAN_SOCK_UDP6         =  4,
    ZAN_SOCK_UNIX_DGRAM   =  5,  //unix sock dgram
    ZAN_SOCK_UNIX_STREAM  =  6,  //unix sock stream
};


int zan_set_nonblocking(int fd, int isNonBlock);
int zan_socket_set_buffersize(int fd, int buffer_size);

static inline int zanSocket_is_dgram(uint8_t type)
{
    return (type == ZAN_SOCK_UDP || type == ZAN_SOCK_UDP6 || type == ZAN_SOCK_UNIX_DGRAM);
}

static inline int zanSocket_is_udpDgram(uint8_t type)
{
    return (type == ZAN_SOCK_UDP || type == ZAN_SOCK_UDP6);
}

static inline int zanSocket_is_stream(uint8_t type)
{
    return (type == ZAN_SOCK_TCP || type == ZAN_SOCK_TCP6 || type == ZAN_SOCK_UNIX_STREAM);
}

static inline int zanSocket_is_tcpStream(uint8_t type)
{
    return (type == ZAN_SOCK_TCP || type == ZAN_SOCK_TCP6);
}

static inline int zanSocket_is_NET6(uint8_t type)
{
    return (type == ZAN_SOCK_TCP6 || type == ZAN_SOCK_UDP6);
}

static inline int zanSocket_is_NET(uint8_t type)
{
    return (type == ZAN_SOCK_TCP || type == ZAN_SOCK_UDP);
}


#ifdef __cplusplus
}
#endif

#endif
