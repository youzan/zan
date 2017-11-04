/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
  | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
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
#ifndef _SW_SOCKET_H_
#define _SW_SOCKET_H_

#include "swoole.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PHP_WIN32
#include "winsock2.h"
#include "ws2tcpip.h"
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netdb.h>
#endif

#include "win32/def.h"

enum swSocket_type
{
    SW_SOCK_UNKNOW       =  0,
    SW_SOCK_TCP          =  1,
    SW_SOCK_UDP          =  2,
    SW_SOCK_TCP6         =  3,
    SW_SOCK_UDP6         =  4,
    SW_SOCK_UNIX_DGRAM   =  5,  //unix sock dgram
    SW_SOCK_UNIX_STREAM  =  6,  //unix sock stream
};

typedef struct _swSocketLocal
{
    socklen_t len;
    char file[0];
} swSocketLocal;

typedef struct
{
    union
    {
        struct sockaddr_in inet_v4;
        struct sockaddr_in6 inet_v6;
#ifndef PHP_WIN32
        struct sockaddr_un un;
#endif
    } addr;
    socklen_t len;

} swSocketAddress;

#ifdef SW_USE_IOCTL
#define swSetNonBlock(sock,flag)   swSocket_ioctl_set_block(sock, flag)
#else
#define swSetNonBlock(sock,flag)   swSocket_fcntl_set_option(sock, flag, 0)
#endif

#if defined(TCP_NOPUSH) || defined(TCP_CORK)
#define HAVE_TCP_NOPUSH
#ifdef TCP_NOPUSH
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_NOPUSH, (const void *) &nopush, sizeof(int));
}

#elif defined(TCP_CORK)
static sw_inline int swSocket_tcp_nopush(int sock, int nopush)
{
    return setsockopt(sock, IPPROTO_TCP, TCP_CORK, (const void *) &nopush, sizeof(int));
}
#endif
#else
#define swSocket_tcp_nopush(sock, nopush)
#endif


static sw_inline int swSocket_is_dgram(uint8_t type)
{
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6 || type == SW_SOCK_UNIX_DGRAM);
}

static sw_inline int swSocket_is_udpDgram(uint8_t type)
{
    return (type == SW_SOCK_UDP || type == SW_SOCK_UDP6);
}

static sw_inline int swSocket_is_stream(uint8_t type)
{
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6 || type == SW_SOCK_UNIX_STREAM);
}

static sw_inline int swSocket_is_tcpStream(uint8_t type)
{
    return (type == SW_SOCK_TCP || type == SW_SOCK_TCP6);
}

static sw_inline int swSocket_is_NET6(uint8_t type)
{
    return (type == SW_SOCK_TCP6 || type == SW_SOCK_UDP6);
}

static sw_inline int swSocket_is_NET(uint8_t type)
{
    return (type == SW_SOCK_TCP || type == SW_SOCK_UDP);
}

int swSocket_create(int type,int *sockType,int *sockDomain);
int swSocket_bind(int sock, int type, char *host, int port);
int swSocket_wait(int fd, int timeout_ms, int events);

void swSocket_clean(int fd);
int swSocket_set_buffer_size(int fd, int buffer_size);
int swSocket_set_timeout(int sock, double timeout);

int swSocket_udp_sendto(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);
int swSocket_udp_sendto6(int server_sock, char *dst_ip, int dst_port, char *data, uint32_t len);

int swSocket_sendfile_sync(int sock, char *filename, double timeout);
int swSocket_write_blocking(int __fd, void *__data, int __len);
int swSocket_sendto_blocking(int fd, void *__buf, size_t __n, int flag, struct sockaddr *__addr, socklen_t __addr_len);

void swSocket_ioctl_set_block(int sock, int nonblock);
void swSocket_fcntl_set_option(int sock, int nonblock, int cloexec);

int zan_set_nonblocking(int fd, int isNonBlock);

int swWrite(int, void *, int);

#ifdef __cplusplus
}
#endif

#endif
