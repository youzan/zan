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


#ifndef SWOOLE_H_
#define SWOOLE_H_


#if defined(HAVE_CONFIG_H) && !defined(COMPILE_DL_ZAN)
#include "config.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

#ifndef PHP_WIN32
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/utsname.h>
#endif

#ifdef SW_USE_OPENSSL
#include <openssl/ssl.h>
#endif

/*----------------------------------------------------------------------------*/
#ifndef ulong
#define ulong unsigned long
#endif

typedef unsigned long ulong_t;

#if defined(__GNUC__)
#if __GNUC__ >= 3
#define sw_inline inline __attribute__((always_inline))
#else
#define sw_inline inline
#endif
#elif defined(_MSC_VER)
#define sw_inline __forceinline
#else
#define sw_inline inline
#endif

#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif

#define SW_START_LINE  "-------------------------START----------------------------"
#define SW_END_LINE    "-------------------------END------------------------------"
#define SW_SPACE       ' '
#define SW_CRLF        "\r\n"
/*----------------------------------------------------------------------------*/

#include "swoole_config.h"

#define SW_MAX_UINT            4294967295
#define SW_MAX_INT             2147483647

#ifndef MAX
#define MAX(a, b)              (a)>(b)?(a):(b);
#endif
#ifndef MIN
#define MIN(a, b)              (a)<(b)?(a):(b);
#endif

#define SW_STRL(s)             s, sizeof(s)
#define SW_START_SLEEP         usleep(100000)  //sleep 1s,wait fork and pthread_create

//-------------------------------------------------------------------------------
#define SW_ASYNCERR            1
#define SW_OK                  0
#define SW_ERR                -1
#define SW_AGAIN              -2
#define SW_BUSY               -3
#define SW_DONE               -4
#define SW_DECLINED           -5
#define SW_ABORT              -6

//===============just for refactor...
#define ZAN_OK                 0
#define ZAN_ERR               -1

//-------------------------------------------------------------------------------
enum swReturnType
{
    SW_CONTINUE = 1,
    SW_WAIT     = 2,
    SW_CLOSE    = 3,
    SW_ERROR    = 4,
    SW_READY    = 5,
};

//-------------------------------------------------------------------------------
enum swFd_type
{
    SW_FD_TCP             = 0, //tcp socket
    SW_FD_LISTEN          = 1, //server socket
    SW_FD_CLOSE           = 2, //socket closed
    SW_FD_ERROR           = 3, //socket error
    SW_FD_UDP             = 4, //udp socket
    SW_FD_PIPE            = 5, //pipe
    SW_FD_WRITE           = 7, //fd can write
    SW_FD_TIMER           = 8, //timer fd
    SW_FD_AIO             = 9, //linux native aio
    SW_FD_SIGNAL          = 11, //signalfd
    SW_FD_DNS_RESOLVER    = 12, //dns resolver
    SW_FD_INOTIFY         = 13, //server socket
    SW_FD_USER            = 15, //SW_FD_USER or SW_FD_USER+n: for custom event
    SW_FD_STREAM_CLIENT   = 16, //swClient stream
    SW_FD_DGRAM_CLIENT    = 17, //swClient dgram
};

enum swBool_type
{
    SW_TRUE = 1,
    SW_FALSE = 0,
};

//-------------------------------------------------------------------------------
enum swCloseType
{
    SW_CLOSE_PASSIVE = 32,          ///被动关闭
    SW_CLOSE_INITIATIVE,            ///主动关闭
};

enum swClientTimeoutType
{
    SW_CLIENT_INVAILED_TIMEOUT = 0,
    SW_CLIENT_CONNECT_TIMEOUT = 1,
    SW_CLIENT_RECV_TIMEOUT = 2,
};

#define SW_MODE_PACKET         0x10
#define SW_SOCK_SSL            (1u << 9)
#define SW_MAX_FDTYPE          32 //32 kinds of event

#define swYield()              sched_yield() //or usleep(1)

#ifndef uchar
typedef unsigned char uchar;
#endif

typedef struct _swDataHead
{
    int      fd;
    uint8_t  type;
    uint8_t  from_fd;
    uint16_t len;
    uint16_t from_id;
    uint16_t worker_id;
    uint16_t networker_id;
} swDataHead;

typedef struct _swUdpFd
{
    struct sockaddr addr;
    int sock;
} swUdpFd;

//=============================
typedef struct
{
    uint32_t session_id;
    uint32_t accept_fd;
    uint8_t  reactor_id;
    uint8_t  networker_id;
} zanSession;

//for test
enum zanServer_mode
{
    ZAN_MODE_BASE          =  1,
    ZAN_MODE_PROCESS       =  2,
};

void zan_init(void);
void zan_clean(void);
void zan_update_time(void);
void zan_set_loglevel(uint8_t);
double get_microtime(void);

#ifdef __cplusplus
}
#endif
#endif /* SWOOLE_H_ */
