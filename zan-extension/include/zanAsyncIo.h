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

#ifndef _ZAN_ZANASYNCIO_H_
#define _ZAN_ZANASYNCIO_H_

#include "zanIpc.h"

#ifdef __cplusplus
extern "C" {
#endif

//=========================================
enum swAioMode
{
    SW_AIO_BASE = 0,
    SW_AIO_LINUX,
};

enum
{
    SW_AIO_READ = 0,
    SW_AIO_WRITE = 1,
    SW_AIO_DNS_LOOKUP = 2,
};

#define SW_FILE_MAX_LEN_ONCE        1*1024*1024

typedef struct _swAio_event
{
    int fd;
    int task_id;
    uint8_t type;
    off_t offset;
    size_t nbytes;
    void *buf;
    void *req;
    int ret;
    int error;
} swAio_event;

typedef struct _zanAsyncIO
{
    uint8_t  init;
    uint8_t  thread_num;
    uint32_t task_num;
    uint32_t buf_max_len;
    uint16_t current_id;
    zanLock  mutexLock;

    int (*read)(int fd, void *outbuf, size_t size, off_t offset);
    int (*write)(int fd, void *inbuf, size_t size, off_t offset);
    void (*callback)(swAio_event *aio_event);
    void (*destroy)(void);
} zanAsyncIO;

int  zanAio_init(void);
void zanAio_free(void);
int  zanAio_dns_lookup(int type,void *hostname, void *ip_addr, size_t size);

#endif  //_ZAN_ZANASYNCIO_H_
