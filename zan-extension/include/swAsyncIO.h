/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2016-2017 Zan Group                                    |
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


#ifndef _SW_ASYNC_H_
#define _SW_ASYNC_H_


#include "swPipe.h"


#ifndef O_DIRECT
#define O_DIRECT         040000
#endif

#ifdef __cplusplus
extern "C"
{
#endif

enum swAioMode
{
    SW_AIO_BASE = 0,
    SW_AIO_GCC,
    SW_AIO_LINUX,
};

enum
{
    SW_AIO_READ = 0,
    SW_AIO_WRITE = 1,
    SW_AIO_DNS_LOOKUP = 2,
};

#define SW_FILE_MAX_LEN_ONCE		1*1024*1024

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

typedef struct
{
    uint8_t init;
    uint8_t mode;
    uint8_t thread_num;
    uint32_t task_num;
    uint32_t buf_max_len;
    uint16_t current_id;
    swLock	 wLock;

    void (*destroy)(void);
    void (*callback)(swAio_event *aio_event);
    int (*read)(int fd, void *outbuf, size_t size, off_t offset);
    int (*write)(int fd, void *inbuf, size_t size, off_t offset);
} swAsyncIO;

void swAio_callback_test(swAio_event *aio_event);
int swAio_init(void);
void swAio_free(void);

int swAio_dns_lookup(int type,void *hostname, void *ip_addr, size_t size);

#ifdef HAVE_GCC_AIO
int swAioGcc_init(int max_aio_events);
#endif

#ifdef HAVE_LINUX_AIO
int swAioLinux_init(int max_aio_events);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _SW_ASYNC_H_ */
