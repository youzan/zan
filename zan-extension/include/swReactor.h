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
#ifndef _SW_REACTOR_H_
#define _SW_REACTOR_H_

#include "swoole.h"
#include "swConnection.h"
#include "swBaseData.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
 *----------------------------------------Reactor---------------------------------------
 */
enum swEvent_type
{
    SW_EVENT_DEAULT = 256,
    SW_EVENT_READ = 1u << 9,
    SW_EVENT_WRITE = 1u << 10,
    SW_EVENT_ERROR = 1u << 11,
};

enum swEventType
{
    //networking socket
    SW_EVENT_TCP             = 0,
    SW_EVENT_UDP             = 1,
    SW_EVENT_TCP6            = 2,
    SW_EVENT_UDP6            = 3,
    //tcp event
    SW_EVENT_CLOSE           = 4,
    SW_EVENT_CONNECT         = 5,
    //timer
    SW_EVENT_TIMER           = 6,
    //task
    SW_EVENT_TASK            = 7,
    SW_EVENT_FINISH          = 8,
    //package
    SW_EVENT_PACKAGE_START   = 9,
    SW_EVENT_PACKAGE_END     = 10,
    SW_EVENT_PACKAGE         = 11,
    SW_EVENT_SENDFILE        = 12,
    SW_EVENT_UNIX_DGRAM      = 13,
    SW_EVENT_UNIX_STREAM     = 14,
    //pipe
    SW_EVENT_PIPE_MESSAGE    = 15,
    //proxy
    SW_EVENT_PROXY_START     = 16,
    SW_EVENT_PROXY_END       = 17,


    //aysnc exit
    SW_EVENT_DENY_REQUEST    = 100,
    SW_EVENT_DENY_EXIT            = 101,
};

struct _swReactor;
struct _swEvent;


typedef int (*swReactor_handle)(struct _swReactor *reactor, struct _swEvent *event);
typedef void (*swCallback)(void *data);

typedef struct _swDefer_callback
{
    struct _swDefer_callback *next, *prev;
    swCallback callback;
    void *data;
}swDefer_callback;

typedef struct _swEvent
{
    int fd;
    int16_t from_id;
    uint8_t type;
    swConnection *socket;
}swEvent;

typedef struct _swEventData
{
    swDataHead info;
    char data[SW_BUFFER_SIZE];
}swEventData;

typedef struct _swReactor
{
    void *object;
    void *ptr;  //reserve

    /**
     * last signal number
     */
    int singal_no;

    uint32_t event_num;
    uint32_t max_event_num;

    uint32_t check_timer :1;
    uint32_t running :1;

    /**
     * disable accept new connection
     */
    uint32_t disable_accept :1;

    uint32_t check_signalfd :1;

    /**
     * multi-thread reactor, cannot realloc sockets.
     */
    uint32_t thread :1;

	/**
	 * reactor->wait timeout (millisecond) or -1
	 */
	int32_t timeout_msec;

	uint16_t id; //Reactor ID
	uint16_t flag; //flag

    uint32_t max_socket;

    /**
     * for thread
     */
    swConnection *socket_list;

    /**
     * for process
     */
    swArray *socket_array;

    swReactor_handle handle[SW_MAX_FDTYPE];        //默认事件
    swReactor_handle write_handle[SW_MAX_FDTYPE];  //扩展事件1(一般为写事件)
    swReactor_handle error_handle[SW_MAX_FDTYPE];  //扩展事件2(一般为错误事件,如socket关闭)

    int (*add)(struct _swReactor *, int fd, int fdtype);
    int (*set)(struct _swReactor *, int fd, int fdtype);
    int (*del)(struct _swReactor *, int fd);
    int (*wait)(struct _swReactor *, struct timeval *);
    void (*free)(struct _swReactor *);

    int (*setHandle)(struct _swReactor *, int fdtype, swReactor_handle);

    swDefer_callback *defer_callback_list;
    swDefer_callback *defer_list_backup;

    void (*onTimeout)(struct _swReactor *);
    void (*onFinish)(struct _swReactor *);

    void (*enable_accept)(struct _swReactor *);

    int (*write)(struct _swReactor *, int, void *, int);
    int (*close)(struct _swReactor *, int);
    int (*defer)(struct _swReactor *, swCallback, void *);

}swReactor;

static sw_inline int swEventData_is_dgram(uint8_t type)
{
    switch (type)
    {
    case SW_EVENT_UDP:
    case SW_EVENT_UDP6:
    case SW_EVENT_UNIX_DGRAM:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int swEventData_is_stream(uint8_t type)
{
    switch (type)
    {
    case SW_EVENT_TCP:
    case SW_EVENT_TCP6:
    case SW_EVENT_UNIX_STREAM:
    case SW_EVENT_PACKAGE_START:
    case SW_EVENT_PACKAGE:
    case SW_EVENT_PACKAGE_END:
    case SW_EVENT_CONNECT:
    case SW_EVENT_CLOSE:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int swReactor_event_read(int fdtype)
{
    return (fdtype < SW_EVENT_DEAULT) || (fdtype & SW_EVENT_READ);
}

static sw_inline int swReactor_event_write(int fdtype)
{
    return fdtype & SW_EVENT_WRITE;
}

static sw_inline int swReactor_event_error(int fdtype)
{
    return fdtype & SW_EVENT_ERROR;
}

static sw_inline int swReactor_fdtype(int fdtype)
{
    return fdtype & (~SW_EVENT_READ) & (~SW_EVENT_WRITE) & (~SW_EVENT_ERROR);
}

static sw_inline int swReactor_events(int fdtype)
{
    int events = 0;
    if (swReactor_event_read(fdtype))
    {
        events |= SW_EVENT_READ;
    }
    if (swReactor_event_write(fdtype))
    {
        events |= SW_EVENT_WRITE;
    }
    if (swReactor_event_error(fdtype))
    {
        events |= SW_EVENT_ERROR;
    }
    return events;
}

int swReactor_init(swReactor *reactor, int max_event);

int swReactor_add(swReactor *reactor, int fd, int type);
swConnection* swReactor_get(swReactor *reactor, int fd);
int swReactor_del(swReactor *reactor, int fd);
int swReactor_onWrite(swReactor *reactor, swEvent *ev);
int swReactor_close(swReactor *reactor, int fd);

int swReactor_error(swReactor *reactor);

int swReactor_wait_write_buffer(swReactor *reactor, int fd);
void swReactor_set(swReactor *reactor, int fd, int fdtype);

int swReactor_add_event(swReactor *reactor, int fd, enum swEvent_type event_type);
int swReactor_del_event(swReactor *reactor, int fd, enum swEvent_type event_type);

swReactor_handle swReactor_getHandle(swReactor *reactor, int event_type, int fdtype);
int swReactorEpoll_create(swReactor *reactor, int max_event_num);
int swReactorPoll_create(swReactor *reactor, int max_event_num);
int swReactorKqueue_create(swReactor *reactor, int max_event_num);
int swReactorSelect_create(swReactor *reactor);

#ifdef __cplusplus
}
#endif

#endif
