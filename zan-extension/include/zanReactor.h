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

#ifndef _ZAN_ZANREACTOR_H_
#define _ZAN_ZANREACTOR_H_

#include "swoole.h"
#include "swConnection.h"
#include "swBaseData.h"

#ifdef __cplusplus
extern "C" {
#endif

///TODO::: reactor 的功能精简，要把哪些提取出来???

enum zanEvent_type
{
    ZAN_EVENT_DEAULT = 256,
    ZAN_EVENT_READ = 1u << 9,
    ZAN_EVENT_WRITE = 1u << 10,
    ZAN_EVENT_ERROR = 1u << 11,
};

enum zanEventType
{
    //networking socket
    ZAN_EVENT_TCP             = 0,
    ZAN_EVENT_UDP             = 1,
    ZAN_EVENT_TCP6            = 2,
    ZAN_EVENT_UDP6            = 3,

    //tcp event
    ZAN_EVENT_CLOSE           = 4,
    ZAN_EVENT_CONNECT         = 5,

    //task
    ZAN_EVENT_TASK            = 7,
    ZAN_EVENT_FINISH          = 8,

    //package
    ZAN_EVENT_PACKAGE_START   = 9,
    ZAN_EVENT_PACKAGE_END     = 10,
    ZAN_EVENT_PACKAGE         = 11,
    ZAN_EVENT_SENDFILE        = 12,
    ZAN_EVENT_UNIX_DGRAM      = 13,
    ZAN_EVENT_UNIX_STREAM     = 14,

    //pipe
    ZAN_EVENT_PIPE_MESSAGE    = 15,

    //aysnc exit
    ZAN_EVENT_DENY_REQUEST    = 100,
    ZAN_EVENT_DENY_EXIT       = 101,
};

struct _zanReactor;
struct _zanEvent;

typedef int (*zanReactor_handle)(struct _zanReactor *reactor, struct _zanEvent *event);
typedef void (*zanCallback)(void *data);

typedef struct _zanDefer_callback
{
    struct _zanDefer_callback *prev;
    struct _zanDefer_callback *next;
    zanCallback callback;
    void *data;
}zanDefer_callback;

typedef struct _zanEvent
{
    int fd;
    int16_t from_id;
    uint8_t type;
    swConnection *socket;
}zanEvent;

typedef struct _zanEventData
{
    swDataHead info;
    char data[SW_BUFFER_SIZE];
}zanEventData;

typedef struct _zanReactor
{
    void *object;
    void *ptr;    //reserve

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

    uint16_t reactor_id;    //Reactor ID
    uint16_t flag;          //flag

    uint32_t max_socket;

    /**
     * for thread
     */
    swConnection *socket_list;

    /**
     * for process
     */
    swArray *socket_array;

    zanDefer_callback *defer_callback_list;
    zanDefer_callback *defer_list_backup;

    zanReactor_handle handle[SW_MAX_FDTYPE];        //默认事件
    zanReactor_handle write_handle[SW_MAX_FDTYPE];  //扩展事件1(一般为写事件)
    zanReactor_handle error_handle[SW_MAX_FDTYPE];  //扩展事件2(一般为错误事件,如socket关闭)

    int (*add)(struct _zanReactor *, int fd, int fdtype);
    int (*set)(struct _zanReactor *, int fd, int fdtype);
    int (*del)(struct _zanReactor *, int fd);
    int (*wait)(struct _zanReactor *, struct timeval *);
    void (*free)(struct _zanReactor *);

    int (*write)(struct _zanReactor *, int, void *, int);
    int (*close)(struct _zanReactor *, int);
    int (*defer)(struct _zanReactor *, zanCallback, void *);

    int (*setHandle)(struct _zanReactor *, int fdtype, zanReactor_handle);

    void (*onTimeout)(struct _zanReactor *);
    void (*onFinish)(struct _zanReactor *);

    void (*enable_accept)(struct _zanReactor *);
}zanReactor;

/*
int zanReactor_init(zanReactor *reactor, int max_event);

int zanReactor_del_fd(zanReactor *reactor, int fd);
int zanReactor_onWrite(zanReactor *reactor, swEvent *ev);
int zanReactor_close(zanReactor *reactor, int fd);
swConnection* zanReactor_get_connection(zanReactor *reactor, int fd);

int zanReactor_add_event(zanReactor *reactor, int fd, enum zanEvent_type event_type);
int zanReactor_del_event(zanReactor *reactor, int fd, enum zanEvent_type event_type);

int zanReactor_wait_write_buffer(zanReactor *reactor, int fd);

//extern int zanReactor_add_fd(zanReactor *reactor, int fd, int type);
//extern int zanReactor_error(zanReactor *reactor);
//extern void zanReactor_set(zanReactor *reactor, int fd, int fdtype);
//extern zanReactor_handle zanReactor_getHandle(zanReactor *reactor, int event_type, int fdtype);

int zanReactorEpoll_create(zanReactor *reactor, int max_event_num);
int zanReactorPoll_create(zanReactor *reactor, int max_event_num);
int zanReactorKqueue_create(zanReactor *reactor, int max_event_num);
int zanReactorSelect_create(zanReactor *reactor);
*/

static sw_inline int zanEventData_is_stream(uint8_t type)
{
    switch (type)
    {
        case ZAN_EVENT_TCP:
        case ZAN_EVENT_TCP6:
        case ZAN_EVENT_UNIX_STREAM:
        case ZAN_EVENT_PACKAGE_START:
        case ZAN_EVENT_PACKAGE:
        case ZAN_EVENT_PACKAGE_END:
        case ZAN_EVENT_CONNECT:
        case ZAN_EVENT_CLOSE:
            return SW_TRUE;
        default:
            return SW_FALSE;
    }
}

static sw_inline int zanEventData_is_dgram(uint8_t type)
{
    switch (type)
    {
    case ZAN_EVENT_UDP:
    case ZAN_EVENT_UDP6:
    case ZAN_EVENT_UNIX_DGRAM:
        return SW_TRUE;
    default:
        return SW_FALSE;
    }
}

static sw_inline int zanReactor_is_read_event(int fdtype)
{
    return (fdtype < ZAN_EVENT_DEAULT) || (fdtype & ZAN_EVENT_READ);
}

static sw_inline int zanReactor_is_write_event(int fdtype)
{
    return fdtype & ZAN_EVENT_WRITE;
}

static sw_inline int zanReactor_is_error_event(int fdtype)
{
    return fdtype & ZAN_EVENT_ERROR;
}

static sw_inline int zanReactor_get_fdtype(int fdtype)
{
    return fdtype & (~ZAN_EVENT_READ) & (~ZAN_EVENT_WRITE) & (~ZAN_EVENT_ERROR);
}

static sw_inline int zanReactor_get_events_type(int fdtype)
{
    int events = 0;
    if (zanReactor_is_read_event(fdtype))
    {
        events |= ZAN_EVENT_READ;
    }
    if (zanReactor_is_write_event(fdtype))
    {
        events |= ZAN_EVENT_WRITE;
    }
    if (zanReactor_is_error_event(fdtype))
    {
        events |= ZAN_EVENT_ERROR;
    }
    return events;
}


#ifdef __cplusplus
}
#endif

#endif
