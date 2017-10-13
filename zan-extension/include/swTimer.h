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
#ifndef _SW_TIMER_H_
#define _SW_TIMER_H_

#include "swoole.h"
#include "swBaseData.h"
#include "zanIpc.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum USER_TYPE{
    PHPTIMER_USED = 1,      /// php 用户
    TCPCLIENT_USED,         /// tcpclient 用户
    HTTPCLIENT_USED,        /// httpClient 用户
    REDIS_USED,             /// redis 用户
    MYSQL_USED,             /// mysql 用户
    CONNPOOL_USED,          /// 连接池 用户
    TIMER_TYPE_NUMS
};

typedef struct _swTimer_node
{
    swHeap_node *heap_node;
    void *data;
    int64_t exec_msec;
    uint32_t interval;
    long id;
    uint8_t remove;
    uint8_t used_type;       //参考 @USER_TYPE
} swTimer_node;

typedef struct _swTimer swTimer;
typedef void (*user_cb)(swTimer* timer,swTimer_node* node);
typedef void (*user_dict_cb)(void* data);

struct _swTimer
{
    /*--------------timerfd & signal timer--------------*/
    swHeap *heap;
    swHashMap *timer_map;
    void* _time_wheel;
    int num;
    int use_pipe;
    int64_t lasttime;
    int fd;             /// fd == 0 未初始化，fd < 0 ;fd > 0 使用信号驱动时为pipe fd，使用time fd 为timefd
    long _next_id;
    long _current_id;
    int64_t _next_msec;
    int64_t _cur_exec_msec;
    ///swPipe pipe;
    zanPipe pipe;

    /*-----------------for EventTimer-------------------*/
    struct timeval basetime;
    /*--------------------------------------------------*/
    int (*set)(struct _swTimer *timer, long exec_msec);
    /*-----------------event callback-------------------*/
    void (*onAfter)(struct _swTimer *timer, swTimer_node *event);
    void (*onTick)(struct _swTimer *timer, swTimer_node *event);
    user_cb* after_cb;
    user_cb* tick_cb;
    user_dict_cb* dict_cb;
};

typedef struct _swTimer_cfg
{
    uint8_t use_time_wheel;
    int     precision;
}swTimer_cfg;

extern swTimer_cfg timer_cfg;
int swTimer_init(swTimer* timer,long msec);

int register_after_cb(swTimer* timer,int type,user_cb callback);
int register_tick_cb(swTimer* timer,int type,user_cb callback);
int register_dict_cb(swTimer* timer,int type,user_dict_cb callback);

long swTimer_add(swTimer *timer, long _msec, int interval, void *data,int used_type);
int swTimer_del(swTimer *timer, long id);
int swTimer_exist(swTimer *timer,long id);

void swTimer_free(swTimer *timer);
int swTimer_select(swTimer *timer);

void swSystemTimer_signal_handler(int sig);

#ifdef __cplusplus
}
#endif

#endif
