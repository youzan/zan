/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swoole.h"
#include "swSignal.h"
#include "swAtomic.h"
#include "swTimer.h"

#include "zanGlobalVar.h"
#include "zanLog.h"

#ifdef HAVE_TIMERFD
#include <sys/timerfd.h>
#endif

/// 时间槽
typedef struct _swTime_slot
{
    swLinkedList* list;
}swTime_slot;

/// 时间轮
typedef struct _swTime_wheel
{
    int precision;
    int slot_index;
    int slot_num;
    int max_timeout;
    long timer_id;
    swTime_slot* slots;
}swTime_wheel;

typedef struct _swTime_wheel_node
{
    int period_num;
    int slot_index;
    void* list_node;
    void* user_data;
}swTime_wheel_node;

swTimer_cfg timer_cfg;

#define SW_TIMEOUT_WHEEL    (1 << 7)
#define SW_TIMEWHEEL_TYPE   (1 << 6)

#define is_wheeltimeout_type(type)      ((type) & SW_TIMEOUT_WHEEL)
#define set_wheeltimeout_type(type)     ((type) |= SW_TIMEOUT_WHEEL)
#define del_wheeltimeout_type(type)     ((type) &= ~SW_TIMEOUT_WHEEL)

static int swReactorTimer_init(long msec);
static int swReactorTimer_set(swTimer *timer, long exec_msec);
static int swSystemTimer_signal_set(swTimer *timer, long interval);
static int swSystemTimer_timerfd_set(swTimer *timer, long interval);
static int swSystemTimer_set(swTimer *timer, long new_interval);

static int swSystemTimer_init(long interval, int use_pipe);
static int swSystemTimer_event_handler(swReactor *reactor, swEvent *event);
static void swSystemTimer_free(swTimer *timer);
static void timer_onTimeout(swTimer *timer, swTimer_node *tnode);
static void timer_onInterval(swTimer *timer, swTimer_node *tnode);
static int swTime_del_node(swTimer* timer,swTimer_node* node);

/// 时间轮操作
static void time_wheel_tick(swTimer* timer,swTimer_node* node);
static swTime_wheel* swTime_wheel_create(long precision,long max_timeout);
static int swTime_wheel_free(swTime_wheel* wheel);

static int swTime_wheel_add(swTime_wheel* wheel,swTimer_node* node,void* usr_data,long timeout);
static int swTime_wheel_del(swTime_wheel* wheel,swTimer_node* node);

static int swReactorTimer_now(struct timeval *time)
{
#if defined(SW_USE_MONOTONIC_TIME) && defined(CLOCK_MONOTONIC)
    struct timespec _now;
    if (clock_gettime(CLOCK_MONOTONIC, &_now) < 0)
    {
        zanError("clock_gettime(CLOCK_MONOTONIC) failed.");
        return ZAN_ERR;
    }
    time->tv_sec = _now.tv_sec;
    time->tv_usec = _now.tv_nsec / 1000;
#else
    if (gettimeofday(time, NULL) < 0)
    {
        zanError("gettimeofday() failed.");
        return ZAN_ERR;
    }
#endif
    return ZAN_OK;
}

static sw_inline int64_t swTimer_get_relative_msec()
{
    struct timeval now;
    if (swReactorTimer_now(&now) < 0)
    {
        return ZAN_ERR;
    }

    int64_t msec1 = (now.tv_sec - ServerG.timer.basetime.tv_sec) * 1000;
    int64_t msec2 = (now.tv_usec - ServerG.timer.basetime.tv_usec) / 1000;
    return msec1 + msec2;
}

int swTimer_init(swTimer* timer,long msec)
{
    if (ServerGS->started && is_master())
    {
        zanWarn("cannot use timer in master and manager process.");
        return ZAN_ERR;
    }

    if (0 != timer->fd)
    {
        return ZAN_OK;
    }

    if (swReactorTimer_now(&timer->basetime) < 0)
    {
        zanError("gettimeofday() failed.");
        return ZAN_ERR;
    }

    timer->_current_id = -1;
    timer->_next_msec = msec;
    timer->_cur_exec_msec = 0;
    timer->_next_id = 1;
    timer->num = 0;
    timer->onAfter = timer_onTimeout;
    timer->onTick = timer_onInterval;
    timer->after_cb = sw_malloc(TIMER_TYPE_NUMS*sizeof(user_cb*));
    timer->tick_cb = sw_malloc(TIMER_TYPE_NUMS*sizeof(user_cb*));
    timer->dict_cb = sw_malloc(TIMER_TYPE_NUMS*sizeof(user_dict_cb*));

    int index = 0;
    for (index = 0;index < TIMER_TYPE_NUMS;index++)
    {
        timer->after_cb[index] = NULL;
        timer->tick_cb[index] = NULL;
        timer->dict_cb[index] = NULL;
    }

    timer->heap = swHeap_create(1024, SW_MIN_HEAP);
    if (!timer->heap)
    {
        return ZAN_ERR;
    }

    timer->timer_map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (!timer->timer_map)
    {
        return ZAN_ERR;
    }

    int iRet = (is_taskworker())? swSystemTimer_init(msec, ServerG.use_timer_pipe):
            swReactorTimer_init(msec);

    if (iRet < 0)
    {
        swHeap_free(timer->heap);
        swHashMap_free(timer->timer_map);
        swSystemTimer_free(timer);
    }

    timer->_time_wheel = NULL;
    if (timer_cfg.use_time_wheel && (is_worker() || is_unknown()))
    {
        swTime_wheel* wheel = swTime_wheel_create(timer_cfg.precision,50*timer_cfg.precision);
        if (wheel)
        {
            long wheel_id = swTimer_add(timer,timer_cfg.precision,1,wheel,SW_TIMEWHEEL_TYPE);
            wheel->timer_id = wheel_id;
        }

        timer->_time_wheel = wheel;
    }

    return iRet;
}

void swTimer_free(swTimer *timer)
{
    if (timer->heap)
    {
        swHeap_free(timer->heap);
        timer->heap = NULL;
    }

    swTime_wheel_free(timer->_time_wheel);
    timer->_time_wheel = NULL;

    sw_free(timer->after_cb);
    sw_free(timer->tick_cb);
    sw_free(timer->dict_cb);
    ///task work时，free timer 句柄没有释放
    swSystemTimer_free(timer);
}

int register_after_cb(swTimer* timer,int type,user_cb callback)
{
    if (type < 0 || type >= TIMER_TYPE_NUMS)
    {
        return ZAN_ERR;
    }

    timer->after_cb[type] = callback;
    return ZAN_OK;
}

int register_tick_cb(swTimer* timer,int type,user_cb callback)
{
    if (type < 0 || type >= TIMER_TYPE_NUMS)
    {
        return ZAN_ERR;
    }

    timer->tick_cb[type] = callback;
    return ZAN_OK;
}

int register_dict_cb(swTimer* timer,int type,user_dict_cb callback)
{
    if (type < 0 || type >= TIMER_TYPE_NUMS)
    {
        return ZAN_ERR;
    }

    timer->dict_cb[type] = callback;
    return ZAN_OK;
}

void swSystemTimer_signal_handler(int sig)
{
    ServerG.signal_alarm = 1;
    uint64_t flag = 1;

    if (ServerG.timer.use_pipe)
    {
        ServerG.timer.pipe.write(&ServerG.timer.pipe, &flag, sizeof(flag));
    }
}

static int swSystemTimer_init(long interval, int use_pipe)
{
    swTimer *timer = &ServerG.timer;
    timer->lasttime = interval;

#ifndef HAVE_TIMERFD
    ServerG.use_timerfd = 0;
#endif

    if (ServerG.use_timerfd && swSystemTimer_timerfd_set(timer, interval) >= 0)
    {
        timer->use_pipe = 0;
    }
    else if (!ServerG.use_timerfd)
    {
        timer->use_pipe = use_pipe;
        //if (use_pipe && swPipeNotify_auto(&timer->pipe, 0, 0) >= 0)
        if (use_pipe && zanPipe_create(&timer->pipe, ZAN_PIPE, 0, 0) >= 0)
        {
            timer->fd = timer->pipe.getFd(&timer->pipe, 0);
        }
        else if (!use_pipe)
        {
            timer->fd = -1;
        }
        else
        {
            return ZAN_ERR;
        }

        if (swSystemTimer_signal_set(timer, interval) < 0)
        {
            return ZAN_ERR;
        }

        swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    }
    else
    {
        return ZAN_ERR;
    }

    if (timer->fd > 1)
    {
        ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_TIMER, swSystemTimer_event_handler);
        ServerG.main_reactor->add(ServerG.main_reactor, ServerG.timer.fd, SW_FD_TIMER);
    }

    timer->set = swSystemTimer_set;
    return ZAN_OK;
}

/**
 * timerfd
 */
static int swSystemTimer_timerfd_set(swTimer *timer, long interval)
{
#ifdef HAVE_TIMERFD
    struct timeval now;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    if (gettimeofday(&now, NULL) < 0)
    {
        zanError("gettimeofday() failed.");
        return ZAN_ERR;
    }

    struct itimerspec timer_set;
    bzero(&timer_set, sizeof(timer_set));

    if (interval < 0)
    {
        if (timer->fd == 0) 
		{
			return ZAN_OK;
        }
    }
    else
    {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_nsec = msec * 1000 * 1000;

        timer_set.it_value.tv_sec = now.tv_sec + sec;
        timer_set.it_value.tv_nsec = (now.tv_usec * 1000) + timer_set.it_interval.tv_nsec;

        if (timer_set.it_value.tv_nsec > 1e9)
        {
            timer_set.it_value.tv_nsec = timer_set.it_value.tv_nsec - 1e9;
            timer_set.it_value.tv_sec += 1;
        }

        if (timer->fd == 0)
        {
            timer->fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK | TFD_CLOEXEC);
            if (timer->fd < 0)
            {
                zanError("timerfd_create() failed.");
                return ZAN_ERR;
            }
        }
    }

    if (timerfd_settime(timer->fd, TFD_TIMER_ABSTIME, &timer_set, NULL) < 0)
    {
        zanError("timerfd_settime() failed.");
        return ZAN_ERR;
    }

    return ZAN_OK;
#else
    zanWarn("kernel not support timerfd.");
    return ZAN_ERR;
#endif
}

/**
 * setitimer
 */
static int swSystemTimer_signal_set(swTimer *timer, long interval)
{
    struct itimerval timer_set;
    int sec = interval / 1000;
    int msec = (((float) interval / 1000) - sec) * 1000;

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
    {
        zanError("gettimeofday() failed.");
        return ZAN_ERR;
    }

    bzero(&timer_set, sizeof(timer_set));

    if (interval > 0)
    {
        timer_set.it_interval.tv_sec = sec;
        timer_set.it_interval.tv_usec = msec * 1000;

        timer_set.it_value.tv_sec = sec;
        timer_set.it_value.tv_usec = timer_set.it_interval.tv_usec;

        if (timer_set.it_value.tv_usec > 1e6)
        {
            timer_set.it_value.tv_usec = timer_set.it_value.tv_usec - 1e6;
            timer_set.it_value.tv_sec += 1;
        }
    }

    if (setitimer(ITIMER_REAL, &timer_set, NULL) < 0)
    {
        zanError("setitimer() failed.");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

static void swSystemTimer_free(swTimer *timer)
{
    if (timer->use_pipe)
    {
        timer->pipe.close(&timer->pipe);
    }
    else if (timer->fd > 2)
    {
        if (close(timer->fd) < 0)
        {
            zanError("close(%d) failed.", timer->fd);
        }
    }

    timer->fd = 0;
}

static int swSystemTimer_set(swTimer *timer, long new_interval)
{
    static long current_interval = 0;
    if (new_interval == current_interval)
    {
        return ZAN_OK;
    }

    current_interval = new_interval;
    if (ServerG.use_timerfd)
    {
        return swSystemTimer_timerfd_set(timer, new_interval);
    }
    else
    {
        return swSystemTimer_signal_set(timer, new_interval);
    }
}

static int swSystemTimer_event_handler(swReactor *reactor, swEvent *event)
{
    swTimer *timer = &ServerG.timer;
    uint64_t exp;
    if (read(timer->fd, &exp, sizeof(uint64_t)) < 0)
    {
        return ZAN_ERR;
    }
    ServerG.signal_alarm = 0;
    return swTimer_select(timer);
}

static int swReactorTimer_init(long exec_msec)
{
    ServerG.main_reactor->check_timer = SW_TRUE;
    ServerG.main_reactor->timeout_msec = exec_msec;
    ServerG.timer.set = swReactorTimer_set;
    ServerG.timer.fd = -1;
    return ZAN_OK;
}

static int swReactorTimer_set(swTimer *timer, long exec_msec)
{
    ServerG.main_reactor->timeout_msec = exec_msec;
    return ZAN_OK;
}

static void timer_onTimeout(swTimer *timer, swTimer_node *tnode)
{
    if (!tnode)
    {
        zanWarn("timer node is null.");
        return;
    }

    if (timer->after_cb[tnode->used_type])
    {
        timer->_current_id = tnode->id;
        user_cb current_cb = timer->after_cb[tnode->used_type];
        current_cb(timer,tnode);
        timer->_current_id = -1;
    }
}

static void timer_onInterval(swTimer *timer, swTimer_node *tnode)
{
    if (!tnode)
    {
        zanWarn("timer node is null.");
        return;
    }

    timer->_current_id = tnode->id;
    if (tnode->used_type == SW_TIMEWHEEL_TYPE)
    {
        time_wheel_tick(timer,tnode);
    }
    else if (timer->tick_cb[tnode->used_type])
    {
        user_cb current_cb = timer->tick_cb[tnode->used_type];
        current_cb(timer,tnode);
    }

    timer->_current_id = -1;
}

static int swTime_del_node(swTimer* timer,swTimer_node* tnode)
{
	void* data = tnode->data;
	tnode->data = NULL;
	if (data && tnode->used_type == SW_TIMEWHEEL_TYPE)
	{
		swTime_wheel_free(data);
	}
	else if (data && timer->dict_cb[tnode->used_type]) {
		user_dict_cb current_cb = timer->dict_cb[tnode->used_type];
		current_cb(data);
	}

	--timer->num;
	if(swHashMap_del_int(timer->timer_map, tnode->id) < 0)
	{
		zanDebug("delete tnode fail");
		return ZAN_ERR;
	}
	
	if(swHeap_remove(timer->heap, tnode->heap_node) < 0)
	{
		zanDebug("remove tnode fail");
		return ZAN_ERR;
	}
	
	sw_free(tnode);
	return ZAN_OK;
}

long swTimer_add(swTimer *timer, long _msec, int interval, void *data,int used_type)
{
    if (_msec <= 0)
    {
        return ZAN_ERR;
    }

    if (!timer->fd)
    {
        swTimer_init(timer,_msec);
    }

    swTimer_node *tnode = sw_malloc(sizeof(swTimer_node));
    if (!tnode)
    {
        zanError("malloc(%ld) failed.", sizeof(swTimer_node));
        return ZAN_ERR;
    }

    memset(tnode,0x00,sizeof(swTimer_node));
    tnode->interval = interval ? _msec : 0;
    tnode->remove = 0;
    tnode->used_type = used_type;

    /// add to time wheel.
    int addToWheel = (interval <= 0 && timer->_time_wheel && (used_type != SW_TIMEWHEEL_TYPE));
    if (addToWheel){
        set_wheeltimeout_type(tnode->used_type);
        if (swTime_wheel_add(timer->_time_wheel,tnode,data,_msec) < 0){
            sw_free(tnode);
            return ZAN_ERR;
        }
    }
    else {
        /// 在定时器回调中添加新的定时器，使用当前定时器执行时间为
        /// 基准校验新增定时器执行时间，避免极端情况下一直在定时器回调中
        int64_t now_msec = swTimer_get_relative_msec();
        now_msec = (timer->_current_id > 0 && now_msec < timer->_cur_exec_msec)? timer->_cur_exec_msec:now_msec;
        if (now_msec < 0)
        {
            sw_free(tnode);
            return ZAN_ERR;
        }

        tnode->data = data;
        tnode->exec_msec = now_msec + _msec;
        tnode->heap_node = swHeap_push(timer->heap, tnode->exec_msec, tnode);
        if (!tnode->heap_node)
        {
            sw_free(tnode);
            return ZAN_ERR;
        }
    }

    /// timer id 从1 开始计算，大于 86400000 时，重置
    timer->_next_id = (timer->_next_id <= 0 || timer->_next_id > 86400000)? 1:timer->_next_id;
    tnode->id = timer->_next_id + 1;
    ++timer->num;
    if (!addToWheel && (timer->_next_msec <= 0 || timer->_next_msec > _msec))
    {
        timer->_next_msec = _msec;
        timer->set(timer, _msec);
    }

    swHashMap_add_int(timer->timer_map, tnode->id, tnode);
    return tnode->id;
}

int swTimer_del(swTimer *timer, long id)
{
    swTimer_node *tnode = swHashMap_find_int(timer->timer_map, id);
    if (!tnode || tnode->remove)
    {
        // php -r '$timerId = swoole_timer_after(10, function() use(&$timerId) { var_dump(swoole_timer_exists($timerId));swoole_timer_clear($timerId);});'
        // swoole_php_onTimeout 会导致重复删除 报错
        zanWarn("timer#%ld is not found.", id);
        return ZAN_ERR;
    }
	
    if (is_wheeltimeout_type(tnode->used_type))
    {
        swTime_wheel_del(timer->_time_wheel,tnode);
    }

    tnode->remove = 0;
	if (timer->_current_id > 0 && tnode->id == timer->_current_id)
    {
        tnode->remove = 1;
        return ZAN_OK;
    }

	if(swTime_del_node(timer,tnode) < 0)
	{
		return ZAN_ERR;
	}
	return ZAN_OK;
}

int swTimer_exist(swTimer *timer,long id)
{
    swTimer_node* node = swHashMap_find_int(timer->timer_map, id);
    if (!node || node->remove)
    {
        return 0;
    }

    return 1;
}

int swTimer_select(swTimer *timer)
{
    int64_t now_msec = swTimer_get_relative_msec();
    if (now_msec < 0)
    {
        return ZAN_ERR;
    }

    swTimer_node *tnode = NULL;
    swHeap_node *tmp = NULL;
    timer->_cur_exec_msec = now_msec;
    while ((tmp = swHeap_top(timer->heap)))
    {
        tnode = tmp->data;
        if (tnode->exec_msec > now_msec)
        {
            break;
        }

        //tick timer
        if (tnode->interval > 0)
        {
            timer->onTick(timer, tnode);
            if (!tnode->remove)
            {
                int64_t _now_msec = swTimer_get_relative_msec();
                tnode->exec_msec = (_now_msec <= 0)? now_msec + tnode->interval:
                                   (tnode->exec_msec + tnode->interval < _now_msec?
                                   _now_msec + tnode->interval:tnode->interval + tnode->exec_msec);

                swHeap_change_priority(timer->heap, tnode->exec_msec, tmp);
                continue;
            }
        }
        //after timer
        else
        {
            timer->onAfter(timer, tnode);
        }

        swTime_del_node(timer,tnode);
    }

    int64_t subMsec = (!tnode)? -1:tnode->exec_msec - now_msec;
    timer->_next_msec = subMsec;
    timer->_cur_exec_msec = 0;
    timer->set(timer,subMsec);
    return ZAN_OK;
}

static swTime_wheel* swTime_wheel_create(long precision,long max_timeout)
{
    if (max_timeout <= 0)
    {
        return NULL;
    }

    /// 最小精度至少为100ms.
    precision = precision < 100? 10:precision;
    /// 最大超时是时间为5000ms.
    max_timeout = max_timeout > 5000? 5000:max_timeout;

    if (max_timeout < precision)
    {
        zanWarn("max timeout and time precision set error.");
        return NULL;
    }

    swTime_wheel* wheel = sw_malloc(sizeof(swTime_wheel));
    memset(wheel,0x00,sizeof(swTime_wheel));
    int slot_num = max_timeout / precision;
    slot_num += (0 == (max_timeout % precision))? 0:1;
    wheel->slots = sw_malloc(slot_num*sizeof(swTime_slot));
    if (!wheel->slots)
    {
        sw_free(wheel);
        return NULL;
    }

    wheel->max_timeout = max_timeout;
    wheel->precision = precision;
    wheel->slot_num = slot_num;
    wheel->slot_index = 0;
    for (int index = 0;index < slot_num;index++)
    {
        swTime_slot* slot = wheel->slots + index;
        memset(slot,0x00,sizeof(swTime_slot));
        slot->list = swLinkedList_create(0,NULL);
    }

    return wheel;
}

static int swTime_wheel_free(swTime_wheel* wheel)
{
    if (!wheel)
    {
        return ZAN_ERR;
    }

    for (int index = 0;index < wheel->slot_num;index++)
    {
        if (wheel->slots[index].list)
        {
            swLinkedList_free(wheel->slots[index].list);
            wheel->slots[index].list = NULL;
        }
    }

    sw_free(wheel->slots);
    sw_free(wheel);
    return ZAN_OK;
}

static int swTime_wheel_add(swTime_wheel* wheel,swTimer_node* node,void* usr_data,long timeout)
{
    if (!wheel || !wheel->slots || !node)
    {
        return ZAN_ERR;
    }

    swTime_wheel_node* wheel_node =  sw_malloc(sizeof(swTime_wheel_node));
    if (!wheel_node)
    {
        return ZAN_ERR;
    }

    wheel_node->period_num = (int)(timeout/wheel->max_timeout);
    timeout = timeout % wheel->max_timeout;
    wheel_node->slot_index = timeout/wheel->precision;
    wheel_node->slot_index += ((timeout%wheel->precision)? 1:0) + wheel->slot_index;

    if (wheel_node->slot_index < 0)
    {
        return ZAN_ERR;
    }

    wheel_node->slot_index %= wheel->slot_num;
    swTime_slot* slot = wheel->slots + wheel_node->slot_index;
    if (!slot || !slot->list)
    {
        return ZAN_ERR;
    }

    swLinkedList_node* list_node = swLinkedList_append(slot->list,node,0);
    if (!list_node)
    {
        return ZAN_ERR;
    }

    wheel_node->list_node = list_node;
    wheel_node->user_data = usr_data;
    node->data = wheel_node;

    return ZAN_OK;
}

static int swTime_wheel_del(swTime_wheel* wheel,swTimer_node* node)
{
    if (!wheel || !wheel->slots || !node)
    {
        return ZAN_ERR;
    }

    swTime_wheel_node* wheel_node = (swTime_wheel_node*)(node->data);
    if (!wheel_node || wheel_node->slot_index < 0 || wheel_node->slot_index >= wheel->slot_num)
    {
        return ZAN_ERR;
    }

    swTime_slot* slot = wheel->slots + wheel_node->slot_index;
    if (!slot || !slot->list)
    {
        return ZAN_ERR;
    }

    swLinkedList_node* list_node = wheel_node->list_node;
    wheel_node->list_node = NULL;
    swLinkedList_remove_node(slot->list,list_node);

    node->data = wheel_node->user_data;
    wheel_node->user_data = NULL;
    del_wheeltimeout_type(node->used_type);

    sw_free(wheel_node);
    return ZAN_OK;
}

static void time_wheel_tick(swTimer* timer,swTimer_node* node)
{
    if (!node || !node->data)
    {
        return ;
    }

    /// 时间轮超时，node data持有的实例是 时间轮
    swTime_wheel* wheel = (swTime_wheel*)(node->data);

    swTime_slot* slot = wheel->slots + wheel->slot_index;
    swLinkedList_node* tmp = slot->list->head;
    while (tmp)
    {
        slot->list->head = slot->list->head->next;
        swTimer_node* usr_node = tmp->data;
        swTime_wheel_node* wheel_node = (swTime_wheel_node*)usr_node->data;
        if (wheel_node->period_num-- > 0)
        {
            tmp = slot->list->head;
            continue;
        }

        usr_node->data = wheel_node->user_data;
        wheel_node->user_data = NULL;
        del_wheeltimeout_type(usr_node->used_type);
        sw_free(tmp);
        sw_free(wheel_node);
        tmp = slot->list->head;
        /// 执行用户callback
        timer_onTimeout(timer,usr_node);
//      swTimer_del(timer,usr_node->id);
    }

    slot->list->tail = slot->list->head = NULL;
    wheel->slot_index++;
    wheel->slot_index = wheel->slot_index < wheel->slot_num? wheel->slot_index:0;
    node->data = wheel;
}
