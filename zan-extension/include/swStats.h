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

#ifndef _SW_STATS_H_
#define _SW_STATS_H_

#include <sys/time.h>
#include "swAtomic.h"

typedef struct {
    time_t start_time;
    sw_atomic_long_t total_request_count;
    sw_atomic_long_t request_count;
    sw_atomic_t start_count;
} swWorkerStats;

typedef struct
{
    time_t             start_time;
    time_t             last_reload;
    sw_atomic_long_t   connection_num;
    sw_atomic_long_t   accept_count;
    sw_atomic_long_t   close_count;
    sw_atomic_t        tasking_num;
    sw_atomic_long_t   request_count;
    sw_atomic_t        active_worker;
    sw_atomic_t        active_task_worker;
    sw_atomic_t        max_active_worker;
    sw_atomic_t        max_active_task_worker;
    sw_atomic_t        worker_normal_exit;
    sw_atomic_t        worker_abnormal_exit;
    sw_atomic_t        task_worker_normal_exit;
    sw_atomic_t        task_worker_abnormal_exit;
    swWorkerStats      *workers;
    swLock             lock;
} swServerStats;

#define sw_stats_incr(val) sw_atomic_fetch_add(val, 1)
#define sw_stats_decr(val) sw_atomic_fetch_sub(val, 1)

void sw_stats_set_worker_status(swWorker *worker, int status);

#endif
