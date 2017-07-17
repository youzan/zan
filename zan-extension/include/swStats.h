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

typedef struct
{
    time_t start_time;
    sw_atomic_t connection_num;
    sw_atomic_t accept_count;
    sw_atomic_t close_count;
    sw_atomic_t tasking_num;
    sw_atomic_t request_count;
} swServerStats;

static sw_inline void sw_stats_incr(sw_atomic_t *val)
{
    sw_atomic_fetch_add(val, 1);
}

static sw_inline void sw_stats_decr(sw_atomic_t *val)
{
    sw_atomic_fetch_sub(val, 1);
}

static sw_inline void sw_stats_settime(time_t *dst, time_t *src)
{
    sw_atomic_set(dst, src);
}

int swoole_stats_init(swServerStats *stats);

#endif
