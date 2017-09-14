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

#include "swWork.h"
#include "swGlobalVars.h"
#include "swLog.h"

void sw_stats_set_worker_status(swWorker *worker, int status)
{
    SwooleStats->lock.lock(&SwooleStats->lock);
    worker->status = status;
    if (status == SW_WORKER_BUSY)
    {
        if (swIsWorker())
        {
            sw_stats_incr(&SwooleStats->active_worker);
            if (SwooleStats->active_worker > SwooleStats->max_active_worker)
            {
                SwooleStats->max_active_worker = SwooleStats->active_worker;
            }
        }
        else if (swIsTaskWorker())
        {
            sw_stats_incr(&SwooleStats->active_task_worker);
            if (SwooleStats->active_task_worker > SwooleStats->max_active_task_worker)
            {
                SwooleStats->max_active_task_worker = SwooleStats->active_task_worker;
            }
        }
    }
    else if (status == SW_WORKER_IDLE)
    {
        if (swIsWorker() && SwooleStats->active_worker > 0)
        {
            sw_stats_decr(&SwooleStats->active_worker);
        }
        else if (swIsTaskWorker() && SwooleStats->active_task_worker > 0)
        {
            sw_stats_decr(&SwooleStats->active_task_worker);
        }
    }
    else
    {
        swWarn("Set worker status failed, unknow worker[%d] status[%d]", worker->id, status);
    }
    SwooleStats->lock.unlock(&SwooleStats->lock);
}

