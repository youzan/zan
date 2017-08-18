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

#include "zanReactor.h"
#include "zanSystem.h"
#include "zanWorkers.h"
#include "zanLog.h"

int zanWorker_loop(zanFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_WORKER;

    //worker_id
    ServerWG.worker_id = worker_id;
    ServerWG.request_count = 0;

    //TODO:::
    //ServerStatsG->workers[SwooleWG.worker_id].request_count = 0;
    //sw_stats_incr(&(ServerStatsG->workers[ServerWG.worker_id].start_count));

    //TODO::: init worker

    ServerG.main_reactor = (swReactor *)zan_malloc(sizeof(swReactor));
    if (swReactor_init(ServerG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
    {
        zanError("[Worker] create worker_reactor failed.");
        return SW_ERR;
    }

    ///Test:::
    while (1)
    {
        zanWarn("zanWorker_loop, process_pid=%d", ServerG.process_pid);
        sleep(3);
    }

    return ZAN_ERR;
}

int zanTaskWorker_loop(zanFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_WORKER;

    //worker_id
    ServerWG.worker_id = worker_id;
    ServerWG.request_count = 0;

    //TODO:::
    //ServerStatsG->workers[SwooleWG.worker_id].request_count = 0;
    //sw_stats_incr(&(ServerStatsG->workers[ServerWG.worker_id].start_count));

    //TODO::: init worker

    ///Test:::
    while (1)
    {
        zanWarn("zanWorker_loop, process_pid=%d", ServerG.process_pid);
        sleep(3);
    }

    return ZAN_ERR;
}

int zanNetWorker_start(zanFactory *factory, int worker_id)
{
    swServer *serv = factory->ptr;

    ServerG.process_pid  = zan_getpid();
    ServerG.process_type = ZAN_PROCESS_NETWORKER;

    //worker_id
    ServerWG.worker_id = worker_id;
    ServerWG.request_count = 0;

    //TODO::: stat

    //TODO::: init worker

    //main_reactor accept


    //sub_reactor thread send/recv


    ///Test:::
    while (1)
    {
        zanWarn("zanNetWorker loop test, process_pid=%d", ServerG.process_pid);
        sleep(3);
    }

    return ZAN_ERR;
}
