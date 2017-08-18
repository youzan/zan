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
#ifndef _ZAN_WORKERS_H_
#define _ZAN_WORKERS_H_

#include "zanGlobalDef.h"

#ifdef __cplusplus
extern "C" {
#endif

///TODO:::进程数据结构及操作

enum zanWorker_status
{
    ZAN_WORKER_BUSY = 1,
    ZAN_WORKER_IDLE = 2,
    ZAN_WORKER_DEL  = 3,
};

enum zanProcessType
{
    ZAN_PROCESS_UNKNOWN    = 0,
    ZAN_PROCESS_MASTER     = 1,
    ZAN_PROCESS_NETWORKER  = 2,
    ZAN_PROCESS_WORKER     = 3,
    ZAN_PROCESS_TASKWORKER = 4,
    ZAN_PROCESS_USERWORKER = 5,
};

#define is_unknown_process()  (ServerG.process_type == ZAN_PROCESS_UNKNOWN)
#define is_master()           (ServerG.process_type == ZAN_PROCESS_MASTER)
#define is_networker()        (ServerG.process_type == ZAN_PROCESS_NETWORKER)
#define is_worker()           (ServerG.process_type == ZAN_PROCESS_WORKER)
#define is_taskworker()       (ServerG.process_type == ZAN_PROCESS_TASKWORKER)
#define is_userworker()       (ServerG.process_type == ZAN_PROCESS_USERWORKER)

//
int zanWorkers_start(zanFactory *factory);


//master process loop
int zanMaster_loop(zanServer *serv);


//workers
int zanWorker_loop(zanFactory *factory, int worker_id);
int zanTaskWorker_loop(zanFactory *factory, int worker_id);
int zanNetWorker_start(zanFactory *factory, int worker_id);

#ifdef __cplusplus
}
#endif

#endif  //_ZAN_WORKERS_H_

