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

#ifndef _ZAN_EXECUTOR_H_
#define _ZAN_EXECUTOR_H_

#include "swReactor.h"

#include "zanGlobalDef.h"

#ifdef __cplusplus
extern "C" {
#endif

////
int zan_reactor_tcp_setup(swReactor *reactor, zanServer *serv);
int zanReactorThread_send2worker(void *data, int len, uint16_t target_worker_id);
int zanReactorThread_onClose(swReactor *reactor, swEvent *event);


#ifdef __cplusplus
}
#endif

#endif
