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

#ifndef _ZAN_GLOBAL_VARS_H_
#define _ZAN_GLOBAL_VARS_H_

#include "zanGlobalDef.h"
#include "zanAsyncIo.h"

#ifdef __cplusplus
extern "C" {
#endif

//==============================================================================
extern zanServerG   ServerG;              //Local Global Variable
extern zanServerGS *ServerGS;             //Share Memory Global Variable
extern zanWorkerG   ServerWG;             //Worker Global Variable
//extern __thread zanThreadG ServerTG;      //Thread Global Variable
extern zanServerStats *ServerStatsG;

extern zanAsyncIO ZanAIO;

#define ZAN_CPU_NUM           (ServerG.cpu_num)
#define ZAN_REACTOR_NUM       ZAN_CPU_NUM

#ifdef __cplusplus
}
#endif

#endif  //_ZAN_GLOBAL_VARS_H_
