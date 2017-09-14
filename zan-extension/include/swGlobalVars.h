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
#ifndef _SW_GLOBAL_VARS_H_
#define _SW_GLOBAL_VARS_H_

#include "swGlobalDef.h"
#include "swAsyncIO.h"
#include "swStats.h"

#ifdef __cplusplus
extern "C" {
#endif


extern swServerG SwooleG;              //Local Global Variable
extern swServerGS *SwooleGS;           //Share Memory Global Variable
extern swWorkerG SwooleWG;             //Worker Global Variable
extern __thread swThreadG SwooleTG;    //Thread Global Variable
extern swServerStats *SwooleStats;

extern swAsyncIO SwooleAIO;
extern swPipe swoole_aio_pipe;

#define SW_CPU_NUM                    (SwooleG.cpu_num)
#define SW_REACTOR_NUM                SW_CPU_NUM
#define SW_WORKER_NUM                 (SW_CPU_NUM*2)

#ifdef __cplusplus
}
#endif

#endif
