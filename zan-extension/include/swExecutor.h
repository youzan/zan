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
#ifndef _SW_NETWORKEXE_H_
#define _SW_NETWORKEXE_H_

#include "swoole.h"
#include "swLock.h"
#include "swFactory.h"
#include "swServer.h"
#include "swMemory/memoryPool.h"

#ifdef __cplusplus
extern "C" {
#endif


int swReactorThread_create(swServer *serv);
int swReactorThread_start(swServer *serv);
void swReactorThread_set_protocol(swServer *serv, swReactor *reactor);
void swReactorThread_free(swServer *serv);
int swReactorThread_close(swReactor *reactor, int fd);
int swReactorThread_onClose(swReactor *reactor, swEvent *event);
int swReactorThread_dispatch(swConnection *conn, char *data, uint32_t length);
int swReactorThread_send(swSendData *_send);
int swReactorThread_send2worker(void *data, int len, uint16_t target_worker_id);

int swServer_master_onAccept(swReactor *reactor, swEvent *event);
void swServer_enable_accept(swReactor *reactor);

int swReactorProcess_start(swServer *serv);
int swReactorProcess_create(swServer *serv);
int swReactorProcess_onClose(swReactor *reactor, swEvent *event);


#ifdef __cplusplus
}
#endif

#endif
