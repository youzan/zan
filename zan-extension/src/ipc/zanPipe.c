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

#include "zanIpc.h"

extern int zanPipeBase_create(zanPipe *pPipe, int isBlocking);
extern int zanUnSock_create(zanPipe *pPipe, int isBlocking, int protocol);

int zanPipe_create(zanPipe *pPipe, enum ZAN_PIPE_TYPE pipe_type, int isNonBlock, int protocpl)
{
    if (ZAN_PIPE == pipe_type) {
        return zanPipeBase_create(pPipe, isNonBlock);
    } else if (ZAN_UNSOCK == pipe_type) {
        return zanUnSock_create(pPipe, isNonBlock, protocpl);
    } else {
        zanFatalError("pipe_type=%d not support, exit.", pipe_type);
        return ZAN_ERR;
    }
}
