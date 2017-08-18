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


#ifndef _ZAN_SERVER_H_
#define _ZAN_SERVER_H_

#include "zanGlobalDef.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//========== TODO:::
void zanServer_init(zanServer *serv);
int zanServer_create(zanServer *serv);
int zanServer_start(zanServer *serv);
void zanServer_clean(zanServer *serv);

#ifdef __cplusplus
}
#endif

#endif /* _ZAN_SERVER_H_ */
