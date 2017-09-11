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

#ifndef _ZAN_ZANFACTORY_H_
#define _ZAN_ZANFACTORY_H_

#include "swoole.h"
//#include "swPipe.h"
//#include "swMemory/memoryPool.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * -----------------------------------Factory--------------------------------------------
 */
enum zanDispatchMode
{
    ZAN_DISPATCH_ROUND  = 1,      //轮循模式
    ZAN_DISPATCH_FDMOD  = 2,      //固定模式，根据连接的文件描述符分配worker
    ZAN_DISPATCH_QUEUE  = 3,      //抢占模式
    ZAN_DISPATCH_IPMOD  = 4,      //对 client IP 取模，分配给一个固定 worker
    ZAN_DISPATCH_UIDMOD = 5,      //UID 分配
};

typedef struct
{
    long target_worker_id;
    //zanEventData data;
    swEventData data;
} zanDispatchData;

typedef struct _zanSendData
{
    swDataHead info;
    /**
     * for big package
     */
    uint32_t length;
    char *data;
} zanSendData;

typedef struct _zanFactory
{
    //void *pPipe;           //zanPipe[worker_num]
    //void *pServ;

    int (*start)(struct _zanFactory *);
    int (*shutdown)(struct _zanFactory *);
    int (*dispatch)(struct _zanFactory *, swDispatchData *);
    int (*finish)(struct _zanFactory *, swSendData *);
    int (*notify)(struct _zanFactory *, swDataHead *);
    int (*end)(struct _zanFactory *, int fd);
} zanFactory;

int zanFactory_create(zanFactory *factory);


#ifdef __cplusplus
}
#endif

#endif   //_ZAN_ZANFACTORY_H_
