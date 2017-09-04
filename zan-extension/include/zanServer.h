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

#include "swoole_config.h"
#include "zanGlobalDef.h"
#include "swPort.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t zan_server_worker_schedule(zanServer *serv, uint32_t conn_fd);

//========== TODO:::
void zanServer_init(zanServer *serv);
int zanServer_create(zanServer *serv);
int zanServer_start(zanServer *serv);
void zanServer_clean(zanServer *serv);

//master process loop
int zan_master_process_loop(zanServer *serv);

////
zanWorker* zanServer_get_worker(zanServer *serv, uint16_t worker_id);

swListenPort* zanServer_add_port(zanServer *serv, int type, char *host, int port);

int zanServer_tcp_deny_exit(zanServer *serv, long nWorkerId);


static inline swConnection* zanServer_connection_get(zanServer *serv, int fd)
{
    if (fd > ServerG.servSet.max_connection || fd <= 2)
    {
        return NULL;
    }
    else
    {
        return &serv->connection_list[fd];
    }
}

static inline swString *zanWorker_get_buffer(zanServer *serv, int worker_id)
{
    //input buffer
    return ServerWG.buffer_input[worker_id];
}


static inline swSession* zanServer_get_session(zanServer *serv, uint32_t session_id)
{
    return &serv->session_list[session_id % SW_SESSION_LIST_SIZE];
}

static inline int zanServer_get_session_id(zanServer *serv, uint32_t session_id)
{
    return serv->session_list[session_id % SW_SESSION_LIST_SIZE].fd;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZAN_SERVER_H_ */
