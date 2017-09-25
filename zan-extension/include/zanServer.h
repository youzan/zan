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


#define ZAN_SERVER_MAX_FD_INDEX          0 //max connection socket
#define ZAN_SERVER_MIN_FD_INDEX          1 //min listen socket

//使用connection_list[0]表示最大的FD
#define zanServer_set_maxfd(serv, networker_index, maxfd) (serv->connection_list[networker_index][ZAN_SERVER_MAX_FD_INDEX].fd=maxfd)
#define zanServer_get_maxfd(serv, networker_index) (serv->connection_list[networker_index][ZAN_SERVER_MAX_FD_INDEX].fd)

//使用connection_list[1]表示最小的FD
#define zanServer_set_minfd(serv, networker_index, maxfd) (serv->connection_list[networker_index][ZAN_SERVER_MIN_FD_INDEX].fd=maxfd)
#define zanServer_get_minfd(serv, networker_index) (serv->connection_list[networker_index][ZAN_SERVER_MIN_FD_INDEX].fd)


/**************************************************************/
void zanServer_init(zanServer *serv);
int zanServer_create(zanServer *serv);
int zanServer_start(zanServer *serv);
void zanServer_clean(zanServer *serv);
int zanServer_send(zanServer *serv, swSendData *resp);

//master process loop
int zan_master_process_loop(zanServer *serv);

////
zanWorker* zanServer_get_worker(zanServer *serv, uint16_t worker_id);

swListenPort* zanServer_add_port(zanServer *serv, int type, char *host, int port);

int zanServer_tcp_deny_exit(zanServer *serv, long nWorkerId);
int zanServer_tcp_send(zanServer *serv, int fd, void *data, uint32_t length);


uint32_t zanServer_worker_schedule(zanServer *serv, uint32_t networker_id, uint32_t conn_fd);

void zanServer_store_listen_socket(zanServer *serv, int networker_id);

void zanServer_connection_ready(zanServer *serv, int fd, int reactor_id);
swConnection *zanServer_verify_connection(zanServer *serv, int session_id);

int zanServer_getSocket(zanServer *serv, int port);

zanSession* zanServer_get_session(zanServer *serv, uint32_t session_id);
swListenPort* zanServer_get_port(zanServer *serv, int networker_id, int fd);
swConnection* zanServer_get_connection(zanServer *serv, int networker_id, int fd);
int zanServer_getFd_bySession(zanServer *serv, uint32_t session_id);
void zanServer_free_connection_buffer(zanServer *serv, int networker_id, int fd);
swConnection* zanServer_get_connection_by_sessionId(zanServer *serv, uint32_t session_id);

int zanServer_get_networker_index(int net_worker_id);

uint32_t zanServer_get_connection_num(zanServer *serv);

int zanServer_tcp_sendfile(zanServer *serv, int fd, char *filename, uint32_t len);

swString *zanServer_get_buffer(zanServer *serv, int networker_id, int fd);


#ifdef __cplusplus
}
#endif

#endif /* _ZAN_SERVER_H_ */
