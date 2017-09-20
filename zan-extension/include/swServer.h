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


#ifndef SW_SERVER_H_
#define SW_SERVER_H_

#include "swoole.h"
//#include "swLog.h"
#include "swBaseData.h"
#include "swPort.h"
#include "swError.h"
#include "swMemory/buffer.h"
#include "swConnection.h"
#include "swFactory.h"
#include "swGlobalDef.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SW_HEARTBEAT_IDLE          0   //心跳存活最大时间
#define SW_HEARTBEAT_CHECK         0   //心跳定时侦测时间


//------------------------------------Server-------------------------------------------
enum swServer_callback_type
{
    SW_SERVER_CALLBACK_onConnect = 1,
    SW_SERVER_CALLBACK_onReceive,
    SW_SERVER_CALLBACK_onClose,
};

int swServer_onFinish(swFactory *factory, swSendData *resp);
int swServer_onFinish2(swFactory *factory, swSendData *resp);

void swServer_init(swServer *serv);

int swServer_start(swServer *serv);
swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port);
int swServer_add_worker(swServer *serv, swWorker *worker);

int swServer_create(swServer *serv);
int swServer_free(swServer *serv);
int swServer_shutdown(swServer *serv);

void swServer_reopen_log_file(swServer *serv);

static sw_inline swString *swServer_get_buffer(swServer *serv, int fd)
{
    swString *buffer = serv->connection_list[fd].object;
    if (buffer == NULL)
    {
        buffer = swString_new(SW_BUFFER_SIZE);
        //alloc memory failed.
        if (!buffer)
        {
            return NULL;
        }
        serv->connection_list[fd].object = buffer;
    }
    return buffer;
}

static sw_inline void swServer_free_buffer(swServer *serv, int fd)
{
    swString *buffer = serv->connection_list[fd].object;
    if (buffer)
    {
        swString_free(buffer);
        serv->connection_list[fd].object = NULL;
    }
}

static sw_inline swListenPort* swServer_get_port(swServer *serv, int fd)
{
    sw_atomic_t server_fd = 0;
    int index = 0;
    for (index = 0;index < 128;index++)
    {
        server_fd = serv->connection_list[fd].from_fd;
        if (server_fd > 0)
        {
            break;
        }

        swYield();
    }

#if defined(__GNUC__)
    if (index > 0)
    {
        //swWarn("get port failed, count=%d. gcc version=%d.%d", index, __GNUC__, __GNUC_MINOR__);
    }
#endif

    return serv->connection_list[server_fd].object;
}

int swServer_udp_send(swServer *serv, swSendData *resp);
int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length);
int swServer_tcp_deny_request(swServer *serv, long nWorkerId);
int swServer_tcp_deny_exit(swServer *serv, long nWorkerId);
int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length);
int swServer_tcp_sendfile(swServer *serv, int fd, char *filename, uint32_t len);

int swServer_register_service();
int swServer_unregister_service();

//UDP, UDP必然超过0x1000000
//原因：IPv4的第4字节最小为1,而这里的conn_fd是网络字节序
#define SW_MAX_SOCKET_ID             0x1000000
#define swServer_is_udp(fd)          ((uint32_t) fd > SW_MAX_SOCKET_ID)


swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd);
void swServer_store_pipe_fd(swServer *serv, swPipe *p);
void swServer_store_listen_socket(swServer *serv);

int swServer_get_manager_pid(swServer *serv);
int swServer_get_socket(swServer *serv, int port);
int swServer_worker_init(swServer *serv, swWorker *worker);
void swServer_close_listen_port(swServer *serv);

#define SW_SERVER_MAX_FD_INDEX          0 //max connection socket
#define SW_SERVER_MIN_FD_INDEX          1 //min listen socket
#define SW_SERVER_TIMER_FD_INDEX        2 //for timerfd

//使用connection_list[0]表示最大的FD
#define swServer_set_maxfd(serv,maxfd) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd=maxfd)
#define swServer_get_maxfd(serv) (serv->connection_list[SW_SERVER_MAX_FD_INDEX].fd)
//使用connection_list[1]表示最小的FD
#define swServer_set_minfd(serv,maxfd) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd=maxfd)
#define swServer_get_minfd(serv) (serv->connection_list[SW_SERVER_MIN_FD_INDEX].fd)

#define swServer_get_thread(serv, reactor_id)    (&(serv->reactor_threads[reactor_id]))

static sw_inline swConnection* swServer_connection_get(swServer *serv, int fd)
{
    if (fd > serv->max_connection || fd <= 2)
    {
        return NULL;
    }
    else
    {
        return &serv->connection_list[fd];
    }
}

static sw_inline swSession* swServer_get_session(swServer *serv, uint32_t session_id)
{
    return &serv->session_list[session_id % SW_SESSION_LIST_SIZE];
}

static sw_inline int swServer_get_fd(swServer *serv, uint32_t session_id)
{
    return serv->session_list[session_id % SW_SESSION_LIST_SIZE].fd;
}

/// workid 按照 work、taskwork、usertaskwork 的顺序累加
swWorker* swServer_get_worker(swServer *serv, uint16_t worker_id);

/*-----------------------------------schedule -----------------------------*/
uint32_t swServer_worker_schedule(swServer *serv, uint32_t schedule_key);

void swServer_set_callback(swServer *serv, int type, void *callback);
void swServer_set_callback_onReceive(swServer *serv, int (*callback)(swServer *, char *, int, int, int));
void swServer_set_callback_onConnect(swServer *serv, void (*callback)(swServer *, int, int));
void swServer_set_callback_onClose(swServer *serv, void (*callback)(swServer *, int, int));


swConnection *swWorker_get_connection(swServer *serv, int session_id);

swString *swWorker_get_buffer(swServer *serv, int worker_id);

swConnection *swServer_connection_verify(swServer *serv, int session_id);
void swServer_connection_ready(swServer *serv, int fd, int reactor_id);

#ifdef __cplusplus
}
#endif

#endif /* SW_SERVER_H_ */
