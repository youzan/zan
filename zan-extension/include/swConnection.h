/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group                                    |
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


#ifndef SW_CONNECTION_H_
#define SW_CONNECTION_H_

#include "swoole.h"
#include "swSocket.h"
#include "swAtomic.h"
#include "swBaseData.h"
#include "swMemory/buffer.h"


#ifdef __cplusplus
extern "C"
{
#endif

#ifdef SW_USE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

typedef struct _swConnection
{
    /**
     * file descript
     */
    int fd;

    /**
     * session id
     */
    uint32_t session_id :24;

    /**
     * socket type, SW_SOCK_TCP or SW_SOCK_UDP
     */
    uint8_t socket_type;

    /**
     * fd type, SW_FD_TCP or SW_FD_PIPE or SW_FD_TIMERFD
     */
    uint8_t fdtype;

    int events;

    /**
     * is active
     * system fd must be 0. en: timerfd, signalfd, listen socket
     */
    uint32_t active :1;

    uint32_t connect_notify :1;

    /**
     * for SWOOLE_BASE mode.
     */
    uint32_t close_notify :1;

    uint32_t recv_wait :1;
    uint32_t send_wait :1;

    uint32_t direct_send :1;
    uint32_t ssl_send :1;

    /**
     * protected connection, cannot be closed by heartbeat thread.
     */
    uint32_t protect :1;

    uint32_t close_wait :1;
    uint32_t closed :1;
    uint32_t closing :1;
    uint32_t close_force :1;
    uint32_t close_reset :1;
    uint32_t event_trigger:1;
    uint32_t removed :1;			//// 是否从reactor 中移除
    uint32_t overflow :1;

    uint32_t tcp_nopush :1;
    uint32_t tcp_nodelay :1;

    uint32_t ssl_want_read :1;
    uint32_t ssl_want_write :1;

    uint32_t http_upgrade :1;
    uint32_t http2_stream :1;

    /**
     * ReactorThread id
     */
    uint16_t from_id;

    /**
     * from which socket fd, 由哪个监听套接字accepte 出来
     */
    uint16_t from_fd;

    /**
     * socket address
     */
    swSocketAddress info;

    /**
     * link any thing, for kernel, do not use with application.
     */
    void *object;

    /*
     * used for user context data
     */
    void *user_data;


    /**
     * input buffer
     */
    struct _swBuffer *in_buffer;

    /**
     * output buffer
     */
    struct _swBuffer *out_buffer;

    /**
     * connect time(seconds)
     */
    time_t connect_time;

    /**
     * received time with last data，可以用于检测连接空闲
     */
    time_t last_time;

    /**
     * bind uid
     */
    long uid;

    /**
     * memory buffer size;
     */
    int buffer_size;

    /**
     *  upgarde websocket
     */
    uint8_t websocket_status;

#ifdef SW_USE_OPENSSL
    SSL *ssl;
    uint32_t ssl_state;
    swString ssl_client_cert;
#endif
    sw_atomic_t lock;
}swConnection;

int swConnection_buffer_send(swConnection *conn);

swString* swConnection_get_string_buffer(swConnection *conn);
void swConnection_clear_string_buffer(swConnection *conn);
swBuffer_trunk* swConnection_get_out_buffer(swConnection *conn, uint32_t type);
swBuffer_trunk* swConnection_get_in_buffer(swConnection *conn);

int swConnection_sendfile_sync(swConnection *conn, char *filename, double timeout);
int swConnection_sendfile_async(swConnection *conn, char *filename);
int swConnection_onSendfile(swConnection *conn, swBuffer_trunk *chunk);
void swConnection_sendfile_destructor(swBuffer_trunk *chunk);
int swConnection_get_ip(swConnection *conn,char* addip,int len);
int swConnection_get_port(swConnection *conn);

/// Receive data from connection
ssize_t swConnection_recv(swConnection *conn, void *__buf, size_t __n, int __flags);

/// Send data to connection
int swConnection_send(swConnection *conn, void *__buf, size_t __n, int __flags);

static sw_inline int swConnection_error(int err)
{
    switch (err)
    {
    case EFAULT:
        abort();
        return SW_ERROR;
	case ECONNRESET:
	case EPIPE:
	case ENOTCONN:
	case ETIMEDOUT:
	case ECONNREFUSED:
	case ENETDOWN:
	case ENETUNREACH:
	case EHOSTDOWN:
	case EHOSTUNREACH:
		return SW_CLOSE;
	case EAGAIN:
#ifdef HAVE_KQUEUE
	case ENOBUFS:
#endif
	case 0:
		return SW_WAIT;
	default:
		return SW_ERROR;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* SW_CONNECTION_H_ */
