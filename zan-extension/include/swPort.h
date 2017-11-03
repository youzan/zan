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
#ifndef _SW_PORT_H_
#define _SW_PORT_H_

#include "swoole.h"
#include "swReactor.h"
#include "swProtocol/protocol.h"
#include "zanThread.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _swListenPort
{
    struct _swListenPort *next, *prev;

    /**
     * tcp socket listen backlog
     */
    uint16_t backlog;
    /**
     * open tcp_defer_accept option
     */
    int tcp_defer_accept;
    /**
     * TCP_FASTOPEN
     */
    int tcp_fastopen;
    /**
     * TCP KeepAlive
     */
    int tcp_keepidle;
    int tcp_keepinterval;
    int tcp_keepcount;

    uint8_t type;
    uint8_t ssl;
    int port;
    int sock;
    zan_thread_t thread_id;
    char host[SW_HOST_MAXSIZE];

    /**
     * check data eof
     */
    uint32_t open_eof_check :1;
    /**
     * built-in http protocol
     */
    uint32_t open_http_protocol :1;
    /**
     * built-in http2.0 protocol
     */
    uint32_t open_http2_protocol :1;
    /**
     * built-in websocket protocol
     */
    uint32_t open_websocket_protocol :1;
    /**
     *  one package: length check
     */
    uint32_t open_length_check :1;
    /**
     * for mqtt protocol
     */
    uint32_t open_mqtt_protocol :1;
    /**
     * open tcp nodelay option
     */
    uint32_t open_tcp_nodelay :1;
    /**
     * open tcp nopush option(for sendfile)
     */
    uint32_t open_tcp_nopush :1;
    /**
     * open tcp keepalive
     */
    uint32_t open_tcp_keepalive :1;
    /**
     * open tcp keepalive
     */
    uint32_t open_ssl_encrypt :1;

#ifdef SW_USE_OPENSSL
    SSL_CTX *ssl_context;
    swSSL_config ssl_config;
    swSSL_option ssl_option;
#endif

    swProtocol protocol;
    void *ptr;
    int (*onRead)(swReactor *reactor, struct _swListenPort *port, swEvent *event);
} swListenPort;


void swPort_init(swListenPort *port);
void swPort_free(swListenPort *port);
void swPort_set_protocol(swListenPort *ls);
int zanPort_set_ListenOption(swListenPort *ls);
#ifdef SW_USE_OPENSSL
int swPort_enable_ssl_encrypt(swListenPort *ls);
#endif

#ifdef __cplusplus
}
#endif

#endif
