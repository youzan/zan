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

#ifndef _ZAN_PORT_H_
#define _ZAN_PORT_H_

#include "swoole.h"
#include "swReactor.h"
#include "swProtocol/protocol.h"

#ifdef SW_USE_OPENSSL
#include "swProtocol/ssl.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

///TODO::: 未确定

typedef struct _zanSslProperty
{
    char *ssl_cert_file;
    char *ssl_key_file;
    char *ssl_client_cert_file;
    SSL_CTX *ssl_context;
    swSSL_config ssl_config;
    uint8_t ssl_method;
    uint8_t ssl_verify_depth;
}zanSslProperty;

typedef struct _zanPortSet
{
    uint16_t backlog;
    uint8_t tcp_defer_accept;

    uint32_t open_tcp_nodelay :1;
    uint32_t open_tcp_keepalive :1;
    uint32_t open_http_protocol :1;
    uint32_t open_websocket_protocol :1;
    uint32_t open_http2_protocol :1;
    uint32_t open_mqtt_protocol :1;
    uint32_t open_length_check :1;

    uint32_t open_eof_split :1;

    uint32_t open_eof_check :1;  //

    char *package_length_type
    char *package_eof
}zanPortSet;

typedef struct _zanListenPort
{
    struct _swListenPort *next, *prev;

    zanPortSet portSet;

#ifdef SW_USE_OPENSSL
    zanSslProperty ssl_property;
#endif

    swProtocol protocol;

    int tcp_fastopen;

    uint8_t type;
    uint8_t ssl;
    int port;
    int sock;
    pthread_t thread_id;
    char host[SW_HOST_MAXSIZE];

    /**
     * open tcp nopush option(for sendfile)
     */
    uint32_t open_tcp_nopush :1;

    /**
     * open tcp keepalive
     */
    uint32_t open_ssl_encrypt :1;

    void *ptr;
    int (*onRead)(swReactor *reactor, struct _zanListenPort *port, swEvent *event);
} zanListenPort;

void zanPort_init(zanListenPort *port);
void zanPort_free(zanListenPort *port);
void zanPort_set_protocol(zanListenPort *port);
int  zanPort_set_option(zanListenPort *port);

#ifdef __cplusplus
}
#endif

#endif
