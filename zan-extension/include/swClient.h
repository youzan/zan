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


#ifndef SW_CLIENT_H_
#define SW_CLIENT_H_

#include "swoole.h"
#include "swProtocol/protocol.h"
#include "swMemory/buffer.h"
#include "swConnection.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SW_SOCK_ASYNC    1
#define SW_SOCK_SYNC     0

typedef struct _swClient
{
    int id;
    int type;
    int _sock_type;
    int _sock_domain;
    int _protocol;
    int reactor_fdtype;
    int64_t timer_id;
    uint8_t timeout_type;
    uint8_t async;
    uint8_t released;
    uint8_t packet_mode;

    /**
     * one package: length check
     */
    uint8_t open_length_check;
    uint8_t open_eof_check;

    swProtocol protocol;

    char *server_str;			/// connect id
    void *ptr;
    void *params;

    uint8_t server_strlen;
    double timeout;

    /**
     * sendto, read only.
     */
    swSocketAddress server_addr;

    /**
     * recvfrom
     */
    swSocketAddress remote_addr;

    swConnection *socket;
    void *object;

    swString *buffer;
    uint32_t wait_length;
    uint32_t buffer_input_size;

#ifdef SW_USE_OPENSSL
    uint8_t open_ssl;
    uint8_t ssl_disable_compress;
    uint8_t ssl_verify;
    char *ssl_cert_file;
    char *ssl_key_file;
    SSL_CTX *ssl_context;
    uint8_t ssl_method;
#endif

    /// 回调操作，回调给用户
    void (*onConnect)(struct _swClient *cli);
    void (*onError)(struct _swClient *cli);
    void (*onReceive)(struct _swClient *cli, char *data, uint32_t length);
    void (*onClose)(struct _swClient *cli);

    /// 用户主动调用
    int (*connect)(struct _swClient *cli, char *host, int port, double _timeout, int sock_flag);
    int (*send)(struct _swClient *cli, char *data, int length, int flags);
    int (*sendfile)(struct _swClient *cli, char *filename);
    int (*recv)(struct _swClient *cli, char *data, int len, int flags);
    int (*close)(struct _swClient *cli);

} swClient;

int swClient_create(swClient *cli, int type, int async);
int swClient_free(swClient* cli);

#ifdef __cplusplus
}
#endif

#endif /* SW_CLIENT_H_ */
