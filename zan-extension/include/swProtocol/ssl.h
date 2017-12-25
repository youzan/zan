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
  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/
#ifndef _SW_SSL_H_
#define _SW_SSL_H_

#include "swConnection.h"

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef SW_USE_OPENSSL

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#define SW_SSL_BUFFER      1
#define SW_SSL_CLIENT      2

typedef struct _swSSL_option
{
    char *cert_file;
    char *key_file;
    char *passphrase;
    char *client_cert_file;
    uint8_t verify_depth;
    uint8_t method;
    uint8_t disable_compress :1;
} swSSL_option;


enum swSSLState
{
    SW_SSL_STATE_HANDSHAKE    = 0,
    SW_SSL_STATE_READY        = 1,
    SW_SSL_STATE_WAIT_STREAM  = 2,
};

enum swSSLMethod
{
    SW_SSLv23_METHOD = 0,
    SW_SSLv3_METHOD,
    SW_SSLv3_SERVER_METHOD,
    SW_SSLv3_CLIENT_METHOD,
    SW_SSLv23_SERVER_METHOD,
    SW_SSLv23_CLIENT_METHOD,
    SW_TLSv1_METHOD,
    SW_TLSv1_SERVER_METHOD,
    SW_TLSv1_CLIENT_METHOD,
#ifdef TLS1_1_VERSION
    SW_TLSv1_1_METHOD,
    SW_TLSv1_1_SERVER_METHOD,
    SW_TLSv1_1_CLIENT_METHOD,
#endif
#ifdef TLS1_2_VERSION
    SW_TLSv1_2_METHOD,
    SW_TLSv1_2_SERVER_METHOD,
    SW_TLSv1_2_CLIENT_METHOD,
#endif
    SW_DTLSv1_METHOD,
    SW_DTLSv1_SERVER_METHOD,
    SW_DTLSv1_CLIENT_METHOD,
};

typedef struct
{
    uint32_t http :1;
    uint32_t http_v2 :1;
    uint32_t prefer_server_ciphers :1;
    uint32_t session_tickets :1;
    uint32_t stapling :1;
    uint32_t stapling_verify :1;
    char *ciphers;
    char *ecdh_curve;
    char *session_cache;
    char *dhparam;
} swSSL_config;

void swSSL_init(void);
int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg);
void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg);
SSL_CTX* swSSL_get_context(swSSL_option *option);
void swSSL_free_context(SSL_CTX* ssl_context);
int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags);
int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth);
int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length);
int swSSL_verify(swConnection *conn, int allow_self_signed);
int swSSL_accept(swConnection *conn);
int swSSL_connect(swConnection *conn);
void swSSL_close(swConnection *conn);
ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n);
ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n);
int swSSL_sendfile(swConnection *conn, int fd, off_t *offset, size_t size);

#endif


#ifdef __cplusplus
}
#endif

#endif
