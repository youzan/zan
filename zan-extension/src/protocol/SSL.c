/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */



#include "swoole.h"
#include "swError.h"
#include "swConnection.h"
#include "swProtocol/ssl.h"
#include "zanLog.h"

#ifdef SW_USE_OPENSSL


static int openssl_init = 0;

static const SSL_METHOD *swSSL_get_method(int method);
static int swSSL_verify_callback(int ok, X509_STORE_CTX *x509_store);
#ifndef OPENSSL_NO_RSA
static RSA* swSSL_rsa_key_callback(SSL *ssl, int is_export, int key_length);
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int swSSL_set_default_dhparam(SSL_CTX* ssl_context);
#endif
static int swSSL_set_dhparam(SSL_CTX* ssl_context, char *file);
static int swSSL_set_ecdh_curve(SSL_CTX* ssl_context);

#ifdef TLSEXT_TYPE_next_proto_neg
static int swSSL_npn_advertised(SSL *ssl, const uchar **out, uint32_t *outlen, void *arg);
#endif

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int swSSL_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen,  const uchar *in, uint32_t inlen, void *arg);
#endif

static const SSL_METHOD *swSSL_get_method(int method)
{
    switch (method)
    {
#ifndef OPENSSL_NO_SSL3_METHOD
    case SW_SSLv3_METHOD:
        return SSLv3_method();
    case SW_SSLv3_SERVER_METHOD:
        return SSLv3_server_method();
    case SW_SSLv3_CLIENT_METHOD:
        return SSLv3_client_method();
#endif
    case SW_SSLv23_SERVER_METHOD:
        return SSLv23_server_method();
    case SW_SSLv23_CLIENT_METHOD:
        return SSLv23_client_method();
/**
 * openssl 1.1.0
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    case SW_TLSv1_METHOD:
        return TLSv1_method();
    case SW_TLSv1_SERVER_METHOD:
        return TLSv1_server_method();
    case SW_TLSv1_CLIENT_METHOD:
        return TLSv1_client_method();
#ifdef TLS1_1_VERSION
    case SW_TLSv1_1_METHOD:
        return TLSv1_1_method();
    case SW_TLSv1_1_SERVER_METHOD:
        return TLSv1_1_server_method();
    case SW_TLSv1_1_CLIENT_METHOD:
        return TLSv1_1_client_method();
#endif
#ifdef TLS1_2_VERSION
    case SW_TLSv1_2_METHOD:
        return TLSv1_2_method();
    case SW_TLSv1_2_SERVER_METHOD:
        return TLSv1_2_server_method();
    case SW_TLSv1_2_CLIENT_METHOD:
        return TLSv1_2_client_method();
#endif
    case SW_DTLSv1_METHOD:
        return DTLSv1_method();
    case SW_DTLSv1_SERVER_METHOD:
        return DTLSv1_server_method();
    case SW_DTLSv1_CLIENT_METHOD:
        return DTLSv1_client_method();
#endif
    case SW_SSLv23_METHOD:
    default:
        return SSLv23_method();
    }
    return SSLv23_method();
}

void swSSL_init(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x10100003L
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
#else
    OPENSSL_config(NULL);
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    openssl_init = 1;
}

void swSSL_server_http_advise(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
    SSL_CTX_set_alpn_select_cb(ssl_context, swSSL_alpn_advertised, cfg);
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(ssl_context, swSSL_npn_advertised, cfg);
#endif

    if (cfg->http)
    {
        SSL_CTX_set_session_id_context(ssl_context, (const unsigned char *) "HTTP", strlen("HTTP"));
        SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ssl_context, 1);
    }
}

int swSSL_server_set_cipher(SSL_CTX* ssl_context, swSSL_config *cfg)
{
#ifndef TLS1_2_VERSION
    return ZAN_OK;
#endif
    SSL_CTX_set_read_ahead(ssl_context, 1);

    if (strlen(cfg->ciphers) > 0)
    {
        if (SSL_CTX_set_cipher_list(ssl_context, cfg->ciphers) == 0)
        {
            zanWarn("SSL_CTX_set_cipher_list(\"%s\") failed", cfg->ciphers);
            return ZAN_ERR;
        }
        if (cfg->prefer_server_ciphers)
        {
            SSL_CTX_set_options(ssl_context, SSL_OP_CIPHER_SERVER_PREFERENCE);
        }
    }

#ifndef OPENSSL_NO_RSA
    SSL_CTX_set_tmp_rsa_callback(ssl_context, swSSL_rsa_key_callback);
#endif

    if (cfg->dhparam && strlen(cfg->dhparam) > 0)
    {
        swSSL_set_dhparam(ssl_context, cfg->dhparam);
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    else
    {
        swSSL_set_default_dhparam(ssl_context);
    }
#endif
    if (cfg->ecdh_curve && strlen(cfg->ecdh_curve) > 0)
    {
        swSSL_set_ecdh_curve(ssl_context);
    }
    return ZAN_OK;
}

static int swSSL_passwd_callback(char *buf, int num, int verify, void *data)
{
    swSSL_option *option = (swSSL_option *) data;
    if (option->passphrase)
    {
        size_t len = strlen(option->passphrase);
        if (len < num - 1)
        {
            memcpy(buf, option->passphrase, len + 1);
            return (int) len;
        }
    }
    return 0;
}

SSL_CTX* swSSL_get_context(swSSL_option *option)
{
    if (!openssl_init)
    {
        swSSL_init();
    }

    SSL_CTX *ssl_context = SSL_CTX_new(swSSL_get_method(option->method));
    if (ssl_context == NULL)
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);
    SSL_CTX_set_options(ssl_context, SSL_OP_MSIE_SSLV2_RSA_PADDING);
    SSL_CTX_set_options(ssl_context, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_TLS_BLOCK_PADDING_BUG);
    SSL_CTX_set_options(ssl_context, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    SSL_CTX_set_options(ssl_context, SSL_OP_SINGLE_DH_USE);

    if (option->passphrase)
    {
        SSL_CTX_set_default_passwd_cb_userdata(ssl_context, option);
        SSL_CTX_set_default_passwd_cb(ssl_context, swSSL_passwd_callback);
    }

    if (option->cert_file)
    {
        /*
         * set the local certificate from CertFile
         */
        if (SSL_CTX_use_certificate_file(ssl_context, option->cert_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * if the crt file have many certificate entry ,means certificate chain
         * we need call this function
         */
        if (SSL_CTX_use_certificate_chain_file(ssl_context, option->cert_file) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * set the private key from KeyFile (may be the same as CertFile)
         */
        if (SSL_CTX_use_PrivateKey_file(ssl_context, option->key_file, SSL_FILETYPE_PEM) <= 0)
        {
            ERR_print_errors_fp(stderr);
            return NULL;
        }
        /*
         * verify private key
         */
        if (!SSL_CTX_check_private_key(ssl_context))
        {
            zanWarn("Private key does not match the public certificate");
            return NULL;
        }
    }

    return ssl_context;
}

static int swSSL_verify_callback(int ok, X509_STORE_CTX *x509_store)
{
#if 0
    char *subject, *issuer;
    int err, depth;
    X509 *cert;
    X509_NAME *sname, *iname;
    X509_STORE_CTX_get_ex_data(x509_store, SSL_get_ex_data_X509_STORE_CTX_idx());
    cert = X509_STORE_CTX_get_current_cert(x509_store);
    err = X509_STORE_CTX_get_error(x509_store);
    depth = X509_STORE_CTX_get_error_depth(x509_store);

    sname = X509_get_subject_name(cert);
    subject = sname ? X509_NAME_oneline(sname, NULL, 0) : "(none)";

    iname = X509_get_issuer_name(cert);
    issuer = iname ? X509_NAME_oneline(iname, NULL, 0) : "(none)";
    zanWarn("verify:%d, error:%d, depth:%d, subject:\"%s\", issuer:\"%s\"", ok, err, depth, subject, issuer);

    if (sname)
    {
        OPENSSL_free(subject);
    }
    if (iname)
    {
        OPENSSL_free(issuer);
    }
#endif

    return 1;
}

int swSSL_set_client_certificate(SSL_CTX *ctx, char *cert_file, int depth)
{
    STACK_OF(X509_NAME) *list;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, swSSL_verify_callback);
    SSL_CTX_set_verify_depth(ctx, depth);

    if (SSL_CTX_load_verify_locations(ctx, cert_file, NULL) == 0)
    {
        zanWarn("SSL_CTX_load_verify_locations(\"%s\") failed.", cert_file);
        return ZAN_ERR;
    }

    ERR_clear_error();
    list = SSL_load_client_CA_file(cert_file);
    if (list == NULL)
    {
        zanWarn("SSL_load_client_CA_file(\"%s\") failed.", cert_file);
        return ZAN_ERR;
    }

    ERR_clear_error();
    SSL_CTX_set_client_CA_list(ctx, list);

    return ZAN_OK;
}

int swSSL_verify(swConnection *conn, int allow_self_signed)
{
    int err = SSL_get_verify_result(conn->ssl);
    switch (err)
    {
    case X509_V_OK:
        return ZAN_OK;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        if (allow_self_signed)
        {
            return ZAN_OK;
        }
        else
        {
            return ZAN_ERR;
        }
    default:
        zanError("Could not verify peer: code:%d %s", err, X509_verify_cert_error_string(err));
        return ZAN_ERR;
    }

    return ZAN_ERR;
}

int swSSL_get_client_certificate(SSL *ssl, char *buffer, size_t length)
{
    long len;
    BIO *bio;
    X509 *cert;

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        return ZAN_ERR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
    {
        zanError("BIO_new() failed.");
        X509_free(cert);
        return ZAN_ERR;
    }

    if (PEM_write_bio_X509(bio, cert) == 0)
    {
        zanWarn("PEM_write_bio_X509() failed.");
		BIO_free(bio);
		X509_free(cert);
		return ZAN_ERR;
    }

    len = BIO_pending(bio);
    if (len < 0 && len > length)
    {
        zanWarn("certificate length[%ld] is too big.", len);
		BIO_free(bio);
		X509_free(cert);
		return ZAN_ERR;
    }

    int n = BIO_read(bio, buffer, len);

    BIO_free(bio);
    X509_free(cert);

    return n;
}

int swSSL_accept(swConnection *conn)
{
    int n = SSL_do_handshake(conn->ssl);
    /**
     * The TLS/SSL handshake was successfully completed
     */
    if (n == 1)
    {
        conn->ssl_state = SW_SSL_STATE_READY;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#ifdef SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS
        if (conn->ssl->s3)
        {
            conn->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }
#endif
#endif
        return SW_READY;
    }
    /**
     * The TLS/SSL handshake was not successful but was shutdown.
     */
    else if (n == 0)
    {
        return SW_ERROR;
    }

    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        return SW_WAIT;
    }
    else if (err == SSL_ERROR_SSL)
    {
        char addr[SW_IP_MAX_LENGTH] = {0};
        swConnection_get_ip(conn,addr,SW_IP_MAX_LENGTH);
        zanWarn("bad SSL client[%s:%d].", addr, swConnection_get_port(conn));
        return ZAN_ERR;
    }
    //EOF was observed
    else if (err == SSL_ERROR_SYSCALL && n == 0)
    {
        return ZAN_ERR;
    }
    zanWarn("swSSL_accept() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
    return ZAN_ERR;
}

int swSSL_connect(swConnection *conn)
{
    int n = SSL_connect(conn->ssl);
    if (n == 1)
    {
        conn->ssl_state = SW_SSL_STATE_READY;
        conn->ssl_want_read = 0;
        conn->ssl_want_write = 0;
        return ZAN_OK;
    }
    long err = SSL_get_error(conn->ssl, n);
    if (err == SSL_ERROR_WANT_READ)
    {
        conn->ssl_want_read = 1;
        conn->ssl_want_write = 0;
        conn->ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return ZAN_OK;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        conn->ssl_want_read = 0;
        conn->ssl_want_write = 1;
        conn->ssl_state = SW_SSL_STATE_WAIT_STREAM;
        return ZAN_OK;
    }
    zanWarn("SSL_connect() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
    return ZAN_ERR;
}

int swSSL_sendfile(swConnection *conn, int fd, off_t *offset, size_t size)
{
    char buf[SW_BUFFER_SIZE_BIG];
    int readn = size > sizeof(buf) ? sizeof(buf) : size;

    int ret;
    int n = pread(fd, buf, readn, *offset);

    if (n > 0)
    {
        ret = swSSL_send(conn, buf, n);
        if (ret < 0)
        {
            zanError("write() failed.");
        }
        else
        {
            *offset += ret;
        }
        return ret;
    }
    else
    {
        zanError("pread() failed.");
        return ZAN_ERR;
    }
}

void swSSL_close(swConnection *conn)
{
    int n, sslerr, err;

    if (SSL_in_init(conn->ssl))
    {
        /*
         * OpenSSL 1.0.2f complains if SSL_shutdown() is called during
         * an SSL handshake, while previous versions always return 0.
         * Avoid calling SSL_shutdown() if handshake wasn't completed.
         */
        SSL_free(conn->ssl);
        conn->ssl = NULL;
        return;
    }

    SSL_set_quiet_shutdown(conn->ssl, 1);
    SSL_set_shutdown(conn->ssl, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);

    n = SSL_shutdown(conn->ssl);

    zanTrace("SSL_shutdown: %d", n);

    sslerr = 0;

    /* before 0.9.8m SSL_shutdown() returned 0 instead of -1 on errors */
    if (n != 1 && ERR_peek_error())
    {
        sslerr = SSL_get_error(conn->ssl, n);
        zanTrace("SSL_get_error: %d", sslerr);
    }

    if (!(n == 1 || sslerr == 0 || sslerr == SSL_ERROR_ZERO_RETURN))
    {
        err = (sslerr == SSL_ERROR_SYSCALL) ? errno : 0;
        zanWarn("SSL_shutdown() failed. Error: %d:%d.", sslerr, err);
    }

    SSL_free(conn->ssl);
    conn->ssl = NULL;
}

static sw_inline void swSSL_connection_error(swConnection *conn)
{
    int reason = ERR_GET_REASON(ERR_peek_error());

#if 0
    /* handshake failures */
    switch (reason)
    {
    case SSL_R_BAD_CHANGE_CIPHER_SPEC: /*  103 */
    case SSL_R_BLOCK_CIPHER_PAD_IS_WRONG: /*  129 */
    case SSL_R_DIGEST_CHECK_FAILED: /*  149 */
    case SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST: /*  151 */
    case SSL_R_EXCESSIVE_MESSAGE_SIZE: /*  152 */
    case SSL_R_LENGTH_MISMATCH:/*  159 */
    case SSL_R_NO_CIPHERS_PASSED:/*  182 */
    case SSL_R_NO_CIPHERS_SPECIFIED:/*  183 */
    case SSL_R_NO_COMPRESSION_SPECIFIED: /*  187 */
    case SSL_R_NO_SHARED_CIPHER:/*  193 */
    case SSL_R_RECORD_LENGTH_MISMATCH: /*  213 */
#ifdef SSL_R_PARSE_TLSEXT
    case SSL_R_PARSE_TLSEXT:/*  227 */
#endif
    case SSL_R_UNEXPECTED_MESSAGE:/*  244 */
    case SSL_R_UNEXPECTED_RECORD:/*  245 */
    case SSL_R_UNKNOWN_ALERT_TYPE: /*  246 */
    case SSL_R_UNKNOWN_PROTOCOL:/*  252 */
    case SSL_R_WRONG_VERSION_NUMBER:/*  267 */
    case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC: /*  281 */
#ifdef SSL_R_RENEGOTIATE_EXT_TOO_LONG
    case SSL_R_RENEGOTIATE_EXT_TOO_LONG:/*  335 */
    case SSL_R_RENEGOTIATION_ENCODING_ERR:/*  336 */
    case SSL_R_RENEGOTIATION_MISMATCH:/*  337 */
#endif
#ifdef SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED
    case SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED: /*  338 */
#endif
#ifdef SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING
    case SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING:/*  345 */
#endif
#ifdef SSL_R_INAPPROPRIATE_FALLBACK
    case SSL_R_INAPPROPRIATE_FALLBACK: /*  373 */
#endif
    case 1000:/* SSL_R_SSLV3_ALERT_CLOSE_NOTIFY */
    case SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE:/* 1010 */
    case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:/* 1020 */
    case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:/* 1021 */
    case SSL_R_TLSV1_ALERT_RECORD_OVERFLOW:/* 1022 */
    case SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE:/* 1030 */
    case SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE:/* 1040 */
    case SSL_R_SSLV3_ALERT_NO_CERTIFICATE:/* 1041 */
    case SSL_R_SSLV3_ALERT_BAD_CERTIFICATE:/* 1042 */
    case SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE: /* 1043 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED:/* 1044 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED:/* 1045 */
    case SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN:/* 1046 */
    case SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER:/* 1047 */
    case SSL_R_TLSV1_ALERT_UNKNOWN_CA:/* 1048 */
    case SSL_R_TLSV1_ALERT_ACCESS_DENIED:/* 1049 */
    case SSL_R_TLSV1_ALERT_DECODE_ERROR:/* 1050 */
    case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:/* 1051 */
    case SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION:/* 1060 */
    case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:/* 1070 */
    case SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY:/* 1071 */
    case SSL_R_TLSV1_ALERT_INTERNAL_ERROR:/* 1080 */
    case SSL_R_TLSV1_ALERT_USER_CANCELLED:/* 1090 */
    case SSL_R_TLSV1_ALERT_NO_RENEGOTIATION: /* 1100 */
        break;
#endif

    char addr[SW_IP_MAX_LENGTH] = {0};
    swConnection_get_ip(conn,addr,SW_IP_MAX_LENGTH);
    zanError("SSL connection[%s:%d] protocol error[%d].", addr, swConnection_get_port(conn), reason);
}

ssize_t swSSL_recv(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_read(conn->ssl, __buf, __n);
    if (n < 0)
    {
        int _errno = SSL_get_error(conn->ssl, n);
        switch (_errno)
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return ZAN_ERR;
            break;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return ZAN_ERR;
        case SSL_ERROR_SYSCALL:
            return ZAN_ERR;
        case SSL_ERROR_SSL:
            swSSL_connection_error(conn);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return ZAN_ERR;

        default:
            zanWarn("SSL_read(%d, %ld) failed, errno=%d.", conn->fd, __n, _errno);
            return ZAN_ERR;
        }
    }
    return n;
}

ssize_t swSSL_send(swConnection *conn, void *__buf, size_t __n)
{
    int n = SSL_write(conn->ssl, __buf, __n);
    if (n < 0)
    {
        int _errno = SSL_get_error(conn->ssl, n);
        switch (_errno)
        {
        case SSL_ERROR_WANT_READ:
            conn->ssl_want_read = 1;
            errno = EAGAIN;
            return ZAN_ERR;

        case SSL_ERROR_WANT_WRITE:
            conn->ssl_want_write = 1;
            errno = EAGAIN;
            return ZAN_ERR;

        case SSL_ERROR_SYSCALL:
            return ZAN_ERR;

        case SSL_ERROR_SSL:
            swSSL_connection_error(conn);
            errno = SW_ERROR_SSL_BAD_CLIENT;
            return ZAN_ERR;

        default:
            break;
        }
    }
    return n;
}

int swSSL_create(swConnection *conn, SSL_CTX* ssl_context, int flags)
{
    SSL *ssl = SSL_new(ssl_context);
    if (ssl == NULL)
    {
        zanError("SSL_new() failed.");
        return ZAN_ERR;
    }
    if (!SSL_set_fd(ssl, conn->fd))
    {
        long err = ERR_get_error();
        zanWarn("SSL_set_fd() failed. Error: %s[%ld]", ERR_reason_error_string(err), err);
        return ZAN_ERR;
    }
    if (flags & SW_SSL_CLIENT)
    {
        SSL_set_connect_state(ssl);
    }
    else
    {
        SSL_set_accept_state(ssl);
    }
    conn->ssl = ssl;
    conn->ssl_state = 0;
    return ZAN_OK;
}

void swSSL_free_context(SSL_CTX* ssl_context)
{
    if (ssl_context)
    {
        SSL_CTX_free(ssl_context);
    }
}

#ifndef OPENSSL_NO_RSA
static RSA* swSSL_rsa_key_callback(SSL *ssl, int is_export, int key_length)
{
    static RSA *rsa_tmp = NULL;
    if (rsa_tmp)
    {
        return rsa_tmp;
    }

    BIGNUM *bn = BN_new();
    if (bn == NULL)
    {
        zanWarn("allocation error generating RSA key.");
        return NULL;
    }

    if (!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL)
            || !RSA_generate_key_ex(rsa_tmp, key_length, bn, NULL))
    {
        if (rsa_tmp)
        {
            RSA_free(rsa_tmp);
        }
        rsa_tmp = NULL;
    }
    BN_free(bn);
    return rsa_tmp;
}
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int swSSL_set_default_dhparam(SSL_CTX* ssl_context)
{
    DH *dh;
    static unsigned char dh1024_p[] =
    { 0xBB, 0xBC, 0x2D, 0xCA, 0xD8, 0x46, 0x74, 0x90, 0x7C, 0x43, 0xFC, 0xF5, 0x80, 0xE9, 0xCF, 0xDB, 0xD9, 0x58, 0xA3,
            0xF5, 0x68, 0xB4, 0x2D, 0x4B, 0x08, 0xEE, 0xD4, 0xEB, 0x0F, 0xB3, 0x50, 0x4C, 0x6C, 0x03, 0x02, 0x76, 0xE7,
            0x10, 0x80, 0x0C, 0x5C, 0xCB, 0xBA, 0xA8, 0x92, 0x26, 0x14, 0xC5, 0xBE, 0xEC, 0xA5, 0x65, 0xA5, 0xFD, 0xF1,
            0xD2, 0x87, 0xA2, 0xBC, 0x04, 0x9B, 0xE6, 0x77, 0x80, 0x60, 0xE9, 0x1A, 0x92, 0xA7, 0x57, 0xE3, 0x04, 0x8F,
            0x68, 0xB0, 0x76, 0xF7, 0xD3, 0x6C, 0xC8, 0xF2, 0x9B, 0xA5, 0xDF, 0x81, 0xDC, 0x2C, 0xA7, 0x25, 0xEC, 0xE6,
            0x62, 0x70, 0xCC, 0x9A, 0x50, 0x35, 0xD8, 0xCE, 0xCE, 0xEF, 0x9E, 0xA0, 0x27, 0x4A, 0x63, 0xAB, 0x1E, 0x58,
            0xFA, 0xFD, 0x49, 0x88, 0xD0, 0xF6, 0x5D, 0x14, 0x67, 0x57, 0xDA, 0x07, 0x1D, 0xF0, 0x45, 0xCF, 0xE1, 0x6B,
            0x9B };

    static unsigned char dh1024_g[] =
    { 0x02 };
    dh = DH_new();
    if (dh == NULL)
    {
        zanError( "DH_new() failed");
        return ZAN_ERR;
    }

    dh->p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
    dh->g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);

    if (dh->p == NULL || dh->g == NULL)
    {
        DH_free(dh);
    }
    SSL_CTX_set_tmp_dh(ssl_context, dh);
    DH_free(dh);
    return ZAN_OK;
}
#endif

static int swSSL_set_ecdh_curve(SSL_CTX* ssl_context)
{
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH

    EC_KEY *ecdh;
    /*
     * Elliptic-Curve Diffie-Hellman parameters are either "named curves"
     * from RFC 4492 section 5.1.1, or explicitly described curves over
     * binary fields. OpenSSL only supports the "named curves", which provide
     * maximum interoperability.
     */
    int nid = OBJ_sn2nid(SW_SSL_ECDH_CURVE);
    if (nid == 0)
    {
        zanWarn("Unknown curve name \"%s\"", SW_SSL_ECDH_CURVE);
        return ZAN_ERR;
    }

    ecdh = EC_KEY_new_by_curve_name(nid);
    if (ecdh == NULL)
    {
        zanWarn("Unable to create curve \"%s\"", SW_SSL_ECDH_CURVE);
        return ZAN_ERR;
    }

    SSL_CTX_set_options(ssl_context, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(ssl_context, ecdh);

    EC_KEY_free(ecdh);
#endif
#endif

    return ZAN_OK;
}

static int swSSL_set_dhparam(SSL_CTX* ssl_context, char *file)
{
    DH *dh;
    BIO *bio;

    bio = BIO_new_file((char *) file, "r");
    if (bio == NULL)
    {
        zanWarn("BIO_new_file(%s) failed", file);
        return ZAN_ERR;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    if (dh == NULL)
    {
        zanWarn("PEM_read_bio_DHparams(%s) failed", file);
        BIO_free(bio);
        return ZAN_ERR;
    }

    SSL_CTX_set_tmp_dh(ssl_context, dh);

    DH_free(dh);
    BIO_free(bio);

    return ZAN_OK;
}

#ifdef TLSEXT_TYPE_application_layer_protocol_negotiation
static int swSSL_alpn_advertised(SSL *ssl, const uchar **out, uchar *outlen, const uchar *in, uint32_t inlen, void *arg)
{
    unsigned int srvlen;
    unsigned char *srv;

#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        srv = (unsigned char *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof(SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        srv = (unsigned char *) SW_SSL_NPN_ADVERTISE;
        srvlen = sizeof(SW_SSL_NPN_ADVERTISE) - 1;
    }
    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen, in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

#ifdef TLSEXT_TYPE_next_proto_neg
static int swSSL_npn_advertised(SSL *ssl, const uchar **out, uint32_t *outlen, void *arg)
{
#ifdef SW_USE_HTTP2
    swSSL_config *cfg = arg;
    if (cfg->http_v2)
    {
        *out = (uchar *) SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof(SW_SSL_HTTP2_NPN_ADVERTISE SW_SSL_NPN_ADVERTISE) - 1;
    }
    else
#endif
    {
        *out = (uchar *) SW_SSL_NPN_ADVERTISE;
        *outlen = sizeof(SW_SSL_NPN_ADVERTISE) - 1;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

#endif
