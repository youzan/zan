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


#include "php_swoole.h"
#include "swoole_http.h"

#include <ext/standard/url.h>
#include <ext/standard/sha1.h>
#include <ext/standard/php_var.h>
#include <ext/standard/php_string.h>
#include <ext/date/php_date.h>
#include <main/php_variables.h>

#include "swError.h"
#include "swProtocol/websocket.h"
#include "swConnection.h"
#include "swProtocol/base64.h"
#include "thirdparty/php_http_parser.h"

static zend_class_entry swoole_websocket_server_ce;
zend_class_entry *swoole_websocket_server_class_entry_ptr;

static zend_class_entry swoole_websocket_frame_ce;
zend_class_entry *swoole_websocket_frame_class_entry_ptr;

static int websocket_handshake(swListenPort *, http_context *);

static PHP_METHOD(swoole_websocket_server, on);
static PHP_METHOD(swoole_websocket_server, push);
static PHP_METHOD(swoole_websocket_server, exist);
static PHP_METHOD(swoole_websocket_server, pack);
static PHP_METHOD(swoole_websocket_server, unpack);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_push, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_pack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
    ZEND_ARG_INFO(0, mask)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_unpack, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_websocket_server_exist, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

const zend_function_entry swoole_websocket_server_methods[] =
{
    PHP_ME(swoole_websocket_server, on,         arginfo_swoole_websocket_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, push,       arginfo_swoole_websocket_server_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, exist,      arginfo_swoole_websocket_server_exist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_websocket_server, pack,       arginfo_swoole_websocket_server_pack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_websocket_server, unpack,     arginfo_swoole_websocket_server_unpack, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_FE_END
};

void swoole_websocket_onOpen(http_context *ctx)
{
	SWOOLE_FETCH_TSRMLS;

    int fd = ctx->fd;

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn)
    {
        swNotice("session[%d] is closed.", fd);
        return;
    }

    conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;

    zval *zcallback = php_swoole_server_get_callback(SwooleG.serv, conn->from_fd, SW_SERVER_CB_onOpen);
    if (zcallback)
    {
        zval **args[2];
        swServer *serv = SwooleG.serv;
        zval *zserv = (zval *) serv->ptr2;
        zval *zrequest_object = ctx->request.zobject;
        zval *retval = NULL;

        args[0] = &zserv;
        args[1] = &zrequest_object;

        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0,  NULL TSRMLS_CC) == FAILURE)
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "onOpen handler error");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }
}

/**
 * default onRequest callback
 */
void swoole_websocket_onRequest(http_context *ctx)
{
    char *content = "<html><body><h2>HTTP ERROR 400</h2><hr><i>Powered by "SW_HTTP_SERVER_SOFTWARE" ("PHP_SWOOLE_VERSION")</i></body></html>";
    char *bad_request = "HTTP/1.1 400 Bad Request\r\n"\
            "Content-Type: text/html; charset=UTF-8\r\n"\
            "Cache-Control: must-revalidate,no-cache,no-store\r\n"\
            "Content-Length: %d\r\n"\
            "Server: "SW_HTTP_SERVER_SOFTWARE"\r\n\r\n%s";

    char buf[512] = {0};

    int n = sprintf(buf, bad_request, strlen(content), content);
    swServer_tcp_send(SwooleG.serv, ctx->fd, buf, n);

    ctx->end = 1;
    SwooleG.serv->factory.end(&SwooleG.serv->factory, ctx->fd);
    ctx->response.release = 1;
}

static int websocket_handshake(swListenPort *port, http_context *ctx)
{
	SWOOLE_FETCH_TSRMLS;

    zval *header = ctx->request.zheader;
    HashTable *ht = Z_ARRVAL_P(header);
    zval *pData;

    if (sw_zend_hash_find(ht, ZEND_STRS("sec-websocket-key"), (void **) &pData) == FAILURE)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "header no sec-websocket-key");
        return SW_ERR;
    }

    if (sw_convert_to_string(pData) < 0)
	{
		swWarn("convert to string failed.");
		return SW_ERR;
	}

    swString_clear(swoole_http_buffer);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"));

    int n;
    char sec_websocket_accept[128] = {0};
    memcpy(sec_websocket_accept, Z_STRVAL_P(pData), Z_STRLEN_P(pData));
    memcpy(sec_websocket_accept + Z_STRLEN_P(pData), SW_WEBSOCKET_GUID, sizeof(SW_WEBSOCKET_GUID) - 1);

    char sha1_str[20] = {0};
    bzero(sha1_str, sizeof(sha1_str));
    php_swoole_sha1(sec_websocket_accept, Z_STRLEN_P(pData) + sizeof(SW_WEBSOCKET_GUID) - 1, (unsigned char *) sha1_str);

    char encoded_str[50] = {0};
    bzero(encoded_str, sizeof(encoded_str));
    n = swBase64_encode((unsigned char *) sha1_str, sizeof(sha1_str), encoded_str);

    char _buf[128] = {0};
    n = snprintf(_buf, sizeof(_buf), "Sec-WebSocket-Accept: %*s\r\n", n, encoded_str);
    n = n > 128?128:n;

    swString_append_ptr(swoole_http_buffer, _buf, n);
    swString_append_ptr(swoole_http_buffer, ZEND_STRL("Sec-WebSocket-Version: "SW_WEBSOCKET_VERSION"\r\n"));
//    if (port->websocket_subprotocol)
//    {
//        swString_append_ptr(swoole_http_buffer, ZEND_STRL("Sec-WebSocket-Protocol: "));
//        swString_append_ptr(swoole_http_buffer, port->websocket_subprotocol, port->websocket_subprotocol_length);
//        swString_append_ptr(swoole_http_buffer, ZEND_STRL("\r\n"));
//    }

    swString_append_ptr(swoole_http_buffer, ZEND_STRL("Server: "SW_WEBSOCKET_SERVER_SOFTWARE"\r\n\r\n"));

    swTrace("websocket header len:%ld\n%s \n", swoole_http_buffer->length, swoole_http_buffer->str);

    return swServer_tcp_send(SwooleG.serv, ctx->fd, swoole_http_buffer->str, swoole_http_buffer->length);
}

int swoole_websocket_onMessage(swEventData *req)
{
	SWOOLE_FETCH_TSRMLS;

    int fd = req->info.fd;

    zval *zdata;
    SW_MAKE_STD_ZVAL(zdata);

    char frame_header[2];
    php_swoole_get_recv_data(zdata, req, frame_header, 2 TSRMLS_CC);

    long finish = frame_header[0] ? 1 : 0;
    long opcode = frame_header[1];

    zval *zframe;
    SW_MAKE_STD_ZVAL(zframe);
    object_init_ex(zframe, swoole_websocket_frame_class_entry_ptr);

    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("fd"), fd TSRMLS_CC);
    zend_update_property_bool(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("finish"), finish TSRMLS_CC);
    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("opcode"), opcode TSRMLS_CC);
    zend_update_property(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("data"), zdata TSRMLS_CC);

    swServer *serv = SwooleG.serv;
    zval *zserv = (zval *) serv->ptr2;

    zval **args[2];
    args[0] = &zserv;
    args[1] = &zframe;

    zval *retval = NULL;


    zval *zcallback = php_swoole_server_get_callback(serv, req->info.from_fd, SW_SERVER_CB_onMessage);
    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_error(E_WARNING, "onMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&zdata);
    sw_zval_ptr_dtor(&zframe);

    return SW_OK;
}

int swoole_websocket_onHandshake(swListenPort *port, http_context *ctx)
{
    int fd = ctx->fd;
    int ret = websocket_handshake(port, ctx);
    if (ret == SW_ERR)
    {
        SwooleG.serv->factory.end(&SwooleG.serv->factory, fd);
    }
    else
    {
        swoole_websocket_onOpen(ctx);
    }

    if (!ctx->end)
    {
    	//free client data
    	ctx->response.release = 1;
    }

    return SW_OK;
}

void swoole_websocket_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_websocket_server_ce, "swoole_websocket_server", "Swoole\\WebSocket\\Server", swoole_websocket_server_methods);
    swoole_websocket_server_class_entry_ptr = sw_zend_register_internal_class_ex(&swoole_websocket_server_ce, swoole_http_server_class_entry_ptr, "swoole_http_server" TSRMLS_CC);

    SWOOLE_INIT_CLASS_ENTRY(swoole_websocket_frame_ce, "swoole_websocket_frame", "Swoole\\WebSocket\\Frame", NULL);
    swoole_websocket_frame_class_entry_ptr = zend_register_internal_class(&swoole_websocket_frame_ce TSRMLS_CC);

    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_TEXT", WEBSOCKET_OPCODE_TEXT_FRAME, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_OPCODE_BINARY", WEBSOCKET_OPCODE_BINARY_FRAME, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_CONNECTION", WEBSOCKET_STATUS_CONNECTION, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_HANDSHAKE", WEBSOCKET_STATUS_HANDSHAKE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_FRAME", WEBSOCKET_STATUS_ACTIVE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("WEBSOCKET_STATUS_ACTIVE", WEBSOCKET_STATUS_ACTIVE, CONST_CS | CONST_PERSISTENT);
}

zval* php_swoole_websocket_unpack(swString *data TSRMLS_DC)
{
    swWebSocket_frame frame;
    swWebSocket_decode(&frame, data);

    zval *zframe;
    SW_MAKE_STD_ZVAL(zframe);
    object_init_ex(zframe, swoole_websocket_frame_class_entry_ptr);

    zend_update_property_bool(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("finish"), frame.header.FIN TSRMLS_CC);
    zend_update_property_long(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("opcode"), frame.header.OPCODE TSRMLS_CC);
    zend_update_property_stringl(swoole_websocket_frame_class_entry_ptr, zframe, ZEND_STRL("data"), frame.payload,  frame.payload_length TSRMLS_CC);

    return zframe;
}

static PHP_METHOD(swoole_websocket_server, on)
{
    zval *callback;
    zval *event_name;

    if (SwooleGS->start > 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &event_name, &callback))
    {
        return;
    }

    swServer *serv = swoole_get_object(getThis());

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
	{
		swoole_php_fatal_error(E_WARNING,"user must set callback.");
		RETURN_FALSE;
	}

    serv->listen_list->open_websocket_protocol = 1;

    if (Z_STRLEN_P(event_name) == strlen("open") && strncasecmp("open", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zend_update_property(swoole_websocket_server_class_entry_ptr, getThis(), ZEND_STRL("onOpen"), callback TSRMLS_CC);
        php_sw_server_callbacks[SW_SERVER_CB_onOpen] = sw_zend_read_property(swoole_websocket_server_class_entry_ptr, getThis(), ZEND_STRL("onOpen"), 0 TSRMLS_CC);
        sw_copy_to_stack(php_sw_server_callbacks[SW_SERVER_CB_onOpen], _php_sw_server_callbacks[SW_SERVER_CB_onOpen]);
    }
    else if (Z_STRLEN_P(event_name) == strlen("message") && strncasecmp("message", Z_STRVAL_P(event_name), Z_STRLEN_P(event_name)) == 0)
    {
        zend_update_property(swoole_websocket_server_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), callback TSRMLS_CC);
        php_sw_server_callbacks[SW_SERVER_CB_onMessage] = sw_zend_read_property(swoole_websocket_server_class_entry_ptr, getThis(), ZEND_STRL("onMessage"), 0 TSRMLS_CC);
        sw_copy_to_stack(php_sw_server_callbacks[SW_SERVER_CB_onMessage], _php_sw_server_callbacks[SW_SERVER_CB_onMessage]);
    }
    else
    {
        zval *obj = getThis();
        sw_zend_call_method_with_2_params(&obj, swoole_http_server_class_entry_ptr, NULL, "on", &return_value, event_name, callback);
    }
}

static PHP_METHOD(swoole_websocket_server, push)
{
    zval *zdata;
    long fd = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz|lb", &fd, &zdata, &opcode, &fin))
    {
        return;
    }

    if (fd <= 0)
    {
        swWarn("fd[%d] is invalid.", (int )fd);
        RETURN_FALSE;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swWarn("opcode max 10");
        RETURN_FALSE;
    }

    char *data;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);

    if (length < 0)
    {
        RETURN_FALSE;
    }
    else if (length == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "data is empty.");
        RETURN_FALSE;
    }

    swConnection *conn = swWorker_get_connection(SwooleG.serv, fd);
    if (!conn || conn->websocket_status < WEBSOCKET_STATUS_HANDSHAKE)
    {
        swWarn("connection[%d] is not a websocket client.", (int ) fd);
        RETURN_FALSE;
    }
    swString_clear(swoole_http_buffer);
    swWebSocket_encode(swoole_http_buffer, data, length, opcode, (int) fin, 0);
    SW_CHECK_RETURN(swServer_tcp_send(SwooleG.serv, fd, swoole_http_buffer->str, swoole_http_buffer->length));
}

static PHP_METHOD(swoole_websocket_server, pack)
{
    char *data;
    zend_size_t length;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool finish = 1;
    zend_bool mask = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lbb", &data, &length, &opcode, &finish, &mask))
    {
        return;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swWarn("opcode max 10");
        RETURN_FALSE;
    }

    if (length <= 0)
    {
        swWarn("data is empty.");
    }

    if (swoole_http_buffer == NULL)
    {
        swoole_http_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
        if (!swoole_http_buffer)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            RETURN_FALSE;
        }
    }

    swString_clear(swoole_http_buffer);
    swWebSocket_encode(swoole_http_buffer, data, length, opcode, (int) finish, mask);
    SW_RETURN_STRINGL(swoole_http_buffer->str, swoole_http_buffer->length, 1);
}

static PHP_METHOD(swoole_websocket_server, unpack)
{
    swString buffer;
    bzero(&buffer, sizeof(buffer));
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &buffer.str, &buffer.length))
    {
        return;
    }

    zval *zframe = php_swoole_websocket_unpack(&buffer TSRMLS_CC);
    RETURN_ZVAL(zframe, 1, 1);
}

static PHP_METHOD(swoole_websocket_server, exist)
{
    if (SwooleGS->start == 0)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "Server is not running.");
        RETURN_FALSE;
    }

    long fd;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &fd))
    {
        return;
    }

    zval *zobject = getThis();
    swServer *serv = swoole_get_object(zobject);
    swConnection *conn = swWorker_get_connection(serv, fd);
    if (!conn)
    {
        RETURN_FALSE;
    }
    //connection is closed
    if (conn->active == 0 || conn->closed)
    {
        RETURN_FALSE;
    }
    swConnection *server_sock = swServer_connection_get(serv, conn->from_fd);
    if (server_sock)
    {
        swListenPort *port = server_sock->object;
        //not websocket port
        if (port && !port->open_websocket_protocol)
        {
            RETURN_TRUE;
        }
    }
    //have not handshake
    if (conn->websocket_status < WEBSOCKET_STATUS_ACTIVE)
    {
        RETURN_FALSE;
    }
    RETURN_TRUE;
}
