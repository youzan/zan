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
  | Author: Fang  <coooold@live.com>                                     |
  |         Tianfeng Han  <mikan.tenny@gmail.com>                        |
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/


#include "php_swoole.h"
#include "swProtocol/websocket.h"
#include "thirdparty/php_http_parser.h"

#include "ext/standard/basic_functions.h"
#include "ext/standard/php_http.h"
#include "ext/standard/base64.h"

#ifdef SW_HAVE_ZLIB
#include <zlib.h>
#endif

enum http_client_state
{
    HTTP_CLIENT_STATE_READY,
    HTTP_CLIENT_STATE_BUSY,
    ///for  WebSocket
    HTTP_CLIENT_STATE_UPGRADE,
    HTTP_CLIENT_STATE_WAIT_CLOSE,
};

#define SW_CLIENT_CB_onTimeout  (SW_CLIENT_CB_onError+1)

typedef struct
{
    zval *onConnect;
    zval *onError;
    zval *onClose;
    zval *onMessage;
    zval *onTimeout;
    zval *onResponse;

    zval *cookies;
    zval *request_header;
    zval *request_body;
    char *request_method;

#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _onConnect;
    zval _onError;
    zval _onClose;
    zval _onMessage;
    zval _cookies;
    zval _request_header;
    zval _request_body;
#endif

} http_client_property;

typedef struct
{
    swClient *cli;
    char *host;
    zend_size_t host_len;
    long port;
    long timeout;
    char* uri;
    zend_size_t uri_len;
    
    swString *tmp_header_field_buf;
    swString *tmp_header_value_buf;

    php_http_parser parser;

    swString *buffer;  //only used for websocket
    swString *body;

    uint8_t state;       //ready busy wait_close
    uint8_t keep_alive;  //0 no 1 keep
    uint8_t upgrade;     //for websocket
    uint8_t gzip;        //SW_HAVE_ZLIB def, the header is Content-Encoding: gzip  
    uint8_t chunked;     //Transfer-Encoding: chunked
    uint8_t completed;   //message_complete

} http_client;

#ifdef SW_HAVE_ZLIB
extern swString *swoole_zlib_buffer;
#endif
static swString *http_client_buffer;  //buffer append for request line and header

static void httpClient_timeout(swTimer* timer,swTimer_node* node);
static int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length);
static int http_client_parser_on_headers_complete(php_http_parser *parser);
static int http_client_parser_on_message_complete(php_http_parser *parser);

static void http_client_execute_callback(zval *zobject, int type);
static void http_client_onReceive(swClient *cli, char *data, uint32_t length);
static void http_client_onConnect(swClient *cli);
static void http_client_onClose(swClient *cli);
static void http_client_onError(swClient *cli);

static void http_client_free_cb(zval* object);

static int http_client_send_http_request(zval *zobject TSRMLS_DC);
static http_client* http_client_create(zval *object TSRMLS_DC);
static void http_client_free(zval *object TSRMLS_DC);
static int http_client_execute(zval *zobject, char *uri, zend_size_t uri_len, zval *callback TSRMLS_DC);

static const php_http_parser_settings http_parser_settings =
{
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    http_client_parser_on_header_field,
    http_client_parser_on_header_value,
    http_client_parser_on_headers_complete,
    http_client_parser_on_body,
    http_client_parser_on_message_complete
};

static zend_class_entry swoole_http_client_ce;
zend_class_entry *swoole_http_client_class_entry_ptr;

static PHP_METHOD(swoole_http_client, __construct);
static PHP_METHOD(swoole_http_client, __destruct);
static PHP_METHOD(swoole_http_client, set);
static PHP_METHOD(swoole_http_client,setReqTimeout);
static PHP_METHOD(swoole_http_client, setMethod);
static PHP_METHOD(swoole_http_client, setHeaders);
static PHP_METHOD(swoole_http_client, setCookies);
static PHP_METHOD(swoole_http_client, setData);
static PHP_METHOD(swoole_http_client, execute);
static PHP_METHOD(swoole_http_client, push);
static PHP_METHOD(swoole_http_client, isConnected);
static PHP_METHOD(swoole_http_client, close);
static PHP_METHOD(swoole_http_client, on);
static PHP_METHOD(swoole_http_client, get);
static PHP_METHOD(swoole_http_client, post);
static PHP_METHOD(swoole_http_client, upgrade);

//check the php method para
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, ssl)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setTimeout, 0, 0, 1)
    ZEND_ARG_INFO(0,timeout)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setMethod, 0, 0, 1)
    ZEND_ARG_INFO(0, method)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setHeaders, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setCookies, 0, 0, 1)
	ZEND_ARG_ARRAY_INFO(0, cookies,0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_setData, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_execute, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, opcode)
    ZEND_ARG_INFO(0, finish)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_get, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, args1)
	ZEND_ARG_INFO(0, args2)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_post, 0, 0, 3)
    ZEND_ARG_INFO(0, path)
    ZEND_ARG_INFO(0, data)
	ZEND_ARG_INFO(0, args1)
	ZEND_ARG_INFO(0, args2)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_http_client_upgrade, 0, 0, 2)
    ZEND_ARG_INFO(0, path)
	ZEND_ARG_INFO(0, args1)
	ZEND_ARG_INFO(0, args2)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_http_client_methods[] =
{
    PHP_ME(swoole_http_client, __construct, arginfo_swoole_http_client_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_http_client, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_http_client, set, arginfo_swoole_http_client_set, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_http_client, setReqTimeout, arginfo_swoole_http_client_setTimeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setMethod, arginfo_swoole_http_client_setMethod, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setHeaders, arginfo_swoole_http_client_setHeaders, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setCookies, arginfo_swoole_http_client_setCookies, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, setData, arginfo_swoole_http_client_setData, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, execute, arginfo_swoole_http_client_execute, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, push, arginfo_swoole_http_client_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, get, arginfo_swoole_http_client_get, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, post, arginfo_swoole_http_client_post, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, upgrade, arginfo_swoole_http_client_upgrade, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_http_client, on, arginfo_swoole_http_client_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static sw_inline void defer_close(void* data)
{
	swClient* cli = (swClient*)data;
	swClient_free(cli);
	cli->released = 0;
	http_client_onClose(cli);
}

static void httpClient_timeout(swTimer* timer,swTimer_node* node)
{
	swClient* cli = node? node->data:NULL;
	zval *zobject = cli? cli->object:NULL;
	if (zobject)
	{
		cli->timer_id = 0;
		http_client_execute_callback(zobject,SW_CLIENT_CB_onTimeout);
	}

	swTimer_del(timer,node->id);
}

//append headers filed for send_http_request
static sw_inline void http_client_swString_append_headers(swString* swStr, char* key, zend_size_t key_len, char* data, zend_size_t data_len)
{
    swString_append_ptr(swStr, key, key_len);
    swString_append_ptr(swStr, ZEND_STRL(": "));
    swString_append_ptr(swStr, data, data_len);
    swString_append_ptr(swStr, ZEND_STRL("\r\n"));
}

//append request line. buffer: GET/POST uri HTTP/1.1
static sw_inline void http_client_buffer_append_request_line(swString* swStr, http_client *http, http_client_property *hcc)
{
    swString_clear(swStr);
    swString_append_ptr(swStr, hcc->request_method, strlen(hcc->request_method));
    hcc->request_method = NULL;
    swString_append_ptr(swStr, ZEND_STRL(" "));
    swString_append_ptr(swStr, http->uri, http->uri_len);
    swString_append_ptr(swStr, ZEND_STRL(" HTTP/1.1\r\n"));
}

//append headers filed of content_length
static sw_inline void http_client_swString_append_contentlength(swString* buf, int length)
{
    char content_length_str[32] = {0};
    int n = snprintf(content_length_str, sizeof(content_length_str) - 1, "Content-Length: %d\r\n\r\n", length);
    n = n > 32? 32:n;
    swString_append_ptr(buf, content_length_str, n);
}

//only used for upgrade method,so just for websocket
static sw_inline void http_client_create_token(int length, char *buf)
{
    char characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"§$%&/()=[]{}";
    assert(length < 1024);
    int index;
    for (index = 0; index < length; index++)
    {
        buf[index] = characters[rand() % sizeof(characters) - 1];
    }

    buf[length] = '\0';
}

static int http_client_execute(zval *zobject, char *uri, zend_size_t uri_len, zval *callback TSRMLS_DC)
{
    if (uri_len <= 0 || !uri)
    {
        swWarn("path is empty.");
        return SW_ERR;
    }

    if (callback && !ZVAL_IS_NULL(callback) && swoole_check_callable(callback TSRMLS_CC) < 0)
    {
    	return SW_ERR;
    }

    /// http is not null when keeping alive
    http_client *http = http_client_create(zobject TSRMLS_CC);
    if (!http)
    {
        return SW_ERR;
    }

    long timeout = 0;
	zval* reqTimeout = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestTimeout"), 1 TSRMLS_CC);
    if (reqTimeout)
    {
    	convert_to_long(reqTimeout);
    	timeout = Z_LVAL_P(reqTimeout);
    }

    if (timeout > 0)
    {
    	http->timeout = timeout;
    }
    http->tmp_header_field_buf = (!http->tmp_header_field_buf)? swString_new(SW_HTTP_RESPONSE_INIT_SIZE) : http->tmp_header_field_buf;
    http->tmp_header_value_buf = (!http->tmp_header_value_buf)? swString_new(SW_HTTP_RESPONSE_INIT_SIZE) : http->tmp_header_value_buf;
    http->body = (!http->body)? swString_new(SW_HTTP_RESPONSE_INIT_SIZE) : http->body;
    if (!http->tmp_header_field_buf || !http->tmp_header_value_buf || !http->body)
    {
		swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
		return SW_ERR;
    }
    swString_clear(http->tmp_header_field_buf);
    swString_clear(http->tmp_header_value_buf);
    swString_clear(http->body);
    http->upgrade = 0;

    http->gzip = 0;
	http->chunked = 0;

	swoole_efree(http->uri);
	http->uri_len = uri_len;
    http->uri = estrndup(uri,http->uri_len);

    http_client_property *hcc = swoole_get_property(zobject, swoole_property_common);
    swClient *cli = http->cli;
    if (cli->object)
    {
    	zval* object = cli->object;
    	sw_zval_ptr_dtor(&object);
    }

    sw_zval_add_ref(&zobject);
    cli->object = zobject;
    sw_copy_to_stack(cli->object, hcc->_object);

	if (!callback || ZVAL_IS_NULL(callback))
	{
		hcc->onResponse = NULL;
		swWarn("response callback is not set.");
	}
	else
	{
		sw_zval_add_ref(&callback);
		hcc->onResponse = sw_zval_dup(callback);
	}

    zval *valuePtr = NULL;
    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        HashTable *vht = Z_ARRVAL_P(zset);
        int value = 1;

        /**
         * TCP_NODELAY
         */
        if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **) &valuePtr) == SUCCESS)
        {
            value = 1;
            if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, &value, sizeof(value)) < 0)
            {
                swSysError("setsockopt(%d, TCP_NODELAY) failed.", cli->socket->fd);
            }
        }
    #ifdef SW_USE_OPENSSL
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_method"), (void **) &valuePtr) == SUCCESS)
        {
            convert_to_long(valuePtr);
            cli->ssl_method = (int) Z_LVAL_P(valuePtr);
            cli->open_ssl = 1;
        }
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_compress"), (void **) &valuePtr) == SUCCESS)
        {
            convert_to_boolean(valuePtr);
            cli->ssl_disable_compress = !Z_BVAL_P(valuePtr);
        }
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &valuePtr) == SUCCESS)
        {
            convert_to_string(valuePtr);
            cli->ssl_cert_file = strdup(Z_STRVAL_P(valuePtr));
            if (access(cli->ssl_cert_file, R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", cli->ssl_cert_file);
                return SW_ERR;
            }
            cli->open_ssl = 1;
        }
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &valuePtr) == SUCCESS)
        {
            convert_to_string(valuePtr);
            cli->ssl_key_file = strdup(Z_STRVAL_P(valuePtr));
            if (access(cli->ssl_key_file, R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", cli->ssl_key_file);
                return SW_ERR;
            }
        }
        if (cli->ssl_cert_file && !cli->ssl_key_file)
        {
            swoole_php_fatal_error(E_ERROR, "ssl require key file.");
            return SW_ERR;
        }
    #endif
    }

    //if connection is active
	if (cli->socket->active)
	{
		http_client_send_http_request(zobject TSRMLS_CC);
		return SW_OK;
	}

    cli->reactor_fdtype = PHP_SWOOLE_FD_STREAM_CLIENT;
    cli->onReceive = http_client_onReceive;
    cli->onConnect = http_client_onConnect;
    cli->onClose = http_client_onClose;
    cli->onError = http_client_onError;

    /// timeout init at create
    if (cli->connect(cli, http->host, http->port, http->timeout, 0) < 0)
    {
    	swWarn("http connect to server[%s:%d] failed.", http->host, (int )http->port);
    	return SW_ERR;
    }

	if (cli->async && http->timeout > 0)
	{
		cli->timer_id = 0;
		cli->timer_id = swTimer_add(&SwooleG.timer,http->timeout,0,cli,HTTPCLIENT_USED);
		if (cli->timer_id <= 0)
		{
			swWarn("set recv msg timeout timer failed.");
			return SW_ERR;
		}

		register_after_cb(&SwooleG.timer,HTTPCLIENT_USED,httpClient_timeout);
	}

    return SW_OK;
}

void swoole_http_client_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_http_client_ce, "swoole_http_client", "Swoole\\Http\\Client", swoole_http_client_methods);
    swoole_http_client_class_entry_ptr = zend_register_internal_class(&swoole_http_client_ce TSRMLS_CC);

    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_http_client_class_entry_ptr, SW_STRL("host")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("port")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_double(swoole_http_client_class_entry_ptr, SW_STRL("requestTimeout")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("headers")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("setting")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("requestHeaders")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("requestBody")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("requestMethod")-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_http_client_class_entry_ptr, SW_STRL("cookies")-1, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_string(swoole_http_client_class_entry_ptr, SW_STRL("body")-1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_http_client_class_entry_ptr, SW_STRL("statusCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    http_client_buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
    if (!http_client_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }

#ifdef SW_HAVE_ZLIB
    swoole_zlib_buffer = swString_new(2048);
    if (!swoole_zlib_buffer)
    {
        swoole_php_fatal_error(E_ERROR, "[2] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
    }
#endif
}

static void http_client_execute_callback(zval *zobject, int type)
{
    SWOOLE_FETCH_TSRMLS;

    http_client_property *hcc = swoole_get_property(zobject,swoole_property_common);
    if (!hcc)
    {
        return;
    }

    char *callback_name = NULL;
	zval *callback = NULL;
    switch(type)
    {
    case SW_CLIENT_CB_onConnect:
        callback = hcc->onConnect;
        callback_name = "onConnect";
        break;
    case SW_CLIENT_CB_onError:
        callback = hcc->onError;
        callback_name = "onError";
        break;
    case SW_CLIENT_CB_onClose:
        callback = hcc->onClose;
        callback_name = "onClose";
        break;
    case SW_CLIENT_CB_onTimeout:
    	callback = hcc->onTimeout;
    	callback_name = "onTimeout";
    	break;
    default:
        return;
    }

    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *retval = NULL;
	zval **args[1];
    args[0] = &zobject;
    sw_zval_add_ref(&zobject);
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swWarn("swoole_http_client->%s handler error.", callback_name);
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (zobject) sw_zval_ptr_dtor(&zobject);
    if (retval)  sw_zval_ptr_dtor(&retval);
}

static void http_client_free_cb(zval* object)
{
	if (!object)
	{
		return;
	}

	http_client_property *hcc = swoole_get_property(object, swoole_property_common);
	if (!hcc)
	{
		return;
	}

	if (hcc->onResponse)
	{
		zval* responseCb = hcc->onResponse;
		hcc->onResponse = NULL;
		sw_zval_free(responseCb);
	}

	if (hcc->onError)  {sw_zval_ptr_dtor(&hcc->onError);hcc->onError = NULL;}
	if (hcc->onConnect) {sw_zval_ptr_dtor(&hcc->onConnect);hcc->onConnect = NULL;}
	if (hcc->onClose) {sw_zval_ptr_dtor(&hcc->onClose); hcc->onClose = NULL;}
	if (hcc->onMessage) {sw_zval_ptr_dtor(&hcc->onMessage);hcc->onMessage = NULL;}
	if (hcc->onTimeout) {sw_zval_free(hcc->onTimeout);hcc->onTimeout = NULL;}
}

// @zobject: swoole_http_client object
static void http_client_onClose(swClient *cli)
{
    if (cli && cli->timer_id > 0)
	{
		swTimer_del(&SwooleG.timer,cli->timer_id);
		cli->timer_id = 0;
	}

    zval *zobject = cli?cli->object:NULL;
    if (!zobject)
    {
		return;
    }

    http_client *http = swoole_get_object(zobject);
    if (http && http->state == HTTP_CLIENT_STATE_WAIT_CLOSE)
    {
        http_client_parser_on_message_complete(&http->parser);
    }

    if (http)
	{
		http->state = HTTP_CLIENT_STATE_READY;
	}

    if (cli->released)
	{
			return;
	}

	cli->released = 1;

    http_client_execute_callback(zobject, SW_CLIENT_CB_onClose);

    http_client_free_cb(zobject);
    if (cli->object)
    {
		zval* obj = cli->object;
		cli->object = NULL;
		sw_zval_ptr_dtor(&obj);
    }
}

/// @zobject: swoole_http_client object
static void http_client_onError(swClient *cli)
{
    SWOOLE_FETCH_TSRMLS;
    if (cli && cli->timer_id > 0)
	{
		swTimer_del(&SwooleG.timer,cli->timer_id);
		cli->timer_id = 0;
	}

    zval *zobject = cli? cli->object:NULL;
    if (!zobject)
    {
        return;
    }

    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
    http_client *http = swoole_get_object(zobject);
	if (http)
	{
	   http->state = HTTP_CLIENT_STATE_READY;
	}
   
	if (cli->released)
	{
		return;
	}

	cli->released = 1;
	http_client_execute_callback(zobject, SW_CLIENT_CB_onError);

	http_client_free_cb(zobject);
	if (cli->object)
	{
		zval* obj = cli->object;
		cli->object = NULL;
		sw_zval_ptr_dtor(&obj);
	}
}

static void http_client_onReceive(swClient *cli, char *data, uint32_t length)
{
    SWOOLE_FETCH_TSRMLS;
    if (cli && cli->timer_id > 0)
    {
		swTimer_del(&SwooleG.timer,cli->timer_id);
		cli->timer_id = 0;
    }

    zval *zobject = cli? cli->object:NULL;
    if (!zobject)
    {
		swWarn("http client has no object.");
		return;
    }

    http_client *http = swoole_get_object(zobject);
    if (!http || !http->cli || !http->cli->socket || !cli->socket)
    {
        swWarn("http client is NULL，or object is not instanceof swoole_http_client.");
        return;
    }

    //the branch for websocket   
    if (http->state == HTTP_CLIENT_STATE_UPGRADE)
    {
        swString *buffer = http->buffer;
        if (swString_append_ptr(buffer, data, length) < 0)
        {
            cli->close(cli);
            return;
        }

        if (cli->socket->recv_wait)
        {
            recv_wait:
            if (buffer->offset == buffer->length)
            {
                zval *zframe = php_swoole_websocket_unpack(buffer TSRMLS_CC);
                zval **args[2];
                args[0] = &zobject;
                args[1] = &zframe;
                sw_zval_add_ref(&zobject);
                sw_zval_add_ref(&zframe);
                http_client_property *hcc = swoole_get_property(zobject, swoole_property_common);
                zval *zcallback = hcc->onMessage;

                zval *retval = NULL;
                if (zcallback && !ZVAL_IS_NULL(zcallback) &&
                		sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC)  == FAILURE)
                {
                    swWarn("swoole_http_client->onMessage: onClose handler error");
                }
                if (EG(exception))
                {
                    zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
                }

                if (zframe)
                {
                    sw_zval_ptr_dtor(&zframe);
                }

                //free the callback return value
                if (retval)
                {
                    sw_zval_ptr_dtor(&retval);
                }

                cli->socket->recv_wait = 0;
                swString_clear(buffer);

				sw_zval_ptr_dtor(&zobject);
                sw_zval_ptr_dtor(&zframe);
            }
        }
        else
        {
            int package_length = swWebSocket_get_package_length(NULL, cli->socket, data, length);
            //invalid package, close connection.
            if (package_length < 0)
            {
                cli->close(cli);
                return;
            }
            //get length success
            else
            {
            	//no length or extend recv buffer failed,return immediately
                if (package_length == 0 || (buffer->size < package_length && swString_extend(buffer, package_length) < 0))
                {
                     return;
                }

                buffer->offset = package_length;
                cli->socket->recv_wait = 1;
                goto recv_wait;
            }
        }
    }
    else
    {
        long parsed_n = php_http_parser_execute(&http->parser, &http_parser_settings, data, length);
        if (parsed_n < 0)
        {
            swSysError("Parsing http over socket[%d] failed.", cli->socket->fd);
            cli->close(cli);
            return ;
        }

        //not complete
        if (!http->completed)
        {
           return;
        }

        http_client_property *hcc = swoole_get_property(zobject, swoole_property_common);
        if (!hcc)
        {
           swWarn("http_client_parser_on_message_complete hcc is NULL");
           return;
        }

        zval *zcallback = hcc->onResponse;
        hcc->onResponse = NULL;
        if (!zcallback || ZVAL_IS_NULL(zcallback))
		{
		   swWarn("swoole http client object have not receive callback.");
		   return;
		}

        zval **args[1];
        args[0] = &zobject;
        sw_zval_add_ref(&zobject);

        if (http->keep_alive)
        {
           http->state = HTTP_CLIENT_STATE_READY;
           http->completed = 0;
        }

        zval *retval = NULL;
        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
        {
            swWarn("onReactorCallback handler error");
        }

        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }

        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }

        //释放回调前所持有的callback
        sw_zval_free(zcallback);

        int socket_close = (cli->released || !cli->socket || cli->socket->closed);
		sw_zval_ptr_dtor(&zobject);

		if (socket_close)
		{
			return;
		}

        /// TODO: Sec-WebSocket-Accept check
        if (http->upgrade)
        {
            http->state = HTTP_CLIENT_STATE_UPGRADE;
            http->buffer = swString_new(SW_HTTP_RESPONSE_INIT_SIZE);
            if (!http->buffer)
            {
                swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
                return;
            }

            swString_clear(http->buffer);
        }
        else if (http->keep_alive == 0 && http->state != HTTP_CLIENT_STATE_WAIT_CLOSE)
        {
        	cli->close(cli);
        }
    }
}

static void http_client_onConnect(swClient *cli)
{
    SWOOLE_FETCH_TSRMLS;

    zval *zobject = cli->object;
    if (!zobject)
    {
    	swWarn("http client has no object.");
    	return;
    }

    http_client *http = swoole_get_object(zobject);
    if (!(http && http->cli && http->cli->socket)) 
    {
        swWarn("http_client is NULL,or object is not instanceof swoole_http_client,or socket is NULL");
        return;
    }

    http_client_execute_callback(zobject, SW_CLIENT_CB_onConnect);
    //send http request on write
    http_client_send_http_request(zobject TSRMLS_CC);
}

static inline char* sw_http_build_query(zval *data, zend_size_t *length, smart_str *formstr TSRMLS_DC)
{
#if PHP_MAJOR_VERSION < 7
#if PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION == 3
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL TSRMLS_CC) == FAILURE)
#else
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738 TSRMLS_CC) == FAILURE)
#endif
    {
        if (formstr->c)
        {
            smart_str_free(formstr);
        }

        return NULL;
    }
    if (!formstr->c)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->len;
    return formstr->c;
#else
    if (php_url_encode_hash_ex(HASH_OF(data), formstr, NULL, 0, NULL, 0, NULL, 0, NULL, NULL, (int) PHP_QUERY_RFC1738) == FAILURE)
    {
        if (formstr->s)
        {
	    	smart_str_free(formstr);
		}
		return NULL;
    }
    if (!formstr->s)
    {
        return NULL;
    }
    smart_str_0(formstr);
    *length = formstr->s->len;
    return formstr->s->val;
#endif
}

static int http_client_send_http_request(zval *zobject TSRMLS_DC)
{
    http_client *http = swoole_get_object(zobject);
    if (!(http && http->cli))
    {
        swWarn("http client is NULL or object is not instanceof swoole_http_client.");
        return SW_ERR;
    }
    
    if (http->cli->socket && http->cli->socket->active == 0)
    {
        swWarn("server is not connected.");
        return SW_ERR;
    }
    
    if (http->state != HTTP_CLIENT_STATE_READY)
    {
        swWarn("http client is not ready.");
        return SW_ERR;
    }
    
    http->state = HTTP_CLIENT_STATE_BUSY;
     //clear errno
    SwooleG.error = 0;
    http_client_property *hcc = swoole_get_property(zobject, swoole_property_common);

    zval *post_data = hcc->request_body;

    //set request_method as get/post
    if (!hcc->request_method)
    {
        hcc->request_method = (post_data && (Z_TYPE_P(post_data) == IS_ARRAY || Z_TYPE_P(post_data) == IS_STRING)? "POST" : "GET");
    }

    http_client_buffer_append_request_line(http_client_buffer, http, hcc);

    char *key = NULL;
    uint32_t keylen = 0;
    int keytype = 0;
    zval *value = NULL;
    zval *send_header = hcc->request_header;
    if (send_header && Z_TYPE_P(send_header) == IS_ARRAY)
    {
        int con_res = sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Connection"), (void **)&value);
        if ((con_res == FAILURE && http->keep_alive) || (con_res == SUCCESS && strcasecmp(Z_STRVAL_P(value), "keep-alive") == 0))
        {
            http->keep_alive = 1;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        }
        else if ((con_res == FAILURE && !http->keep_alive) || (con_res == SUCCESS && strcasecmp( Z_STRVAL_P(value), "closed") == 0))
        {
            http->keep_alive = 0;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        }

        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Host"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
        }

#ifdef SW_HAVE_ZLIB
        if (sw_zend_hash_find(Z_ARRVAL_P(send_header), ZEND_STRS("Accept-Encoding"), (void **) &value) == FAILURE)
        {
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
        }
#endif

        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(send_header), key, keylen, keytype, value)
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }

        	if (sw_convert_to_string(value) < 0)
			{
				swWarn("convert to string failed.");
				return SW_ERR;
			}

            http_client_swString_append_headers(http_client_buffer, key, keylen, Z_STRVAL_P(value), Z_STRLEN_P(value));
        SW_HASHTABLE_FOREACH_END();
    }
    else
    {
        if(http->keep_alive)
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("keep-alive"));
        else
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Connection"), ZEND_STRL("closed"));
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Host"), http->host, http->host_len);
#ifdef SW_HAVE_ZLIB
        http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Accept-Encoding"), ZEND_STRL("gzip"));
#endif
    }

    if (hcc->cookies && Z_TYPE_P(hcc->cookies) == IS_ARRAY)
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("Cookie: "));
        int n_cookie = Z_ARRVAL_P(hcc->cookies)->nNumOfElements;

        int index = 0;
        SW_HASHTABLE_FOREACH_START2(Z_ARRVAL_P(hcc->cookies), key, keylen, keytype, value)
            index++;
            if (HASH_KEY_IS_STRING != keytype)
            {
                continue;
            }

            if (sw_convert_to_string(value) < 0)
			{
				swWarn("convert to string failed.");
				return SW_ERR;
			}
            swString_append_ptr(http_client_buffer, key, keylen);
            swString_append_ptr(http_client_buffer, "=", 1);

            int encoded_value_len = 0;
            char *encoded_value = sw_php_url_encode( Z_STRVAL_P(value), Z_STRLEN_P(value), &encoded_value_len);
            if (encoded_value)
            {
                swString_append_ptr(http_client_buffer, encoded_value, encoded_value_len);
                swoole_efree(encoded_value);
            }

            if (index < n_cookie)
            {
                swString_append_ptr(http_client_buffer, "; ", 2);
            }

        SW_HASHTABLE_FOREACH_END();
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    if (post_data)
    {
        if (Z_TYPE_P(post_data) == IS_ARRAY)
        {
            zend_size_t len = 0;
            http_client_swString_append_headers(http_client_buffer, ZEND_STRL("Content-Type"), ZEND_STRL("application/x-www-form-urlencoded"));
            smart_str formstr_s = {0};
            char *formstr = sw_http_build_query(post_data, &len, &formstr_s TSRMLS_CC);
            if (!formstr)
            {
                swWarn("http_build_query failed.");
                return SW_ERR;
            }

            http_client_swString_append_contentlength(http_client_buffer, len);
            swString_append_ptr(http_client_buffer, formstr, len);
            smart_str_free(&formstr_s);
        }
        else if (Z_TYPE_P(post_data) == IS_STRING)
        {
            http_client_swString_append_contentlength(http_client_buffer,Z_STRLEN_P(post_data));
            swString_append_ptr(http_client_buffer, Z_STRVAL_P(post_data), Z_STRLEN_P(post_data));
        }
        else
        {
        	swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
        }

        zend_update_property_null(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("requestBody") TSRMLS_CC);
        hcc->request_body = NULL;
    }
    else
    {
        swString_append_ptr(http_client_buffer, ZEND_STRL("\r\n"));
    }

    swTrace("[%d]: %s\n", (int)http_client_buffer->length, http_client_buffer->str);

    int ret = http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0);
    if (ret < 0)
    {
        SwooleG.error = errno;
        swoole_php_sys_error(E_WARNING, "send(%d) %d bytes failed.", http->cli->socket->fd, (int )http_client_buffer->length);
        zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
    }

    return ret;
}

/// 该内部接口不触发close 回调.
static void http_client_free(zval *object TSRMLS_DC)
{   
    //host/buffer why not free?
    http_client *http = swoole_get_object(object);
    if (!http)
    {
        return;
    }

    swoole_efree(http->uri);
    swoole_efree(http->host);

    if (http->tmp_header_field_buf)
	{
		swString_free(http->tmp_header_field_buf);
		http->tmp_header_field_buf = NULL;
	}
    if (http->tmp_header_value_buf)
	{
		swString_free(http->tmp_header_value_buf);
		http->tmp_header_value_buf = NULL;
	}

	if (http->body)
	{
		swString_free(http->body);
		http->body = NULL;
	}

    //http->buffer only apply to websocket
    if (http->buffer)
    {
        swString_free(http->buffer);
        http->buffer = NULL;
    }

    swClient *cli = http->cli;
    if (cli)
    {
    	http->cli = NULL;
    	cli->object = NULL;   	/// 将不会触发php 回调
        php_swoole_client_free(object, cli TSRMLS_CC);
    }
    else
    {
    	swoole_set_object(object, NULL);
    }

    swoole_efree(http);
}

static http_client* http_client_create(zval *object TSRMLS_DC)
{
	swClient *cli = NULL;
	http_client *http = swoole_get_object(object);
	if (http)
	{
		//http not ready
		int connectionActive = http->cli && http->cli->socket && http->cli->socket->active;
		if (http->state == HTTP_CLIENT_STATE_READY && connectionActive)
		{
		//	swWarn("Operation now in progress phase %d,or socket is closed", http->state);
			return http;
		}
		else
		{
			return NULL;
		}
	}

    http = (http_client*) emalloc(sizeof(http_client));
    if (!http)
    {
    	return NULL;
    }

    bzero(http, sizeof(http_client));
    php_http_parser_init(&http->parser, PHP_HTTP_RESPONSE);
    http->parser.data = http;

    zval *ztmp = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("host"), 0 TSRMLS_CC);
    http->host_len = Z_STRLEN_P(ztmp);
    swoole_efree(http->host);
    http->host = estrndup(Z_STRVAL_P(ztmp),http->host_len);

    ztmp = NULL;
    ztmp = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("port"), 0 TSRMLS_CC);
    convert_to_long(ztmp);
    http->port = Z_LVAL_P(ztmp);

    http->timeout = 0;
    http->keep_alive = 1;  //default close

    zval *zset = sw_zend_read_property(swoole_http_client_class_entry_ptr, object, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
    	HashTable *vht = Z_ARRVAL_P(zset);

        /// timeout
    	ztmp = NULL;
        if (php_swoole_array_get_value(vht, "timeout", ztmp))
        {
            convert_to_double(ztmp);
            http->timeout = (double) Z_DVAL_P(ztmp);
        }

        /// keep_alive
        ztmp = NULL;
        if (php_swoole_array_get_value(vht, "keep_alive", ztmp))
        {
            convert_to_boolean(ztmp);
            http->keep_alive = (int) Z_LVAL_P(ztmp);
        }
    }

	cli = http->cli;
	if (cli && cli->released)
	{
		return NULL;
	}

	if (cli)
    {
		if (cli->object) {
			zval* object = cli->object;
			sw_zval_ptr_dtor(&object);
			cli->object = NULL;
		}

    	php_swoole_client_free(object,cli TSRMLS_CC);
    }

	swoole_set_object(object, http);
    cli = php_swoole_client_new(object, http->host, http->host_len, http->port,&cli);
    if (!cli)
    {
    	swoole_php_sys_error(E_WARNING, "http create client[%s:%d] failed.", http->host, (int )http->port);
        return NULL;
    }

    http->cli = cli;
    http->state = HTTP_CLIENT_STATE_READY;
    
    return http;
}

static PHP_METHOD(swoole_http_client, __construct)
{
    char *host = NULL;
    zend_size_t host_len = 0;
    long port = 80;
    zend_bool ssl = SW_FALSE;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &host, &host_len, &port, &ssl))
    {
        return;
    }
    
    if (!host || host_len <= 0)
    {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "construct swoole_http_client host is empty", 0 TSRMLS_CC);
        RETURN_FALSE;
    }

    zend_update_property_stringl(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("host"), host, host_len TSRMLS_CC);   
    zend_update_property_long(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);

	//check here
    php_swoole_check_reactor();
    
	//init
    swoole_set_object(getThis(), NULL);

    zval *headers = NULL;
    SW_MAKE_STD_ZVAL(headers);
    array_init(headers);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("headers"), headers TSRMLS_CC);
    sw_zval_ptr_dtor(&headers);

    http_client_property *hcc = NULL;
    hcc = (http_client_property*) emalloc(sizeof(http_client_property));
    bzero(hcc, sizeof(http_client_property));
    swoole_set_property(getThis(), swoole_property_common, hcc);

    int flags = SW_SOCK_TCP | SW_FLAG_ASYNC;
#ifdef SW_USE_OPENSSL
    flags |= (ssl)? SW_SOCK_SSL:0;
#endif

    zend_update_property_long(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), flags TSRMLS_CC);
    
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, __destruct)
{
	http_client_free(getThis() TSRMLS_CC);

	http_client_free_cb(getThis());

	http_client_property *hcc = swoole_get_property(getThis(),swoole_property_common);
	swoole_efree(hcc);
	swoole_set_property(getThis(), swoole_property_common, NULL);
}

static PHP_METHOD(swoole_http_client, set)
{
    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset))
    {
        return;
    }

    php_swoole_array_separate(zset);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    sw_zval_ptr_dtor(&zset);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client,setReqTimeout)
{
	long timeout = 0;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
	{
		swWarn("parse parameters error.");
		RETURN_FALSE;
	}

	zend_update_property_long(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestTimeout"), timeout TSRMLS_CC);
	RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setHeaders)
{
    zval *headers = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &headers))
    {
        return;
    }

    http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
    if (!hcc)
    {
        swDebug("http_client_property is NULL ");
        RETURN_FALSE;
    }

    php_swoole_array_separate(headers);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), headers TSRMLS_CC);

    hcc->request_header = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestHeaders"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_header,hcc->_request_header);
    sw_zval_ptr_dtor(&headers);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setCookies)
{
    zval *cookies = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &cookies))
    {
        return;
    }

    http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
	if (!hcc)
	{
		swDebug("http_client_property is NULL ");
		RETURN_FALSE;
	}

    php_swoole_array_separate(cookies);
    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("cookies"), cookies TSRMLS_CC);
    sw_zval_ptr_dtor(&cookies);

    hcc->cookies = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("cookies"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->cookies,hcc->_cookies);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setData)
{
    zval *data = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data))
    {
        return;
    }

    /// post_data 参数可以为空或者null. post_data存在时，必须为string类型或者array 类型
	if (data && !ZVAL_IS_NULL(data) && Z_TYPE_P(data) != IS_ARRAY && Z_TYPE_P(data) != IS_STRING)
	{
		swDebug("post data must be string or array.");
		RETURN_FALSE;
	}

	http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
	if (!hcc)
	{
		swDebug("http_client_property is NULL ");
		RETURN_FALSE;
	}

	if (IS_ARRAY == Z_TYPE_P(data))
	{
		php_swoole_array_separate(data);
		zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data TSRMLS_CC);
		sw_zval_ptr_dtor(&data);
	}
	else
	{
		zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), data TSRMLS_CC);
	}

    hcc->request_body = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_body,hcc->_request_body);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, setMethod)
{
    zval *method = NULL;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &method))
	{
		return;
	}

	if (sw_convert_to_string(method) < 0)
	{
		swWarn("convert to string failed.");
		RETURN_FALSE;
	}

	zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestMethod"),
																			method TSRMLS_CC);
	http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
	if (!hcc)
	{
		swDebug("http_client_property is NULL ");
		RETURN_FALSE;
	}

	zval* tmpMethod = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(),
													ZEND_STRL("requestMethod"), 1 TSRMLS_CC);
													
	hcc->request_method = Z_STRVAL_P(tmpMethod);
	RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, isConnected)
{
    http_client *http = swoole_get_object(getThis());
    if (!http || !http->cli || http->cli->released || !http->cli->socket)
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(http->cli->socket->active);
}

static PHP_METHOD(swoole_http_client, close)
{
	http_client *http = swoole_get_object(getThis());
	if(!http)
	{
		swDebug("have no http client object.");
		RETURN_FALSE;
	}

	swClient *cli = http->cli;
	if (!cli || cli->released || !cli->socket || cli->socket->closed)
	{
		RETURN_FALSE;
	}

	zend_bool force = 0;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &force))
	{
		RETURN_FALSE;
	}

	zval* obj = cli->object;
	/// 将不触发php 回调
	cli->object = NULL;
	cli->close(cli);

	/// 延迟触发回调
	if (obj)
	{
		cli->object = obj;
		cli->released = 1;
		SwooleG.main_reactor->defer(SwooleG.main_reactor,defer_close,cli);
	}

	RETURN_TRUE;
}

static PHP_METHOD(swoole_http_client, on)
{
	http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
	if (!hcc)
	{
		swDebug("http_client_property is NULL ");
		RETURN_FALSE;
	}

    char *cb_name = NULL;
    zend_size_t cb_name_len = 0;
    zval *zcallback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback))
    {
    	swWarn("parse user set parameters error.");
    	RETURN_FALSE;
    }
    
    if (cb_name_len <= 0 || !cb_name || swoole_check_callable(zcallback TSRMLS_CC) < 0)
    {
    	RETURN_FALSE;
    }

    if (cb_name_len == strlen("error") && strncasecmp("error", cb_name, cb_name_len) == 0)
    {
		if (hcc->onError) sw_zval_ptr_dtor(&hcc->onError);

		hcc->onError = zcallback;
        sw_copy_to_stack(hcc->onError ,hcc->_onError);
    }
    else if (cb_name_len == strlen("timeout") && strncasecmp("timeout",cb_name,cb_name_len) == 0)
    {
		if (hcc->onTimeout) sw_zval_free(hcc->onTimeout);
		hcc->onTimeout = sw_zval_dup(zcallback);
    }
    else if (cb_name_len == strlen("connect") && strncasecmp("connect", cb_name, cb_name_len) == 0)
    {
		if (hcc->onConnect) sw_zval_ptr_dtor(&hcc->onConnect);

        hcc->onConnect = zcallback;
        sw_copy_to_stack(hcc->onConnect,hcc->_onConnect);
    }
    else if (cb_name_len == strlen("close") && strncasecmp("close", cb_name, cb_name_len) == 0)
    {
        if (hcc->onClose)  sw_zval_ptr_dtor(&hcc->onClose);
        hcc->onClose = zcallback;
        sw_copy_to_stack(hcc->onClose,hcc->_onClose);
    }
    else if (cb_name_len == strlen("message") && strncasecmp("message", cb_name, cb_name_len) == 0)
    {    
        if (hcc->onMessage) sw_zval_ptr_dtor(&hcc->onMessage);
        hcc->onMessage = zcallback;
        sw_copy_to_stack(hcc->onMessage,hcc->_onMessage);
    }
    else
    {
        swWarn("swoole_http_client: event callback[%s] is unknow", cb_name);
        RETURN_FALSE;
    }

    sw_zval_add_ref(&zcallback);
    RETURN_TRUE;
}

enum state
{
    s_start_res = 4,
    s_header_field_start = 40,
    s_header_field,
    s_header_value_start,
    s_header_value
};

static int http_client_parser_on_header_field(php_http_parser *parser, const char *at, size_t length)
{
	http_client* http = (http_client*)parser->data;
    if (!http)
    {
        swWarn("http is NULL");
        return SW_ERR;
    }
    enum state state = (enum state) parser->state;
    if(state == s_header_field_start || state == s_start_res)
    {
    	swString_clear(http->tmp_header_field_buf);
    }

    if (swString_append_ptr(http->tmp_header_field_buf, (char *) at, length) < 0)
    {
    	swWarn("append string to http header_field failed");
        return SW_ERR;
    }

    return SW_OK;
}

static int http_client_parser_on_header_value(php_http_parser *parser, const char *at, size_t length)
{
    SWOOLE_FETCH_TSRMLS;

    http_client* http = (http_client*) parser->data;
    if (!http || !http->cli)
    {
        swWarn("http_client_parser_on_header_value http or http->cli is NULL");
        return SW_ERR;
    }

    zval* zobject = (zval*) http->cli->object;
    if (!zobject)
    {
        swWarn("http_client_parser_on_header_value http->cli->obejct is NULL");
        return SW_ERR;
    }
     enum state state = (enum state) parser->state;

    zval *headers = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject,
    																	ZEND_STRL("headers"), 0 TSRMLS_CC);

    if(state == s_header_value_start || state == s_start_res)
    {
      swString_clear(http->tmp_header_value_buf);
    }
    if (swString_append_ptr(http->tmp_header_value_buf, (char *) at, length) < 0)
    {
    	swWarn("append string to http header_value failed");
        return SW_ERR;
    }                                                                    

    /// zend_str_tolower_dup,会emalloc 并返回给header_name,需要外部来进行释放
    char *header_name = zend_str_tolower_dup(http->tmp_header_field_buf->str, http->tmp_header_field_buf->length);
    zend_str_tolower(http->tmp_header_value_buf->str, http->tmp_header_value_buf->length);
    sw_add_assoc_stringl_ex(headers, header_name, http->tmp_header_field_buf->length + 1, http->tmp_header_value_buf->str, http->tmp_header_value_buf->length, 1);    

    //websocket client
    if (strncasecmp(header_name, "Upgrade",strlen("Upgrade")) == 0 &&
    					strncasecmp(at, "websocket", length) == 0)
    {
        http->upgrade = 1;
    }
    else if (strncasecmp(header_name, "Set-Cookie",strlen("Set-Cookie")) == 0)
    {
        int l_cookie = strchr(at, ';')? (strchr(at, ';') - at):(strstr(at, "\r\n") - at);
        int l_key = strchr(at, '=') - at;

        zval *cookies = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("cookies"), 1 TSRMLS_CC);
        if (!cookies || ZVAL_IS_NULL(cookies) || Z_TYPE_P(cookies) != IS_ARRAY)
        {
        	zval* tmp = NULL;
            SW_MAKE_STD_ZVAL(tmp);
            array_init(tmp);
            zend_update_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("cookies"), tmp TSRMLS_CC);
            cookies = sw_zend_read_property(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("cookies"), 1 TSRMLS_CC);
            sw_zval_ptr_dtor(&tmp);
        }

        char keybuf[SW_HTTP_COOKIE_KEYLEN] = {0};
        memcpy(keybuf, at, l_key);
        keybuf[l_key] = '\0';
        sw_add_assoc_stringl_ex(cookies, keybuf, l_key + 1, (char*) at + l_key + 1, l_cookie - l_key - 1, 1);
    }
#ifdef SW_HAVE_ZLIB
    else if (strncasecmp(header_name, "Content-Encoding",strlen("Content-Encoding")) == 0 &&
    										strncasecmp(at, "gzip", length) == 0)
    {
        http->gzip = 1;
    }
#endif
    else if (strncasecmp(header_name, "Transfer-Encoding",strlen("Transfer-Encoding")) == 0 &&
    										strncasecmp(at, "chunked", length) == 0)
    {
        http->chunked = 1;
    }

    swoole_efree(header_name);
    return 0;
}


static int http_response_uncompress(char *body, int length)
{
#ifdef SW_HAVE_ZLIB
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (Z_OK != inflateInit2(&stream, MAX_WBITS + 16))
    {
        swWarn("inflateInit2() failed.");
        return SW_ERR;
    }

    stream.avail_in = length;
    stream.next_in = (Bytef *) body;

    swString_clear(swoole_zlib_buffer);

    int ret = SW_OK;
    while (1)
    {
        stream.avail_out = swoole_zlib_buffer->size - stream.total_out;
        stream.next_out = (Bytef *) (swoole_zlib_buffer->str + stream.total_out);

        int status = inflate(&stream, Z_SYNC_FLUSH);
        if (status == Z_STREAM_END)
        {
            swoole_zlib_buffer->length = stream.total_out;
            ret = SW_OK;
            break;
        }
        else if (status == Z_OK)
        {
            if (stream.total_out >= swoole_zlib_buffer->size &&
            		swString_extend(swoole_zlib_buffer, swoole_zlib_buffer->size * 2) < 0)
            {
            	ret = SW_ERR;
            	break;
            }
        }
        else
        {
        	ret = SW_ERR;
        	break;
        }
    }

    inflateEnd(&stream);
    return ret;
#else
    return SW_OK;
#endif
}

static int http_client_parser_on_body(php_http_parser *parser, const char *at, size_t length)
{
    http_client* http = (http_client*) parser->data;
    if (!http)
    {
        swWarn("http client is NULL");
        return SW_ERR;
    }

    if (swString_append_ptr(http->body, (char *) at, length) < 0)
    {
    	swWarn("append string to http body failed");
        return SW_ERR;
    }

    return SW_OK;
}

static int http_client_parser_on_headers_complete(php_http_parser *parser)
{
    http_client* http = (http_client*) parser->data;
    if (!http)
    {
    	swWarn("http client is NULL");
    	return SW_ERR;
    }

    http->state = (http->chunked == 0 && parser->content_length < 0)? HTTP_CLIENT_STATE_WAIT_CLOSE:http->state;
    return SW_OK;
}

static int http_client_parser_on_message_complete(php_http_parser *parser)
{
    SWOOLE_FETCH_TSRMLS;

    http_client* http = (http_client*) parser->data;
    if (!http || !http->cli)
    {
        swWarn("http_client_parser_on_message_complete http or http->cli is NULL");
        return SW_ERR;
    }

    zval* zobject = (zval*) http->cli->object;
    if (!zobject)
    {
        swWarn("http_client_parser_on_message_complete http->cli->object is NULL");
        return SW_ERR;
    }

    char* str = http->body->str;
    int length = http->body->length;
#ifdef SW_HAVE_ZLIB
    if (http->gzip && http->body->length > 0)
    {
        if (http_response_uncompress(http->body->str, http->body->length) < 0)
        {
            swWarn("uncompress http response failed.");
            return SW_ERR;
        }

        str = swoole_zlib_buffer->str;
        length = swoole_zlib_buffer->length;
    }
#endif

    http->completed = 1;
    zend_update_property_stringl(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("body"),str,length TSRMLS_CC);
    zend_update_property_long(swoole_http_client_class_entry_ptr, zobject, ZEND_STRL("statusCode"), http->parser.status_code TSRMLS_CC);

    return SW_OK;
}

static PHP_METHOD(swoole_http_client, execute)
{
    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb))
    {
        return;
    }

    int ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, get)
{
	http_client_property *hcc = swoole_get_property(getThis(),swoole_property_common);
	if (!hcc)
	{
		swWarn("http client property is NULL ");
		RETURN_FALSE;
	}

    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb))
    {
        return;
    }

    hcc->request_method = "GET";
    int ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_http_client, post)
{
	http_client_property *hcc = swoole_get_property(getThis(),swoole_property_common);
	if (!hcc)
	{
		swWarn("http_client_property is NULL ");
		RETURN_FALSE;
	}

    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *callback = NULL;
    zval *post_data = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "szz", &uri, &uri_len, &post_data, &callback))
    {
        return;
    }

    /// post_data 参数可以为空或者null. post_data存在时，必须为string类型或者array 类型
    if (post_data && !ZVAL_IS_NULL(post_data) && Z_TYPE_P(post_data) != IS_ARRAY && Z_TYPE_P(post_data) != IS_STRING)
    {
        swWarn("post data must be string or array.");
        RETURN_FALSE;
    }

    zend_update_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), post_data TSRMLS_CC);
    hcc->request_body = sw_zend_read_property(swoole_http_client_class_entry_ptr, getThis(), ZEND_STRL("requestBody"), 1 TSRMLS_CC);
    sw_copy_to_stack(hcc->request_body,hcc->_request_body);  //just for PHP7

    hcc->request_method = "POST";  
    int ret = http_client_execute(getThis(), uri, uri_len, callback TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}
    
//websocket method
static PHP_METHOD(swoole_http_client, upgrade)
{
	http_client_property *hcc = swoole_get_property(getThis(), swoole_property_common);
	if (!hcc)
	{
		swWarn("http_client_property is NULL ");
		RETURN_FALSE;
	}

    char *uri = NULL;
    zend_size_t uri_len = 0;
    zval *finish_cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &uri, &uri_len, &finish_cb))
    {
        return;
    }

    char buf[SW_WEBSOCKET_KEY_LENGTH + 1] = {0};
    http_client_create_token(SW_WEBSOCKET_KEY_LENGTH, buf);

    sw_add_assoc_string(hcc->request_header, "Connection", "Upgrade", 1);
    sw_add_assoc_string(hcc->request_header, "Upgrade", "websocket", 1);

    int encoded_value_len = 0;

#if PHP_MAJOR_VERSION < 7
    uchar *encoded_value = php_base64_encode((const unsigned char *)buf, SW_WEBSOCKET_KEY_LENGTH + 1, &encoded_value_len);
#else
    zend_string *str = php_base64_encode((const unsigned char *)buf, SW_WEBSOCKET_KEY_LENGTH + 1);
    char *encoded_value = str->val;
    encoded_value_len = str->len;
#endif

    sw_add_assoc_stringl(hcc->request_header, "Sec-WebSocket-Key", (char*)encoded_value, encoded_value_len, 1);

    int ret = http_client_execute(getThis(), uri, uri_len, finish_cb TSRMLS_CC);
    SW_CHECK_RETURN(ret);
}

//just for websocket
static PHP_METHOD(swoole_http_client, push)
{
    char *data = NULL;
    zend_size_t length = 0;
    long opcode = WEBSOCKET_OPCODE_TEXT_FRAME;
    zend_bool fin = 1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|lb", &data, &length, &opcode, &fin))
    {
        return;
    }

    if (opcode > WEBSOCKET_OPCODE_PONG)
    {
        swWarn("opcode max 10");
        RETURN_FALSE;
    }

    if (length <= 0 || !data)
    {
        swWarn("data is empty.");
        RETURN_FALSE;
    }

    http_client *http = swoole_get_object(getThis());
    if (!http || !http->cli || !http->cli->socket)
    {
    	swDebug("http client or client object or socket is NULL");
        RETURN_FALSE;
    }

    if (!http->upgrade)
    {
        swWarn("connection[%d] is not a websocket client.", (int ) http->cli->socket->fd);
        RETURN_FALSE;
    }

    swString_clear(http_client_buffer);
    swWebSocket_encode(http_client_buffer, data, length, opcode, (int) fin, 0);
    SW_CHECK_RETURN(http->cli->send(http->cli, http_client_buffer->str, http_client_buffer->length, 0));
}
