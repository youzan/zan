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
#include "swWork.h"
#include "swBaseOperator.h"

#include "ext/standard/basic_functions.h"

typedef struct
{
    zval *onConnect;
    zval *onReceive;
    zval *onClose;
    zval *onError;
    zval* onTimeout;
#if PHP_MAJOR_VERSION >= 7
    zval _object;
    zval _onConnect;
	zval _onClose;
	zval _onError;
#endif
} client_callback;

enum client_callback_type
{
    SW_CLIENT_CALLBACK_onConnect = 1,
    SW_CLIENT_CALLBACK_onReceive,
    SW_CLIENT_CALLBACK_onError,
    SW_CLIENT_CALLBACK_onClose,
};

static int 				swoole_client_ce_inited = 0;

static zend_class_entry swoole_client_ce;
zend_class_entry *swoole_client_class_entry_ptr = NULL;

static void tcpClient_timeout(swTimer* timer,swTimer_node* node);
static void client_execute_callback(swClient *cli, enum client_callback_type type);
static void client_onConnect(swClient *cli);
static void client_onReceive(swClient *cli, char *data, uint32_t length);
static int  client_onPackage(swConnection *conn, char *data, uint32_t length);
static void client_onClose(swClient *cli);
static void client_onError(swClient *cli);

static PHP_METHOD(swoole_client, __construct);
static PHP_METHOD(swoole_client, __destruct);
static PHP_METHOD(swoole_client, set);
static PHP_METHOD(swoole_client,setConnectTimeout);
static PHP_METHOD(swoole_client,setSendTimeout);
static PHP_METHOD(swoole_client, connect);
static PHP_METHOD(swoole_client, recv);
static PHP_METHOD(swoole_client, send);
static PHP_METHOD(swoole_client, sendfile);
static PHP_METHOD(swoole_client, sendto);
static PHP_METHOD(swoole_client, sleep);
static PHP_METHOD(swoole_client, wakeup);
static PHP_METHOD(swoole_client, isConnected);
static PHP_METHOD(swoole_client, getsockname);
static PHP_METHOD(swoole_client, getpeername);
static PHP_METHOD(swoole_client, close);
static PHP_METHOD(swoole_client, on);
static PHP_METHOD(swoole_client, getSocket);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, type)
    ZEND_ARG_INFO(0, async)
    ZEND_ARG_INFO(0, id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_setTimeout, 0, 0, 1)
    ZEND_ARG_INFO(0,timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_connect, 0, 0, 2)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_recv, 0, 0, 0)
    ZEND_ARG_INFO(0, size)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_send, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendfile, 0, 0, 1)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_sendto, 0, 0, 3)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_close, 0, 0, 0)
    ZEND_ARG_INFO(0, force)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()


static void client_free_callback(zval *object);
static int client_select_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC);
static int client_select_wait(zval *sock_array, fd_set *fds TSRMLS_DC);
static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC);

static const zend_function_entry swoole_client_methods[] =
{
    PHP_ME(swoole_client, __construct, arginfo_swoole_client_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_client, __destruct, arginfo_swoole_client_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_client, set, arginfo_swoole_client_set, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, setSendTimeout, arginfo_swoole_client_setTimeout, ZEND_ACC_PUBLIC)
	PHP_ME(swoole_client, setConnectTimeout,arginfo_swoole_client_setTimeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, connect, arginfo_swoole_client_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, recv, arginfo_swoole_client_recv, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, send, arginfo_swoole_client_send, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendfile, arginfo_swoole_client_sendfile, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sendto, arginfo_swoole_client_sendto, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, sleep, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, wakeup, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, isConnected, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getsockname, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getpeername, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, close, arginfo_swoole_client_close, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, on, arginfo_swoole_client_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_client, getSocket, arginfo_swoole_client_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static sw_inline void defer_close(void* data)
{
	swClient* cli = (swClient*)data;
	swClient_free(cli);
	cli->released = 0;
	client_onClose(cli);
}

static void client_execute_callback(swClient *cli, enum client_callback_type type)
{
    SWOOLE_FETCH_TSRMLS;

    zval *zobject = cli->object;
    if (!zobject)
    {
    		return;
    }

    zval *callback = NULL;
    char *callback_name = NULL;

    client_callback *cb = swoole_get_property(zobject, swoole_property_common);

    switch(type)
    {
    case SW_CLIENT_CALLBACK_onConnect:
        callback = (!cb)? NULL:cb->onConnect;
        callback_name = "onConnect";
        break;
    case SW_CLIENT_CALLBACK_onError:
        callback = (!cb)? NULL:cb->onError;
        callback_name = "onError";
        break;
    case SW_CLIENT_CALLBACK_onClose:
        callback = (!cb)? NULL:cb->onClose;
        callback_name = "onClose";
        break;
    default:
        return;
    }

    if (!callback || ZVAL_IS_NULL(callback))
    {
        swWarn("object have not %s callback.", callback_name);
        return;
    }

    zval **args[1];
    args[0] = &zobject;
    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swWarn("%s handler error.", callback_name);
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

static void tcpClient_timeout(swTimer* timer,swTimer_node* node)
{
	SWOOLE_FETCH_TSRMLS;
	swClient* cli = node? node->data:NULL;
	uint8_t timer_type = cli? cli->timeout_type:SW_CLIENT_INVAILED_TIMEOUT;
	if (timer_type == SW_CLIENT_CONNECT_TIMEOUT || timer_type == SW_CLIENT_RECV_TIMEOUT)
	{
		cli->timer_id = 0;
		zval *zobject = cli->object;
		client_callback *cb = zobject? swoole_get_property(zobject, swoole_property_common):NULL;
		if (cb && cb->onTimeout)
		{
			zval* callback = cb->onTimeout;
			zval* eventType = NULL;
			SW_MAKE_STD_ZVAL(eventType);
			ZVAL_LONG(eventType,timer_type);
			zval **args[2];
			args[0] = &zobject;
			args[1] = &eventType;
			zval *retval = NULL;
			if (sw_call_user_function_ex(EG(function_table), NULL,callback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
			{
				swWarn("timeout event handler error.");
			}

			if (EG(exception))
			{
				zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
			}

			if (retval) sw_zval_ptr_dtor(&retval);
			if (eventType) sw_zval_ptr_dtor(&eventType);
		}
	}

	swTimer_del(timer,node->id);
}

static void client_onConnect(swClient *cli)
{
	if (cli && cli->timer_id > 0)
	{
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
	}

	if (cli->object)
	{
		client_execute_callback(cli, SW_CLIENT_CALLBACK_onConnect);
	}
}

static void client_onClose(swClient *cli)
{
    if (cli && cli->timer_id > 0)
	{
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
	}

    if (cli->released)
    {
    		return;
    }

    cli->released = 1;
    zval *zobject = cli->object;
    if (zobject){
		client_execute_callback(cli, SW_CLIENT_CALLBACK_onClose);

		client_free_callback(zobject);
		if (cli->object)
		{
			zval* obj = cli->object;
			cli->object = NULL;
			sw_zval_ptr_dtor(&obj);
		}
    }
}

static void client_onError(swClient *cli)
{
    SWOOLE_FETCH_TSRMLS;
    if (cli && cli->timer_id > 0)
	{
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
	}

    if (cli->released)
	{
		return;
	}

    zval *zobject = cli->object;
    cli->released = 1;
    if (zobject){
		zend_update_property_long(swoole_client_class_entry_ptr, zobject, ZEND_STRL("errCode"), SwooleG.error TSRMLS_CC);
		client_execute_callback(cli, SW_CLIENT_CALLBACK_onError);

		client_free_callback(zobject);
		if (cli->object)
		{
			zval* obj = cli->object;
			cli->object = NULL;
			sw_zval_ptr_dtor(&obj);
		}
	}
}

static int client_onPackage(swConnection *conn, char *data, uint32_t length)
{
    client_onReceive(conn->object, data, length);
    return SW_OK;
}

static void client_onReceive(swClient *cli, char *data, uint32_t length)
{
    SWOOLE_FETCH_TSRMLS;
    if (cli && cli->timer_id > 0)
	{
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
	}

    zval *zobject = cli? cli->object:NULL;
    if (!zobject)
    {
    	   return ;
    }

    zval *zcallback = NULL;
    zval **args[2];
    zval *retval = NULL;

    zval *zdata = NULL;
    SW_MAKE_STD_ZVAL(zdata);
    SW_ZVAL_STRINGL(zdata, data, length, 1);
    sw_zval_add_ref(&zobject);

    args[0] = &zobject;
    args[1] = &zdata;

    client_callback *cb = swoole_get_property(zobject, swoole_property_common);
	zcallback = (!cb)? NULL:cb->onReceive;

    if (zcallback &&
    		sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
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

    if (zdata) {
        sw_zval_ptr_dtor(&zdata);
    }

    sw_zval_ptr_dtor(&zobject);
}

static void client_free_callback(zval* object)
{
	client_callback *cb = swoole_get_property(object, swoole_property_common);
    if (cb && cb->onConnect)  {sw_zval_ptr_dtor(&cb->onConnect);cb->onConnect = NULL;}

    if (cb && cb->onReceive) {sw_zval_free(cb->onReceive);cb->onReceive = NULL;}

    if (cb && cb->onError) {sw_zval_ptr_dtor(&cb->onError);cb->onError = NULL;}

    if (cb && cb->onClose) {sw_zval_ptr_dtor(&cb->onClose);cb->onClose = NULL;}

    if (cb && cb->onTimeout) {sw_zval_free(cb->onTimeout);cb->onTimeout = NULL;}
}

void swoole_client_init(int module_number TSRMLS_DC)
{
	if (swoole_client_ce_inited){
		return ;
	}

	swoole_client_ce_inited = 1;

    SWOOLE_INIT_CLASS_ENTRY(swoole_client_ce, "swoole_client", "Swoole\\Client", swoole_client_methods);
    swoole_client_class_entry_ptr = zend_register_internal_class(&swoole_client_ce TSRMLS_CC);

    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sock")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
//    zend_declare_property_bool(swoole_client_class_entry_ptr, SW_STRL("reuse")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_client_class_entry_ptr, SW_STRL("internal_user")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("connectTimeout")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_client_class_entry_ptr, SW_STRL("sendTimeout")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_client_class_entry_ptr,ZEND_STRL("type"),ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_client_class_entry_ptr,ZEND_STRL("id"),ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_client_class_entry_ptr,ZEND_STRL("setting"),ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_OOB"), MSG_OOB TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_PEEK"), MSG_PEEK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_DONTWAIT"), MSG_DONTWAIT TSRMLS_CC);
    zend_declare_class_constant_long(swoole_client_class_entry_ptr, ZEND_STRL("MSG_WAITALL"), MSG_WAITALL TSRMLS_CC);
}

static int client_select_wait(zval *sock_array, fd_set *fds TSRMLS_DC)
{
    zval *element = NULL;
    zval *zsock = NULL;
    zend_class_entry *ce;

    ulong_t num = 0;
    if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
    {
        return 0;
    }

#if PHP_MAJOR_VERSION < 7
    HashTable *new_hash;
    char *key = NULL;
    zval **dest_element;
    uint32_t key_len;

    ALLOC_HASHTABLE(new_hash);
    zend_hash_init(new_hash, zend_hash_num_elements(Z_ARRVAL_P(sock_array)), NULL, ZVAL_PTR_DTOR, 0);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
        if (Z_TYPE_P(element) != IS_OBJECT)
        {
            swWarn("object is not swoole_client object[1].");
            continue;
        }
        ce = Z_OBJCE_P(element);
        zsock = sw_zend_read_property(ce, element, SW_STRL("sock")-1, 0 TSRMLS_CC);
        if (zsock == NULL || ZVAL_IS_NULL(zsock))
        {
            swWarn("object is not swoole_client object[2].");
            continue;
        }
        if ((Z_LVAL(*zsock) < FD_SETSIZE) && FD_ISSET(Z_LVAL(*zsock), fds))
        {
            switch (sw_zend_hash_get_current_key(Z_ARRVAL_P(sock_array), &key, &key_len, &num))
            {
            case HASH_KEY_IS_STRING:
                sw_zend_hash_add(new_hash, key, key_len, (void * ) &element, sizeof(zval *), (void ** )&dest_element);
                break;
            case HASH_KEY_IS_LONG:
                sw_zend_hash_index_update(new_hash, num, (void * ) &element, sizeof(zval *), (void ** )&dest_element);
                break;
            }
            if (dest_element)
            {
                sw_zval_add_ref(dest_element);
            }
        }
        num ++;
    SW_HASHTABLE_FOREACH_END();

    zend_hash_destroy(Z_ARRVAL_P(sock_array));
    swoole_efree(Z_ARRVAL_P(sock_array));

    zend_hash_internal_pointer_reset(new_hash);
    Z_ARRVAL_P(sock_array) = new_hash;
#else
    zval new_array;
    array_init(&new_array);
    zend_ulong num_key;
    zend_string *key;
    zval *dest_element;

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(sock_array), num_key, key, element)
    {
        if (Z_TYPE_P(element) != IS_OBJECT)
        {
            swWarn("object is not swoole_client object[1].");
            continue;
        }
        ce = Z_OBJCE_P(element);
        zsock = sw_zend_read_property(ce, element, SW_STRL("sock")-1, 0 TSRMLS_CC);
        if (zsock == NULL || ZVAL_IS_NULL(zsock))
        {
            swWarn("object is not swoole_client object[2].");
            continue;
        }

        if ((Z_LVAL(*zsock) < FD_SETSIZE) && FD_ISSET(Z_LVAL(*zsock), fds))
        {
            if (key)
            {
                dest_element = zend_hash_add(Z_ARRVAL(new_array), key, element);
            }
            else
            {
                dest_element = zend_hash_index_update(Z_ARRVAL(new_array), num_key, element);
            }
            if (dest_element)
            {
                Z_ADDREF_P(dest_element);
            }
        }
        num++;
    } ZEND_HASH_FOREACH_END();

    zval_ptr_dtor(sock_array);
    ZVAL_COPY_VALUE(sock_array, &new_array);
#endif
    return num ? 1 : 0;
}

static int client_select_add(zval *sock_array, fd_set *fds, int *max_fd TSRMLS_DC)
{
    zval *element = NULL;
    zval *zsock;
    zend_class_entry *ce;

    if (SW_Z_TYPE_P(sock_array) != IS_ARRAY)
    {
        return 0;
    }

    int num = 0;
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(sock_array), element)
        if (Z_TYPE_P(element) != IS_OBJECT)
        {
            swWarn("object is not swoole_client object[1].");
            continue;
        }
        ce = Z_OBJCE_P(element);
        zsock = sw_zend_read_property(ce, element, SW_STRL("sock")-1, 0 TSRMLS_CC);
        if (zsock == NULL || ZVAL_IS_NULL(zsock))
        {
            swWarn("object is not swoole_client object[2].");
            continue;
        }
        if (Z_LVAL(*zsock) < FD_SETSIZE)
        {
            FD_SET(Z_LVAL(*zsock), fds);
        }
        else
        {
            swWarn("socket[%ld] > FD_SETSIZE[%d].", Z_LVAL(*zsock), FD_SETSIZE);
            continue;
        }
        if (Z_LVAL(*zsock) > *max_fd)
        {
            *max_fd = Z_LVAL(*zsock);
        }
        num ++;
    SW_HASHTABLE_FOREACH_END();
    return num ? 1 : 0;
}

static void client_check_setting(swClient *cli, zval *zset TSRMLS_DC)
{
    zval *valuePtr = NULL;
    int value = 1;

    char *bind_address = NULL;
    int bind_port = 0;

    HashTable *vht = Z_ARRVAL_P(zset);

    //buffer: check eof
    if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_split"), (void **) &valuePtr) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("open_eof_check"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_boolean(valuePtr);
        cli->open_eof_check = Z_BVAL_P(valuePtr);
        cli->protocol.split_by_eof = 1;
    }
    //package eof
    if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &valuePtr) == SUCCESS)
    {
		if (sw_convert_to_string(valuePtr) < 0)
		{
			swWarn("convert to string failed.");
			return;
		}
        cli->protocol.package_eof_len = Z_STRLEN_P(valuePtr);
        if (cli->protocol.package_eof_len <= SW_DATA_EOF_MAXLEN)
        {
        	bzero(cli->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        	memcpy(cli->protocol.package_eof, Z_STRVAL_P(valuePtr), Z_STRLEN_P(valuePtr));
        	cli->protocol.onPackage = client_onPackage;
        }

    }
    //open length check
    if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_boolean(valuePtr);
        cli->open_length_check = Z_BVAL_P(valuePtr);
        cli->protocol.get_package_length = swProtocol_get_package_length;
        cli->protocol.onPackage = client_onPackage;
    }
    //package length size
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **) &valuePtr) == SUCCESS)
    {
        if (sw_convert_to_string(valuePtr) < 0)
		{
			swWarn("convert to string failed.");
			return;
		}

        cli->protocol.package_length_type = Z_STRVAL_P(valuePtr)[0];
        cli->protocol.package_length_size = swoole_type_size(cli->protocol.package_length_type);

        if (cli->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "Unknown package_length_type name '%c', see pack(). Link: http://php.net/pack", cli->protocol.package_length_type);
            return;
        }
    }
    //package length offset
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_long(valuePtr);
        cli->protocol.package_length_offset = (int) Z_LVAL_P(valuePtr);
    }
    //package body start
    if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_long(valuePtr);
        cli->protocol.package_body_offset = (int) Z_LVAL_P(valuePtr);
    }
    /**
     * package max length
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_long(valuePtr);
        cli->protocol.package_max_length = (int) Z_LVAL_P(valuePtr);
    }
    else
    {
        cli->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;
    }
    /**
     * socket send/recv buffer size
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("socket_buffer_size"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_long(valuePtr);
        value = (int) Z_LVAL_P(valuePtr);
        value = (value <= 0 || value > SW_MAX_INT)? SW_MAX_INT:value;
        swSocket_set_buffer_size(cli->socket->fd, value);
        cli->socket->buffer_size = cli->buffer_input_size = value;
    }
    /**
     * bind address
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("bind_address"), (void **) &valuePtr) == SUCCESS)
    {
		if (sw_convert_to_string(valuePtr) < 0)
		{
			swWarn("convert to string failed.");
			return;
		}

        bind_address = Z_STRVAL_P(valuePtr);
    }
    /**
     * bind port
     */
    if (sw_zend_hash_find(vht, ZEND_STRS("bind_port"), (void **) &valuePtr) == SUCCESS)
    {
        convert_to_long(valuePtr);
        bind_port = (int) Z_LVAL_P(valuePtr);
    }
    if (bind_address)
    {
        swSocket_bind(cli->socket->fd, cli->type, bind_address, bind_port);
    }
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
    	if (sw_convert_to_string(valuePtr) < 0)
		{
			swWarn("convert to string failed.");
			return;
		}

        cli->ssl_cert_file = strdup(Z_STRVAL_P(valuePtr));
        if (access(cli->ssl_cert_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", cli->ssl_cert_file);
            return;
        }
        cli->open_ssl = 1;
    }
    if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &valuePtr) == SUCCESS)
    {
    	if (sw_convert_to_string(valuePtr) < 0)
		{
			swWarn("convert to string failed.");
			return;
		}

        cli->ssl_key_file = strdup(Z_STRVAL_P(valuePtr));
        if (access(cli->ssl_key_file, R_OK) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", cli->ssl_key_file);
            return;
        }
    }
    if (cli->ssl_cert_file && !cli->ssl_key_file)
    {
        swoole_php_fatal_error(E_ERROR, "ssl require key file.");
        return;
    }
#endif
}

void php_swoole_at_shutdown(char *function)
{
    SWOOLE_FETCH_TSRMLS;

#if PHP_MAJOR_VERSION >=7
    php_shutdown_function_entry shutdown_function_entry;
    shutdown_function_entry.arg_count = 1;
    shutdown_function_entry.arguments = (zval *) safe_emalloc(sizeof(zval), 1, 0);
    ZVAL_STRING(&shutdown_function_entry.arguments[0], function);

    if (!register_user_shutdown_function(function, strlen(function), &shutdown_function_entry TSRMLS_CC))
    {
        zval_ptr_dtor(&shutdown_function_entry.arguments[0]);
        swoole_efree(shutdown_function_entry.arguments);
        swWarn("Unable to register shutdown function [%s]",function);
    }
#else

    zval *callback = NULL;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback, function, 1);

#if PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4

    php_shutdown_function_entry shutdown_function_entry;

    shutdown_function_entry.arg_count = 1;
    shutdown_function_entry.arguments = (zval **) safe_emalloc(sizeof(zval *), 1, 0);

    shutdown_function_entry.arguments[0] = callback;

    if (!register_user_shutdown_function(function, strlen(function), &shutdown_function_entry TSRMLS_CC))
    {
        swoole_efree(shutdown_function_entry.arguments);
        sw_zval_ptr_dtor(&callback);
        swWarn("Unable to register shutdown function [%s]",function);
    }
#else
    zval *register_shutdown_function = NULL;
    SW_MAKE_STD_ZVAL(register_shutdown_function);
    SW_ZVAL_STRING(register_shutdown_function, "register_shutdown_function", 1);
    zval **args[1] = {&callback};

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, register_shutdown_function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swWarn("Unable to register shutdown function [%s]",function);
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
    	sw_zval_ptr_dtor(&retval);
    }

#endif

#endif
}

void php_swoole_check_reactor()
{
    if (SwooleWG.reactor_init)
    {
        return;
    }

    SWOOLE_FETCH_TSRMLS;

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "async-io must use in cli environment.");
        return;
    }

    if (swIsTaskWorker())
    {
        swoole_php_fatal_error(E_ERROR, "cannot use async-io in task process.");
        return;
    }

    if (SwooleG.main_reactor == NULL)
    {
        swTrace("init reactor");

        SwooleG.main_reactor = sw_malloc(sizeof(swReactor));
        if (swReactor_init(SwooleG.main_reactor, SW_REACTOR_MAXEVENTS) < 0)
        {
            swoole_php_fatal_error(E_ERROR, "create reactor failed.");
            return;
        }

        //client, swoole_event_exit will set swoole_running = 0
        SwooleWG.in_client = 1;
        SwooleWG.reactor_wait_onexit = 1;
        SwooleWG.reactor_ready = 0;
    }

    //only client side
    php_swoole_at_shutdown("swoole_event_wait");
    php_swoole_event_init();
    SwooleWG.reactor_init = 1;
}

void swoole_thread_clean()
{
	/// 释放async io线程资源
	swAio_free();
}

void php_swoole_client_free(zval *object, swClient *cli TSRMLS_DC)
{
	//unset object
	if (object)
	{
		swoole_set_object(object, NULL);
	}

	if (cli && cli->timer_id > 0)
	{
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
	}

    if (cli)
    {
        swoole_efree(cli->server_str);
        swClient_free(cli);
        swoole_efree(cli);
    }
}

swClient* php_swoole_client_new(zval *object, char *host, int host_len, int port,swClient** client)
{

    SWOOLE_FETCH_TSRMLS;

    zval *ztype = sw_zend_read_property(swoole_client_class_entry_ptr, object, SW_STRL("type")-1, 0 TSRMLS_CC);
    if (!ztype || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get swoole_client->type failed.");
        return NULL;
    }

    long type_tmp = Z_LVAL_P(ztype);
    int packet_mode = (type_tmp & SW_MODE_PACKET) >> 4;
    long type = type_tmp & (~SW_MODE_PACKET);

    //new flag, swoole-1.6.12+
    int async = (type & SW_FLAG_ASYNC)? 1: 0;

    char conn_key[SW_LONG_CONNECTION_KEY_LEN] = {0};
    int conn_key_len = 0;
    bzero(conn_key, SW_LONG_CONNECTION_KEY_LEN);

    zval *connection_id = sw_zend_read_property(swoole_client_class_entry_ptr, object, ZEND_STRL("id"), 1 TSRMLS_CC);
    conn_key_len = (!connection_id || ZVAL_IS_NULL(connection_id))?
    		snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN - 1, "%s:%d", host, port) + 1:
    		snprintf(conn_key, SW_LONG_CONNECTION_KEY_LEN - 1, "%s", Z_STRVAL_P(connection_id)) + 1;

    swClient* cli = NULL;
    if (*client)
    {
    	cli = *client;
    	goto create_client;
    }
    else
    {
    	cli = (swClient*) emalloc(sizeof(swClient));
    	/// 新分配的结构，必须要用bzero 处理，否则会出现问题（cli 中的内容是随机的）
    	bzero(cli,sizeof(swClient));
    	*client = cli;
    }

create_client:
	if (swClient_create(cli, php_swoole_socktype(type), async) < 0) {
		swWarn("swClient_create() failed.");
		zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("errCode"), errno TSRMLS_CC);
		return NULL;
	}

	//don't forget free it
	if (!cli->server_str)
	{
		cli->server_str = estrndup(conn_key,conn_key_len);
		cli->server_strlen = conn_key_len;
	}

	zend_update_property_long(swoole_client_class_entry_ptr, object, ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

#ifdef SW_USE_OPENSSL
	cli->open_ssl = (type & SW_SOCK_SSL)? 1:0;
#endif

	cli->packet_mode = (packet_mode == 1)? 1: 0;
    return cli;
}

static PHP_METHOD(swoole_client, __construct)
{
    long async = SW_SOCK_SYNC;
    zval *ztype;
    char *id = NULL;
    zend_size_t len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|ls", &ztype, &async, &id, &len))
    {
        swoole_php_fatal_error(E_ERROR, "require socket type param.");
        RETURN_FALSE;
    }

#if PHP_MEMORY_DEBUG
    php_vmstat.new_client++;
#endif

    Z_LVAL_P(ztype) = (async == SW_SOCK_ASYNC)? (Z_LVAL_P(ztype) | SW_FLAG_ASYNC) : Z_LVAL_P(ztype);
    int client_type = php_swoole_socktype(Z_LVAL_P(ztype));
	if (client_type < SW_SOCK_TCP || client_type > SW_SOCK_UNIX_STREAM)
	{
		swoole_php_fatal_error(E_ERROR, "Unknown client type '%d'.", client_type);
		RETURN_FALSE;
	}

    if ((Z_LVAL_P(ztype) & SW_FLAG_ASYNC))
    {
        php_swoole_check_reactor();
    }

    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("type"), ztype TSRMLS_CC);

    if (id)
    {
        zend_update_property_stringl(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("id"), id, len TSRMLS_CC);
    }
    else
    {
        zend_update_property_null(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("id") TSRMLS_CC);
    }

    //init
    swoole_set_object(getThis(), NULL);
    swoole_set_property(getThis(),swoole_property_socket,NULL);

    client_callback *cb = emalloc(sizeof(client_callback));
	bzero(cb, sizeof(client_callback));
	swoole_set_property(getThis(), swoole_property_common, cb);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, __destruct)
{
    swClient *cli = swoole_get_object(getThis());
    //no keep connection
    if (cli)
    {
    	cli->object = NULL;
        php_swoole_client_free(getThis(), cli TSRMLS_CC);
    }

    releaseConnobj(getThis());

#ifdef SW_USE_SOCKETS
    zval *zsocket = swoole_get_property(getThis(), swoole_property_socket);
    if (zsocket)
    {
        sw_zval_free(zsocket);
        swoole_set_property(getThis(), swoole_property_socket, NULL);
    }
#endif

#if PHP_MEMORY_DEBUG
    php_vmstat.free_client++;
    if (php_vmstat.free_client % 10000 == 0)
    {
        printf("php_vmstat.free_client=%d\n", php_vmstat.free_client);
    }
#endif

    //free callback function
    client_callback *cb = swoole_get_property(getThis(), swoole_property_common);
	client_free_callback(getThis());
	swoole_efree(cb);
	swoole_set_property(getThis(), swoole_property_common, NULL);
}

static PHP_METHOD(swoole_client, set)
{
    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset))
    {
        return;
    }

    php_swoole_array_separate(zset);
    zend_update_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
    sw_zval_ptr_dtor(&zset);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client,setConnectTimeout)
{
	long timeout = 0;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
	{
		swWarn("parse parameters error.");
		RETURN_FALSE;
	}

	zend_update_property_long(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), timeout TSRMLS_CC);
	RETURN_TRUE;
}

static PHP_METHOD(swoole_client,setSendTimeout)
{
	long timeout = 0;
	if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
	{
		swWarn("parse parameters error.");
		RETURN_FALSE;
	}

	zend_update_property_long(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("sendTimeout"), timeout TSRMLS_CC);
	RETURN_TRUE;
}

static PHP_METHOD(swoole_client, connect)
{
	swClient *cli = swoole_get_object(getThis());
	if (cli && cli->socket && cli->socket->active)
	{
		RETURN_TRUE;
	}

	if (cli && cli->released)
	{
		RETURN_FALSE;
	}

	if (cli && cli->socket)
	{
		RETURN_FALSE;
	}

	zval *internal_user = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
	if (internal_user && Z_BVAL_P(internal_user))
	{
		RETURN_FALSE;
	}

    long port = 0, sock_flag = 0;
    char *host = NULL;
    zend_size_t host_len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|l", &host, &host_len, &port, &sock_flag))
    {
		swWarn("parse parameters error.");
		RETURN_FALSE;
    }

    if (!host || host_len <= 0)
    {
        swWarn("The host is empty.");
        RETURN_FALSE;
    }

    /// 取消定时器
    if (cli && cli->timer_id > 0)
    {
		long timer_id = cli->timer_id;
		cli->timer_id = 0;
		swTimer_del(&SwooleG.timer,timer_id);
    }

    cli = php_swoole_client_new(getThis(), host, host_len, port,&cli);
    if (!cli)
    {
		swWarn("create swClient failed.");
		RETURN_FALSE;
    }

    if (swSocket_is_tcpStream(cli->type) && (port <= 0 || port > SW_CLIENT_MAX_PORT))
	{
		swWarn("The port is invalid.");
		RETURN_FALSE;
	}

    /// for tcp: is async
    /// for udp: wether use connect.
    if (swSocket_is_tcpStream(cli->type) && cli->async)
    {
    		sock_flag = 1;
    }

//    sock_flag = (swSocket_is_tcpStream(cli->type) || cli->async)? cli->async:sock_flag;

    zval *zset = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zset && !ZVAL_IS_NULL(zset))
    {
        client_check_setting(cli, zset TSRMLS_CC);
    }

    /// 异步时关联了 zval object对象实例
    if (cli->async)
    {
        client_callback *cb = swoole_get_property(getThis(), swoole_property_common);
        if (swSocket_is_stream(cli->type))
        {
        	    if (!cb || !cb->onConnect || !cb->onClose)
			{
				swWarn("no receive or connect or close callback.");
				RETURN_FALSE;
			}

			cli->onReceive = client_onReceive;
			cli->onConnect = client_onConnect;
			cli->onClose = client_onClose;
            cli->onError = client_onError;
        }
        else
        {
           	if (!cb || !cb->onReceive)
			{
				swWarn("no receive or connect or close callback.");
				RETURN_FALSE;
			}

            if (cb->onConnect)
            {
                cli->onConnect = client_onConnect;
            }
            if (cb->onClose)
            {
                cli->onClose = client_onClose;
            }
            cli->onReceive = client_onReceive;
            cli->reactor_fdtype = PHP_SWOOLE_FD_DGRAM_CLIENT;
        }

        cli->reactor_fdtype = swSocket_is_stream(cli->type)? PHP_SWOOLE_FD_STREAM_CLIENT:PHP_SWOOLE_FD_DGRAM_CLIENT;
        if (!cli->object)
		{
			zval *obj = getThis();
			cli->object = obj;
			sw_zval_add_ref(&obj);
			sw_copy_to_stack(cli->object,cb->_object);
		}
    }

	swoole_set_object(getThis(), cli);

	long timeout = 0;
	zval* connectTimeout = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), 1 TSRMLS_CC);
	if (connectTimeout)
	{
		convert_to_long(connectTimeout);
		timeout = Z_LVAL_P(connectTimeout);
	}

    if (cli->connect(cli, host, port, timeout/1000.0,sock_flag) < 0)
    {
    	if (!cli->async && EINPROGRESS == errno)
		{
			RETURN_TRUE;
		}

        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, errno TSRMLS_CC);
        swWarn("connect to server[%s:%d] failed.", host, (int )port);
        RETURN_FALSE;
    }

    if (cli->async && swSocket_is_stream(cli->type) && timeout > 0)
	{
    		cli->timer_id = 0;
		cli->timer_id = swTimer_add(&SwooleG.timer,timeout,0,cli,TCPCLIENT_USED);
		if (cli->timer_id <= 0)
		{
			swWarn("set connect time out timer failed.");
			RETURN_FALSE;
		}

		cli->timeout_type = SW_CLIENT_CONNECT_TIMEOUT;
		register_after_cb(&SwooleG.timer,TCPCLIENT_USED,tcpClient_timeout);
	}

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, send)
{
	swClient *cli = swoole_get_object(getThis());
	if (!cli || !cli->socket || cli->released)
	{
		RETURN_FALSE;
	}

	if (!cli->socket->active)
	{
		swWarn("socket[%d] is not active",cli->socket->fd);
		RETURN_FALSE;
	}

	char *data = NULL;
    zend_size_t data_len = 0;
    long flags = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &data, &data_len, &flags))
    {
    		RETURN_FALSE;
    }

    if (!data || data_len <= 0)
    {
        swWarn("data is empty or data len < 0.");
        RETURN_FALSE;
    }

    //clear errno
    int ret = 0;
    SwooleG.error = 0;
    if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = htonl(data_len);
        if (cli->send(cli, (char *) &len_tmp,sizeof(uint32_t), flags) < 0)
        {
            goto send_error;
        }
    }

    ret = cli->send(cli, data, data_len, flags);
    if (ret < 0)
    {
send_error:
        SwooleG.error = errno;
        swSysError("client(%d) send %d bytes failed.", cli->socket->fd, data_len);
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }
    else if (cli->async && swSocket_is_stream(cli->type))
    {
    	if (cli->timer_id > 0)
    	{
    		long timer_id = cli->timer_id;
    		cli->timer_id = 0;
    		swTimer_del(&SwooleG.timer,timer_id);
    	}

		long timeout = 0;
		zval* sendTimeout = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("sendTimeout"), 1 TSRMLS_CC);
		if (sendTimeout)
		{
			convert_to_long(sendTimeout);
			timeout = Z_LVAL_P(sendTimeout);
		}

		timeout = timeout <= 0? 0:timeout;
		if (timeout > 0)
		{
			cli->timer_id = swTimer_add(&SwooleG.timer,timeout,0,cli,TCPCLIENT_USED);
			if (cli->timer_id <= 0)
			{
				swWarn("set recv msg time out timer failed.");
				RETURN_FALSE;
			}

			cli->timeout_type = SW_CLIENT_RECV_TIMEOUT;
			register_after_cb(&SwooleG.timer,TCPCLIENT_USED,tcpClient_timeout);
		}

		if (ret > 0)
		{
			RETURN_LONG(ret);
		}

		RETURN_TRUE;
    }

    RETURN_LONG(ret);
}

static PHP_METHOD(swoole_client, sendto)
{
    char* ip = NULL;
    zend_size_t ip_len = 0;
    zend_size_t port = 0;

    char *data = NULL;
    zend_size_t len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls", &ip, &ip_len, &port, &data, &len))
    {
    	RETURN_FALSE;
    }

    if (!data || len <= 0)
    {
        swWarn("data is empty.");
        RETURN_FALSE;
    }

    swClient *cli = swoole_get_object(getThis());
    if (!cli)
    {
    		cli = php_swoole_client_new(getThis(), ip, ip_len, port,&cli);
		if (cli == NULL)
		{
			RETURN_FALSE;
		}

		cli->socket->active = 1;
		swoole_set_object(getThis(), cli);
    }

    if (!cli || !cli->socket || cli->released)
    {
		swWarn("swoole_client_sendto cli or socket is null or cli is released.\n");
		RETURN_FALSE;
    }

    if (!swSocket_is_udpDgram(cli->type))
    {
		swWarn("only support udp dgram.");
		RETURN_FALSE;
    }

    int ret = (cli->type == SW_SOCK_UDP)?
    		swSocket_udp_sendto(cli->socket->fd, ip, port, data, len):
    		swSocket_udp_sendto6(cli->socket->fd, ip, port, data, len);

    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, sendfile)
{
	swClient *cli = swoole_get_object(getThis());
	if (!cli || !cli->socket || !cli->socket->active || cli->released)
	{
		swNotice("socekt is not active.");
		RETURN_FALSE;
	}

    char *file = NULL;
    zend_size_t file_len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &file, &file_len))
    {
    	RETURN_FALSE;
    }

    if (!file || file_len <= 0)
    {
        swWarn("file is empty or filename is null.");
        RETURN_FALSE;
    }

    if (!swSocket_is_stream(cli->type))
    {
        swWarn("dgram socket cannot use sendfile.");
        RETURN_FALSE;
    }

    //clear errno
    SwooleG.error = 0;
    if (cli->sendfile(cli, file) < 0)
    {
        SwooleG.error = errno;
        swSysError("sendfile() failed.");
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        RETVAL_FALSE;
    }

    RETVAL_TRUE;
}

static PHP_METHOD(swoole_client, recv)
{
    long buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    long flags = 0;
    char *buf = NULL;
    char stack_buf[SW_BUFFER_SIZE_BIG] = {0};

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &buf_len, &flags))
    {
        return;
    }

    //waitall
    flags = (1 == flags)? MSG_WAITALL:flags;
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket || !cli->socket->active)
    {
        swWarn("object(client or socket) is not instance or socket is not active.");
        RETURN_FALSE;
    }

    if ((flags & MSG_WAITALL) && buf_len > SW_PHP_CLIENT_BUFFER_SIZE)
    {
        buf_len = SW_PHP_CLIENT_BUFFER_SIZE;
    }

    swProtocol *protocol = &cli->protocol;
    int ret = -1;
    if (cli->open_eof_check)
    {
    	cli->buffer = (!cli->buffer)? swString_new(SW_BUFFER_SIZE_BIG) : cli->buffer;
        swString *buffer = cli->buffer;
        int eof = -1;
        while (1)
        {
            buf = buffer->str + buffer->length;
            buf_len = buffer->size - buffer->length;
            buf_len = (buf_len > SW_BUFFER_SIZE_BIG)? SW_BUFFER_SIZE_BIG:buf_len;

            ret = cli->recv(cli, buf, buf_len, 0);
            if (ret < 0)
            {
                swWarn("recv() failed. Error: %s [%d]", strerror(errno), errno);
                buffer->length = 0;
                RETURN_FALSE;
            }
            else if (ret == 0)
            {
                buffer->length = 0;
                RETURN_EMPTY_STRING();
            }

            buffer->length += ret;
            if (buffer->length < protocol->package_eof_len)
            {
                continue;
            }

            eof = swoole_strnpos(buffer->str, buffer->length, protocol->package_eof, protocol->package_eof_len);
            if (eof >= 0)
            {
                eof += protocol->package_eof_len;
                SW_RETVAL_STRINGL(buffer->str, eof, 1);
                buffer->length = (buffer->length > eof)? (buffer->length - eof):0;
                if (buffer->length > 0)
                {
                    memcpy(stack_buf, buffer->str + eof, buffer->length);
                    memcpy(buffer->str, stack_buf, buffer->length);
                }

                return;
            }
            else if (buffer->length == protocol->package_max_length)
            {
				swWarn("no package eof");
				buffer->length = 0;
				RETURN_FALSE;
            }
            else if (buffer->length == buffer->size && buffer->size < protocol->package_max_length)
			{
				int new_size = buffer->size * 2;
				new_size = (new_size > protocol->package_max_length)? protocol->package_max_length:new_size;
				if (swString_extend(buffer, new_size) < 0)
				{
					buffer->length = 0;
					RETURN_FALSE;
				}
			}
        }

        buffer->length = 0;
        RETURN_FALSE;
    }
    else if (cli->open_length_check)
    {
        uint32_t header_len = protocol->package_length_offset + protocol->package_length_size;
        ret = cli->recv(cli, stack_buf, header_len, MSG_WAITALL);
        if (ret <= 0)
        {
            goto check_return;
        }

        buf_len = swProtocol_get_package_length(protocol, cli->socket, stack_buf, ret);

        //error package
        if (buf_len < 0)
        {
        	RETURN_EMPTY_STRING();
        }
        //empty package
        else if (buf_len == header_len)
        {
            RETURN_EMPTY_STRING();
        }
        else if (buf_len > protocol->package_max_length)
        {
			swWarn("Package is too big. package_length=%ld", buf_len);
        	RETURN_EMPTY_STRING();
        }

        buf = emalloc(buf_len + 1);
        memcpy(buf, stack_buf, header_len);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf + header_len, buf_len - header_len, MSG_WAITALL);
        if (ret > 0)
        {
            ret += header_len;
        }
    }
    else if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = 0;
        ret = cli->recv(cli, (char*) &len_tmp, sizeof(uint32_t), MSG_WAITALL);
        if (ret < 0)
        {
			swSysError("recv() header failed.");
            RETURN_FALSE;
        }
        else
        {
        	buf_len = ntohl(len_tmp);
        }

        buf = emalloc(buf_len + 1);
        SwooleG.error = 0;
        //PACKET mode, must use waitall.
        ret = cli->recv(cli, buf, buf_len, MSG_WAITALL);
    }
    else
    {
        buf = emalloc(buf_len + 1);
        SwooleG.error = 0;
        ret = cli->recv(cli, buf, buf_len, flags);
    }

check_return:
    if (ret < 0)
    {
        SwooleG.error = errno;
        swSysError("recv() failed.");
        zend_update_property_long(swoole_client_class_entry_ptr, getThis(), SW_STRL("errCode")-1, SwooleG.error TSRMLS_CC);
        swoole_efree(buf);
        RETURN_FALSE;
    }
    else if (0 == ret)
    {
		swoole_efree(buf);
		RETURN_EMPTY_STRING();
    }
	else
	{
		buf[ret] = 0;
		SW_RETVAL_STRINGL(buf, ret, 0);
	}
}

static PHP_METHOD(swoole_client, isConnected)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket || cli->released)
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(cli->socket->active);
}

static PHP_METHOD(swoole_client, getsockname)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket || !cli->socket->active)
    {
        swWarn("object(client or socket) is not instance or socket is not active.");
        RETURN_FALSE;
    }

    if (!swSocket_is_tcpStream(cli->type) && !swSocket_is_udpDgram(cli->type))
    {
        swWarn("getsockname() only support AF_INET family socket.");
        RETURN_FALSE;
    }

    cli->socket->info.len = sizeof(cli->socket->info.addr);
    if (getsockname(cli->socket->fd, (struct sockaddr*) &cli->socket->info.addr, &cli->socket->info.len) < 0)
    {
        swWarn("getsockname() failed.");
        RETURN_FALSE;
    }

    array_init(return_value);
    char tmp[SW_IP_MAX_LENGTH] = {0};
    if (swConnection_get_ip(cli->socket,tmp,SW_IP_MAX_LENGTH) < 0)
    {
    	swWarn("get socket ip failed.");
    }
    else{
    	add_assoc_long(return_value, "port", swConnection_get_port(cli->socket));
    	sw_add_assoc_string(return_value, "host", tmp, 1);
    }
}

static PHP_METHOD(swoole_client, getSocket)
{
	zval *zsocket = swoole_get_property(getThis(), swoole_property_socket);
	if (zsocket)
	{
		RETURN_ZVAL(zsocket, 1, NULL);
	}

    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket)
    {
        swWarn("object(%s) is null.",cli? "swClient":"socket");
        RETURN_FALSE;
    }

#ifdef SW_USE_SOCKETS
    php_socket *socket_object = swoole_convert_to_socket(cli->socket->fd);
    if (!socket_object)
    {
        RETURN_FALSE;
    }

    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zsocket = sw_zval_dup(return_value);
	sw_zval_add_ref(&zsocket);
	swoole_set_property(getThis(), swoole_property_socket, zsocket);
	RETURN_ZVAL(return_value,1,NULL);
#else
	RETURN_FALSE;
#endif
}

static PHP_METHOD(swoole_client, getpeername)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket || !cli->socket->active)
	{
		swNotice("socket is not active.");
		RETURN_FALSE;
	}

    if (!swSocket_is_udpDgram(cli->type))
    {
		swWarn("only support udp dgram");
		RETURN_FALSE;
    }

    array_init(return_value);

    int type = AF_INET;
    void* addrPtr = NULL;
    if (cli->type == SW_SOCK_UDP)
    {
    	add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v4.sin_port));
    	addrPtr = (void*)((struct sockaddr*)(&cli->remote_addr.addr.inet_v4.sin_addr));
    }
    else if (cli->type == SW_SOCK_UDP6)
    {
        add_assoc_long(return_value, "port", ntohs(cli->remote_addr.addr.inet_v6.sin6_port));
        addrPtr = (void*)((struct sockaddr*)(&cli->remote_addr.addr.inet_v6.sin6_addr));
        type = AF_INET6;
    }

    char tmp[SW_IP_MAX_LENGTH] = {0};
	if (inet_ntop(type, addrPtr, tmp, sizeof(tmp)))
	{
		sw_add_assoc_string(return_value, "host", tmp, 1);
	}
	else
	{
		swWarn("inet_ntop() failed.");
	}
}

static PHP_METHOD(swoole_client, close)
{
	swClient *cli = swoole_get_object(getThis());
	if (!cli || !cli->socket)
	{
		RETURN_FALSE;
	}

	if (cli->released || cli->socket->closed)
	{
		swNotice("client socket is Closed.");
		RETURN_TRUE;
	}

	zval *internal_user = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
	if (internal_user && Z_BVAL_P(internal_user))
	{
		RETURN_TRUE;
	}

    zend_bool force = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &force))
    {
    		RETURN_FALSE;
    }

    if (cli->timer_id > 0)
    {
    	swTimer_del(&SwooleG.timer,cli->timer_id);
    	cli->timer_id = 0;
    }

    zval* obj = cli->object;
    cli->object = NULL;		///关闭连接,但不回调
    cli->close(cli);

    /// 手动调用回调
    if (obj)
    {
    	cli->released = 1;
        cli->object = obj;
		SwooleG.main_reactor->defer(SwooleG.main_reactor,defer_close,cli);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, on)
{
	zval *internal_user = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
	int disable_set = internal_user && Z_BVAL_P(internal_user);

    char *cb_name = NULL;
    zend_size_t cb_name_len = 0;
    zval *zcallback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback))
    {
        return;
    }

    if (!cb_name || cb_name_len <= 0)
    {
		swoole_php_fatal_error(E_ERROR,"parse callback name error.");
		return;
    }

	if (swoole_check_callable(zcallback TSRMLS_CC) < 0)
	{
		return ;
	}

    zval *ztype = sw_zend_read_property(swoole_client_class_entry_ptr, getThis(), SW_STRL("type")-1, 0 TSRMLS_CC);
    if (!ztype || ZVAL_IS_NULL(ztype))
    {
        swoole_php_fatal_error(E_ERROR, "get client type failed.");
        return;
    }

    if (!(Z_LVAL_P(ztype) & SW_FLAG_ASYNC))
    {
        swoole_php_fatal_error(E_ERROR, "sync-client cannot set event callback.");
        return;
    }

    client_callback *cb = swoole_get_property(getThis(), swoole_property_common);
    if (!cb)
    {
        cb = emalloc(sizeof(client_callback));
        bzero(cb, sizeof(client_callback));
        swoole_set_property(getThis(), swoole_property_common, cb);
    }

    if (cb_name_len == strlen("connect") && strncasecmp("connect", cb_name, cb_name_len) == 0)
    {
		if (disable_set)
		{
			swDebug("object created by connection pool,disable set connect event");
			RETURN_FALSE;
		}

    	    if (cb->onConnect) sw_zval_ptr_dtor(&cb->onConnect);
        cb->onConnect = zcallback;
        sw_copy_to_stack(cb->onConnect,cb->_onConnect);
    }
    else if (cb_name_len == strlen("receive") && strncasecmp("receive", cb_name, cb_name_len) == 0)
    {
        if (cb->onReceive) sw_zval_free(cb->onReceive);
        cb->onReceive = sw_zval_dup(zcallback);
    }
    else if (cb_name_len == strlen("close") && strncasecmp("close", cb_name, cb_name_len) == 0)
    {
       	if (disable_set)
		{
       		swDebug("object created by connection pool,disable set close event");
			RETURN_FALSE;
		}

        if (cb->onClose) sw_zval_ptr_dtor(&cb->onClose);
		cb->onClose = zcallback;
		sw_copy_to_stack(cb->onClose,cb->_onClose);
    }
    else if (cb_name_len == strlen("timeout") && strncasecmp("timeout",cb_name,cb_name_len) == 0)
	{
		if (cb->onTimeout) sw_zval_free(cb->onTimeout);
		cb->onTimeout = sw_zval_dup(zcallback);
	}
    else if (cb_name_len == strlen("error") && strncasecmp("error", cb_name, cb_name_len) == 0)
    {
    	if (disable_set)
		{
    		swDebug("object created by connection pool,disable set error event");
			RETURN_FALSE;
		}

        if (cb->onError) sw_zval_ptr_dtor(&cb->onError);
    	cb->onError = zcallback;
		sw_copy_to_stack(cb->onError,cb->_onError);
    }
    else
    {
        swWarn("Unknown event callback type name '%s'.", cb_name);
        RETURN_FALSE;
    }

    sw_zval_add_ref(&zcallback);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_client, sleep)
{
    swClient *cli = swoole_get_object(getThis());
    if (!cli || !cli->socket || !cli->socket->active || cli->released)
    {
        RETURN_FALSE;
    }

    int ret = (cli->socket->events & SW_EVENT_WRITE)?
    		SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_WRITE):
    		SwooleG.main_reactor->del(SwooleG.main_reactor, cli->socket->fd);

    SW_CHECK_RETURN(ret);
}

static PHP_METHOD(swoole_client, wakeup)
{
	swClient *cli = swoole_get_object(getThis());
	if (!cli || !cli->socket || !cli->socket->active || cli->released)
	{
		RETURN_FALSE;
	}

    int ret = (cli->socket->events & SW_EVENT_WRITE)?
    		SwooleG.main_reactor->set(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE):
    		SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, cli->socket->fdtype | SW_EVENT_READ);

    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_client_select)
{
    zval *r_array, *w_array, *e_array;
    r_array = w_array = e_array = NULL;
    fd_set rfds, wfds, efds;

    int max_fd = 0;
    int sets = 0;
    double timeout = SW_CLIENT_DEFAULT_TIMEOUT;
    struct timeval timeo;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a!a!a!|d", &r_array, &w_array, &e_array, &timeout))
    {
        return;
    }

    if (!r_array && !w_array && !e_array){
    	swoole_php_fatal_error(E_ERROR,"read/write/error array is null.");
    	return ;
    }

    /// todo 替换成reactor接口的模式
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);

    if (r_array != NULL) sets += client_select_add(r_array, &rfds, &max_fd TSRMLS_CC);
    if (w_array != NULL) sets += client_select_add(w_array, &wfds, &max_fd TSRMLS_CC);
    if (e_array != NULL) sets += client_select_add(e_array, &efds, &max_fd TSRMLS_CC);

    if (!sets)
    {
        swWarn("no resource arrays were passed to select");
        RETURN_FALSE;
    }

    if (max_fd >= FD_SETSIZE)
    {
        swWarn("select max_fd > FD_SETSIZE[%d]", FD_SETSIZE);
        RETURN_FALSE;
    }

    timeo.tv_sec = (int) timeout;
    timeo.tv_usec = (int) ((timeout - timeo.tv_sec) * 1000 * 1000);

    int retval = select(max_fd + 1, &rfds, &wfds, &efds, &timeo);
    if (retval < 0)
    {
        swSysError("unable to select.");
        RETURN_FALSE;
    }

    if (r_array != NULL)
    {
        client_select_wait(r_array, &rfds TSRMLS_CC);
    }
    if (w_array != NULL)
    {
        client_select_wait(w_array, &wfds TSRMLS_CC);
    }
    if (e_array != NULL)
    {
        client_select_wait(e_array, &efds TSRMLS_CC);
    }

    RETURN_LONG(retval);
}
