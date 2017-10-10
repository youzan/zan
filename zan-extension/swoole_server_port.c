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
#include "swBaseOperator.h"
#include "zanGlobalVar.h"
#include "zanLog.h"

static char *callback[PHP_SERVER_PORT_CALLBACK_NUM] = {
        "Connect",
        "Receive",
        "Close",
        "Packet",
};

zend_class_entry swoole_server_port_ce;
zend_class_entry *swoole_server_port_class_entry_ptr;

static PHP_METHOD(swoole_server_port, __construct);
static PHP_METHOD(swoole_server_port, __destruct);
static PHP_METHOD(swoole_server_port, on);
static PHP_METHOD(swoole_server_port, set);

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_port_set, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, set, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_port_on, 0, 0, 2)
    ZEND_ARG_INFO(0, name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()
const zend_function_entry swoole_server_port_methods[] =
{
    PHP_ME(swoole_server_port, __construct,     arginfo_swoole_void, ZEND_ACC_PRIVATE | ZEND_ACC_CTOR)
    PHP_ME(swoole_server_port, __destruct,      arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_server_port, set,             arginfo_swoole_server_port_set, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server_port, on,              arginfo_swoole_server_port_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

void swoole_server_port_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_server_port_ce, "swoole_server_port", "Swoole\\Server\\Port", swoole_server_port_methods);
    swoole_server_port_class_entry_ptr = zend_register_internal_class(&swoole_server_port_ce TSRMLS_CC);

    zend_declare_property_null(swoole_server_port_class_entry_ptr,ZEND_STRL("setting"),ZEND_ACC_PUBLIC TSRMLS_CC);

    char property_name[128] = {0};
    memcpy(property_name, "on", 2);
    int index = 0;
    for (index = 0; index < PHP_SERVER_PORT_CALLBACK_NUM; index++)
    {
        int l_property_name = 2;
        int callbackLen = strlen(callback[index]);
        memcpy(property_name + l_property_name, callback[index],callbackLen);
        l_property_name += callbackLen;
        property_name[l_property_name] = '\0';
        zend_declare_property_null(swoole_server_port_class_entry_ptr,property_name,l_property_name,ZEND_ACC_PUBLIC TSRMLS_CC);
    }
}

static PHP_METHOD(swoole_server_port, __construct)
{
    swoole_php_fatal_error(E_ERROR, "Please use the swoole_server->listen method.");
    return;
}

static PHP_METHOD(swoole_server_port, __destruct)
{
    swoole_server_port_property *property = swoole_get_property(getThis(), swoole_property_common);
    swoole_efree(property);
    swoole_set_property(getThis(), swoole_property_common, NULL);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_server_port, set)
{
    swListenPort *port = swoole_get_object(getThis());
    swoole_server_port_property *property = swoole_get_property(getThis(), swoole_property_common);
    if (port == NULL || property == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Please use the swoole_server->listen method.");
        RETURN_FALSE;
    }

    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "z", &zset))
    {
        RETURN_FALSE;
    }

    php_swoole_array_separate(zset);
    HashTable *vht = Z_ARRVAL_P(zset);
    property->setting = zset;

    //backlog
    zval *value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("backlog"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->backlog = (int) Z_LVAL_P(value);
    }
    //tcp_nodelay
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_nodelay"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_tcp_nodelay = Z_BVAL_P(value);
    }
    //tcp_defer_accept
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_defer_accept"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->tcp_defer_accept = (uint8_t) Z_LVAL_P(value);
    }
    //tcp_keepalive
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_tcp_keepalive"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_tcp_keepalive = Z_BVAL_P(value);
    }
    //buffer: split package with eof
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_eof_split"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->protocol.split_by_eof = Z_BVAL_P(value);
        port->open_eof_check = (port->protocol.split_by_eof)? 1:port->open_eof_check;
    }
    //package eof
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("package_eof"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }

        port->protocol.package_eof_len = Z_STRLEN_P(value);
        if (port->protocol.package_eof_len > SW_DATA_EOF_MAXLEN)
        {
            swoole_php_fatal_error(E_ERROR, "pacakge_eof max length is %d", SW_DATA_EOF_MAXLEN);
            RETURN_FALSE;
        }

        bzero(port->protocol.package_eof, SW_DATA_EOF_MAXLEN);
        memcpy(port->protocol.package_eof, Z_STRVAL_P(value), Z_STRLEN_P(value));
    }
    //http_protocol
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_http_protocol"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_http_protocol = Z_BVAL_P(value);
    }
    //websocket protocol
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_websocket_protocol"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_websocket_protocol = Z_BVAL_P(value);
    }
#ifdef SW_USE_HTTP2
    //http2 protocol
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_http2_protocol"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_http2_protocol = Z_BVAL_P(value);
    }
#endif
    //buffer: mqtt protocol
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_mqtt_protocol"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_mqtt_protocol = Z_BVAL_P(value);
    }
    //tcp_keepidle
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepidle"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->tcp_keepidle = (uint16_t) Z_LVAL_P(value);
    }
    //tcp_keepinterval
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepinterval"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->tcp_keepinterval = (uint16_t) Z_LVAL_P(value);
    }
    //tcp_keepcount
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("tcp_keepcount"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->tcp_keepcount = (uint16_t) Z_LVAL_P(value);
    }
    //open length check
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_length_check"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        port->open_length_check = Z_BVAL_P(value);
    }
    //package length size
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_type"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }
        port->protocol.package_length_type = Z_STRVAL_P(value)[0];
        port->protocol.package_length_size = swoole_type_size(port->protocol.package_length_type);

        if (port->protocol.package_length_size == 0)
        {
            swoole_php_fatal_error(E_ERROR, "unknow package_length_type, see pack(). Link: http://php.net/pack");
            RETURN_FALSE;
        }
    }
    //package length offset
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("package_length_offset"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->protocol.package_length_offset = (int) Z_LVAL_P(value);
    }
    //package body start
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("package_body_offset"), (void **) &value) == SUCCESS
            || sw_zend_hash_find(vht, ZEND_STRS("package_body_start"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->protocol.package_body_offset = (int) Z_LVAL_P(value);
    }

    /// package max length
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("package_max_length"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        port->protocol.package_max_length = (int) Z_LVAL_P(value);
    }

    /// swoole_packet_mode
    if (ServerG.serv->packet_mode == 1)
    {
        port->protocol.package_max_length = 64 * 1024 * 1024;
        port->open_length_check = 1;
        port->protocol.package_length_offset = 0;
        port->protocol.package_body_offset = 4;
        port->protocol.package_length_type = 'N';
        port->open_eof_check = 0;
    }

#ifdef SW_USE_OPENSSL
    if (port->ssl)
    {
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_cert_file"), (void **) &value) == SUCCESS)
        {
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            if (access(Z_STRVAL_P(value), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", Z_STRVAL_P(value));
                return;
            }
            port->ssl_cert_file = strdup(Z_STRVAL_P(value));
            port->open_ssl_encrypt = 1;
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_key_file"), (void **) &value) == SUCCESS)
        {
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            if (access(Z_STRVAL_P(value), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl key file[%s] not found.", Z_STRVAL_P(value));
                return;
            }
            port->ssl_key_file = strdup(Z_STRVAL_P(value));
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_method"), (void **) &value) == SUCCESS)
        {
            convert_to_long(value);
            port->ssl_method = (int) Z_LVAL_P(value);
        }
        //verify client cert
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_client_cert_file"), (void **) &value) == SUCCESS)
        {
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            if (access(Z_STRVAL_P(value), R_OK) < 0)
            {
                swoole_php_fatal_error(E_ERROR, "ssl cert file[%s] not found.", port->ssl_cert_file);
                return;
            }
            port->ssl_client_cert_file = strdup(Z_STRVAL_P(value));
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_verify_depth"), (void **) &value) == SUCCESS)
        {
            convert_to_long(value);
            port->ssl_verify_depth = (int) Z_LVAL_P(value);
        }

        if (port->open_ssl_encrypt && !port->ssl_key_file)
        {
            swoole_php_fatal_error(E_ERROR, "ssl require key file.");
            RETURN_FALSE;
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_prefer_server_ciphers"), (void **) &value) == SUCCESS)
        {
            convert_to_boolean(value);
            port->ssl_config.prefer_server_ciphers = Z_BVAL_P(value);
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_ciphers"), (void **) &value) == SUCCESS)
        {
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            port->ssl_config.ciphers = strdup(Z_STRVAL_P(value));
        }
        value = NULL;
        if (sw_zend_hash_find(vht, ZEND_STRS("ssl_ecdh_curve"), (void **) &value) == SUCCESS)
        {
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }
            port->ssl_config.ecdh_curve = strdup(Z_STRVAL_P(value));
        }

    }
#endif

    zend_update_property(swoole_server_port_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);
}

static PHP_METHOD(swoole_server_port, on)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    swListenPort *port = swoole_get_object(getThis());
    swoole_server_port_property *property = swoole_get_property(getThis(), swoole_property_common);
    if (port == NULL || property == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "Please use the swoole_server->listen method.");
        RETURN_FALSE;
    }

    char *name = NULL;
    zend_size_t len = 0;
    zval *cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sz", &name, &len, &cb))
    {
        RETURN_FALSE;
    }

    if (!name || len <= 0)
    {
        RETURN_FALSE;
    }


    if (swoole_check_callable(cb TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    port->ptr = (!port->ptr)? property:port->ptr;

    char property_name[128] = {0};
    memcpy(property_name, "on", 2);
    int l_property_name = 2;

    int index = 0;
    for (index = 0; index < PHP_SERVER_PORT_CALLBACK_NUM; index++)
    {
        if (len == strlen(callback[index]) && strncasecmp(callback[index], name, len) == 0)
        {
            memcpy(property_name + l_property_name, callback[index], len);
            l_property_name += len;
            property_name[l_property_name] = '\0';
            zend_update_property(swoole_server_port_class_entry_ptr, getThis(), property_name, l_property_name, cb TSRMLS_CC);
            property->callbacks[index] = sw_zend_read_property(swoole_server_port_class_entry_ptr, getThis(), property_name, l_property_name, 0 TSRMLS_CC);
            sw_copy_to_stack(property->callbacks[index], property->_callbacks[index]);

            if (index == SW_SERVER_CB_onConnect && !ServerG.serv->onConnect)
            {
                ServerG.serv->onConnect = php_swoole_onConnect;
            }
            else if (index == SW_SERVER_CB_onClose && !ServerG.serv->onClose)
            {
                ServerG.serv->onClose = php_swoole_onClose;
            }

            break;
        }
    }

    if (index == PHP_SERVER_PORT_CALLBACK_NUM)
    {
        zanWarn("Unknown event types[%s]", name);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}
