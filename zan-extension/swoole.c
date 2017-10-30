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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "php_swoole.h"
#include "swError.h"
#include "swBaseOperator.h"
#include "zanLog.h"

#if PHP_MAJOR_VERSION < 7
#include "ext/standard/php_smart_str.h"
#else
#include "zend_smart_str.h"
#endif
#include <ext/session/php_session.h>
#include <ext/standard/php_var.h>

#include "zend_variables.h"

ZEND_DECLARE_MODULE_GLOBALS(swoole)

extern sapi_module_struct sapi_module;


// arginfo server
// *_oo : for object style

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

//arginfo nova
ZEND_BEGIN_ARG_INFO_EX(arginfo_nova_decode, 0, 0, 8)
    ZEND_ARG_INFO(0, buf)
    ZEND_ARG_INFO(1, service_name)
    ZEND_ARG_INFO(1, method_name)
    ZEND_ARG_INFO(1, ip)
    ZEND_ARG_INFO(1, port)
    ZEND_ARG_INFO(1, seq_no)
    ZEND_ARG_INFO(1, attach)
    ZEND_ARG_INFO(1, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_nova_encode, 0, 0, 8)
    ZEND_ARG_INFO(0, service_name)
    ZEND_ARG_INFO(0, method_name)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, seq_no)
    ZEND_ARG_INFO(0, attach)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(1, buf)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_nova_decode_new, 0, 0, 1)
    ZEND_ARG_INFO(0, buf)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_nova_encode_new, 0, 0, 7)
    ZEND_ARG_INFO(0, service_name)
    ZEND_ARG_INFO(0, method_name)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, seq_no)
    ZEND_ARG_INFO(0, attach)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_is_nova_packet, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

//arginfo event
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_add, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, read_callback)
    ZEND_ARG_INFO(0, write_callback)
    ZEND_ARG_INFO(0, event_flag)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_set, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, read)
    ZEND_ARG_INFO(0, write)
    ZEND_ARG_INFO(0, events)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_write, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_defer, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_event_del, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_set, 0, 0, 1)
    ZEND_ARG_INFO(0, settings)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_read, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, chunk_size)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_write, 0, 0, 2)
    ZEND_ARG_INFO(0, filename)
    ZEND_ARG_INFO(0, content)
    ZEND_ARG_INFO(0, offset)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_async_dns_lookup, 0, 0, 2)
    ZEND_ARG_INFO(0, domain_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_tick, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_after, 0, 0, 2)
    ZEND_ARG_INFO(0, ms)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, param)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_clear, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_set, 0, 0, 1)
    ZEND_ARG_INFO(0, settings)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_timer_exists, 0, 0, 1)
    ZEND_ARG_INFO(0, timer_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_client_select, 0, 0, 3)
    ZEND_ARG_INFO(1, read_array)
    ZEND_ARG_INFO(1, write_array)
    ZEND_ARG_INFO(1, error_array)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_set_process_name, 0, 0, 1)
    ZEND_ARG_INFO(0, process_name)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_strerror, 0, 0, 1)
    ZEND_ARG_INFO(0, errno)
ZEND_END_ARG_INFO()

//arginfo end

#include "zend_exceptions.h"

const zend_function_entry zan_functions[] =
{
    PHP_FE(swoole_version, NULL)
    PHP_FE(swoole_cpu_num, NULL)

    /*------nova_packet------*/
    PHP_FE(nova_decode, arginfo_nova_decode)
    PHP_FE(nova_encode, arginfo_nova_encode)
    PHP_FE(nova_decode_new, arginfo_nova_decode_new)
    PHP_FE(nova_encode_new, arginfo_nova_encode_new)
    PHP_FE(is_nova_packet, arginfo_is_nova_packet)
    PHP_FE(nova_get_sequence, NULL)
    PHP_FE(nova_get_time, NULL)
    PHP_FE(nova_get_ip, NULL)

    /*------swoole_event-----*/
    PHP_FE(swoole_event_add, arginfo_swoole_event_add)
    PHP_FE(swoole_event_set, arginfo_swoole_event_set)
    PHP_FE(swoole_event_del, arginfo_swoole_event_del)
    PHP_FE(swoole_event_exit, arginfo_swoole_void)
    PHP_FE(swoole_event_wait, arginfo_swoole_void)
    PHP_FE(swoole_event_write, arginfo_swoole_event_write)
    PHP_FE(swoole_event_defer, arginfo_swoole_event_defer)
    /*------swoole_timer-----*/
    PHP_FE(swoole_timer_after, arginfo_swoole_timer_after)
    PHP_FE(swoole_timer_tick, arginfo_swoole_timer_tick)
    PHP_FE(swoole_timer_exists, arginfo_swoole_timer_exists)
    PHP_FE(swoole_timer_clear, arginfo_swoole_timer_clear)
    PHP_FE(swoole_timer_set,arginfo_swoole_timer_set)
    /*------swoole_async_io------*/
    PHP_FE(swoole_async_set, arginfo_swoole_async_set)
    PHP_FE(swoole_async_read, arginfo_swoole_async_read)
    PHP_FE(swoole_async_write, arginfo_swoole_async_write)
    PHP_FE(swoole_async_dns_lookup, arginfo_swoole_async_dns_lookup)
    PHP_FE(swoole_clean_dns_cache,arginfo_swoole_void)

    /*------other-----*/
    PHP_FE(swoole_client_select, arginfo_swoole_client_select)
    PHP_FE(swoole_set_process_name, arginfo_swoole_set_process_name)
    PHP_FE(swoole_strerror, arginfo_swoole_strerror)
    PHP_FE(swoole_errno, arginfo_swoole_void)
    PHP_FE(swoole_get_local_ip, arginfo_swoole_void)

    PHP_FE(onClientClose,NULL)
    PHP_FE(onClientTimeout,NULL)
    PHP_FE(onClientConnect,NULL)
    PHP_FE(onClientRecieve,NULL)
    PHP_FE(onSubClientConnect,NULL)

    PHP_FE_END /* Must be the last line in swoole_functions[] */
};


#if PHP_MEMORY_DEBUG
php_vmstat_t php_vmstat;
#endif


zend_module_entry zan_module_entry =
{
#if ZEND_MODULE_API_NO >= 20050922
    STANDARD_MODULE_HEADER_EX,
    NULL,
    NULL,
#else
    STANDARD_MODULE_HEADER,
#endif
    "zan",
    zan_functions,
    PHP_MINIT(zan),
    NULL,
    PHP_RINIT(zan),     //RINIT
    PHP_RSHUTDOWN(zan), //RSHUTDOWN
    PHP_MINFO(zan),
    PHP_SWOOLE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_ZAN
ZEND_GET_MODULE(zan)
#endif

/* {{{ PHP_INI
 */

PHP_INI_BEGIN()
STD_PHP_INI_ENTRY("zan.aio_thread_num", "2", PHP_INI_ALL, OnUpdateLong, aio_thread_num, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("zan.log_level", "5", PHP_INI_ALL, OnUpdateLong, log_level, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("zan.display_errors", "On", PHP_INI_ALL, OnUpdateBool, display_errors, zend_swoole_globals, swoole_globals)
/**
 * namespace class style
 */
STD_PHP_INI_ENTRY("zan.use_namespace", "Off", PHP_INI_SYSTEM, OnUpdateBool, use_namespace, zend_swoole_globals, swoole_globals)
STD_PHP_INI_ENTRY("zan.message_queue_key", "0", PHP_INI_ALL, OnUpdateString, message_queue_key, zend_swoole_globals, swoole_globals)
/**
 * Unix socket buffer size
 */
STD_PHP_INI_ENTRY("zan.unixsock_buffer_size", "8388608", PHP_INI_ALL, OnUpdateLong, socket_buffer_size, zend_swoole_globals, swoole_globals)
PHP_INI_END()

static void php_swoole_init_globals(zend_swoole_globals *swoole_globals)
{
    swoole_globals->message_queue_key = 0;
    swoole_globals->aio_thread_num = SW_AIO_THREAD_NUM_DEFAULT;
    swoole_globals->log_level = ZAN_LOG_WARNING;
    swoole_globals->socket_buffer_size = SW_SOCKET_BUFFER_SIZE;
    swoole_globals->display_errors = 1;
    swoole_globals->use_namespace = 0;
}

void swoole_set_object(zval *object, void *ptr)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    assert(handle < SWOOLE_OBJECT_MAX);
    if (handle >= swoole_objects.size)
    {
        uint32_t old_size = swoole_objects.size;
        uint32_t new_size = old_size * 2;
        while(new_size < handle) {
            new_size *= 2;
        }
        new_size = (new_size > SWOOLE_OBJECT_MAX)? SWOOLE_OBJECT_MAX:new_size;

        void *old_ptr = swoole_objects.array;
        void *new_ptr = realloc(old_ptr, sizeof(void*) * new_size);
        if (!new_ptr)
        {
            zanWarn("alloc global memory failed");
            return ;
        }

        bzero(new_ptr + (old_size * sizeof(void*)), (new_size - old_size) * sizeof(void*));
        swoole_objects.array = new_ptr;
        swoole_objects.size = new_size;
    }

    swoole_objects.array[handle] = ptr;
    return ;
}

void* swoole_get_object(zval *object)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int)Z_OBJ_HANDLE(*object);
#endif

    assert(handle < swoole_objects.size);
    return swoole_objects.array[handle];
}

void* swoole_get_property(zval *object, int property_id)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    if (handle >= swoole_objects.property_size[property_id])
    {
        return NULL;
    }
    return swoole_objects.property[property_id][handle];
}

void swoole_set_property(zval *object, int property_id, void *ptr)
{
#if PHP_MAJOR_VERSION < 7
    zend_object_handle handle = Z_OBJ_HANDLE_P(object);
#else
    int handle = (int) Z_OBJ_HANDLE(*object);
#endif
    assert(handle < SWOOLE_OBJECT_MAX);

    if (handle >= swoole_objects.property_size[property_id])
    {
        uint32_t old_size = swoole_objects.property_size[property_id];
        uint32_t new_size = 0;

        void *old_ptr = NULL;
        void *new_ptr = NULL;

        if (old_size == 0)
        {
            new_size = 65536;
            new_ptr = calloc(new_size, sizeof(void *));
        }
        else
        {
            new_size = old_size * 2;
            while (new_size < handle)
            {
                new_size = 2*new_size;
            }

            if (new_size > SWOOLE_OBJECT_MAX)
            {
                new_size = SWOOLE_OBJECT_MAX;
            }

            old_ptr = swoole_objects.property[property_id];
            new_ptr = realloc(old_ptr, new_size * sizeof(void *));
        }
        if (new_ptr == NULL)
        {
            return;
        }
        if (old_size > 0)
        {
            bzero(new_ptr + old_size * sizeof(void*), (new_size - old_size) * sizeof(void*));
        }
        swoole_objects.property_size[property_id] = new_size;
        swoole_objects.property[property_id] = new_ptr;
    }

    swoole_objects.property[property_id][handle] = ptr;
}

#ifdef ZTS
__thread swoole_object_array swoole_objects;
void ***sw_thread_ctx;
#else
swoole_object_array swoole_objects;
#endif

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(zan)
{
    ZEND_INIT_MODULE_GLOBALS(swoole, php_swoole_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    /**
     * mode type
     */
    REGISTER_LONG_CONSTANT("SWOOLE_BASE", ZAN_MODE_BASE, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_PROCESS", ZAN_MODE_PROCESS, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("SWOOLE_PACKET", SW_MODE_PACKET, CONST_CS | CONST_PERSISTENT);

    /**
     * ipc mode
     */
    REGISTER_LONG_CONSTANT("SWOOLE_IPC_UNSOCK", ZAN_IPC_UNSOCK, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_IPC_MSGQUEUE", ZAN_IPC_MSGQUEUE, CONST_CS | CONST_PERSISTENT);

    /**
     * socket type
     */
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_UNIX_STREAM", SW_SOCK_UNIX_STREAM, CONST_CS | CONST_PERSISTENT);

    /**
     * simple api, socket type
     */
    REGISTER_LONG_CONSTANT("SWOOLE_TCP", SW_SOCK_TCP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TCP6", SW_SOCK_TCP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UDP", SW_SOCK_UDP, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UDP6", SW_SOCK_UDP6, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UNIX_DGRAM", SW_SOCK_UNIX_DGRAM, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_UNIX_STREAM", SW_SOCK_UNIX_STREAM, CONST_CS | CONST_PERSISTENT);

    /**
     * simple api
     */
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_SYNC", SW_SOCK_SYNC, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SOCK_ASYNC", SW_SOCK_ASYNC, CONST_CS | CONST_PERSISTENT);

    //REGISTER_LONG_CONSTANT("SWOOLE_SYNC", SW_FLAG_SYNC, CONST_CS | CONST_PERSISTENT);
    //REGISTER_LONG_CONSTANT("SWOOLE_ASYNC", SW_FLAG_ASYNC, CONST_CS | CONST_PERSISTENT);

    REGISTER_LONG_CONSTANT("SWOOLE_ASYNC_CONNECT_TIMEOUT", SW_CLIENT_CONNECT_TIMEOUT, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_ASYNC_RECV_TIMEOUT", SW_CLIENT_RECV_TIMEOUT, CONST_CS | CONST_PERSISTENT);

#ifdef SW_USE_OPENSSL
    REGISTER_LONG_CONSTANT("SWOOLE_SSL", SW_SOCK_SSL, CONST_CS | CONST_PERSISTENT);

    /**
     * SSL method
     */
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_METHOD", SW_SSLv3_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_SERVER_METHOD", SW_SSLv3_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv3_CLIENT_METHOD", SW_SSLv3_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_METHOD", SW_SSLv23_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_SERVER_METHOD", SW_SSLv23_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_SSLv23_CLIENT_METHOD", SW_SSLv23_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_METHOD", SW_TLSv1_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_SERVER_METHOD", SW_TLSv1_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_CLIENT_METHOD", SW_TLSv1_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
#ifdef TLS1_1_VERSION
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_METHOD", SW_TLSv1_1_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_SERVER_METHOD", SW_TLSv1_1_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_1_CLIENT_METHOD", SW_TLSv1_1_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef TLS1_2_VERSION
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_METHOD", SW_TLSv1_2_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_SERVER_METHOD", SW_TLSv1_2_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_TLSv1_2_CLIENT_METHOD", SW_TLSv1_2_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
#endif
    REGISTER_LONG_CONSTANT("SWOOLE_DTLSv1_METHOD", SW_DTLSv1_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_DTLSv1_SERVER_METHOD", SW_DTLSv1_SERVER_METHOD, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_DTLSv1_CLIENT_METHOD", SW_DTLSv1_CLIENT_METHOD, CONST_CS | CONST_PERSISTENT);
#endif

    REGISTER_LONG_CONSTANT("SWOOLE_EVENT_READ", SW_EVENT_READ, CONST_CS | CONST_PERSISTENT);
    REGISTER_LONG_CONSTANT("SWOOLE_EVENT_WRITE", SW_EVENT_WRITE, CONST_CS | CONST_PERSISTENT);

    REGISTER_STRINGL_CONSTANT("SWOOLE_VERSION", PHP_SWOOLE_VERSION, sizeof(PHP_SWOOLE_VERSION) - 1, CONST_CS | CONST_PERSISTENT);

    zan_init();

    swoole_server_init(module_number TSRMLS_CC);
    swoole_client_init(module_number TSRMLS_CC);
    swoole_server_port_init(module_number TSRMLS_CC);

    swoole_timer_init(module_number TSRMLS_CC);
    swoole_aio_init(module_number TSRMLS_CC);
    swoole_process_init(module_number TSRMLS_CC);
    swoole_buffer_init(module_number TSRMLS_CC);
    swoole_connpool_init(module_number TSRMLS_CC);

#ifdef SW_USE_REDIS
    swoole_redis_init(module_number TSRMLS_CC);
#endif
    swoole_http_client_init(module_number TSRMLS_CC);
    swoole_http_server_init(module_number TSRMLS_CC);
    swoole_websocket_init(module_number TSRMLS_CC);
    swoole_mysql_init(module_number TSRMLS_CC);

    if (SWOOLE_G(aio_thread_num) > 0)
    {
        if (SWOOLE_G(aio_thread_num) > SW_AIO_THREAD_NUM_MAX)
        {
            SWOOLE_G(aio_thread_num) = SW_AIO_THREAD_NUM_MAX;
        }
        ZanAIO.thread_num = SWOOLE_G(aio_thread_num);
    }

    if (strcasecmp("cli", sapi_module.name) == 0)
    {
        SWOOLE_G(cli) = 1;
    }

    swoole_objects.size = 65536;
    swoole_objects.array = calloc(swoole_objects.size, sizeof(void*));

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(zan)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "zan support", "enabled");
    php_info_print_table_row(2, "Version", PHP_SWOOLE_VERSION);
    php_info_print_table_row(2, "Author", "Zan Group  <zan@zanphp.io>");
    php_info_print_table_row(2, "      ", "tianfeng.han[email: mikan.tenny@gmail.com]");

#ifdef HAVE_EPOLL
    php_info_print_table_row(2, "epoll", "enabled");
#endif
#ifdef HAVE_EVENTFD
    php_info_print_table_row(2, "eventfd", "enabled");
#endif
#ifdef HAVE_KQUEUE
    php_info_print_table_row(2, "kqueue", "enabled");
#endif
#ifdef HAVE_TIMERFD
    php_info_print_table_row(2, "timerfd", "enabled");
#endif
#ifdef HAVE_SIGNALFD
    php_info_print_table_row(2, "signalfd", "enabled");
#endif
#ifdef SW_USE_ACCEPT4
    php_info_print_table_row(2, "accept4", "enabled");
#endif
#ifdef HAVE_CPU_AFFINITY
    php_info_print_table_row(2, "cpu affinity", "enabled");
#endif
#ifdef HAVE_SPINLOCK
    php_info_print_table_row(2, "spinlock", "enabled");
#endif
#ifdef HAVE_RWLOCK
    php_info_print_table_row(2, "rwlock", "enabled");
#endif
#ifdef SW_ASYNC_MYSQL
    php_info_print_table_row(2, "async mysql client", "enabled");
#endif
#ifdef SW_USE_REDIS
    php_info_print_table_row(2, "async redis client", "enabled");
#endif

    php_info_print_table_row(2, "async http/websocket client", "enabled");

#ifdef SW_USE_SOCKETS
    php_info_print_table_row(2, "sockets", "enabled");
#endif
#ifdef SW_USE_OPENSSL
    php_info_print_table_row(2, "openssl", "enabled");
#endif
#ifdef SW_USE_HTTP2
    php_info_print_table_row(2, "http2", "enabled");
#endif
#ifdef SW_USE_RINGBUFFER
    php_info_print_table_row(2, "ringbuffer", "enabled");
#endif

#ifdef HAVE_PCRE
    php_info_print_table_row(2, "pcre", "enabled");
#endif
#ifdef SW_HAVE_ZLIB
    php_info_print_table_row(2, "zlib", "enabled");
#endif
#ifdef HAVE_MUTEX_TIMEDLOCK
    php_info_print_table_row(2, "mutex_timedlock", "enabled");
#endif
#ifdef HAVE_PTHREAD_BARRIER
    php_info_print_table_row(2, "pthread_barrier", "enabled");
#endif

    php_info_print_table_end();

    DISPLAY_INI_ENTRIES();
}
/* }}} */

PHP_RINIT_FUNCTION(zan)
{
    //running
    //SwooleG.running = 1;
    ServerG.running = 1;

#ifdef ZTS
    if (sw_thread_ctx == NULL)
    {
        TSRMLS_SET_CTX(sw_thread_ctx);
    }
#endif

#ifdef SW_DEBUG_REMOTE_OPEN
    swoole_open_remote_debug();
#endif

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(zan)
{
    //clear pipe buffer
    if (is_worker())
    {
        zanWorker_clean();
    }

    if (ServerGS->started > 0 && ServerG.running > 0)
    {
        if (PG(last_error_message))
        {
            switch(PG(last_error_type))
            {
            case E_ERROR:
            case E_CORE_ERROR:
            case E_USER_ERROR:
            case E_COMPILE_ERROR:
                    zanWarn("PHP_RSHUTDOWN_FUNCTION(swoole).");
                    zanError("Fatal error: %s in %s on line %d.",
                        PG(last_error_message), PG(last_error_file)?PG(last_error_file):"-", PG(last_error_lineno));
                break;
            default:
                break;
            }
        }
        else
        {
            zanDebug("worker process is terminated by exit/die.");
        }
    }

    /// clean client information
    swoole_thread_clean();
    //SwooleWG.reactor_wait_onexit = 0;
    return SUCCESS;
}

PHP_FUNCTION(swoole_version)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_version can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    char swoole_version[32] = {0};
    snprintf(swoole_version, sizeof(PHP_SWOOLE_VERSION), "%s", PHP_SWOOLE_VERSION);
    SW_RETURN_STRING(swoole_version, 1);
}

PHP_FUNCTION(swoole_cpu_num)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_cpu_num can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    long cpu_num = 1;
    cpu_num = sysconf(_SC_NPROCESSORS_CONF);
    if(cpu_num < 1)
    {
        cpu_num = 1;
    }

    RETURN_LONG(cpu_num);
}

PHP_FUNCTION(swoole_strerror)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_strerror can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

#define STRERROR_MAX_LEN   256
    long swoole_errno = 0;
    char error_msg[STRERROR_MAX_LEN] = {0};
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &swoole_errno))
    {
        return;
    }

    snprintf(error_msg, STRERROR_MAX_LEN - 1, "%s", strerror(swoole_errno));
    SW_RETURN_STRING(error_msg,1);
}

PHP_FUNCTION(swoole_errno)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_errno can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }
    RETURN_LONG(errno);
}

PHP_FUNCTION(swoole_set_process_name)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_set_process_name can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    zval *name = NULL;
    long size = 128;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &name, &size))
    {
        return;
    }

    if (Z_STRLEN_P(name) <= 0 || Z_STRLEN_P(name) > 127)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "process name max len is 127");
        return;
    }

    size = (size > ServerG.pagesize)? ServerG.pagesize:size;

#if PHP_MAJOR_VERSION >= 7 || (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 4)
    zval *function = NULL;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function, "cli_set_process_title", 1);

    zval **args[1];
    args[0] = &name;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, function, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        return;
    }

    sw_zval_ptr_dtor(&function);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
#else
    bzero(sapi_module.executable_location, size);
    memcpy(sapi_module.executable_location, Z_STRVAL_P(name), Z_STRLEN_P(name));
#endif

}

PHP_FUNCTION(swoole_get_local_ip)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_get_local_ip can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    struct ifaddrs *ipaddrs = NULL;
    if (getifaddrs(&ipaddrs) != 0 || !ipaddrs)
    {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "getifaddrs() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    array_init(return_value);
    struct ifaddrs *ifa = NULL;
    for (ifa = ipaddrs; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL || !(ifa->ifa_flags & IFF_UP))
        {
            continue;
        }

        void *in_addr = NULL;
        switch (ifa->ifa_addr->sa_family)
        {
            case AF_INET:
                in_addr = &(((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr);
                break;
//            case AF_INET6:
//                in_addr = &(((struct sockaddr_in6 *)(ifa->ifa_addr))->sin6_addr);
//                break;
            default:
                continue;
        }

        char ip[SW_IP_MAX_LENGTH] = {0};
        if (!inet_ntop(ifa->ifa_addr->sa_family, in_addr, ip, sizeof(ip)))
        {
            php_error_docref(NULL TSRMLS_CC, E_WARNING, "%s: inet_ntop failed.", ifa->ifa_name);
        }
        else if (strncmp(ip, "127.",strlen("127.")) != 0)
        {
            sw_add_assoc_string(return_value, ifa->ifa_name, ip, 1);
        }
    }

    freeifaddrs(ipaddrs);
}
