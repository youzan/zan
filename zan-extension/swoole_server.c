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
#include "swConnection.h"
#include "swBaseOperator.h"
#include "swSendfile.h"

#include "zanServer.h"
#include "zanSocket.h"

#include "ext/standard/php_var.h"

#ifdef HAVE_PCRE
#include <ext/spl/spl_iterators.h>
#endif

#if PHP_MAJOR_VERSION < 7
#include "ext/standard/php_smart_str.h"
#else
#include "zend_smart_str.h"
#include "zend_hash.h"
#endif

static void php_swoole_onStart(zanServer *);
static void php_swoole_onShutdown(zanServer *);

static void php_swoole_onWorkerStart(zanServer *, int worker_id);
static void php_swoole_onWorkerStop(zanServer *, int worker_id);
static void php_swoole_onWorkerError(zanServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo);
static void php_swoole_onUserWorkerStart(zanServer *serv, zanWorker *worker);

static int php_swoole_onTask(zanServer *, swEventData *task);
static int php_swoole_onFinish(zanServer *, swEventData *task);

static int php_swoole_onPacket(zanServer *, swEventData *);
static void php_swoole_onPipeMessage(zanServer *serv, swEventData *req);

static zval* php_swoole_server_add_port(swListenPort *port TSRMLS_DC);
static zval* php_swoole_get_task_result(swEventData *task_result TSRMLS_DC);
static int php_swoole_task_finish(zanServer *serv, zval *data TSRMLS_DC);
static int php_swoole_task_setBuf(zval *data,swEventData *buf TSRMLS_DC);

/******************************************************************************/
static int php_swoole_task_id;
static int udp_server_socket;
static int dgram_server_socket;

zend_class_entry swoole_server_ce;
zend_class_entry *swoole_server_class_entry_ptr;

#ifdef HAVE_PCRE
static zend_class_entry swoole_connection_iterator_ce;
zend_class_entry *swoole_connection_iterator_class_entry_ptr;
#endif

zval *php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];

#if PHP_MAJOR_VERSION >= 7
zval _php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
#endif

static struct
{
    zval *zobjects[SW_MAX_LISTEN_PORT];
    zval *zports;
    uint8_t num;
} server_port_list;

static char *swoole_server_callback[PHP_SERVER_CALLBACK_NUM] = {
    "Connect",
    "Receive",
    "Close",
    "Packet",
    "Start",
    "Shutdown",
    "WorkerStart",
    "WorkerStop",
    "Task",
    "Finish",
    "WorkerError",
    //"ManagerStart",
    //"ManagerStop",
    "PipeMessage",
    NULL,
    NULL,
    NULL,
    NULL
};

/******************************************************************************/
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server__construct, 0, 0, 2)
    ZEND_ARG_INFO(0, serv_host)
    ZEND_ARG_INFO(0, serv_port)
    ZEND_ARG_INFO(0, serv_mode)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_set_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, zset)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_denyRequest_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_send_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, conn_fd)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, extra_data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_exist, 0, 0, 1)
    ZEND_ARG_INFO(0, conn_fd)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_protect, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, is_protected)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendto_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, ip)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, send_data)
    ZEND_ARG_INFO(0, server_socket)
ZEND_END_ARG_INFO()

//for object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendfile_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, filename)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_close_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, reset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_listen, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, sock_type)
ZEND_END_ARG_INFO()

//object style
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_task_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, data)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_finish_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_reload_oo, 0, 0, 0)
    ZEND_ARG_INFO(0, only_reload_taskworkrer)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_stop, 0, 0, 0)
    ZEND_ARG_INFO(0, worker_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_heartbeat_oo, 0, 0, 0)
    ZEND_ARG_INFO(0, if_close_connection)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_bind, 0, 0, 2)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, uid)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_sendMessage, 0, 0, 2)
    ZEND_ARG_INFO(0, msg)
    ZEND_ARG_INFO(0, work_id)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getSocket, 0, 0, 1)
    ZEND_ARG_INFO(0, port)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientInfo_oo, 0, 0, 1)
    ZEND_ARG_INFO(0, fd)
    ZEND_ARG_INFO(0, from_id)
    ZEND_ARG_INFO(0, ignore_close)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_getClientList_oo, 0, 0, 2)
    ZEND_ARG_INFO(0, start_fd)
    ZEND_ARG_INFO(0, find_count)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_server_addProcess_oo, 0, 0, 1)
    ZEND_ARG_OBJ_INFO(0, process, swoole_process, 0)
ZEND_END_ARG_INFO()

static zend_function_entry swoole_server_methods[] = {
    PHP_ME(swoole_server, __construct, arginfo_swoole_server__construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_server, listen, arginfo_swoole_server_listen, ZEND_ACC_PUBLIC)
    PHP_MALIAS(swoole_server, addListener, listen, arginfo_swoole_server_listen, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, on, arginfo_swoole_server_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, set, arginfo_swoole_server_set_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, start, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, send, arginfo_swoole_server_send_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendto, arginfo_swoole_server_sendto_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, exist, arginfo_swoole_server_exist, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, protect, arginfo_swoole_server_protect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, sendfile, arginfo_swoole_server_sendfile_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, close, arginfo_swoole_server_close_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, task, arginfo_swoole_server_task_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, finish, arginfo_swoole_server_finish_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, reload, arginfo_swoole_server_reload_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, shutdown, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stop, arginfo_swoole_server_stop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getLastError, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, heartbeat, arginfo_swoole_server_heartbeat_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getClientInfo, arginfo_swoole_server_getClientInfo_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getClientList, arginfo_swoole_server_getClientList_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, denyRequest, arginfo_swoole_server_denyRequest_oo, ZEND_ACC_PUBLIC)
    //PHP_ME(swoole_server, exit, arginfo_swoole_void, ZEND_ACC_PUBLIC)

    //process
    PHP_ME(swoole_server, sendMessage, arginfo_swoole_server_sendMessage, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, addProcess, arginfo_swoole_server_addProcess_oo, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, stats, NULL, ZEND_ACC_PUBLIC)

    PHP_ME(swoole_server, getSocket, arginfo_swoole_server_getSocket, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, bind, arginfo_swoole_server_bind, ZEND_ACC_PUBLIC)

    //
    PHP_ME(swoole_server, getWorkerId, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getWorkerType, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_server, getWorkerPid, arginfo_swoole_void, ZEND_ACC_PUBLIC)

    {NULL, NULL, NULL}
};

#ifdef HAVE_PCRE
static const zend_function_entry swoole_connection_iterator_methods[] =
{
    PHP_ME(swoole_connection_iterator, rewind,      arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, next,        arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, current,     arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, key,         arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, valid,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_connection_iterator, count,       arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_FE_END
};
#endif

void swoole_server_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_server_ce, "swoole_server", "Swoole\\Server", swoole_server_methods);
    swoole_server_class_entry_ptr = zend_register_internal_class(&swoole_server_ce TSRMLS_CC);

#ifdef HAVE_PCRE
    SWOOLE_INIT_CLASS_ENTRY(swoole_connection_iterator_ce, "swoole_connection_iterator", "Swoole\\ConnectionIterator",  swoole_connection_iterator_methods);
    swoole_connection_iterator_class_entry_ptr = zend_register_internal_class(&swoole_connection_iterator_ce TSRMLS_CC);
    zend_class_implements(swoole_connection_iterator_class_entry_ptr TSRMLS_CC, 2, spl_ce_Iterator, spl_ce_Countable);
#endif

    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("master_pid"),0,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("worker_pid"),0,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_server_class_entry_ptr,ZEND_STRL("taskworker"),0,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_server_class_entry_ptr,ZEND_STRL("pid"),0,ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("id"),0,ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_stringl(swoole_server_class_entry_ptr,ZEND_STRL("host"),"",0,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("port"),-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("type"),0,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_server_class_entry_ptr,ZEND_STRL("mode"),0,ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_null(swoole_server_class_entry_ptr,ZEND_STRL("setting"),ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_server_class_entry_ptr,ZEND_STRL("ports"),ZEND_ACC_PUBLIC TSRMLS_CC);

    char property_name[32] = {0};
    memcpy(property_name, "on", 2);
    int index;
    for (index = 0; index < PHP_SERVER_CALLBACK_NUM; index++)
    {
        if (NULL == swoole_server_callback[index])
        {
            continue;
        }

        int l_property_name = 2;
        int callbackLen = strlen(swoole_server_callback[index]);
        memcpy(property_name + l_property_name, swoole_server_callback[index],callbackLen);
        l_property_name += callbackLen;
        property_name[l_property_name] = '\0';
        zend_declare_property_null(swoole_server_class_entry_ptr,property_name,l_property_name,ZEND_ACC_PUBLIC TSRMLS_CC);
    }

#ifdef HAVE_PCRE
    zend_declare_property_null(swoole_server_class_entry_ptr,ZEND_STRL("connections"),ZEND_ACC_PUBLIC TSRMLS_CC);
#endif
}

void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length TSRMLS_DC)
{
    char *data_ptr = NULL;
    int data_len = 0;

    if (req->info.type == SW_EVENT_PACKAGE_END)
    {
        int networker_index = zanServer_get_networker_index(req->info.networker_id);
        swString *worker_buffer = zanWorker_get_buffer(networker_index);
        data_ptr = worker_buffer->str;
        data_len = worker_buffer->length;
    }
    else
    {
        data_ptr = req->data;
        data_len = req->info.len;
    }

    //add by andy
    if (header_length >= data_len)
    {
        SW_ZVAL_STRING(zdata, "", 1);
    }
    else
    {
        SW_ZVAL_STRINGL(zdata, data_ptr + header_length, data_len - header_length, 1);
    }

    if (header_length > 0 && header)
    {
        memcpy(header, data_ptr, header_length);
    }
}

int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC)
{
    if (!zdata)
    {
        return 0;
    }

    int length = -1;
    if (SW_Z_TYPE_P(zdata) == IS_OBJECT)
    {
        if (!instanceof_function(Z_OBJCE_P(zdata), swoole_buffer_class_entry_ptr TSRMLS_CC))
        {
            goto convert;
        }

        swString *str_buffer = swoole_get_object(zdata);
        if (!str_buffer->str)
        {
            zanWarn("swoole_buffer object is empty.");
            return ZAN_ERR;
        }

        length = str_buffer->length - str_buffer->offset;
        *str = str_buffer->str + str_buffer->offset;
    }
    else
    {
convert:
        if (sw_convert_to_string(zdata) < 0)
        {
            zanWarn("convert to string failed.");
            return ZAN_ERR;
        }
        length = Z_STRLEN_P(zdata);
        *str = Z_STRVAL_P(zdata);
    }

    if (length >= ServerG.servSet.buffer_output_size)
    {
        zanWarn("send data max_size is %d.", ServerG.servSet.buffer_output_size);
        *str = NULL;
        length = -1;
    }

    return length;
}

void php_swoole_server_before_start(zanServer *serv, zval *zobject TSRMLS_DC)
{
    zanServerSet *servSet = &ServerG.servSet;

    zanLog_init(servSet->log_file, 0);

    /// create swoole server
    if (zanServer_create(serv) < 0)
    {
        zanFatalError("create server failed.");
        return;
    }

    zanTrace("Create swoole_server host=%s, port=%d, mode=%d, type=%d", serv->listen_list->host,
             (int) serv->listen_list->port, ServerG.factory_mode, (int) serv->listen_list->type);

    /// Master Process ID
    zend_update_property_long(swoole_server_class_entry_ptr, zobject, ZEND_STRL("master_pid"), getpid() TSRMLS_CC);

    zval *zsetting = sw_zend_read_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), 1 TSRMLS_CC);
    if (zsetting == NULL || ZVAL_IS_NULL(zsetting))
    {
        SW_ALLOC_INIT_ZVAL(zsetting);
        array_init(zsetting);
        zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zsetting TSRMLS_CC);
    }

    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("net_worker_num")))
    {
        add_assoc_long(zsetting, "net_worker_num", servSet->net_worker_num);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("worker_num")))
    {
        add_assoc_long(zsetting, "worker_num", servSet->worker_num);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("task_worker_num")))
    {
        add_assoc_long(zsetting, "task_worker_num", servSet->task_worker_num);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("pipe_buffer_size")))
    {
        add_assoc_long(zsetting, "pipe_buffer_size", servSet->pipe_buffer_size);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("buffer_output_size")))
    {
        add_assoc_long(zsetting, "buffer_output_size", servSet->buffer_output_size);
    }
    if (!sw_zend_hash_exists(Z_ARRVAL_P(zsetting), ZEND_STRL("max_connection")))
    {
        add_assoc_long(zsetting, "max_connection", servSet->max_connection);
    }

    int index = 0;
    for (index = 1; index < server_port_list.num; index++)
    {
        zval *port_object = server_port_list.zobjects[index];
        zval *port_setting = sw_zend_read_property(swoole_server_port_class_entry_ptr,
                                                   port_object, ZEND_STRL("setting"), 1 TSRMLS_CC);
        //use swoole_server->setting
        if ((port_object && !ZVAL_IS_NULL(port_object)) &&
                        (!port_setting || ZVAL_IS_NULL(port_setting)))
        {
            sw_zval_add_ref(&port_setting);
            sw_zval_add_ref(&port_object);
            zval *retval = NULL;
            sw_zend_call_method_with_1_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "set", &retval, zsetting);
            if (retval)
            {
                sw_zval_ptr_dtor(&retval);
            }
        }
    }
}

zval* php_swoole_server_get_callback(zanServer *serv, int server_fd, int networker_id, int event_type)
{
    int networker_index = zanServer_get_networker_index(networker_id);
    zanDebug("fd=%d, networker_id=%d, networker_index=%d, event_type=%d", server_fd, networker_id, networker_index, event_type);

    swListenPort *port = serv->connection_list[networker_index][server_fd].object;
    swoole_server_port_property *property = (port)? port->ptr:NULL;
    if (event_type >= PHP_SERVER_PORT_CALLBACK_NUM || !property)
    {
        return php_sw_server_callbacks[event_type];
    }

    zval *callback = property->callbacks[event_type];
    if (!callback)
    {
        return php_sw_server_callbacks[event_type];
    }
    else
    {
        return callback;
    }
}

/******************************************************************************/
static void php_swoole_onStart(zanServer *serv)
{
    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onStart];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        zanWarn("swoole_server: no onStart callback");
        return;
    }

    zval *zserv = (zval *) serv->ptr2;
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("master_pid"), ServerGS->master_pid TSRMLS_CC);

    zval **args[1];
    args[0] = &zserv;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                 &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onStart handler error");
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

static void php_swoole_onShutdown(zanServer *serv)
{

    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onShutdown];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zserv = (zval *) serv->ptr2;
    zval **args[1];
    args[0] = &zserv;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                        &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onShutdown handler error");
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

static void php_swoole_onWorkerStart(zanServer *serv, int worker_id)
{
    SWOOLE_FETCH_TSRMLS;

    zval *zworker_id = NULL;
    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval *zserv = (zval *) serv->ptr2;
    zval **args[2];
    args[0] = &zserv;
    args[1] = &zworker_id;

    /// update Worker ID property
    zend_update_property(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_id"), zworker_id TSRMLS_CC);

    /// update Is a task worker property
    int isTaskWork = 0;
    if (worker_id >= ServerG.servSet.worker_num && worker_id < ServerG.servSet.task_worker_num)
    {
        isTaskWork = 1;
    }
    zend_update_property_bool(swoole_server_class_entry_ptr, zserv, ZEND_STRL("taskworker"), isTaskWork TSRMLS_CC);

    /// Worker Process ID
    zend_update_property_long(swoole_server_class_entry_ptr, zserv, ZEND_STRL("worker_pid"), getpid() TSRMLS_CC);

    ///Have not set the event callback
    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onWorkerStart];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        sw_zval_ptr_dtor(&zworker_id);
        return;
    }

    if (is_worker()) {
        ServerGS->event_workers.workers[worker_id].deny_request = 0;
    } else if (is_taskworker()) {
        ServerGS->task_workers.workers[worker_id - ServerG.servSet.worker_num].deny_request = 0;
    }

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                 &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onWorkerStart handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zworker_id);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onWorkerError(zanServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo)
{

    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onWorkerError];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zworker_id = NULL;
    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval *zworker_pid = NULL;
    SW_MAKE_STD_ZVAL(zworker_pid);
    ZVAL_LONG(zworker_pid, worker_pid);

    zval *zexit_code = NULL;
    SW_MAKE_STD_ZVAL(zexit_code);
    ZVAL_LONG(zexit_code, exit_code);

    zval *zsigno = NULL;
    SW_MAKE_STD_ZVAL(zsigno);
    ZVAL_LONG(zsigno, signo);

    zval *zobject = (zval *) serv->ptr2;

    zval **args[5];
    args[0] = &zobject;
    args[1] = &zworker_id;
    args[2] = &zworker_pid;
    args[3] = &zexit_code;
    args[4] = &zsigno;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                 &retval, 5, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onWorkerError handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zworker_id);
    sw_zval_ptr_dtor(&zworker_pid);
    sw_zval_ptr_dtor(&zexit_code);
    sw_zval_ptr_dtor(&zsigno);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static void php_swoole_onWorkerStop(zanServer *serv, int worker_id)
{
    SWOOLE_FETCH_TSRMLS;

    if (ServerWG.shutdown)
    {
        zanWarn("ServerWG.shutdow=%d", ServerWG.shutdown);
        return;
    }

    ServerWG.shutdown = 1;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onWorkerStop];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        zanWarn("onWorkerStop callback is null");
        return;
    }

    zval *zworker_id = NULL;
    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, worker_id);

    zval *zobject = (zval *) serv->ptr2;

    zval **args[2];
    args[0] = &zobject;
    args[1] = &zworker_id;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback, &retval, 2, args, 0,NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onWorkerStop handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&zworker_id);

    shutdown_memory_manager(0, 1 TSRMLS_CC);
}

static void php_swoole_onUserWorkerStart(zanServer *serv, zanWorker *worker)
{
    SWOOLE_FETCH_TSRMLS;

    zval *object = worker->ptr;
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("worker_id"), worker->worker_id TSRMLS_CC);

    ///TODO
    php_swoole_process_start(worker, object TSRMLS_CC);
}

static int php_swoole_onTask(zanServer *serv, swEventData *req)
{
    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onTask];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        zanWarn("not set onTask callback");
        return ZAN_ERR;
    }

    zval *zfd = NULL;
    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, (long) req->info.fd);

    zval *zfrom_id = NULL;
    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, (long) req->info.from_id);

    zanDebug("type=%d, worker_id=%d", ServerG.process_type, ServerWG.worker_id);
    zval* zdata = php_swoole_get_task_result(req TSRMLS_CC);

    zval **args[4];
    zval *zserv = (zval *) serv->ptr2;
    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                    &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onTask handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_free(zdata);

    if (retval)
    {
        if (SW_Z_TYPE_P(retval) != IS_NULL)  php_swoole_task_finish(serv, retval TSRMLS_CC);
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

static int php_swoole_onFinish(zanServer *serv, swEventData *req)
{
    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onFinish];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        zanWarn("not set onFinish callback");
        return ZAN_ERR;
    }

    zval *ztask_id = NULL;
    SW_MAKE_STD_ZVAL(ztask_id);
    ZVAL_LONG(ztask_id, (long) req->info.fd);

    zval * zdata = php_swoole_get_task_result(req TSRMLS_CC);
    zval **args[3];
    zval *zserv = (zval *) serv->ptr2;
    args[0] = &zserv;
    args[1] = &ztask_id;
    args[2] = &zdata;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL,callback,
                                        &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onFinish handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&ztask_id);
    sw_zval_free(zdata);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

static zval* php_swoole_get_task_result(swEventData *task_result TSRMLS_DC)
{
    zval *result_data = NULL;
    char *result_data_str = NULL;
    int result_data_len = 0;

    int data_len = -1;
    char *data_str = NULL;

    /// Large result package
    if (swTask_type(task_result) & ZAN_TASK_TMPFILE)
    {
        swTaskWorker_large_unpack(task_result, emalloc, data_str, data_len);

        /// unpack failed
        if (data_len <= 0 || !data_str)
        {
            goto result;
        }

        result_data_str = data_str;
        result_data_len = data_len;
    }
    else
    {
        result_data_str = task_result->data;
        result_data_len = task_result->info.len;
    }

    if (swTask_type(task_result) & ZAN_TASK_SERIALIZE)
    {
        php_unserialize_data_t var_hash;
        PHP_VAR_UNSERIALIZE_INIT(var_hash);
        zval *result_unserialized_data = NULL;
        SW_ALLOC_INIT_ZVAL(result_unserialized_data);

        if (sw_php_var_unserialize(&result_unserialized_data, (const unsigned char **) &result_data_str,
            (const unsigned char *) (result_data_str + result_data_len), &var_hash TSRMLS_CC))
        {
            result_data = result_unserialized_data;
        }
        else
        {
            sw_zval_free(result_unserialized_data);
            SW_ALLOC_INIT_ZVAL(result_data);
            SW_ZVAL_STRINGL(result_data, result_data_str, result_data_len, 1);
        }

        PHP_VAR_UNSERIALIZE_DESTROY(var_hash);
    }
    else
    {
        SW_ALLOC_INIT_ZVAL(result_data);
        SW_ZVAL_STRINGL(result_data, result_data_str, result_data_len, 1);
    }

result:
    if (data_str)
    {
        swoole_efree(data_str);
    }

    return result_data;
}

static int php_swoole_task_finish(zanServer *serv, zval *data TSRMLS_DC)
{
    char *data_str = NULL;
    int data_len = 0;

    //need serialize
    int flags = 0;
    smart_str serialized_data = {0};
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        flags |= ZAN_TASK_SERIALIZE;

        //serialize
        php_serialize_data_t var_hash;
        PHP_VAR_SERIALIZE_INIT(var_hash);
        sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

#if PHP_MAJOR_VERSION<7
        data_str = serialized_data.c;
        data_len = serialized_data.len;
#else
        data_str = serialized_data.s->val;
        data_len = serialized_data.s->len;
#endif
    }
    else
    {
        data_str = Z_STRVAL_P(data);
        data_len = Z_STRLEN_P(data);
    }

    int ret = zanTaskworker_finish(data_str, data_len, flags);
    smart_str_free(&serialized_data);
    return ret;
}

static int php_swoole_task_setBuf(zval *data,swEventData *buf TSRMLS_DC)
{
    buf->info.type = SW_EVENT_TASK;

    //task_id
    buf->info.fd = php_swoole_task_id++;

    //source worker_id
    buf->info.from_id  = ServerWG.worker_id;
    swTask_type(buf) |= ZAN_TASK_NONBLOCK;

    char *task_data_str = NULL;
    int task_data_len = 0;
    smart_str serialized_data = {0};

    //need serialize
    if (SW_Z_TYPE_P(data) != IS_STRING)
    {
        //serialize
        swTask_type(buf) |= ZAN_TASK_SERIALIZE;
        //TODO php serialize
        php_serialize_data_t var_hash;
        PHP_VAR_SERIALIZE_INIT(var_hash);
        sw_php_var_serialize(&serialized_data, data, &var_hash TSRMLS_CC);
        PHP_VAR_SERIALIZE_DESTROY(var_hash);

#if PHP_MAJOR_VERSION<7
        task_data_str = serialized_data.c;
        task_data_len = serialized_data.len;
#else
        task_data_str = serialized_data.s->val;
        task_data_len = serialized_data.s->len;
#endif
    }
    else
    {
        task_data_str = Z_STRVAL_P(data);
        task_data_len = Z_STRLEN_P(data);
    }

    //write to file
    if (task_data_len >= SW_IPC_MAX_SIZE - sizeof(buf->info) &&
        swTaskWorker_large_pack(buf, task_data_str, task_data_len) < 0)
    {
        smart_str_free(&serialized_data);
        zanWarn("large task pack failed(), task_data_len=%d", task_data_len);
        return ZAN_ERR;
    }
    else
    {
        memcpy(buf->data, task_data_str, task_data_len);
        buf->info.len = task_data_len;
    }

    smart_str_free(&serialized_data);
    return ZAN_OK;
}

void php_swoole_onConnect(zanServer *serv, swDataHead *info)
{
    SWOOLE_FETCH_TSRMLS;

    zanTrace("onConnect in, fd=%d, from_fd=%d, from_id=%d, from_netid=%d, type=%d, worker_id=%d",
             info->fd, info->from_fd, info->from_id, info->networker_id, info->type, info->worker_id);

    zval *callback = php_swoole_server_get_callback(serv, info->from_fd, info->networker_id, SW_SERVER_CB_onConnect);
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zfd = NULL;
    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    zval *zfrom_id = NULL;
    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, info->networker_id);  ///TODO

    zval *zserv = (zval *) serv->ptr2;

    zval **args[3];
    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onConnect handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    zanTrace("onConnect out, fd=%d, from_fd=%d, networker_id=%d", info->fd, info->from_fd, info->networker_id);
}

int php_swoole_onReceive(zanServer *serv, swEventData *req)
{
    SWOOLE_FETCH_TSRMLS;

    zval *callback = php_swoole_server_get_callback(serv, req->info.from_fd, req->info.networker_id, SW_SERVER_CB_onReceive);
    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        return ZAN_OK;
    }

    zval *zfd = NULL;
    zval *zfrom_id = NULL;
    zval *zdata = NULL;
    SW_MAKE_STD_ZVAL(zfd);
    SW_MAKE_STD_ZVAL(zfrom_id);
    SW_MAKE_STD_ZVAL(zdata);

    //dgram
    if (swEventData_is_dgram(req->info.type))
    {
        //TODO
        swString *buffer = zanWorker_get_buffer(req->info.from_id);
        swDgramPacket *packet = (swDgramPacket*) buffer->str;

        //UDP使用from_id作为port,fd做为ip
        php_swoole_udp_t udp_info;
        if (req->info.type == SW_EVENT_UDP)
        {
            //udp ipv4
            udp_info.from_fd = req->info.from_fd;
            udp_info.port = packet->port;
            memcpy(&udp_server_socket, &udp_info, sizeof(udp_server_socket));

            zanTrace("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);
            SW_ZVAL_STRINGL(zdata, packet->data, packet->length, 1);
            ZVAL_LONG(zfrom_id, (long ) udp_server_socket);
            ZVAL_LONG(zfd, (long ) packet->addr.v4.s_addr);
        }
        //udp ipv6
        else if (req->info.type == SW_EVENT_UDP6)
        {
            udp_info.from_fd = req->info.from_fd;
            udp_info.port = packet->port;
            memcpy(&dgram_server_socket, &udp_info, sizeof(udp_server_socket));

            zanDebug("SendTo: from_id=%d|from_fd=%d", (uint16_t) req->info.from_id, req->info.from_fd);
            ZVAL_LONG(zfrom_id, (long ) dgram_server_socket);
            char tmp[SW_IP_MAX_LENGTH] = {0};
            inet_ntop(AF_INET6, &packet->addr.v6, tmp, sizeof(tmp));
            SW_ZVAL_STRING(zfd, tmp, 1);
            SW_ZVAL_STRINGL(zdata, packet->data, packet->length, 1);
        }
        //unix dgram
        else
        {
            SW_ZVAL_STRINGL(zfd, packet->data, packet->addr.un.path_length, 1);
            SW_ZVAL_STRINGL(zdata, packet->data + packet->addr.un.path_length, packet->length - packet->addr.un.path_length, 1);
            ZVAL_LONG(zfrom_id, (long ) req->info.from_fd);
            dgram_server_socket = req->info.from_fd;
        }
    }
    //stream
    else
    {
        ///ZVAL_LONG(zfrom_id, (long ) req->info.from_id);
        ZVAL_LONG(zfrom_id, (long ) req->info.networker_id);  ///TODO
        ZVAL_LONG(zfd, (long ) req->info.fd);
        int headlen = (ServerG.serv->packet_mode == 1)? 4:0;
        php_swoole_get_recv_data(zdata, req, NULL,headlen TSRMLS_CC);
    }

    zval **args[4];
    zval* zserv = (zval *) serv->ptr2;
    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;
    args[3] = &zdata;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 4, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onReceive handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);
    sw_zval_ptr_dtor(&zdata);
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

static void php_swoole_onPipeMessage(zanServer *serv, swEventData *req)
{
    SWOOLE_FETCH_TSRMLS;

    zval* callback = php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zserv = (zval *) serv->ptr2;
    zval *zworker_id = NULL;
    SW_MAKE_STD_ZVAL(zworker_id);
    ZVAL_LONG(zworker_id, (long) req->info.from_id);

    zval *zdata = php_swoole_get_task_result(req TSRMLS_CC);

    zval **args[3];
    args[0] = &zserv;
    args[1] = &zworker_id;
    args[2] = &zdata;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback,
                                 &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onPipeMessage handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zworker_id);
    sw_zval_free(zdata);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static int php_swoole_onPacket(zanServer *serv, swEventData *req)
{
    SWOOLE_FETCH_TSRMLS;

    zval *callback = php_swoole_server_get_callback(serv, req->info.from_fd, req->info.networker_id, SW_SERVER_CB_onPacket);
    if (!callback || ZVAL_IS_NULL(callback))
    {
        swoole_php_fatal_error(E_WARNING, "onPacket callback is null.");
        return ZAN_ERR;
    }

    zval *zdata = NULL;
    zval *zaddr = NULL;

    SW_MAKE_STD_ZVAL(zdata);
    SW_MAKE_STD_ZVAL(zaddr);

    array_init(zaddr);
    add_assoc_long(zaddr, "server_socket", req->info.from_fd);

    //udp ipv4
    zanDebug("networker_id=%d, from_id=%d, networker_num=%d, worker_num=%d", req->info.networker_id, req->info.from_id, ServerG.servSet.net_worker_num, ServerG.servSet.worker_num);
    swString *buffer = zanWorker_get_buffer(req->info.from_id);
    swDgramPacket *packet = (swDgramPacket*) buffer->str;
    if (req->info.type == SW_EVENT_UDP)
    {
        char tmp[SW_IP_MAX_LENGTH] = {0};
        inet_ntop(AF_INET, &packet->addr.v4, tmp, sizeof(tmp));
        sw_add_assoc_string(zaddr, "address", tmp, 1);
        add_assoc_long(zaddr, "port", packet->port);
        SW_ZVAL_STRINGL(zdata, packet->data, packet->length, 1);
    }
    //udp ipv6
    else if (req->info.type == SW_EVENT_UDP6)
    {
        char tmp[SW_IP_MAX_LENGTH] = {0};
        inet_ntop(AF_INET6, &packet->addr.v6, tmp, sizeof(tmp));
        sw_add_assoc_string(zaddr, "address", tmp, 1);
        add_assoc_long(zaddr, "port", packet->port);
        SW_ZVAL_STRINGL(zdata, packet->data, packet->length, 1);
    }
    //unix dgram
    else if (req->info.type == SW_EVENT_UNIX_DGRAM)
    {
        sw_add_assoc_stringl(zaddr, "address", packet->data, packet->addr.un.path_length, 1);
        SW_ZVAL_STRINGL(zdata, packet->data + packet->addr.un.path_length, packet->length - packet->addr.un.path_length, 1);
        dgram_server_socket = req->info.from_fd;
    }

    zval **args[3];
    zval *zserv = (zval *) serv->ptr2;
    args[0] = &zserv;
    args[1] = &zdata;
    args[2] = &zaddr;
    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_server: onPacket handler error");
    }
    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    sw_zval_ptr_dtor(&zaddr);
    sw_zval_ptr_dtor(&zdata);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

void php_swoole_onClose(zanServer *serv, swDataHead *info)
{
    SWOOLE_FETCH_TSRMLS;

    zval *callback = php_swoole_server_get_callback(serv, info->from_fd, info->networker_id, SW_SERVER_CB_onClose);
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zfd = NULL;
    SW_MAKE_STD_ZVAL(zfd);
    ZVAL_LONG(zfd, info->fd);

    zval *zfrom_id = NULL;
    SW_MAKE_STD_ZVAL(zfrom_id);
    ZVAL_LONG(zfrom_id, info->networker_id);  ///TODO

    zval *zserv = (zval *) serv->ptr2;

    zval **args[3];
    args[0] = &zserv;
    args[1] = &zfd;
    args[2] = &zfrom_id;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 3,
                                                args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("onClose handler error");
    }

    if (EG(exception))
    {
        ServerWG.fatal_error = 1;
    }

    sw_zval_ptr_dtor(&zfd);
    sw_zval_ptr_dtor(&zfrom_id);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static sw_inline int php_swoole_check_task_param(int dst_worker_id TSRMLS_DC)
{
    if (ServerG.servSet.task_worker_num < 1)
    {
        zanWarn("Task method cannot use, Please set task_worker_num=%d", ServerG.servSet.task_worker_num);
        return ZAN_ERR;
    }

    int task_worker_num = (int)ServerG.servSet.task_worker_num;
    if (dst_worker_id >= task_worker_num)
    {
        zanWarn("dst_worker_id=%d must be less than servSet.task_worker_num=%d.", dst_worker_id, task_worker_num);
        return ZAN_ERR;
    }

    /// should be worker
    if (!is_worker())
    {
        zanWarn("The method can only be used in the worker process.");
        return ZAN_ERR;
    }

    return ZAN_OK;
}

static zval* php_swoole_server_add_port(swListenPort *port TSRMLS_DC)
{
    zval *port_object = NULL;
    SW_ALLOC_INIT_ZVAL(port_object);
    object_init_ex(port_object, swoole_server_port_class_entry_ptr);
    server_port_list.zobjects[server_port_list.num++] = port_object;

    swoole_server_port_property *property = emalloc(sizeof(swoole_server_port_property));
    bzero(property, sizeof(swoole_server_port_property));
    swoole_set_property(port_object, swoole_property_common, property);
    swoole_set_object(port_object, port);

    zend_update_property_string(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("host"), port->host TSRMLS_CC);
    zend_update_property_long(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("port"), port->port TSRMLS_CC);
    zend_update_property_long(swoole_server_port_class_entry_ptr, port_object, ZEND_STRL("type"), port->type TSRMLS_CC);

    add_next_index_zval(server_port_list.zports, port_object);

    return port_object;
}

void php_swoole_register_callback(zanServer *serv)
{
    serv->onReceive = php_swoole_onReceive;

    if (php_sw_server_callbacks[SW_SERVER_CB_onStart])
    {
        serv->onStart = php_swoole_onStart;
    }

    serv->onShutdown = php_swoole_onShutdown;
    serv->onWorkerStart = php_swoole_onWorkerStart;

    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerStop])
    {
        serv->onWorkerStop = php_swoole_onWorkerStop;
    }

    /// UDP Packet
    if (php_sw_server_callbacks[SW_SERVER_CB_onPacket])
    {
        serv->onPacket = php_swoole_onPacket;
    }

    /// Task Worker
    if (php_sw_server_callbacks[SW_SERVER_CB_onTask])
    {
        serv->onTask = php_swoole_onTask;
    }
    if (php_sw_server_callbacks[SW_SERVER_CB_onFinish])
    {
        serv->onFinish = php_swoole_onFinish;
    }

    if (php_sw_server_callbacks[SW_SERVER_CB_onWorkerError])
    {
        serv->onWorkerError = php_swoole_onWorkerError;
    }

    if (php_sw_server_callbacks[SW_SERVER_CB_onPipeMessage])
    {
        serv->onPipeMessage = php_swoole_onPipeMessage;
    }
}

void php_swoole_sha1(const char *str, int _len, unsigned char *digest)
{
    PHP_SHA1_CTX context;
    PHP_SHA1Init(&context);
    PHP_SHA1Update(&context, (unsigned char *) str, _len);
    PHP_SHA1Final(digest, &context);
}

int swoole_check_callable(zval *callback TSRMLS_DC)
{
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return ZAN_ERR;
    }

    char *func_name = NULL;
    int iRet = sw_zend_is_callable(callback, 0, &func_name TSRMLS_CC)? ZAN_OK:ZAN_ERR;

    if (func_name)
    {
        if (iRet < 0) swoole_php_fatal_error(E_ERROR, "Function '%s' is not callable", func_name);
        swoole_efree(func_name);
    }

    return iRet;
}

/******************************************************************************/
PHP_METHOD(swoole_server, __construct)
{
    //only cli env
    if (strcasecmp("cli", sapi_module.name) != 0)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_server must run at php_cli environment.");
        RETURN_FALSE;
    }

    if (ServerGS->started > 0)
    {
        zanWarn("server is already running. Unable to create swoole_server.");
        RETURN_FALSE;
    }

    zend_size_t host_len = 0;
    char *serv_host = NULL;
    long serv_port  = -1;
    long sock_type  = ZAN_SOCK_TCP;
    long serv_mode  = ZAN_MODE_PROCESS;

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl|ll", &serv_host,
                                         &host_len, &serv_port, &serv_mode, &sock_type))
    {
        swoole_php_fatal_error(E_ERROR, "invalid parameters.");
        RETURN_FALSE;
    }

    ServerG.factory_mode = serv_mode;
    zanServer *serv = sw_malloc(sizeof(zanServer));
    if (!serv)
    {
        swoole_php_fatal_error(E_ERROR, "malloc zanServer failed.");
        RETURN_FALSE;
    }
    zanServer_init(serv);

    swListenPort *port = zanServer_add_port(serv, sock_type, serv_host, serv_port);
    if (!port)
    {
        swoole_php_fatal_error(E_ERROR, "listen server port failed.");
        RETURN_FALSE;
    }

    bzero(php_sw_server_callbacks, sizeof (zval*) * PHP_SERVER_CALLBACK_NUM);
    zval* server_object = getThis();

#ifdef HAVE_PCRE
    zval *connection_iterator_object = NULL;
    SW_MAKE_STD_ZVAL(connection_iterator_object);
    object_init_ex(connection_iterator_object, swoole_connection_iterator_class_entry_ptr);
    zend_update_property(swoole_server_class_entry_ptr, server_object,
                         ZEND_STRL("connections"), connection_iterator_object TSRMLS_CC);
#endif

    zend_update_property_stringl(swoole_server_class_entry_ptr, server_object,
                                 ZEND_STRL("host"), serv_host, host_len TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object,
                               ZEND_STRL("port"), serv_port TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object,
                              ZEND_STRL("mode"), serv_mode TSRMLS_CC);
    zend_update_property_long(swoole_server_class_entry_ptr, server_object,
                              ZEND_STRL("type"), sock_type TSRMLS_CC);

    swoole_set_object(server_object, serv);

    zval *ports = NULL;
    SW_ALLOC_INIT_ZVAL(ports);
    array_init(ports);
    server_port_list.zports = ports;

    php_swoole_server_add_port(port TSRMLS_CC);
    zend_update_property(swoole_server_class_entry_ptr, server_object, ZEND_STRL("ports"), ports TSRMLS_CC);
}

PHP_METHOD(swoole_server, set)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. Unable to execute swoole_server_set now.");
        RETURN_FALSE;
    }

    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zset))
    {
        zanWarn("set: parameters error");
        RETURN_FALSE;
    }

    zval *zobject = getThis();
    zanServer *serv = ServerG.serv; //swoole_get_object(zobject);
    if (!serv)
    {
        zanWarn("servers is not created.");
        RETURN_FALSE;
    }

    php_swoole_array_separate(zset);
    HashTable *vht = Z_ARRVAL_P(zset);

    zanServerSet *servSet = &(ServerG.servSet);

    //chroot
    zval *value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("chroot"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }
        servSet->chroot = strndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    //user
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("user"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }
        servSet->user = strndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    //group
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("group"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }
        servSet->group = strndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    //daemonize
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("daemonize"), (void **) &value) == SUCCESS)
    {
        zan_convert_to_boolean(value);
        servSet->daemonize = (uint16_t)Z_BVAL_P(value);
    }

    //net_worker_num
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("net_worker_num"), (void **) &value) == SUCCESS)
    {
        zan_convert_to_long(value);
        servSet->net_worker_num = (uint32_t) Z_LVAL_P(value);
    }

    //worker_num
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("worker_num"), (void **) &value) == SUCCESS)
    {
        zan_convert_to_long(value);
        servSet->worker_num = (uint32_t) Z_LVAL_P(value);
    }

    //dispatch_mode
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("dispatch_mode"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->dispatch_mode = (uint8_t) Z_LVAL_P(value);
    }

    //log_file
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("log_file"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }
        servSet->log_file = strndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
    }

    //set log level
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("log_level"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->log_level = (uint8_t) Z_LVAL_P(value);
        zan_set_loglevel((uint8_t) Z_LVAL_P(value));
    }

    /// for dispatch_mode = 1/3
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("discard_timeout_request"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        servSet->discard_timeout_request = (uint16_t)Z_BVAL_P(value);
    }

    //onConnect/onClose event
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("enable_unsafe_event"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        servSet->enable_unsafe_event = (uint16_t)Z_BVAL_P(value);
    }

    //port reuse
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("enable_reuse_port"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        servSet->enable_reuse_port = (uint16_t)Z_BVAL_P(value);
    }

    //task_worker_num
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("task_worker_num"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->task_worker_num = (uint32_t) Z_LVAL_P(value);
    }

    //task ipc mode, 1,2,3
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("task_ipc_mode"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->task_ipc_mode = (uint8_t) Z_LVAL_P(value);
    }

    /// Temporary file directory for task_worker
    servSet->task_tmpdir = strndup(SW_TASK_TMP_FILE, sizeof (SW_TASK_TMP_FILE));
    servSet->task_tmpdir_len = sizeof (SW_TASK_TMP_FILE);
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("task_tmpdir"), (void **) &value) == SUCCESS)
    {
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }

        servSet->task_tmpdir = emalloc(SW_TASK_TMPDIR_SIZE);
        servSet->task_tmpdir_len = snprintf(servSet->task_tmpdir, SW_TASK_TMPDIR_SIZE,
                                            "%s/task.XXXXXX", Z_STRVAL_P(value)) + 1;

        if (servSet->task_tmpdir_len > SW_TASK_TMPDIR_SIZE - 1)
        {
            swoole_php_fatal_error(E_ERROR, "task_tmpdir is too long, max size is %d.", SW_TASK_TMPDIR_SIZE - 1);
            RETURN_FALSE;
        }
    }

    //task_max_request
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("task_max_request"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->task_max_request = (uint32_t) Z_LVAL_P(value);
    }
    //max_connection
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("max_connection"), (void **) &value) == SUCCESS ||
        sw_zend_hash_find(vht, ZEND_STRS("max_conn"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->max_connection = (uint32_t) Z_LVAL_P(value);
    }
    //heartbeat_check_interval
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_check_interval"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->heartbeat_check_interval = (uint16_t) Z_LVAL_P(value);
    }
    //heartbeat idle time
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("heartbeat_idle_time"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->heartbeat_idle_time = (uint16_t) Z_LVAL_P(value);

        if (servSet->heartbeat_check_interval > servSet->heartbeat_idle_time)
        {
            zanWarn("heartbeat_idle_time must be greater than heartbeat_check_interval.");
            servSet->heartbeat_check_interval = servSet->heartbeat_idle_time / 2;
        }
    }
    else if (servSet->heartbeat_check_interval > 0)
    {
        servSet->heartbeat_idle_time = servSet->heartbeat_check_interval * 2;
    }
    //max_request
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("max_request"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->max_request = (uint32_t) Z_LVAL_P(value);
    }
    //cpu affinity
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("open_cpu_affinity"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        servSet->open_cpu_affinity = (uint16_t)Z_BVAL_P(value);
    }
    //cpu affinity set
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("cpu_affinity_ignore"), (void **) &value) == SUCCESS)
    {
        uint32_t ignore_num = zend_hash_num_elements(Z_ARRVAL_P(value));
        if (ignore_num >= ZAN_CPU_NUM)
        {
            swoole_php_fatal_error(E_ERROR, "cpu_affinity_ignore num must be less than cpu num (%d)", ZAN_CPU_NUM);
            RETURN_FALSE;
        }

        uint32_t available_num = ZAN_CPU_NUM - ignore_num;
        uint32_t *available_cpu = (uint32_t *) sw_malloc(sizeof(int) * available_num);
        uint32_t index = 0;
        uint32_t available_i = 0;
        for (index = 0; index < ZAN_CPU_NUM; index++)
        {
            uint32_t flag = 1;
            zval *zval_core = NULL;
            SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(value), zval_core)
                if (index == (int) Z_LVAL_P(zval_core))
                {
                    flag = 0;
                    break;
                }
            SW_HASHTABLE_FOREACH_END();
            if (flag)
            {
                available_cpu[available_i] = index;
                available_i++;
            }
        }

        serv->cpu_affinity_available_num = available_num;
        serv->cpu_affinity_available = available_cpu;
    }

    /// buffer input size
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_input_size"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->buffer_input_size = (uint32_t) Z_LVAL_P(value);
    }

    /// buffer output size
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("buffer_output_size"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->buffer_output_size = (uint32_t) Z_LVAL_P(value);
    }

    /// set pipe memory buffer size
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("pipe_buffer_size"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->pipe_buffer_size = (uint32_t) Z_LVAL_P(value);
    }

    //message queue key
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("message_queue_key"), (void **) &value) == SUCCESS)
    {
        convert_to_long(value);
        servSet->message_queue_key = (uint64_t) Z_LVAL_P(value);
    }

    //paser x-www-form-urlencoded form data
    value = NULL;
    if (sw_zend_hash_find(vht, ZEND_STRS("http_parse_post"), (void **) &value) == SUCCESS)
    {
        convert_to_boolean(value);
        servSet->http_parse_post = (uint16_t)Z_BVAL_P(value);
    }

    zval *retval = NULL;
    zval *port_object = server_port_list.zobjects[0];

    sw_zval_add_ref(&port_object);
    //sw_zval_add_ref(&zset);
    sw_zval_add_ref(&zobject);

    sw_zend_call_method_with_1_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "set", &retval, zset);
    zend_update_property(swoole_server_class_entry_ptr, zobject, ZEND_STRL("setting"), zset TSRMLS_CC);

    sw_zval_ptr_dtor(&zset);

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, on)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. Unable to set event callback now.");
        RETURN_FALSE;
    }

    zval *zobject = getThis();
    zanServer *serv = swoole_get_object(zobject);
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zval *name = NULL;
    zval *cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "zz", &name, &cb))
    {
        zanWarn("zend_parse_parameters failed.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(cb TSRMLS_CC) < 0)
    {
        zanWarn("check callable failed.");
        RETURN_FALSE ;
    }

    if (sw_convert_to_string(name) < 0)
    {
        zanWarn("convert to string failed.");
        RETURN_FALSE;
    }

    char property_name[32] = {0};
    memcpy(property_name, "on", 2);
    int l_property_name = 2;
    int index;
    for (index = 0; index < PHP_SERVER_CALLBACK_NUM; index++)
    {
        if (NULL == swoole_server_callback[index])
        {
            continue;
        }

        if (Z_STRLEN_P(name) == strlen(swoole_server_callback[index]) &&
                strncasecmp(swoole_server_callback[index], Z_STRVAL_P(name), Z_STRLEN_P(name)) == 0)
        {
            memcpy(property_name + l_property_name, swoole_server_callback[index], Z_STRLEN_P(name));
            l_property_name += Z_STRLEN_P(name);
            property_name[l_property_name] = '\0';
            zend_update_property(swoole_server_class_entry_ptr, getThis(), property_name, l_property_name, cb TSRMLS_CC);
            php_sw_server_callbacks[index] = sw_zend_read_property(swoole_server_class_entry_ptr, getThis(), property_name,
                                                                    l_property_name, 0 TSRMLS_CC);
            sw_copy_to_stack(php_sw_server_callbacks[index], _php_sw_server_callbacks[index]);
            break;
        }
    }

    if (index == PHP_SERVER_CALLBACK_NUM)
    {
        zanWarn("Unknown event types[%s]", Z_STRVAL_P(name));
        RETURN_FALSE;
    }

    if (index < SW_SERVER_CB_onStart)
    {
        zval *port_object = server_port_list.zobjects[0];
        zval *retval = NULL;
        sw_zval_add_ref(&port_object);
        sw_zend_call_method_with_2_params(&port_object, swoole_server_port_class_entry_ptr, NULL, "on", &retval, name, cb);
        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, start)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. Unable to execute swoole_server::start.");
        RETURN_FALSE;
    }

    zval* zobject = getThis();
    zanServer *serv = swoole_get_object(zobject);
    if (!serv)
    {
        zanWarn("Server object not found.");
        RETURN_FALSE;
    }

    php_swoole_register_callback(serv);
    if (!php_sw_server_callbacks[SW_SERVER_CB_onReceive] && !php_sw_server_callbacks[SW_SERVER_CB_onPacket])
    {
        swoole_php_fatal_error(E_ERROR, "require onReceive/onPacket callback");
        RETURN_FALSE;
    }

    serv->send = zanServer_send;
    serv->ptr2 = zobject;
    sw_zval_add_ref(&zobject);

    php_swoole_server_before_start(serv, zobject TSRMLS_CC);
    if (zanServer_start(serv) < 0)
    {
        swoole_php_fatal_error(E_ERROR, "zanServer_start failed. Error");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, send)
{
    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zval *zfd = NULL;
    zval *zdata = NULL;
    long server_socket = -1;  ///udp: doc...
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &zfd, &zdata, &server_socket))
    {
        RETURN_FALSE;
    }

    char *data = NULL;
    int length = php_swoole_get_send_data(zdata, &data TSRMLS_CC);
    if (length <= 0 || !data)
    {
        zanWarn("data is invailed or empty.");
        RETURN_FALSE;
    }

    int ret = -1;
    if (serv->have_udp_sock && SW_Z_TYPE_P(zfd) == IS_STRING)
    {
        server_socket = (server_socket < 0)? dgram_server_socket:server_socket;
        //UDP IPv6
        if (strchr(Z_STRVAL_P(zfd), ':'))
        {
            php_swoole_udp_t udp_info;
            memcpy(&udp_info, &server_socket, sizeof(udp_info));
            ret = swSocket_udp_sendto6(udp_info.from_fd, Z_STRVAL_P(zfd), udp_info.port, data, length);
        }
        //UNIX DGRAM
        else if (Z_STRVAL_P(zfd)[0] == '/')
        {
            struct sockaddr_un addr_un;
            memcpy(addr_un.sun_path, Z_STRVAL_P(zfd), Z_STRLEN_P(zfd));
            addr_un.sun_family = AF_UNIX;
            addr_un.sun_path[Z_STRLEN_P(zfd)] = 0;
            ret = swSocket_sendto_blocking(server_socket, data, length, 0, (struct sockaddr *) &addr_un, sizeof(addr_un));
        }
        else
        {
            goto convert;
        }

        SW_CHECK_RETURN(ret);
    }

convert:
    convert_to_long(zfd);
    uint32_t fd = (uint32_t) Z_LVAL_P(zfd);

    if (swServer_is_udp(fd))
    {
        //UDP
        server_socket = (server_socket < 0)? udp_server_socket:server_socket;

        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &server_socket, sizeof(udp_info));

        struct sockaddr_in addr_in;
        addr_in.sin_family = AF_INET;
        addr_in.sin_port = htons(udp_info.port);
        addr_in.sin_addr.s_addr = fd;
        SW_CHECK_RETURN(swSocket_sendto_blocking(udp_info.from_fd, data, length, 0,
                                                (struct sockaddr *) &addr_in, sizeof(addr_in)));
    }
    //TCP
    else
    {
        zanDebug("tcp server->send: fd=%d, length=%d", fd, length);
        SW_CHECK_RETURN(zanServer_tcp_send(serv, fd, data, length));
    }
}

PHP_METHOD(swoole_server, sendto)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    char *ip = NULL;
    char *data = NULL;
    zend_size_t len = 0, ip_len = 0;
    long port = -1;
    long server_socket = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sls|l", &ip, &ip_len, &port, &data, &len, &server_socket))
    {
        RETURN_FALSE;
    }

    if (!data || len <= 0)
    {
        zanWarn("data is empty.");
        RETURN_FALSE;
    }

    zend_bool ipv6 = (strchr(ip, ':'))? 1:0;

    if ((!ipv6 && serv->udp_socket_ipv4 <= 0) || (ipv6 && serv->udp_socket_ipv6 <= 0))
    {
        zanWarn("You must use Rigth socket type to server before using sendto.");
        RETURN_FALSE;
    }

    server_socket = ipv6 ?  serv->udp_socket_ipv6 : serv->udp_socket_ipv4;

    int ret = (ipv6)?swSocket_udp_sendto6(server_socket, ip, port, data, len):
                     swSocket_udp_sendto(server_socket, ip, port, data, len);

    SW_CHECK_RETURN(ret);
}

PHP_METHOD(swoole_server, listen)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. cannot add listener.");
        RETURN_FALSE;
    }

    char *host = NULL;
    zend_size_t host_len = 0;
    long sock_type = 0;
    long port = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sll", &host, &host_len, &port, &sock_type))
    {
        RETURN_FALSE;
    }

    zanServer *serv = swoole_get_object(getThis());
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    swListenPort *lsPort = zanServer_add_port(serv, (int) sock_type, host, (int) port);
    if (!lsPort)
    {
        zanWarn("add port failed.");
        RETURN_FALSE;
    }

    zval *port_object = php_swoole_server_add_port(lsPort TSRMLS_CC);
    RETURN_ZVAL(port_object, 1, NULL);
}

PHP_METHOD(swoole_server, addProcess)
{
    if (ServerGS->started > 0)
    {
        zanWarn("Server is running. cannot add process.");
        RETURN_FALSE;
    }

    zval *process = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &process))
    {
        return;
    }

    if (!process || ZVAL_IS_NULL(process))
    {
        zanWarn("parameter 1 cannot be empty.");
        RETURN_FALSE;
    }

    if (!instanceof_function(Z_OBJCE_P(process), swoole_process_class_entry_ptr TSRMLS_CC))
    {
        swoole_php_fatal_error(E_ERROR, "object is not instanceof swoole_process.");
        RETURN_FALSE;
    }

    zanServer *serv = swoole_get_object(getThis());
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    serv->onUserWorkerStart = (!serv->onUserWorkerStart)? php_swoole_onUserWorkerStart:
                              serv->onUserWorkerStart;

#if PHP_MAJOR_VERSION >= 7
    zval *tmp_process = emalloc(sizeof(zval));
    memcpy(tmp_process, process, sizeof(zval));
    process = tmp_process;
#endif

    sw_zval_add_ref(&process);

    zanWorker *worker = swoole_get_object(process);
    if (!worker){
        zanWarn("get object form process failed.");
        RETURN_FALSE;
    }

    worker->ptr = process;

    int id = zanServer_adduserworker(serv, worker);
    if (id < 0)
    {
        zanWarn("swServer add worker failed.");
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_process_class_entry_ptr, process, ZEND_STRL("id"), id TSRMLS_CC);
    RETURN_LONG(id);
}

PHP_METHOD(swoole_server, sendfile)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

#ifdef __CYGWIN__
    zanWarn("cannot use swoole_server->sendfile() in cygwin.");
    RETURN_FALSE;
#endif

    zend_size_t len = 0;
    char *filename = NULL;
    long fd = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ls", &fd, &filename, &len))
    {
        RETURN_FALSE;
    }

    //check fd
    if (fd <= 0 || fd > SW_MAX_SOCKET_ID)
    {
        zanWarn("invalid fd[%ld].", fd);
        RETURN_FALSE;
    }

    SW_CHECK_RETURN(zanServer_tcp_sendfile(serv, (int) fd, filename, len));
}

PHP_METHOD(swoole_server, close)
{
    if (is_master())
    {
        zanWarn("Cannot close connection in master process.");
        RETURN_FALSE;
    }

    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zval *zfd = NULL;
    zend_bool reset = SW_FALSE;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|b", &zfd, &reset))
    {
        return;
    }

    convert_to_long(zfd);

    //Reset send buffer, Immediately close the connection.
    if (reset)
    {
        swConnection *conn = zanServer_verify_connection(serv, Z_LVAL_P(zfd));
        if (!conn)
        {
            RETURN_FALSE;
        }

        conn->close_reset = 1;
    }

    SW_CHECK_RETURN(serv->factory.end(&serv->factory, Z_LVAL_P(zfd)));
}

PHP_METHOD(swoole_server, stats)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    array_init(return_value);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("start_time"), ServerStatsG->start_time);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("last_reload"), ServerStatsG->last_reload);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("connection_num"), ServerStatsG->connection_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("accept_count"), ServerStatsG->accept_count);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("close_count"), ServerStatsG->close_count);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("tasking_num"), ServerStatsG->tasking_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("request_count"), ServerStatsG->request_count);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("total_worker"), ServerG.servSet.worker_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("total_task_worker"), ServerG.servSet.task_worker_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("total_net_worker"), ServerG.servSet.net_worker_num);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("active_worker"), ServerStatsG->active_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("idle_worker"), ServerG.servSet.worker_num - ServerStatsG->active_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("active_task_worker"), ServerStatsG->active_task_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("idle_task_worker"), ServerG.servSet.task_worker_num - ServerStatsG->active_task_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("max_active_worker"), ServerStatsG->max_active_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("max_active_task_worker"), ServerStatsG->max_active_task_worker);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("worker_normal_exit"), ServerStatsG->worker_normal_exit);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("worker_abnormal_exit"), ServerStatsG->worker_abnormal_exit);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("task_worker_normal_exit"), ServerStatsG->task_worker_normal_exit);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("task_worker_abnormal_exit"), ServerStatsG->task_worker_abnormal_exit);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("net_worker_normal_exit"), ServerStatsG->net_worker_normal_exit);
    sw_add_assoc_long_ex(return_value, ZEND_STRS("net_worker_abnormal_exit"), ServerStatsG->net_worker_abnormal_exit);

    // workers_detail
    int i = 0;
    zanWorker *worker = NULL;
    zval *workers_detail, *worker_stats;
    SW_MAKE_STD_ZVAL(workers_detail);
    SW_MAKE_STD_ZVAL(worker_stats);
    array_init(workers_detail);

    for (; i < ServerG.servSet.worker_num + ServerG.servSet.task_worker_num; ++i) {
        array_init(worker_stats);
        worker = zanServer_get_worker(serv, i);

        sw_add_assoc_long_ex(worker_stats, ZEND_STRS("start_time"), ServerStatsG->workers_state[i].start_time);
        sw_add_assoc_long_ex(worker_stats, ZEND_STRS("total_request_count"), ServerStatsG->workers_state[i].total_request_count);
        sw_add_assoc_long_ex(worker_stats, ZEND_STRS("request_count"), ServerStatsG->workers_state[i].request_count);
        sw_add_assoc_stringl_ex(worker_stats, ZEND_STRS("status"),
                worker->status == ZAN_WORKER_BUSY ? "BUSY" : "IDLE", 4, 0);
        if (i < ServerG.servSet.worker_num) {
            sw_add_assoc_stringl_ex(worker_stats, ZEND_STRS("type"),ZEND_STRL("worker"), 0);
        } else {
            sw_add_assoc_stringl_ex(worker_stats, ZEND_STRS("type"),ZEND_STRL("task_worker"), 0);
        }
#if PHP_MAJOR_VERSION < 7
        zval **dest;
        zend_hash_index_update(Z_ARRVAL_P(workers_detail), i, (void *)&worker_stats, sizeof(zval *), (void **)&dest);
        if (dest) {
            sw_zval_add_ref(dest);
        }
    }
    zend_hash_add(Z_ARRVAL_P(return_value), "workers_detail", sizeof("workers_detail") - 1, (void **)&workers_detail, sizeof(zval *), NULL);
#else
        zend_hash_index_add(Z_ARRVAL_P(workers_detail), i, worker_stats);
    }
    zend_hash_str_add(Z_ARRVAL_P(return_value), "workers_detail", sizeof("workers_detail") - 1, (void *)workers_detail);
#endif

    if (ServerG.servSet.task_ipc_mode > ZAN_IPC_UNSOCK)
    {
        int queue_num = -1;
        int queue_bytes = -1;
        if (zanMsgQueue_stat(ServerGS->task_workers.queue, &queue_num, &queue_bytes) == 0)
        {
            sw_add_assoc_long_ex(return_value, ZEND_STRS("task_queue_num"), queue_num);
            sw_add_assoc_long_ex(return_value, ZEND_STRS("task_queue_bytes"), queue_bytes);
        }
    }
}

PHP_METHOD(swoole_server, reload)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zval* zobject = getThis();
    zanServer *serv = swoole_get_object(zobject);
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zend_bool only_reload_taskworker = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &only_reload_taskworker))
    {
        return;
    }

    if (swKill(ServerGS->master_pid, only_reload_taskworker ? SIGUSR2 : SIGUSR1) < 0)
    {
        zanSysError("kill() failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, heartbeat)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zval* zobject = getThis();
    zanServer *serv = swoole_get_object(zobject);
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zend_bool close_connection = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &close_connection))
    {
        return;
    }

    if (ServerG.servSet.heartbeat_idle_time < 1)
    {
        RETURN_FALSE;
    }

    int checktime = (int) (ServerGS->server_time - (time_t)(ServerG.servSet.heartbeat_idle_time));

    int tempfd = 0;
    for(int networker_index = 0; networker_index < ServerG.servSet.net_worker_num; ++networker_index)
    {
        int serv_maxfd = zanServer_get_maxfd(serv, networker_index);
        int serv_minfd = zanServer_get_minfd(serv, networker_index);
        array_init(return_value);

        for (tempfd = serv_minfd; tempfd <= serv_maxfd && tempfd >= 2; ++tempfd)
        {
            zanDebug("heartbeat check fd=%d", tempfd);
            swConnection *conn = &serv->connection_list[networker_index][tempfd];

            if (conn->active && conn->last_time < checktime)
            {
                conn->close_force = 1;
                /**
                 * Close the connection
                 */
                if (close_connection)
                {
                    serv->factory.end(&serv->factory, tempfd);
                }
#ifdef SW_REACTOR_USE_SESSION
                add_next_index_long(return_value, conn->session_id);
#else
                add_next_index_long(return_value, tempfd);
#endif
            }
        }
    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, task)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zval *data = NULL;
    long dst_worker_id = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &data, &dst_worker_id))
    {
        return;
    }

    if (php_swoole_check_task_param(dst_worker_id TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    swEventData buf;
    memset(&buf,0x00,sizeof(swEventData));
    if (php_swoole_task_setBuf(data,&buf TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    if (zanPool_dispatch_to_taskworker(&ServerGS->task_workers, &buf, (int*) &dst_worker_id) < 0)
    {
        RETURN_FALSE;
    }

    RETURN_LONG(buf.info.fd);
}

PHP_METHOD(swoole_server, sendMessage)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    char *msg = NULL;
    zend_size_t msglen = 0;
    long worker_id = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sl", &msg, &msglen, &worker_id))
    {
        RETURN_FALSE;
    }

    if (worker_id == ServerWG.worker_id)
    {
        zanWarn("cannot send message to self.");
        RETURN_FALSE;
    }

    if (worker_id >= ServerG.servSet.worker_num + ServerG.servSet.task_worker_num)
    {
        zanWarn("worker_id[%d] is invalid.", (int) worker_id);
        RETURN_FALSE;
    }

    if (!serv->onPipeMessage)
    {
        zanWarn("onPipeMessage is null, cannot use sendMessage.");
        RETURN_FALSE;
    }

    swEventData buf;
    buf.info.type = SW_EVENT_PIPE_MESSAGE;  //ZAN_EVENT_PIPE_MESSAGE;
    buf.info.from_id = ServerWG.worker_id;
    buf.info.worker_id = worker_id;         //dst_worker_id, for test

    //write to file
    if (msglen >= SW_IPC_MAX_SIZE - sizeof(buf.info))
    {
        if (zanTaskWorker_largepack(&buf, msg, msglen) < 0)
        {
            zanWarn("large task pack failed()");
            RETURN_FALSE;
        }
    }
    else
    {
        memcpy(buf.data, msg, msglen);
        buf.info.len = msglen;
        buf.info.from_fd = 0;
    }

    zanWorker *to_worker = zanServer_get_worker(serv, worker_id);
    SW_CHECK_RETURN(zanWorker_send2worker(to_worker, &buf, sizeof(buf.info) +buf.info.len,ZAN_PIPE_MASTER | ZAN_PIPE_NONBLOCK));
}

PHP_METHOD(swoole_server, finish)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zval *data = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &data))
    {
        return;
    }

    SW_CHECK_RETURN(php_swoole_task_finish(serv, data TSRMLS_CC));
}

///TODO:::似乎没有实际用处
PHP_METHOD(swoole_server, bind)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long fd = 0;
    long uid = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ll", &fd, &uid))
    {
        RETURN_FALSE;
    }

    swConnection *conn = zanServer_get_connection_by_sessionId(serv, fd);
    if (!conn || !conn->active || conn->uid)
    {
        zanWarn("%ld conn error", fd);
        RETURN_FALSE;
    }

    ServerGS->lock.lock(&ServerGS->lock);
    conn->uid = (!conn->uid)? uid:conn->uid;
    int ret = (!conn->uid)? 1:0;
    ServerGS->lock.unlock(&ServerGS->lock);
    SW_CHECK_RETURN(ret);
}

//TODO:::应当在 networker 进程中运行???
PHP_METHOD(swoole_server, getSocket)
{
    long port = 0;
    if (!is_master())
    {
        zanWarn("listen socket info only in master process.");
        RETURN_FALSE;
    }

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &port))
    {
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

#ifdef SW_USE_SOCKETS
    /// todo find socket.
    int sock = zanServer_getSocket(serv, port);
    php_socket *socket_object = swoole_convert_to_socket(sock);
    if (!socket_object)
    {
        RETURN_FALSE;
    }

    SW_ZEND_REGISTER_RESOURCE(return_value, (void *) socket_object, php_sockets_le_socket());
    zval *zsocket = sw_zval_dup(return_value);
    sw_zval_add_ref(&zsocket);
#else
    RETURN_FALSE;
#endif
}

PHP_METHOD(swoole_server, getClientInfo)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    zend_bool noCheckConnection = 0;
    zval *zfd = NULL;
    long from_id = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|lb", &zfd, &from_id, &noCheckConnection))
    {
        RETURN_FALSE;
    }

    long fd = 0;
    zend_bool ipv6_udp = 0;

    //judge ipv6 udp
    if (SW_Z_TYPE_P(zfd) == IS_STRING)
    {
        /// php 接口
        #if PHP_MAJOR_VERSION < 7
        if (!is_numeric_string(Z_STRVAL_P(zfd), Z_STRLEN_P(zfd), &fd, NULL, 0))
        #else
        if (!is_numeric_string(Z_STRVAL_P(zfd), Z_STRLEN_P(zfd), (zend_long*)(&fd), NULL, 0))
        #endif
        {
            fd = 0;
            ipv6_udp = 1;
        }
    }
    else
    {
        convert_to_long(zfd);
        fd = Z_LVAL_P(zfd);
    }

    //udp
    if (ipv6_udp || swServer_is_udp(fd))
    {
        array_init(return_value);

        /// ipv6
        if (ipv6_udp)
        {
            add_assoc_zval(return_value, "remote_ip", zfd);
        }
        else
        {
            struct in_addr sin_addr;
            sin_addr.s_addr = fd;
            char tmpip[SW_IP_MAX_LENGTH] = {0};
            inet_ntop(AF_INET,&sin_addr,tmpip,SW_IP_MAX_LENGTH);
            sw_add_assoc_string(return_value, "remote_ip", tmpip, 1);
        }

        if (!from_id)
        {
            return;
        }

        php_swoole_udp_t udp_info;
        memcpy(&udp_info, &from_id, sizeof(udp_info));
        add_assoc_long(return_value, "remote_port", udp_info.port);
        swConnection *from_sock = zanServer_get_connection(serv, from_id, udp_info.from_fd); ///TODO
        if (from_sock != NULL)
        {
            add_assoc_long(return_value, "server_fd", from_sock->fd);
            add_assoc_long(return_value, "socket_type", from_sock->socket_type);
            add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
        }
        return;
    }

    swConnection *conn = zanServer_get_connection_by_sessionId(serv, fd);
    //connection is invaild
    if (!conn || (!conn->active && !noCheckConnection))
    {
        zanWarn("conn is null or conn is closed.");
        RETURN_FALSE;
    }

    array_init(return_value);
    if (conn->uid > 0 || ServerG.servSet.dispatch_mode == ZAN_DISPATCH_UIDMOD)
    {
        add_assoc_long(return_value, "uid", conn->uid);
    }

    swListenPort *port = zanServer_get_port(serv, conn->networker_id, conn->fd);
    if (port->open_websocket_protocol)
    {
        add_assoc_long(return_value, "websocket_status", conn->websocket_status);
    }

#ifdef SW_USE_OPENSSL
    if (conn->ssl_client_cert.length > 0)
    {
        sw_add_assoc_stringl(return_value, "ssl_client_cert", conn->ssl_client_cert.str, conn->ssl_client_cert.length - 1, 1);
    }
#endif

    add_assoc_long(return_value, "server_fd", conn->from_fd);
    add_assoc_long(return_value, "socket_type", conn->socket_type);

    swConnection *from_sock = zanServer_get_connection(serv, conn->networker_id, conn->from_fd);
    add_assoc_long(return_value, "server_port", swConnection_get_port(from_sock));
    add_assoc_long(return_value, "remote_port", swConnection_get_port(conn));

    char addr[SW_IP_MAX_LENGTH] = {0};
    swConnection_get_ip(conn,addr,SW_IP_MAX_LENGTH);
    sw_add_assoc_string(return_value, "remote_ip", addr, 1);

    add_assoc_long(return_value, "from_id", conn->from_id);
    add_assoc_long(return_value, "from_networker_id", conn->networker_id);
    add_assoc_long(return_value, "connect_time", conn->connect_time);
    add_assoc_long(return_value, "last_time", conn->last_time);
}

PHP_METHOD(swoole_server, getClientList)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long start_fd = 0;
    long find_count = 10;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &start_fd, &find_count))
    {
        RETURN_FALSE;
    }

    //超过最大查找数量
    if (find_count > SW_MAX_FIND_COUNT)
    {
        zanWarn("swoole_connection_list max_find_count=%d", SW_MAX_FIND_COUNT);
        find_count = SW_MAX_FIND_COUNT;
    }

    int networker_index = 0;
    zanSession *tempSession = zanServer_get_session(serv,start_fd);

    if(tempSession == NULL)
    {
        zanWarn("not find this session");
        RETURN_FALSE;
    }

    networker_index = tempSession->networker_id;
    array_init(return_value);

    for(; networker_index < ServerG.servSet.net_worker_num; ++networker_index)
    {
        int min_fd = zanServer_get_minfd(serv, networker_index);
        int max_fd = zanServer_get_maxfd(serv, networker_index);

        if(max_fd == 0)
        {
            break;
        }

        for(; min_fd <= max_fd && find_count > 0; ++min_fd)
        {
            zanDebug("maxfd=%d, minfd=%d, find_count=%ld, start_fd=%ld", max_fd, min_fd, find_count, start_fd);
            swConnection *conn = &serv->connection_list[networker_index][min_fd];
            if (conn->active && !conn->closed)
            {
#ifdef SW_USE_OPENSSL
                if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
                {
                    continue;
                }
#endif
#ifdef SW_REACTOR_USE_SESSION
                add_next_index_long(return_value, conn->session_id);
#else
                add_next_index_long(return_value, min_fd);
#endif
                --find_count;
            }
        }

    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, exist)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long fd = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &fd))
    {
        RETURN_FALSE;
    }

    swConnection *conn = zanServer_get_connection_by_sessionId(serv, fd);
    if (!conn)
    {
        zanWarn("conn is NULL, sessionId=%d", fd);
        RETURN_FALSE;
    }

    if (conn->active == 0 || conn->closed)
    {
        zanWarn("conn>active=%d, conn->closed=%d", conn->active, conn->closed);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_METHOD(swoole_server, protect)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long fd;
    zend_bool value = 1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|b", &fd, &value))
    {
        RETURN_FALSE;
    }

    swConnection *conn = zanServer_get_connection_by_sessionId(serv, fd);
    if (!conn || conn->active == 0 || conn->closed)
    {
        zanWarn("connection is invailed.");
        RETURN_FALSE;
    }

    conn->protect = value;

    RETURN_TRUE;
}

///=================================
PHP_METHOD(swoole_server, shutdown)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    if (swKill(ServerGS->master_pid, SIGTERM) < 0)
    {
        swoole_php_sys_error(E_WARNING, "shutdown failed. kill(%d, SIGTERM) failed.", ServerGS->master_pid);
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_server, stop)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long worker_id = ServerWG.worker_id;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &worker_id))
    {
        RETURN_FALSE;
    }

    if (worker_id == ServerWG.worker_id)
    {
        ServerG.main_reactor->running = 0;
        ServerG.running = 0;
    }
    else
    {
        zanWorker *worker = zanServer_get_worker(serv, worker_id);
        if (!worker || swKill(worker->worker_pid, SIGTERM) < 0)
        {
            swoole_php_sys_error(E_WARNING, "kill(%d, SIGTERM) failed.", worker->worker_pid);
            RETURN_FALSE;
        }
    }
    RETURN_TRUE;
}

PHP_METHOD(swoole_server, getLastError)
{
    RETURN_LONG(ServerG.error);
}

//TODO::用处不大, 而且无配对的 acceptRequest 接口
PHP_METHOD(swoole_server, denyRequest)
{
    if (!ServerGS->started)
    {
        zanWarn("Server is not running.");
        RETURN_FALSE;
    }

    zanServer *serv = ServerG.serv;
    if (!serv)
    {
        zanWarn("not create servers.");
        RETURN_FALSE;
    }

    long nWorkerId = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &nWorkerId))
    {
        RETURN_FALSE;
    }

    zanServer_tcp_deny_request(serv, nWorkerId);
}

#if 0
PHP_METHOD(swoole_server, exit)
{
    ServerG.running = 0;
    ServerG.main_reactor->running = 0;
}
#endif

///for test
PHP_METHOD(swoole_server, getWorkerId)
{
    RETURN_LONG(ServerWG.worker_id);
}

PHP_METHOD(swoole_server, getWorkerType)
{
    RETURN_LONG(ServerG.process_type);
}

PHP_METHOD(swoole_server, getWorkerPid)
{
    RETURN_LONG(ServerG.process_pid);
}

#ifdef HAVE_PCRE
static struct
{
    int current_fd;
    int max_fd;
    uint32_t session_id;
    int end;
    int index;
} server_itearator;

PHP_METHOD(swoole_connection_iterator, rewind)
{
    bzero(&server_itearator, sizeof(server_itearator));
    server_itearator.session_id = zanServer_get_first_sessionId(ServerG.serv);
}

PHP_METHOD(swoole_connection_iterator, valid)
{
    zanServer *serv = ServerG.serv;
    int session_id = server_itearator.session_id;
    zanSession *session = zanServer_get_session(serv, session_id);
    int networker_index = zanServer_get_networker_index(session->networker_id);
    int accept_fd = session->accept_fd;

    for (int index = networker_index; index < ServerG.servSet.net_worker_num; index++)
    {
        int minfd = (accept_fd >= 2) ? accept_fd : zanServer_get_minfd(serv, index);
        int maxfd = zanServer_get_maxfd(serv, index);
        for (int fd = minfd; fd <= maxfd && fd >= 2 ; fd++)
        {
            swConnection *conn = &serv->connection_list[index][fd];
            if (conn && conn->active && !conn->closed)
            {
#ifdef SW_USE_OPENSSL
                if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
                {
                    continue;
                }
#endif
                server_itearator.session_id = conn->session_id;
                server_itearator.current_fd = fd;
                server_itearator.index++;
                RETURN_TRUE;
            }
        }
        accept_fd = 0;
    }
    RETURN_FALSE;
}

PHP_METHOD(swoole_connection_iterator, current)
{
    RETURN_LONG(server_itearator.session_id);
}

PHP_METHOD(swoole_connection_iterator, next)
{
    zanServer *serv = ServerG.serv;
    int session_id = server_itearator.session_id;
    zanSession *session = zanServer_get_session(serv, session_id);
    int networker_index = zanServer_get_networker_index(session->networker_id);
    int accept_fd = session->accept_fd;

    for (int index = networker_index; index < ServerG.servSet.net_worker_num; index++)
    {
        int minfd = (accept_fd >= 2) ? accept_fd : zanServer_get_minfd(serv, index);
        int maxfd = zanServer_get_maxfd(serv, index);
        for (int fd = minfd + 1; fd <= maxfd && fd >= 2 ; fd++)
        {
            swConnection *conn = &serv->connection_list[index][fd];
            if (conn && conn->active && !conn->closed)
            {
                server_itearator.session_id = conn->session_id;
                return;
            }
        }
        accept_fd = 0;
    }
    server_itearator.session_id++;
}

PHP_METHOD(swoole_connection_iterator, key)
{
    RETURN_LONG(server_itearator.index);
}

PHP_METHOD(swoole_connection_iterator, count)
{
    RETURN_LONG(ServerStatsG->connection_num);
}
#endif
