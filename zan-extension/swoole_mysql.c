/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
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


#include "php_swoole.h"
#include "php7_wrapper.h"
#include "swoole_mysql.h"
#include "swLog.h"


static PHP_METHOD(swoole_mysql, __construct);
static PHP_METHOD(swoole_mysql, __destruct);
static PHP_METHOD(swoole_mysql, connect);
static PHP_METHOD(swoole_mysql, isConnected);
static PHP_METHOD(swoole_mysql, setConnectTimeout);
static PHP_METHOD(swoole_mysql, setQueryTimeout);
#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql, escape);
#endif
static PHP_METHOD(swoole_mysql, begin);
static PHP_METHOD(swoole_mysql, commit);
static PHP_METHOD(swoole_mysql, rollback);
static PHP_METHOD(swoole_mysql, isUsedindex);
static PHP_METHOD(swoole_mysql, query);
static PHP_METHOD(swoole_mysql, safe_query);
static PHP_METHOD(swoole_mysql, close);
static PHP_METHOD(swoole_mysql, on);

static zend_class_entry swoole_mysql_ce;
zend_class_entry *swoole_mysql_class_entry_ptr;

static swString *mysql_request_buffer = NULL;
static int isset_event_callback = 0;

#define SERVER_QUERY_NO_GOOD_INDEX_USED 16
#define SERVER_QUERY_NO_INDEX_USED      32

#define SW_MYSQL_DEFAULT_PORT            3306
#define SW_MYSQL_QUERY_INIT_SIZE         8192
#define SW_MYSQL_CONNECT_TIMEOUT         1.0
#define SW_MYSQL_DEFAULT_CHARSET         33  //0x21, utf8_general_ci

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_connect, 0, 0, 2)
    ZEND_ARG_ARRAY_INFO(0, server_config, 0)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

#ifdef SW_USE_MYSQLND
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_escape, 0, 0, 1)
    ZEND_ARG_INFO(0, string)
    ZEND_ARG_INFO(0, flags)
ZEND_END_ARG_INFO()
#endif

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_setTimeout, 0, 0, 1)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_query, 0, 0, 2)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_mysql_prepare,0,0,3)
    ZEND_ARG_INFO(0, sql)
    ZEND_ARG_ARRAY_INFO(0,input_params,1)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_mysql_methods[] =
{
    PHP_ME(swoole_mysql, __construct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_mysql, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_mysql, connect, arginfo_swoole_mysql_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)

#ifdef SW_USE_MYSQLND
    PHP_ME(swoole_mysql, escape, arginfo_swoole_mysql_escape, ZEND_ACC_PUBLIC)
#endif

    PHP_ME(swoole_mysql, setConnectTimeout, arginfo_swoole_mysql_setTimeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, setQueryTimeout, arginfo_swoole_mysql_setTimeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, begin, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, commit, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, rollback, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, isUsedindex, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, query, arginfo_swoole_mysql_query, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, safe_query, arginfo_swoole_mysql_prepare, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_mysql, on, arginfo_swoole_mysql_on, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static void mysql_Client_timeout(swTimer* timer,swTimer_node* node);
static void mysql_client_free(mysql_client *client);
static void mysql_close(mysql_client *client);

static void mysql_free_cb(mysql_client *client);

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event);
static int swoole_mysql_onWrite(swReactor *reactor, swEvent *event);
static int swoole_mysql_onError(swReactor *reactor, swEvent *event);
static void swoole_mysql_onConnect(mysql_client *client TSRMLS_DC);
static int swoole_mysql_onQuery(mysql_client *client TSRMLS_DC);
static int query_handler(mysql_client *client,zval* zobject,swString* sql);
static int really_register_bound_param(struct mysql_bound_param_data *param, struct mysql_bound_param_stmt *stmt);

#ifdef SW_MYSQL_DEBUG
static void debug_mysql_client_info(mysql_client *client);
static void debug_mysql_column_info(mysql_field *field);
#endif

static sw_inline void defer_close(void* data)
{
    mysql_client* client = (mysql_client*)data;
    client->released = 0;
    mysql_close(client);
}

void swoole_mysql_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_mysql_ce, "swoole_mysql", "Swoole\\Mysql", swoole_mysql_methods);
    swoole_mysql_class_entry_ptr = zend_register_internal_class(&swoole_mysql_ce TSRMLS_CC);

    zend_declare_property_null(swoole_mysql_class_entry_ptr,ZEND_STRL("serverInfo"),ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_mysql_class_entry_ptr, SW_STRL("internal_user")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("sock"), -1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_mysql_class_entry_ptr, ZEND_STRL("connected"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("errno"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("connectTimeout"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("queryTimeout"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_stringl(swoole_mysql_class_entry_ptr, ZEND_STRL("error"),"",0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_stringl(swoole_mysql_class_entry_ptr, ZEND_STRL("connect_error"),"",0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("connect_errno"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("affected_rows"), 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("insert_id"),-1, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("warnings"),0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_mysql_class_entry_ptr, ZEND_STRL("status_code"),0, ZEND_ACC_PUBLIC TSRMLS_CC);
}

static void mysql_Client_timeout(swTimer* timer,swTimer_node* node)
{
    SWOOLE_FETCH_TSRMLS;
    mysql_client *client = node? node->data:NULL;
    uint8_t timer_type = client && client->cli? client->cli->timeout_type:SW_CLIENT_INVAILED_TIMEOUT;
    if (timer_type == SW_CLIENT_CONNECT_TIMEOUT || timer_type == SW_CLIENT_RECV_TIMEOUT)
    {
        client->cli->timer_id = 0;
        zval *zobject = client->object;
        if (client->onTimeout)
        {
            zval* callback = client->onTimeout;
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

static void mysql_client_free(mysql_client *client)
{
    if (client->buffer)
    {
        swString_free(client->buffer);
        client->buffer = NULL;
    }

    if (client->cli && client->cli->timer_id > 0)
    {
        long timer_id = client->cli->timer_id;
        client->cli->timer_id = 0;
        swTimer_del(&SwooleG.timer,timer_id);
    }

    if (client->response.result_array)
    {
        zval* result_array = client->response.result_array;
        client->response.result_array = NULL;
        sw_zval_free(result_array);
    }

    if (client->response.columns)
    {
        int i;
        for (i = 0; i < client->response.num_column; i++)
        {
            swoole_efree(client->response.columns[i].buffer);
        }

        swoole_efree(client->response.columns);
    }

    mysql_close(client);

    client->handshake = SW_MYSQL_HANDSHAKE_INIT;
    client->state = SW_MYSQL_STATE_INIT;
}

#ifdef SW_MYSQL_DEBUG
static void debug_mysql_client_info(mysql_client *client)
{
    printf("\n"SW_START_LINE"\nmysql_client\nbuffer->offset=%ld\nbuffer->length=%ld\nstatus=%d\n"
            "packet_length=%d\npacket_number=%d\n"
            "insert_id=%d\naffected_rows=%d\n"
            "warnings=%d\n"SW_END_LINE, client->buffer->offset, client->buffer->length, client->response.status_code,
            client->response.packet_length, client->response.packet_number,
            client->response.insert_id, client->response.affected_rows,
            client->response.warnings);
    int i;

    if (client->response.num_column)
    {
        for (i = 0; i < client->response.num_column; i++)
        {
            mysql_column_info(&client->response.columns[i]);
        }
    }
}

static void debug_mysql_column_info(mysql_field *field)
{
    printf("\n"SW_START_LINE"\nname=%s, table=%s, db=%s\n"
            "name_length=%d, table_length=%d, db_length=%d\n"
            "catalog=%s, default_value=%s\n"
            "length=%ld, type=%d\n"SW_END_LINE,
            field->name, field->table, field->db,
            field->name_length, field->table_length, field->db_length,
            field->catalog, field->def,
            field->length, field->type
           );

}
#endif

static void mysql_close(mysql_client *client)
{
    SWOOLE_FETCH_TSRMLS;
    if (!client)
    {
        return;
    }

    if (client->fd > 0)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);
        swConnection *socket = swReactor_get(SwooleG.main_reactor, client->fd);
        socket->object = NULL;
        client->fd = -1;
    }

    swoole_efree(client->connector.host);
    swoole_efree(client->connector.password);
    swoole_efree(client->connector.database);
    swoole_efree(client->connector.user);

    if (client->cli)
    {
        if (client->cli->timer_id > 0)
        {
            long timer_id = client->cli->timer_id;
            client->cli->timer_id = 0;
            swTimer_del(&SwooleG.timer,timer_id);
        }

        swClient_free(client->cli);
        swoole_efree(client->cli);
    }

    if (client->released)
    {
        return;
    }

    client->released = 1;
    zval *object = client->object;
    if (client->onClose && object)
    {
        zval *retval = NULL;
        zval **args[1];
        args[0] = &object;

        if (sw_call_user_function_ex(EG(function_table), NULL, client->onClose, &retval, 1, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_mysql onClose callback error.");
        }

        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    mysql_free_cb(client);
    if (client->object)
    {
        zval* obj = client->object;
        client->object = NULL;
        sw_zval_ptr_dtor(&obj);
    }
}

static void mysql_free_cb(mysql_client *client)
{
    if (!client)
    {
        return ;
    }

    if (client->onClose) {sw_zval_ptr_dtor(&client->onClose);client->onClose = NULL;}
    if (client->onTimeout) {sw_zval_free(client->onTimeout);client->onTimeout = NULL;}
    if (client->onConnect) {sw_zval_free(client->onConnect);client->onConnect = NULL;}
    if (client->callback) {sw_zval_free(client->callback);client->callback = NULL;}
}

static PHP_METHOD(swoole_mysql, __construct)
{
    if (!mysql_request_buffer)
    {
        mysql_request_buffer = swString_new(SW_MYSQL_QUERY_INIT_SIZE);
        if (!mysql_request_buffer)
        {
            swoole_php_fatal_error(E_ERROR, "[1] swString_new(%d) failed.", SW_HTTP_RESPONSE_INIT_SIZE);
            RETURN_FALSE;
        }
    }

    mysql_client *client = emalloc(sizeof(mysql_client));
    bzero(client, sizeof(mysql_client));
    client->fd = -1;
    client->handshake = SW_MYSQL_HANDSHAKE_INIT;
    client->state = SW_MYSQL_STATE_INIT;

    swoole_set_object(getThis(), client);
}

static PHP_METHOD(swoole_mysql, __destruct)
{
    mysql_client *client = swoole_get_object(getThis());
    if (client)
    {
        client->object = NULL;   /// 对象析构不回调至php层
        mysql_client_free(client);
    }

    releaseConnobj(getThis());

    swoole_efree(client);
    swoole_set_object(getThis(), NULL);
}

static PHP_METHOD(swoole_mysql, on)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swWarn("object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }

    zval *internal_user = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    int disable_set = internal_user && Z_BVAL_P(internal_user);

    char *name = NULL;
    zend_size_t len = 0;
    zval *cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &name, &len, &cb))
    {
        RETURN_FALSE;
    }

    if (!name || len <= 0 || swoole_check_callable(cb TSRMLS_CC) < 0)
    {
        swWarn("error callback.");
        RETURN_FALSE;
    }

    if (len == strlen("close") && strncasecmp("close", name, len) == 0)
    {
        if (disable_set)
        {
            swWarn("object created by connection pool,disable set close event");
            RETURN_FALSE;
        }

        if (client->onClose) sw_zval_ptr_dtor(&client->onClose);
        client->onClose = cb;
        sw_copy_to_stack(client->onClose, client->_onClose);
    }
    else if (len == strlen("timeout") && strncasecmp("timeout", name, len) == 0)
    {
        if (client->onTimeout) sw_zval_free(client->onTimeout);
        client->onTimeout = sw_zval_dup(cb);
    }
    else
    {
        swWarn("Unknown callback type[%s]", name);
        RETURN_FALSE;
    }

    sw_zval_add_ref(&cb);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, connect)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || client->released)
    {
        swWarn("please construct swoole_mysql first");
        RETURN_FALSE;
    }

    if (client->cli)
    {
        RETURN_FALSE;
    }

    zval *internal_user = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    if (internal_user && Z_BVAL_P(internal_user))
    {
        return;
    }

    zval *server_info = NULL;
    zval *callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "az", &server_info, &callback))
    {
        RETURN_FALSE;
    }

    php_swoole_array_separate(server_info);
    HashTable *_ht = Z_ARRVAL_P(server_info);

    mysql_connector *connector = &client->connector;
    zval *value = NULL;
    if (php_swoole_array_get_value(_ht, "host", value))
    {
        if (sw_convert_to_string(value) < 0)
        {
                sw_zval_ptr_dtor(&server_info);
            swWarn("convert to string failed.");
            RETURN_FALSE;
        }

        swoole_efree(connector->host);
        connector->host_len = Z_STRLEN_P(value);
        connector->host = estrndup(Z_STRVAL_P(value),connector->host_len);
    }
    else
    {
        sw_zval_ptr_dtor(&server_info);
        swWarn("HOST parameter is required.");
        RETURN_FALSE;
    }

    value = NULL;
    connector->port = SW_MYSQL_DEFAULT_PORT;
    if (php_swoole_array_get_value(_ht, "port", value))
    {
        convert_to_long(value);
        connector->port = Z_LVAL_P(value);
    }

    value = NULL;
    if (php_swoole_array_get_value(_ht, "user", value))
    {
        if (sw_convert_to_string(value) < 0)
        {
            sw_zval_ptr_dtor(&server_info);
            swWarn("convert to string failed.");
            RETURN_FALSE;
        }
        swoole_efree(connector->user);
        connector->user_len = Z_STRLEN_P(value);
        connector->user = estrndup(Z_STRVAL_P(value),connector->user_len);
    }
    else
    {
            sw_zval_ptr_dtor(&server_info);
        swWarn("USER parameter is required.");
        RETURN_FALSE;
    }

    if (php_swoole_array_get_value(_ht, "password", value))
    {
        if (sw_convert_to_string(value) < 0)
        {
            sw_zval_ptr_dtor(&server_info);
            swWarn("convert to string failed.");
            RETURN_FALSE;
        }
        swoole_efree(connector->password);
        connector->password_len = Z_STRLEN_P(value);
        connector->password = estrndup(Z_STRVAL_P(value),connector->password_len);
    }
    else
    {
        connector->password = NULL;
        connector->password_len = 0;
    }
    if (php_swoole_array_get_value(_ht, "database", value))
    {
        if (sw_convert_to_string(value) < 0)
        {
            sw_zval_ptr_dtor(&server_info);
            swWarn("convert to string failed.");
            RETURN_FALSE;
        }
        swoole_efree(connector->database);
        connector->database_len = Z_STRLEN_P(value);
        connector->database = estrndup(Z_STRVAL_P(value),connector->database_len);
    }
    else
    {
        sw_zval_ptr_dtor(&server_info);
        swWarn("DATABASE parameter is required.");
        RETURN_FALSE;
    }

    value = NULL;
    connector->character_set = 0;
    if (php_swoole_array_get_value(_ht, "charset", value))
    {
        if (sw_convert_to_string(value) < 0)
        {
            sw_zval_ptr_dtor(&server_info);
            swWarn("convert to string failed.");
            RETURN_FALSE;
        }
        connector->character_set = mysql_get_charset(Z_STRVAL_P(value));
        if (connector->character_set < 0)
        {
            char buf[1024] = {0};
            snprintf(buf, sizeof(buf), "unknown charset [%s].", Z_STRVAL_P(value));
            sw_zval_ptr_dtor(&server_info);
            swWarn("%s",buf);
            RETURN_FALSE;
        }
    }

    sw_zval_ptr_dtor(&server_info);

    int type = SW_SOCK_TCP;
    if (strncasecmp(connector->host, ZEND_STRL("unix:/")) == 0)
    {
        connector->host = connector->host + 5;
        connector->host_len = connector->host_len - 5;
        type = SW_SOCK_UNIX_STREAM;
    }
    else if (strchr(connector->host, ':'))
    {
        type = SW_SOCK_TCP6;
    }

    php_swoole_check_reactor();
    if (!isset_event_callback)
    {
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ, swoole_mysql_onRead);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE, swoole_mysql_onWrite);
        SwooleG.main_reactor->setHandle(SwooleG.main_reactor, PHP_SWOOLE_FD_MYSQL | SW_EVENT_ERROR, swoole_mysql_onError);
        isset_event_callback = 1;
    }

    swClient *cli = emalloc(sizeof(swClient));
    if (!cli)
    {
        swWarn("emalloc swoole Client failed.");
        RETURN_FALSE;
    }

    client->cli = cli;
    bzero(cli,sizeof(swClient));
    if (swClient_create(cli, type, 0) < 0)
    {
        swWarn("swClient_create failed.");
        RETURN_FALSE;
    }

    if (type != SW_SOCK_UNIX_STREAM)
    {
        int tcp_nodelay = 1;
        //tcp nodelay
        if (setsockopt(cli->socket->fd, IPPROTO_TCP, TCP_NODELAY, (const void *) &tcp_nodelay, sizeof(int)) == -1)
        {
            swoole_php_sys_error(E_WARNING, "setsockopt(%d, IPPROTO_TCP, TCP_NODELAY) failed.", cli->socket->fd);
        }
    }

    swConnection *_socket = swReactor_get(SwooleG.main_reactor, cli->socket->fd);
    if (!_socket)
    {
        swWarn("get socket from reactor error.");
        RETURN_FALSE;
    }

    bzero(_socket,sizeof(swConnection));
    _socket->object = client;
    _socket->fd = cli->socket->fd;

    //connect to mysql server
    int ret = cli->connect(cli, connector->host, connector->port, 0,1);
    if ((ret < 0 && errno == EINPROGRESS) || ret == 0)
    {
        if (SwooleG.main_reactor->add(SwooleG.main_reactor, cli->socket->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_WRITE) < 0)
        {
            RETURN_FALSE;
        }
    }
    else
    {
        char buf[1024] = {0};
        snprintf(buf, sizeof(buf), "connect to mysql server[%s:%d] failed.", connector->host, connector->port);
        swWarn("%s", buf);
        RETURN_FALSE;
    }

    client->fd = cli->socket->fd;
    if (!callback || ZVAL_IS_NULL(callback))
    {
        client->onConnect = NULL;
    }
    else if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }
    else
    {
        sw_zval_add_ref(&callback);
        client->onConnect = sw_zval_dup(callback);
    }

    zend_update_property_long(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("sock"), cli->socket->fd TSRMLS_CC);

    client->buffer = swString_new(SW_BUFFER_SIZE_BIG);
    client->object = getThis();
    sw_zval_add_ref(&(client->object));
    sw_copy_to_stack(client->object, client->_object);

    long timeout = 0;
    zval* connectTimeout = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), 1 TSRMLS_CC);
    if (connectTimeout)
    {
        convert_to_long(connectTimeout);
        timeout = Z_LVAL_P(connectTimeout);
    }

    if (client->cli && timeout > 0)
    {
            client->cli->timer_id = 0;
            client->cli->timer_id = swTimer_add(&SwooleG.timer,timeout,0,client,MYSQL_USED);
        if (cli->timer_id <= 0)
        {
            swWarn("set connect timeout timer failed.");
            RETURN_FALSE;
        }

        client->cli->timeout_type = SW_CLIENT_CONNECT_TIMEOUT;
        register_after_cb(&SwooleG.timer,MYSQL_USED,mysql_Client_timeout);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql,isConnected)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || client->released || !client->cli)
    {
        RETURN_FALSE;
    }

    zval* value = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 1 TSRMLS_CC);
    int connected = (value && Z_BVAL_P(value))? 1:0;

    RETURN_BOOL(connected && client->fd > 0);
}

static PHP_METHOD(swoole_mysql, setConnectTimeout)
{
    long timeout = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
    {
        swWarn("parse parameters error.");
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), timeout TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, setQueryTimeout)
{
    long timeout = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
    {
        swWarn("parse parameters error.");
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("queryTimeout"), timeout TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, close)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || client->released)
    {
        return;
    }

    zval *internal_user = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    if (internal_user && Z_BVAL_P(internal_user))
    {
        return;
    }

    zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);

    client->released = 1;
    if (client->fd > 0)
    {
        SwooleG.main_reactor->del(SwooleG.main_reactor, client->fd);
        swConnection *socket = swReactor_get(SwooleG.main_reactor, client->fd);
        socket->object = NULL;
        client->fd = -1;
    }

    if (client->cli)
    {
        if (client->cli->timer_id > 0)
        {
            long timer_id = client->cli->timer_id;
            client->cli->timer_id = 0;
            swTimer_del(&SwooleG.timer,timer_id);
        }

        swClient_free(client->cli);
        swoole_efree(client->cli);
    }

    SwooleG.main_reactor->defer(SwooleG.main_reactor,defer_close,client);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, query)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli || client->released)
    {
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    zval* callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz",
                        &sql.str, &sql.length, &callback))
    {
        RETURN_FALSE;
    }

    if (sql.length <= 0 || !sql.str)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE
    }

    sw_zval_add_ref(&callback);
    client->callback = sw_zval_dup(callback);

    if (query_handler(client,getThis(),&sql) < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_mysql, safe_query)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli || client->released)
    {
        RETURN_FALSE;
    }

    if (client->state != SW_MYSQL_STATE_QUERY)
    {
        swoole_php_fatal_error(E_WARNING, "mysql client is waiting response, cannot send new sql query.");
        RETURN_FALSE;
    }

    swString sql;
    bzero(&sql, sizeof(sql));
    zval* input_params = NULL;
    zval* callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "saz",
                        &sql.str, &sql.length, &input_params,&callback))
    {
        RETURN_FALSE;
    }

    if (sql.length <= 0 || !sql.str)
    {
        swoole_php_fatal_error(E_WARNING, "Query is empty.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE
    }

    sw_zval_add_ref(&callback);
    client->callback = sw_zval_dup(callback);

    struct mysql_bound_param_stmt stmt;
    memset(&stmt,0,sizeof(stmt));
    stmt.supports_placeholders = MYSQL_PLACEHOLDER_NONE;
    struct mysql_bound_param_data param;

#if PHP_MAJOR_VERSION < 7
    zval **tmp;
    uint str_len = 0;
    ulong num_index = 0;

    zend_hash_internal_pointer_reset(Z_ARRVAL_P(input_params));
    while (zend_hash_get_current_data(Z_ARRVAL_P(input_params), (void*)&tmp) == SUCCESS)
     {
        memset(&param, 0, sizeof(param));

        if ( zend_hash_get_current_key_ex(Z_ARRVAL_P(input_params),&param.name, &str_len,
                &num_index, 0, NULL) == HASH_KEY_IS_STRING)
         {
            param.name_len = str_len - 1;
            param.paramno = -1;
        }
         else
         {
            param.paramno = num_index;
        }

        MAKE_STD_ZVAL(param.parameter);
        MAKE_COPY_ZVAL(tmp, param.parameter);

        if (!really_register_bound_param(&param, &stmt))
         {
            if (param.parameter)
             {
                zval_ptr_dtor(&param.parameter);
            }
            RETURN_FALSE;
        }

        zend_hash_move_forward(Z_ARRVAL_P(input_params));

    }
#else
    zval *tmp = NULL;
    zend_string *key = NULL;
    zend_ulong num_index = 0;

    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(input_params), num_index, key, tmp)
    {
        memset(&param, 0, sizeof(param));
        if (key) {
            /* yes this is correct.  we don't want to count the null byte. */
            param.name = key;
            param.paramno = -1;
        } else {
            param.paramno = num_index;
        }

        //param.param_type = MYSQL_PARAM_STR;
        ZVAL_COPY(&param.parameter, tmp);

        if (!really_register_bound_param(&param, &stmt)) {
            if (!Z_ISUNDEF(param.parameter)) {
                zval_ptr_dtor(&param.parameter);
            }

            RETURN_FALSE
        }
    }
    ZEND_HASH_FOREACH_END();
#endif
    char *nsql = NULL;
    size_t nsql_len = 0;
    int ret = mysql_parse_params(stmt, sql.str, sql.length, &nsql, &nsql_len TSRMLS_CC);
    if (ret == 1) {
        sql.str = nsql;
        sql.length = nsql_len;
    }
    else if(ret == -1) {
        /* failed to parse */
        RETURN_FALSE;
    }

    ret = query_handler(client,getThis(),&sql);
    swoole_efree(nsql);

    if (ret < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;

}

static PHP_METHOD(swoole_mysql, begin)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli)
    {
        swWarn("please construct swoole_mysql first.and mysql connection must be active.");
        RETURN_FALSE;
    }

    zval *callback = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    if(client->in_txn)
    {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "There is already an active transaction", 0 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        swWarn("callback is invailed.");
        RETURN_FALSE;
    }

    sw_zval_add_ref(&callback);
    client->callback = sw_zval_dup(callback);

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("START TRANSACTION"));
    swString_clear(mysql_request_buffer);

    if (mysql_request(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //send
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        client->in_txn = 1;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, commit)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli)
    {
        swWarn("please construct swoole_mysql first.and mysql connection must be active.");
        RETURN_FALSE;
    }

    zval *callback = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        RETURN_FALSE;
    }

    if(!client->in_txn)
    {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "There is no active transaction", 0 TSRMLS_CC);
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        swWarn("callback is invailed.");
        RETURN_FALSE;
    }

    sw_zval_add_ref(&callback);
    client->callback = sw_zval_dup(callback);

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("COMMIT"));

    if (mysql_request(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //send
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        client->in_txn = 0;
        RETURN_TRUE;
    }

}
static PHP_METHOD(swoole_mysql, rollback)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli)
    {
        swWarn("please construct swoole_mysql first.and mysql connection must be active.");
        RETURN_FALSE;
    }

    zval *callback = NULL;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback) == FAILURE)
    {
        RETURN_FALSE;
    }
    if(!client->in_txn)
    {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "There is no active transaction", 0 TSRMLS_CC);
        RETURN_FALSE;
    }
    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        swWarn("callback is invailed.");
        RETURN_FALSE;
    }

    sw_zval_add_ref(&callback);
    client->callback = sw_zval_dup(callback);

    swString sql;
    bzero(&sql, sizeof(sql));
    swString_append_ptr(&sql, ZEND_STRL("ROLLBACK"));

    //client->state = SW_MYSQL_STATE_ROLLBACK;
    if (mysql_request(&sql, mysql_request_buffer) < 0)
    {
        RETURN_FALSE;
    }
    //send
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }
        RETURN_FALSE;
    }
    else
    {
        client->state = SW_MYSQL_STATE_READ_START;
        client->in_txn = 0;
        RETURN_TRUE;
    }
}

static PHP_METHOD(swoole_mysql, isUsedindex)
{
    mysql_client *client = swoole_get_object(getThis());
    if (!client || !client->cli)
    {
        swWarn("please construct swoole_mysql first.and mysql connection must be active.");
        RETURN_FALSE;
    }
    zval *status_code = sw_zend_read_property(swoole_mysql_class_entry_ptr, getThis(), ZEND_STRL("status_code"), 0 TSRMLS_CC);
    long status_value = Z_LVAL_P(status_code);
    RETURN_BOOL(!(status_value & SERVER_QUERY_NO_INDEX_USED) &&
                !(status_value & SERVER_QUERY_NO_GOOD_INDEX_USED));
}

static int really_register_bound_param(struct mysql_bound_param_data *param, struct mysql_bound_param_stmt *stmt)
{
    struct mysql_bound_param_data *pparam = NULL;
    HashTable *hash = stmt->bound_params;
    if (!hash)
    {
        ALLOC_HASHTABLE(hash);
        zend_hash_init(hash, 13, NULL, NULL, 0);  //param_dtor
        stmt->bound_params = hash;
    }

#if PHP_MAJOR_VERSION < 7
    if (sw_convert_to_string(param->parameter) < 0)
    {
        swWarn("convert to string failed.");
        return -1;
    }

    if (param->name)
     {
        if (param->name[0] != ':')
         {
            char *temp = emalloc(++param->name_len + 1);
            temp[0] = ':';
            memmove(temp + 1, param->name, param->name_len + 1);
            param->name = temp;
        }
        else
        {
            param->name = estrndup(param->name, param->name_len);
        }
    }

    /* delete any other parameter registered with this number.
     * If the parameter is named, it will be removed and correctly
     * disposed of by the hash_update call that follows */
    if (param->paramno >= 0)
    {
        zend_hash_index_del(hash, param->paramno);
    }

    /* allocate storage for the parameter, keyed by its "canonical" name */
    if (param->name)
    {
        zend_hash_update(hash, param->name, param->name_len, param, sizeof(*param), (void**)&pparam);
    }
    else
    {
        zend_hash_index_update(hash, param->paramno, param, sizeof(*param), (void**)&pparam);
    }

 #else
    zval *parameter = Z_ISREF(param->parameter)? Z_REFVAL(param->parameter):&param->parameter;
    if (sw_convert_to_string(parameter) < 0)
    {
        swWarn("convert to string failed.");
        return -1;
    }

    if (param->name)
    {
        if (ZSTR_VAL(param->name)[0] != ':')
        {
            zend_string *temp = zend_string_alloc(ZSTR_LEN(param->name) + 1, 0);
            ZSTR_VAL(temp)[0] = ':';
            memmove(ZSTR_VAL(temp) + 1, ZSTR_VAL(param->name), ZSTR_LEN(param->name) + 1);
            param->name = temp;
        }
        else
        {
            param->name = zend_string_init(ZSTR_VAL(param->name), ZSTR_LEN(param->name), 0);
        }
    }

    /* delete any other parameter registered with this number.
     * If the parameter is named, it will be removed and correctly
     * disposed of by the hash_update call that follows */
    if (param->paramno >= 0)
    {
        zend_hash_index_del(hash, param->paramno);
    }

    /* allocate storage for the parameter, keyed by its "canonical" name */
    pparam = (param->name)? zend_hash_update_mem(hash, param->name, param, sizeof(*pparam)):
            zend_hash_index_update_mem(hash, param->paramno, param, sizeof(*pparam));
#endif
    return 1;
}

static int swoole_mysql_onError(swReactor *reactor, swEvent *event)
{

    if (event->socket->active)
    {
        mysql_client *client = event->socket->object;
        if (!client)
        {
//            close(event->fd);
            reactor->close(reactor, event->fd);
            return SW_ERR;
        }

        if (client->cli && client->cli->timer_id > 0)
        {
            long timer_id = client->cli->timer_id;
            client->cli->timer_id = 0;
            swTimer_del(&SwooleG.timer,timer_id);
        }
        mysql_close(client);
        return SW_OK;
    }
    else
    {
        return swoole_mysql_onWrite(reactor, event);
    }
}

static void swoole_mysql_onConnect(mysql_client *client TSRMLS_DC)
{
    if (client->cli && client->cli->timer_id > 0)
    {
        long timer_id = client->cli->timer_id;
        client->cli->timer_id = 0;
        swTimer_del(&SwooleG.timer,timer_id);
    }
    zval *zobject = client->object;
    if (!zobject)
    {
        return;
    }

    zval *callback = client->onConnect;
    client->onConnect = NULL;
    if (client->connector.error_code > 0)
    {
        zend_update_property_stringl(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connect_error"), client->connector.error_msg, client->connector.error_length TSRMLS_CC);
        zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connect_errno"), client->connector.error_code TSRMLS_CC);
    }

    zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), client->connector.error_code > 0? 0:1 TSRMLS_CC);

    zval *retval = NULL;
    sw_zval_add_ref(&zobject);
    if (callback && !ZVAL_IS_NULL(callback)){
        zval *result;
        zval **args[2];
        SW_MAKE_STD_ZVAL(result);
        ZVAL_BOOL(result, client->connector.error_code > 0? 0:1);
        args[0] = &zobject;
        args[1] = &result;
        if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            swoole_php_fatal_error(E_WARNING, "swoole_mysql onConnect handler error.");
        }
        if (EG(exception))
        {
            zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
        }
        if (retval != NULL)
        {
            sw_zval_ptr_dtor(&retval);
        }
        sw_zval_ptr_dtor(&result);
    }

    if (client->connector.error_code > 0)
    {
        //close
        mysql_close(client);
    }

    if (callback) sw_zval_free(callback);
    sw_zval_ptr_dtor(&zobject);
}

static int swoole_mysql_onWrite(swReactor *reactor, swEvent *event)
{
    SWOOLE_FETCH_TSRMLS;

    mysql_client *client = event->socket->object;
    if (event->socket->active)
    {
        int iRet = swReactor_onWrite(SwooleG.main_reactor, event);
        if (iRet != SW_OK && client)
        {
            client->fd = -1;
            if (client->cli && client->cli->socket)
            {
                client->cli->socket->closed = 1;
                client->cli->socket->removed = 1;
            }

            mysql_close(client);
        }

        return SW_OK;
    }

    socklen_t len = sizeof(SwooleG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &SwooleG.error, &len) < 0)
    {
        swWarn("getsockopt(%d) failed. Error: %s[%d]", event->fd, strerror(errno), errno);
        return SW_ERR;
    }

    //success
    if (SwooleG.error == 0)
    {
        //listen read event
        SwooleG.main_reactor->set(SwooleG.main_reactor, event->fd, PHP_SWOOLE_FD_MYSQL | SW_EVENT_READ);
        //connected
        event->socket->active = 1;
        client->handshake = SW_MYSQL_HANDSHAKE_WAIT_REQUEST;
    }
    else
    {
        client->connector.error_code = SwooleG.error;
        client->connector.error_msg = strerror(SwooleG.error);
        client->connector.error_length = strlen(client->connector.error_msg);
        swoole_mysql_onConnect(client TSRMLS_CC);
    }

    return SW_OK;
}

static int swoole_mysql_onHandShake(mysql_client *client TSRMLS_DC)
{
    swString *buffer = client->buffer;
    swClient *cli = client->cli;
    mysql_connector *connector = &client->connector;

    int n = cli->recv(cli, buffer->str + buffer->length, buffer->size - buffer->length, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            swSysError("Read from socket[%d] failed.", cli->socket->fd);
            return SW_ERR;
        case SW_CLOSE:
            goto system_call_error;
        case SW_WAIT:
            return SW_OK;
        default:
            return SW_ERR;
        }
    }
    else if (n == 0)
    {
        errno = ECONNRESET;
        goto system_call_error;
    }

    buffer->length += n;

    int ret;
    if (client->handshake == SW_MYSQL_HANDSHAKE_WAIT_REQUEST)
    {
        ret = mysql_handshake(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            if (cli->send(cli, connector->buf, connector->packet_length + 4, 0) < 0)
            {
                system_call_error: connector->error_code = errno;
                connector->error_msg = strerror(errno);
                connector->error_length = strlen(connector->error_msg);
                swoole_mysql_onConnect(client TSRMLS_CC);
                return SW_OK;
            }
            else
            {
                swString_clear(buffer);
                client->handshake = SW_MYSQL_HANDSHAKE_WAIT_RESULT;
            }
        }
    }
    else
    {
        ret = mysql_get_result(connector, buffer->str, buffer->length);
        if (ret < 0)
        {
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
        else if (ret > 0)
        {
            swString_clear(buffer);
            client->handshake = SW_MYSQL_HANDSHAKE_COMPLETED;
            client->state = SW_MYSQL_STATE_QUERY;
            swoole_mysql_onConnect(client TSRMLS_CC);
        }
    }
    return SW_OK;
}

static int swoole_mysql_onRead(swReactor *reactor, swEvent *event)
{
    SWOOLE_FETCH_TSRMLS;

    mysql_client *client = event->socket->object;
    if (client->handshake != SW_MYSQL_HANDSHAKE_COMPLETED)
    {
        return swoole_mysql_onHandShake(client TSRMLS_CC);
    }

    if (client->cli && client->cli->timer_id > 0)
    {
        long timer_id = client->cli->timer_id;
        client->cli->timer_id = 0;
        swTimer_del(&SwooleG.timer,timer_id);
    }
    int sock = event->fd;
    int ret;

    zval *zobject = client->object;
    swString *buffer = client->buffer;

    while(1)
    {
        ret = recv(sock, buffer->str + buffer->length, buffer->size - buffer->length, 0);
        if (ret < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                switch (swConnection_error(errno))
                {
                case SW_ERROR:
                    swSysError("Read from socket[%d] failed.", event->fd);
                    return SW_ERR;
                case SW_CLOSE:
                    goto close_fd;
                case SW_WAIT:
                    goto parse_response;
                default:
                    return SW_ERR;
                }
            }
        }
        else if (ret == 0)
        {
            close_fd:
            if (client->state == SW_MYSQL_STATE_READ_END)
            {
                goto parse_response;
            }

            mysql_close(client);
            return SW_OK;
        }
        else
        {
            buffer->length += ret;
            //recv again
            if (buffer->length == buffer->size)
            {
                if (swString_extend(buffer, buffer->size * 2) < 0)
                {
                    swoole_php_fatal_error(E_ERROR, "malloc failed.");
                    reactor->del(reactor, event->fd);
                    swConnection *socket = swReactor_get(reactor, client->fd);
                    socket->object = NULL;
                    client->fd = -1;
                    return SW_ERR;
                }
                continue;
            }

            parse_response:
            if (mysql_response(client) < 0)
            {
                return SW_OK;
            }

            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("affected_rows"), client->response.affected_rows TSRMLS_CC);
            zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("insert_id"), client->response.insert_id TSRMLS_CC);
            if (swoole_mysql_onQuery(client TSRMLS_CC) < 0)
            {
                reactor->del(SwooleG.main_reactor, event->fd);
            }
            return SW_OK;
        }
    }

    return SW_OK;
}

static int swoole_mysql_onQuery(mysql_client *client TSRMLS_DC)
{
    zval **args[2];
    zval *callback = NULL;
    zval *retval = NULL;
    zval *result = NULL;

    int iRet = SW_OK;
    client->state = SW_MYSQL_STATE_QUERY;
    zval *zobject = client->object;
    args[0] = &zobject;

    //OK
    if (client->response.response_type == 0 || client->response.response_type == 0xfe)
    {
        SW_ALLOC_INIT_ZVAL(result);
        ZVAL_BOOL(result, 1);
    }
    //ERROR
    else if (client->response.response_type == 255)
    {
        SW_ALLOC_INIT_ZVAL(result);
        ZVAL_BOOL(result, 0);

        zend_update_property_stringl(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("error"), client->response.server_msg, client->response.l_server_msg TSRMLS_CC);
        zend_update_property_long(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), client->response.error_code TSRMLS_CC);
    }
    //ResultSet
    else
    {
        result = client->response.result_array;
        client->response.result_array = NULL;
    }

    args[1] = &result;
    callback = client->callback;
    client->callback = NULL;
    swString_clear(client->buffer);
    bzero(&client->response, sizeof(client->response));
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        swoole_php_fatal_error(E_WARNING, "swoole_async_mysql callback[2] handler error.");
        swReactor_del(SwooleG.main_reactor, client->fd);
        swConnection *socket = swReactor_get(SwooleG.main_reactor, client->fd);
        socket->object = NULL;
        client->fd = -1;
    }

    /* free memory */
    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
    if (result)
    {
        sw_zval_free(result);
    }

            //free callback object
    if (callback)   sw_zval_free(callback);
//            swConnection *_socket = swReactor_get(SwooleG.main_reactor, event->fd);
//            if (_socket->object)
//            {
//                //clear buffer
//                swString_clear(client->buffer);
//                bzero(&client->response, sizeof(client->response));
//            }

    return iRet;
}

static int query_handler(mysql_client *client,zval* zobject,swString* sql)
{
    SWOOLE_FETCH_TSRMLS;
    swString_clear(mysql_request_buffer);
    if (mysql_request(sql, mysql_request_buffer) < 0)
    {
        return SW_ERR;
    }
    //send query
    if (SwooleG.main_reactor->write(SwooleG.main_reactor, client->fd, mysql_request_buffer->str, mysql_request_buffer->length) < 0)
    {
        //connection is closed
        if (swConnection_error(errno) == SW_CLOSE)
        {
            zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
            zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), 2006 TSRMLS_CC);
        }

        return SW_ERR;
    }
    else
    {
        long timeout = 0;
        zval* queryTimeout = sw_zend_read_property(swoole_mysql_class_entry_ptr,zobject, ZEND_STRL("queryTimeout"), 1 TSRMLS_CC);
        if (queryTimeout)
        {
            convert_to_long(queryTimeout);
            timeout = Z_LVAL_P(queryTimeout);
        }

        if (client->cli && timeout > 0)
        {
            client->cli->timer_id = 0;
            client->cli->timer_id = swTimer_add(&SwooleG.timer,timeout,0,client,MYSQL_USED);
            if (client->cli->timer_id <= 0)
            {
                zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("connected"), 0 TSRMLS_CC);
                zend_update_property_bool(swoole_mysql_class_entry_ptr, zobject, ZEND_STRL("errno"), 2007 TSRMLS_CC);
                swWarn("set recv msg time out timer failed.");
                return SW_ERR;
            }

            client->cli->timeout_type = SW_CLIENT_RECV_TIMEOUT;
            register_after_cb(&SwooleG.timer,MYSQL_USED,mysql_Client_timeout);
        }

        client->state = SW_MYSQL_STATE_READ_START;
        return SW_OK;
    }
}

#ifdef SW_USE_MYSQLND
static PHP_METHOD(swoole_mysql, escape)
{
    swString str;
    bzero(&str, sizeof(str));
    long flags;

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s|l", &str.str, &str.length, &flags))
    {
        return;
    }

    if (str.length <= 0)
    {
        swoole_php_fatal_error(E_WARNING, "String is empty.");
        RETURN_FALSE;
    }

    mysql_client *client = swoole_get_object(getThis());
    if (!client)
    {
        swoole_php_fatal_error(E_WARNING, "object is not instanceof swoole_mysql.");
        RETURN_FALSE;
    }
    if (!client->cli)
    {
        swoole_php_fatal_error(E_WARNING, "mysql connection#%d is closed.", client->fd);
        RETURN_FALSE;
    }

    char *newstr = safe_emalloc(2, str.length + 1, 1);
    if (newstr == NULL)
    {
        swoole_php_fatal_error(E_ERROR, "emalloc(%ld) failed.", str.length + 1);
        RETURN_FALSE;
    }

    const MYSQLND_CHARSET* cset = mysqlnd_find_charset_nr(client->connector.character_set);
    int newstr_len = mysqlnd_cset_escape_slashes(cset, newstr, str.str, str.length TSRMLS_CC);
    if (newstr_len < 0)
    {
        swoole_php_fatal_error(E_ERROR, "mysqlnd_cset_escape_slashes() failed.");
        RETURN_FALSE;
    }
    SW_RETURN_STRINGL(newstr, newstr_len, 0);
}
#endif
