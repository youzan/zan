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
#include "zanLog.h"

#ifdef SW_USE_REDIS
#include "hiredis/hiredis.h"
#include "hiredis/async.h"
#define SW_REDIS_COMMAND_BUFFER_SIZE   64
#define SW_REDIS_COMMAND_KEY_SIZE      128

typedef struct
{
    redisAsyncContext *context;

    uint8_t state;
    uint8_t subscribe;
    uint8_t released;
    uint8_t timeout_type;
    int fd;
    uint64_t timer_id;

    char *password;
    uint8_t password_len;
    int8_t database;
    uint8_t failure;
    uint8_t wait_count;

    zval *object;
    zval *message_callback;
    zval *result_callback;
    zval *onConnect;
    zval *onClose;
    zval *onTimeout;

#if PHP_MAJOR_VERSION >= 7
    zval _message_callback;
    zval _onClose;
    zval _onTimeout;
    zval _object;
#endif
} swRedisClient;

enum swoole_redis_state
{
    SWOOLE_REDIS_STATE_CONNECT,
    SWOOLE_REDIS_STATE_READY,
    SWOOLE_REDIS_STATE_WAIT_RESULT,
    SWOOLE_REDIS_STATE_SUBSCRIBE,
    SWOOLE_REDIS_STATE_CLOSED,
};

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_construct, 0, 0,0)
    ZEND_ARG_ARRAY_INFO(0,settings, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_connect, 0, 0, 3)
    ZEND_ARG_INFO(0, host)
    ZEND_ARG_INFO(0, port)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_call, 0, 0, 2)
    ZEND_ARG_INFO(0, command)
    ZEND_ARG_INFO(0, params)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_timeout, 0, 0, 1)
    ZEND_ARG_INFO(0, timeout)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_redis_on, 0, 0, 2)
    ZEND_ARG_INFO(0, event_name)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()


static PHP_METHOD(swoole_redis, __construct);
static PHP_METHOD(swoole_redis, __destruct);
static PHP_METHOD(swoole_redis, on);
static PHP_METHOD(swoole_redis,setConnectTimeout);
static PHP_METHOD(swoole_redis,setQueryTimeout);
static PHP_METHOD(swoole_redis, connect);
static PHP_METHOD(swoole_redis,isConnected);
static PHP_METHOD(swoole_redis, __call);
static PHP_METHOD(swoole_redis, close);

static void redis_Client_timeout(swTimer* timer,swTimer_node* node);
static void swoole_redis_onConnect(const redisAsyncContext *c, int status);
static void swoole_redis_onClose(const redisAsyncContext *c, int status);
static void handle_close(swRedisClient* redis);
static void swoole_redis_onCompleted(redisAsyncContext *c, void *r, void *privdata);
static void swoole_redis_connect_cb(swRedisClient *redis, int connected TSRMLS_DC);
static int swoole_redis_onRead(swReactor *reactor, swEvent *event);
static int swoole_redis_onWrite(swReactor *reactor, swEvent *event);
static int swoole_redis_onError(swReactor *reactor, swEvent *event);
static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata);
static void swoole_redis_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC);
static int disconnect_client(swRedisClient* redis);

static void redis_client_free_cb(swRedisClient* redis);

static void swoole_redis_event_AddRead(void *privdata);
static void swoole_redis_event_AddWrite(void *privdata);
static void swoole_redis_event_DelRead(void *privdata);
static void swoole_redis_event_DelWrite(void *privdata);
static void swoole_redis_event_Cleanup(void *privdata);

static zend_class_entry swoole_redis_ce;
zend_class_entry *swoole_redis_class_entry_ptr;
static int isset_event_callback = 0;

static const zend_function_entry swoole_redis_methods[] =
{
    PHP_ME(swoole_redis, __construct, arginfo_swoole_redis_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_redis, __destruct, arginfo_swoole_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_redis, on, arginfo_swoole_redis_on, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, setConnectTimeout, arginfo_swoole_redis_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, setQueryTimeout, arginfo_swoole_redis_timeout, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, connect, arginfo_swoole_redis_connect, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, close, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, isConnected, arginfo_swoole_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_redis, __call, arginfo_swoole_redis_call, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

/*
static sw_inline void defer_close(void* data)
{
    swRedisClient *redis = (swRedisClient *)data;
    redis->released = 0;
    handle_close(redis);
}
*/

static void redis_Client_timeout(swTimer* timer,swTimer_node* node)
{
    SWOOLE_FETCH_TSRMLS;
    swRedisClient *redis = node? node->data:NULL;
    uint8_t timeout_type = redis?redis->timeout_type:SW_CLIENT_INVAILED_TIMEOUT;
    if (timeout_type == SW_CLIENT_CONNECT_TIMEOUT || timeout_type == SW_CLIENT_RECV_TIMEOUT)
    {
        redis->timer_id = 0;
        if (redis->object && redis->onTimeout)
        {
            zval* callback = redis->onTimeout;
            zval* eventType = NULL;
            SW_MAKE_STD_ZVAL(eventType);
            ZVAL_LONG(eventType,timeout_type);
            zval **args[2];
            args[0] = &(redis->object);
            args[1] = &eventType;
            zval *retval = NULL;
            if (sw_call_user_function_ex(EG(function_table), NULL,callback, &retval, 2, args, 0, NULL TSRMLS_CC) == FAILURE)
            {
                zanWarn("timeout event handler error.");
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

static void redis_client_free_cb(swRedisClient* redis)
{
    if (!redis)
    {
        return;
    }

    if (redis->result_callback) {sw_zval_free(redis->result_callback);redis->result_callback = NULL;}
    if (redis->onConnect) {sw_zval_free(redis->onConnect);redis->onConnect = NULL;}
    if (redis->onClose) {sw_zval_ptr_dtor(&redis->onClose);redis->onClose = NULL;}
    if (redis->onTimeout) {sw_zval_free(redis->onTimeout);redis->onTimeout = NULL;}
    if (redis->message_callback) {sw_zval_ptr_dtor(&redis->message_callback);redis->message_callback = NULL;}
}

static sw_inline int swoole_redis_is_message_command(char *command, int command_len)
{
    if (strncasecmp("subscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("psubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("unsubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else if (strncasecmp("punsubscribe", command, command_len) == 0)
    {
        return SW_TRUE;
    }
    else
    {
        return SW_FALSE;
    }
}

void swoole_redis_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_redis_ce, "swoole_redis", "Swoole\\Redis", swoole_redis_methods);
    swoole_redis_class_entry_ptr = zend_register_internal_class(&swoole_redis_ce TSRMLS_CC);

    zend_declare_property_long(swoole_redis_class_entry_ptr, SW_STRL("errCode") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_bool(swoole_redis_class_entry_ptr, SW_STRL("internal_user")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_redis_class_entry_ptr, SW_STRL("connectTimeout") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_redis_class_entry_ptr, SW_STRL("queryTimeout") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);

    zend_declare_property_long(swoole_redis_class_entry_ptr, SW_STRL("sock") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_redis_class_entry_ptr, SW_STRL("port") - 1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_redis_class_entry_ptr, SW_STRL("errMsg") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_string(swoole_redis_class_entry_ptr, SW_STRL("host") - 1, "", ZEND_ACC_PUBLIC TSRMLS_CC);
}

static PHP_METHOD(swoole_redis, __construct)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->setConnectTimeout can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    zval *zset = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|z", &zset))
    {
        return;
    }

    swRedisClient *redis = emalloc(sizeof(swRedisClient));
    bzero(redis, sizeof(swRedisClient));
    redis->fd = -1;
    redis->database = -1;

    if (zset && Z_TYPE_P(zset) == IS_ARRAY)
    {
        php_swoole_array_separate(zset);
//      zend_update_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("setting"), zset TSRMLS_CC);

        HashTable *vht;
        vht = Z_ARRVAL_P(zset);

        /// password
        zval* ztmp = NULL;
        if (php_swoole_array_get_value(vht, "password", ztmp))
        {
            sw_convert_to_string(ztmp);
            if (Z_STRLEN_P(ztmp) >= 1 << 8)
            {
                swoole_php_fatal_error(E_WARNING, "redis password is too long.");
            }
            else if (Z_STRLEN_P(ztmp) > 0)
            {
                redis->password_len = Z_STRLEN_P(ztmp);
                redis->password = estrndup(Z_STRVAL_P(ztmp),redis->password_len);
            }
        }

        /// database
        ztmp = NULL;
        if (php_swoole_array_get_value(vht, "database", ztmp))
        {
            zan_convert_to_long(ztmp);
            if (Z_LVAL_P(ztmp) > 1 << 8)
            {
                swoole_php_fatal_error(E_WARNING, "redis database is too big.");
            }
            else
            {
                redis->database = (int8_t) Z_LVAL_P(ztmp);
            }
        }

        sw_zval_ptr_dtor(&zset);
    }

    swoole_set_object(getThis(), redis);
}

static PHP_METHOD(swoole_redis, on)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if(!redis)
    {
        zanWarn("Reis __construct may not be called");
        RETURN_FALSE;
    }

    zval *internal_user = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    int disable_set = internal_user && Z_BVAL_P(internal_user);

    char *name = NULL;
    zend_size_t len = 0;
    zval *cb = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "sz", &name, &len, &cb))
    {
        RETURN_FALSE;
    }

    if (len == strlen("close") && strncasecmp("close", name, len) == 0)
    {
        if (disable_set)
        {
            zanWarn("object created by connection pool,disable set close event");
            RETURN_FALSE;
        }

        if (redis->onClose)
            sw_zval_ptr_dtor(&redis->onClose);
        redis->onClose = cb;
        sw_copy_to_stack(redis->onClose, redis->_onClose);
    }
    else if (len == strlen("timeout") && strncasecmp("timeout", name, len) == 0)
    {
        if (redis->onTimeout)
            sw_zval_free(redis->onTimeout);
        redis->onTimeout = sw_zval_dup(cb);
    }
    else if (len == strlen("message") && strncasecmp("message", name, len) == 0)
    {
        if (redis->message_callback)
            sw_zval_ptr_dtor(&redis->message_callback);
        redis->message_callback = cb;
        sw_copy_to_stack(redis->message_callback, redis->_message_callback);
        redis->subscribe = 1;
    }
    else
    {
        zanWarn("Unknown event type[%s]", name);
        RETURN_FALSE;
    }

    sw_zval_add_ref(&cb);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis,setConnectTimeout)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->setConnectTimeout can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    long timeout = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",&timeout))
    {
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), timeout TSRMLS_CC);
    RETURN_TRUE
}

static PHP_METHOD(swoole_redis,setQueryTimeout)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->setQueryTimeout can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    long timeout = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &timeout))
    {
        zanWarn("parse parameters error.");
        RETURN_FALSE;
    }

    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("queryTimeout"), timeout TSRMLS_CC);
    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis, connect)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->close can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if(!redis || redis->context || redis->released)
    {
        RETURN_FALSE;
    }

    zval *internal_user = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    if (internal_user && Z_BVAL_P(internal_user))
    {
        return;
    }

    char *host = NULL;
    zend_size_t host_len = 0;
    long port = 0;
    redisAsyncContext* context = NULL;
    zval* callback = NULL;
    /// port <= 0 使用unix sock 方式连接
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "slz", &host, &host_len, &port,&callback))
    {
        RETURN_FALSE;
    }

    if (host_len <= 0 || !host)
    {
        zanWarn("host is empty.");
        RETURN_FALSE;
    }

    if (port > 65535)
    {
        zanWarn("port is invalid.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    int host_unix = 0;
    if (strncasecmp(host, ZEND_STRL("unix:/")) == 0)
    {
        host_unix = 1;
        host += 5;
    }

    context = (port <= 0 || host_unix)? redisAsyncConnectUnix(host):redisAsyncConnect(host, (int) port);
    if (context->err)
    {
        zanWarn("connect to redis-server[%s:%d] failed, Erorr: %s[%d]", host, (int) port, context->errstr, context->err);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    if (!isset_event_callback)
    {
        ServerG.main_reactor->setHandle(ServerG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_READ, swoole_redis_onRead);
        ServerG.main_reactor->setHandle(ServerG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE, swoole_redis_onWrite);
        ServerG.main_reactor->setHandle(ServerG.main_reactor, PHP_SWOOLE_FD_REDIS | SW_EVENT_ERROR, swoole_redis_onError);
        isset_event_callback = 1;
    }

    redisAsyncSetConnectCallback(context, swoole_redis_onConnect);
    redisAsyncSetDisconnectCallback(context, swoole_redis_onClose);
    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("sock"), context->c.fd TSRMLS_CC);

    sw_zval_add_ref(&callback);
    redis->onConnect = sw_zval_dup(callback);

    redis->context = context;
    context->ev.addRead = swoole_redis_event_AddRead;
    context->ev.delRead = swoole_redis_event_DelRead;
    context->ev.addWrite = swoole_redis_event_AddWrite;
    context->ev.delWrite = swoole_redis_event_DelWrite;
    context->ev.cleanup = swoole_redis_event_Cleanup;
    context->ev.data = redis;
    redis->fd = context->c.fd;

    zend_update_property_string(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("host"), host TSRMLS_CC);
    zend_update_property_long(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("port"), port TSRMLS_CC);

    swConnection *conn = swReactor_get(ServerG.main_reactor, redis->context->c.fd);
    bzero(conn,sizeof(swConnection));
    conn->fd = context->c.fd;
    conn->object = redis;

    if (ServerG.main_reactor->add(ServerG.main_reactor, redis->context->c.fd, PHP_SWOOLE_FD_REDIS | SW_EVENT_WRITE) < 0)
    {
        zanWarn("swoole_event_add failed. Erorr: %s[%d].", redis->context->errstr, redis->context->err);
        RETURN_FALSE;
    }

    redis->object = getThis();
    sw_zval_add_ref(&redis->object);
    sw_copy_to_stack(redis->object, redis->_object);

    long timeout = 0;
    zval* connectTimeout = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("connectTimeout"), 1 TSRMLS_CC);
    if (connectTimeout)
    {
        zan_convert_to_long(connectTimeout);
        timeout = Z_LVAL_P(connectTimeout);
    }

    if (timeout > 0)
    {
        redis->timer_id = 0;
        redis->timer_id = swTimer_add(&ServerG.timer,timeout,0,redis,REDIS_USED);
        if (redis->timer_id <= 0)
        {
            zanWarn("set connect timeout timer failed.");
            RETURN_FALSE;
        }

        redis->timeout_type = SW_CLIENT_CONNECT_TIMEOUT;
        register_after_cb(&ServerG.timer,REDIS_USED,redis_Client_timeout);
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis, close)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->close can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    zval *internal_user = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    if (internal_user && Z_BVAL_P(internal_user))
    {
        return;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis || redis->released)
    {
        RETURN_TRUE;
    }

    redis->released = 1;
    disconnect_client(redis);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_redis, __destruct)
{
    swRedisClient *redis = swoole_get_object(getThis());
    if (redis && redis->context)
    {
        disconnect_client(redis);
    }

    releaseConnobj(getThis());
    redis_client_free_cb(redis);
    swoole_set_object(getThis(), NULL);
    swoole_efree(redis);
}

static PHP_METHOD(swoole_redis,isConnected)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->isConnected can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if (!redis || redis->released)
    {
        RETURN_FALSE;
    }
    RETURN_BOOL(redis->state != SWOOLE_REDIS_STATE_CONNECT && redis->state != SWOOLE_REDIS_STATE_CLOSED);
}

static PHP_METHOD(swoole_redis, __call)
{
    if (is_master() || is_networker())
    {
        zanWarn("swoole_redis->__call can not be used in master or networker process, type=%d", ServerG.process_type);
        RETURN_FALSE;
    }

    swRedisClient *redis = swoole_get_object(getThis());
    if(!redis || redis->released || !redis->context)
    {
        RETURN_FALSE;
    }

    zval *params;
    char *command;
    zend_size_t command_len;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &command, &command_len, &params))
    {
        RETURN_FALSE;
    }

    if (Z_TYPE_P(params) != IS_ARRAY)
    {
        zanWarn("invalid params.");
        RETURN_FALSE;
    }

    switch (redis->state)
    {
    case SWOOLE_REDIS_STATE_CONNECT:
        zanWarn("redis client is not connected.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_STATE_WAIT_RESULT:
        zanWarn("redis client is waiting for response.");
        RETURN_FALSE;
        break;
    case SWOOLE_REDIS_STATE_SUBSCRIBE:
        if (!swoole_redis_is_message_command(command, command_len))
        {
            zanWarn("redis client is waiting for subscribe message.");
            RETURN_FALSE;
        }
        break;
    case SWOOLE_REDIS_STATE_CLOSED:
        zanWarn("redis client connection is closed.");
        RETURN_FALSE;
        break;
    default:
        break;
    }

    int argc = zend_hash_num_elements(Z_ARRVAL_P(params));
    size_t stack_argvlen[SW_REDIS_COMMAND_BUFFER_SIZE];
    char *stack_argv[SW_REDIS_COMMAND_BUFFER_SIZE];

    size_t *argvlen;
    char **argv;
    zend_bool free_mm = 0;

    if (argc > SW_REDIS_COMMAND_BUFFER_SIZE)
    {
        argvlen = emalloc(sizeof(size_t) * argc);
        argv = emalloc(sizeof(char*) * argc);
        free_mm = 1;
    }
    else
    {
        argvlen = stack_argvlen;
        argv = stack_argv;
    }

    int i = 0;
#define FREE_MEM() do {                 \
    for (i = 1; i < argc; i++)          \
    {                                   \
        efree((void* )argv[i]);         \
    }                                   \
                                        \
    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE) \
    {                                   \
        efree(argv[argc]);              \
    }                                   \
                                        \
    if (free_mm)                        \
    {                                   \
        efree(argvlen);                 \
        efree(argv);                    \
    }                                   \
    } while (0)

    assert(command_len < SW_REDIS_COMMAND_KEY_SIZE - 1);
    char command_name[SW_REDIS_COMMAND_KEY_SIZE] = {0};
    memcpy(command_name, command, command_len);
    command_name[command_len] = '\0';

    argv[0] = command_name;
    argvlen[0] = command_len;

    zval *value = NULL;
    int index = 1;

    //subscribe command
    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE || (redis->subscribe && swoole_redis_is_message_command(command, command_len)))
    {
        redis->state = SWOOLE_REDIS_STATE_SUBSCRIBE;
        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            argvlen[index] = (size_t) Z_STRLEN_P(value);
            argv[index] = estrndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
            if (index == argc)
            {
                break;
            }
            index++;
        SW_HASHTABLE_FOREACH_END();

        if (redisAsyncCommandArgv(redis->context, swoole_redis_onResult, NULL, argc + 1, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            zanWarn("call redisAsyncCommandArgv failed.");
            FREE_MEM();
            RETURN_FALSE;
        }
    }
    else
    {
        ///storage command
        redis->state = SWOOLE_REDIS_STATE_WAIT_RESULT;

#if PHP_MAJOR_VERSION < 7
        zval *callback = NULL;
        zval **cb_tmp = NULL;
        if (zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1, (void **) &cb_tmp) == FAILURE)
        {
            zanWarn("index out of array.");
            FREE_MEM();
            RETURN_FALSE;
        }
        callback = *cb_tmp;
#else
        zval *callback = zend_hash_index_find(Z_ARRVAL_P(params), zend_hash_num_elements(Z_ARRVAL_P(params)) - 1);
        if (callback == NULL)
        {
            zanWarn("index out of array.");
            FREE_MEM();
            RETURN_FALSE;
        }
#endif
        sw_zval_add_ref(&callback);
        redis->result_callback = sw_zval_dup(callback);

        SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(params), value)
            if (index == argc)
            {
                break;
            }

            if (sw_convert_to_string(value) < 0)
            {
                zanWarn("convert to string failed.");
                RETURN_FALSE;
            }

            argvlen[index] = (size_t) Z_STRLEN_P(value);
            argv[index] = estrndup(Z_STRVAL_P(value), Z_STRLEN_P(value));
            index++;
        SW_HASHTABLE_FOREACH_END();

        if (redisAsyncCommandArgv(redis->context, swoole_redis_onResult, NULL, argc, (const char **) argv, (const size_t *) argvlen) < 0)
        {
            zanWarn("call redisAsyncCommandArgv failed.");
            FREE_MEM();
            RETURN_FALSE;
        }

        long timeout = 0;
        zval* querytimeout = sw_zend_read_property(swoole_redis_class_entry_ptr, getThis(), ZEND_STRL("queryTimeout"), 1 TSRMLS_CC);
        if (querytimeout)
        {
            zan_convert_to_long(querytimeout);
            timeout = Z_LVAL_P(querytimeout);
        }

        if (timeout > 0)
        {
            redis->timer_id = 0;
            redis->timer_id = swTimer_add(&ServerG.timer,timeout,0,redis,REDIS_USED);
            if (redis->timer_id <= 0)
            {
                zanWarn("set recv msg timeout failed.");
                FREE_MEM();
                RETURN_FALSE;
            }

            redis->timeout_type = SW_CLIENT_RECV_TIMEOUT;
            register_after_cb(&ServerG.timer,REDIS_USED,redis_Client_timeout);
        }
    }

    FREE_MEM();
    RETURN_TRUE;
}

static void swoole_redis_parse_result(swRedisClient *redis, zval* return_value, redisReply* reply TSRMLS_DC)
{
    zval *val;
    int j = 0;

    SW_MAKE_STD_ZVAL(val);

    switch (reply->type)
    {
    case REDIS_REPLY_INTEGER:
        ZVAL_LONG(return_value, reply->integer);
        break;

    case REDIS_REPLY_ERROR:
        {
            ZVAL_FALSE(return_value);
            zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), REDIS_ERR TSRMLS_CC);
            char *str = zend_str_tolower_dup(reply->str, reply->len);
            zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), str TSRMLS_CC);
            swoole_efree(str);
        }

        break;

    case REDIS_REPLY_STATUS:
        if (redis->context->err == 0)
        {
            if(reply->len > 0)
            {
                SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
            }
            else
            {
                ZVAL_TRUE(return_value);
            }
        }
        else
        {
            zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), redis->context->err TSRMLS_CC);
            zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), redis->context->errstr TSRMLS_CC);
        }
        break;

    case REDIS_REPLY_STRING:
        SW_ZVAL_STRINGL(return_value, reply->str, reply->len, 1);
        break;

    case REDIS_REPLY_ARRAY:
        array_init(return_value);
        for (j = 0; j < reply->elements; j++)
        {
            swoole_redis_parse_result(redis, val, reply->element[j] TSRMLS_CC);
            add_next_index_zval(return_value, val);
        }
        break;

    case REDIS_REPLY_NIL:
    default:
        ZVAL_NULL(return_value);
        return;
    }
}

static void swoole_redis_onResult(redisAsyncContext *c, void *r, void *privdata)
{
    SWOOLE_FETCH_TSRMLS;

    redisReply *reply = r;
    if (reply == NULL)
    {
        return;
    }

    swRedisClient *redis = c->ev.data;
    if (!redis)
    {
        return;
    }

    if (redis && redis->timer_id > 0)
    {
        long timer_id = redis->timer_id;
        redis->timer_id = 0;
        swTimer_del(&ServerG.timer,timer_id);
    }

    char *callback_type = NULL;
    zval *result = NULL, *retval = NULL, *callback = NULL;

    SW_MAKE_STD_ZVAL(result);
    swoole_redis_parse_result(redis, result, reply TSRMLS_CC);

    int free_cb = 0;
    if (redis->state == SWOOLE_REDIS_STATE_SUBSCRIBE)
    {
        callback = redis->message_callback;
        callback_type = "message";
    }
    else
    {
        callback = redis->result_callback;
        redis->result_callback = NULL;
        callback_type = "result";
        redis->state = SWOOLE_REDIS_STATE_READY;
        free_cb = 1;
    }

    zval **args[2];
    args[0] = &redis->object;
    args[1] = &result;

    if (callback && sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
    {
        zanWarn("redis %s callback handler error.", callback_type);
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&result);
    if (free_cb && callback) sw_zval_free(callback);
}

static void swoole_redis_onConnect(const redisAsyncContext *c, int status)
{
    SWOOLE_FETCH_TSRMLS;
    swRedisClient *redis = c->ev.data;
    if (!redis)
    {
        return ;
    }

    if (status != REDIS_OK)
    {
        zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"),redis->context->err TSRMLS_CC);
        zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"),redis->context->errstr TSRMLS_CC);
        redis->state = SWOOLE_REDIS_STATE_CLOSED;
        swoole_redis_connect_cb(redis,0 TSRMLS_CC);
        return ;
    }
    else
    {
        redis->state = SWOOLE_REDIS_STATE_READY;
    }

    if (redis->password)
    {
        redisAsyncCommand((redisAsyncContext *) c, swoole_redis_onCompleted, NULL, "AUTH %b", redis->password, redis->password_len);
        redis->wait_count++;
    }

    if (redis->database >= 0)
    {
        redisAsyncCommand((redisAsyncContext *) c, swoole_redis_onCompleted, (char*) "end-1", "SELECT %d", redis->database);
        redis->wait_count++;
    }

    if (0 == redis->wait_count)
    {
        swoole_redis_connect_cb(redis,1 TSRMLS_CC);
    }
}

static void swoole_redis_onCompleted(redisAsyncContext *c, void *r, void *privdata)
{
    SWOOLE_FETCH_TSRMLS;
    swRedisClient *redis = c->ev.data;
    if (redis->state == SWOOLE_REDIS_STATE_CLOSED)
    {
        return;
    }

    if (redis->failure == 0)
    {
        redisReply *reply = r;
        switch (reply->type)
        {
        case REDIS_REPLY_ERROR:
            zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"), 0 TSRMLS_CC);
            zend_update_property_stringl(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"), reply->str,reply->len TSRMLS_CC);
            redis->failure = 1;
            break;

        case REDIS_REPLY_STATUS:
            if (redis->context->err == 0)
            {
                break;
            }
            else
            {
                zend_update_property_long(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errCode"),redis->context->err TSRMLS_CC);
                zend_update_property_string(swoole_redis_class_entry_ptr, redis->object, ZEND_STRL("errMsg"),redis->context->errstr TSRMLS_CC);
                redis->failure = 1;
            }
            break;
        }
    }

    if (--redis->wait_count == 0)
    {
        swoole_redis_connect_cb(redis, redis->failure > 0? 0:1 TSRMLS_CC);
    }
}

static void swoole_redis_connect_cb(swRedisClient *redis, int connected TSRMLS_DC)
{
    if (!redis)
    {
        return;
    }

    if (redis->timer_id > 0)
    {
        long timer_id = redis->timer_id;
        redis->timer_id = 0;
        swTimer_del(&ServerG.timer,timer_id);
    }

    zval *zcallback = redis->onConnect;
    redis->onConnect = NULL;
    if (zcallback)
    {
        zval *result = NULL;
        zval *retval = NULL;
        SW_MAKE_STD_ZVAL(result);
        ZVAL_BOOL(result, connected);

        zval **args[2];
        zval* object = redis->object;
        sw_zval_add_ref(&object);
        args[0] = &object;
        args[1] = &result;

        if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 2, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            zanWarn("swoole_async_redis connect_callback handler error.");
        }

        if (retval != NULL)
            sw_zval_ptr_dtor(&retval);

        sw_zval_ptr_dtor(&result);

        if (zcallback)
            sw_zval_free(zcallback);

        sw_zval_ptr_dtor(&object);
    }
}

//hiredis disconnect callback
static void swoole_redis_onClose(const redisAsyncContext *c,int status)
{
    swRedisClient *redis = !c? NULL:c->ev.data;
    if (!redis)
    {
        return ;
    }

    redis->released = 0;
    handle_close(redis);
}

static void handle_close(swRedisClient* redis)
{
    zanDebug("handle close in, fd=%d", redis->fd);
    if (!redis)
    {
        return;
    }

    SWOOLE_FETCH_TSRMLS;
    if (redis->released)
    {
        return;
    }

    redis->released = 1;
    if (redis->timer_id > 0)
    {
        long timer_id = redis->timer_id;
        redis->timer_id = 0;
        swTimer_del(&ServerG.timer,timer_id);
    }

    swoole_efree(redis->password);
    if (redis->object && redis->onClose)
    {
        zval *retval = NULL;
        zval **args[1];
        args[0] = &redis->object;
        zval* callback = redis->onClose;
        if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL TSRMLS_CC) != SUCCESS)
        {
            zanWarn("swoole_async_redis close_callback handler error.");
        }

        if (retval)
        {
            sw_zval_ptr_dtor(&retval);
        }
    }

    if (redis->fd > 2)
    {
        ServerG.main_reactor->close(ServerG.main_reactor, redis->fd);
        redis->fd = -1;
    }

    redis_client_free_cb(redis);
    if (redis->object)
    {
        zval* object = redis->object;
        redis->object = NULL;
        sw_zval_ptr_dtor(&object);
    }
}

static int swoole_redis_onError(swReactor *reactor, swEvent *event)
{
    zanDebug("onError in, fd=%d", event->fd);
    swRedisClient *redis = event->socket->object;
    if (!redis)
    {
        return SW_OK;
    }

    disconnect_client(redis);
    handle_close(redis);
    return SW_OK;
}

static int disconnect_client(swRedisClient* redis)
{
    zanDebug("disconnect client in, fd=%d", redis->fd);
    if (redis && redis->timer_id > 0)
    {
        long timer_id = redis->timer_id;
        redis->timer_id = 0;
        swTimer_del(&ServerG.timer,timer_id);
    }

    redis->database = -1;
    if (redis && redis->context)
    {
        redisAsyncContext* context = redis->context;
        if (redis->state != SWOOLE_REDIS_STATE_CLOSED)
        {
            redis->state = SWOOLE_REDIS_STATE_CLOSED;
            redisAsyncDisconnect(context);
        }
        redis->context = NULL;
    }

    return SW_OK;
}

static void swoole_redis_event_AddRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && ServerG.main_reactor)
    {
        swReactor_add_event(ServerG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_event_DelRead(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && ServerG.main_reactor)
    {
        swReactor_del_event(ServerG.main_reactor, redis->context->c.fd, SW_EVENT_READ);
    }
}

static void swoole_redis_event_AddWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && ServerG.main_reactor)
    {
        swReactor_add_event(ServerG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

static void swoole_redis_event_DelWrite(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    if (redis->context && ServerG.main_reactor)
    {
        swReactor_del_event(ServerG.main_reactor, redis->context->c.fd, SW_EVENT_WRITE);
    }
}

//hiredis disconnect-->cleanup-->redisfree 时调用
static void swoole_redis_event_Cleanup(void *privdata)
{
    swRedisClient *redis = (swRedisClient*) privdata;
    redis->state = SWOOLE_REDIS_STATE_CLOSED;
    if (redis && ServerG.main_reactor)
    {
        zanDebug("cleanup, close fd=%d", redis->fd);
        ServerG.main_reactor->close(ServerG.main_reactor, redis->fd);
        //ServerG.main_reactor->defer(ServerG.main_reactor,defer_close,redis);
        redis->fd = -1;
        redis->context = NULL;
    }
}

static int swoole_redis_onRead(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    if (redis->context && ServerG.main_reactor)
    {
        redisAsyncHandleRead(redis->context);
    }
    return SW_OK;
}

static int swoole_redis_onWrite(swReactor *reactor, swEvent *event)
{
    swRedisClient *redis = event->socket->object;
    if (redis->context && ServerG.main_reactor)
    {
        redisAsyncHandleWrite(redis->context);
    }
    return SW_OK;
}

#endif
