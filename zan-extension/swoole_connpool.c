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
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#include "php_swoole.h"
#include "ext/standard/basic_functions.h"
#include "Zend/zend_operators.h"

#include "zanLog.h"

static zend_class_entry swoole_connpool_ce;
zend_class_entry *swoole_connpool_class_entry_ptr = NULL;

enum timeout_cb_type{
    SW_PHP_USER_CALL = 0,        /// php 调用超时,特指调用get 方法超时
    SW_CONNINTERVAL_CALL = 1,    /// 内部调用连接方法的时间间隔
    SW_HBINTERVAL_CALL = 2,     /// 心跳间隔超时
};

enum connpool_type{
    SW_CONNPOOL_TYPE_INVAIL = 0,    /// 无效类型的连接池
    SW_CONNPOOL_TCP = 1,               /// async tcp client 连接池
#ifdef SW_USE_REDIS
    SW_CONNPOOL_REDIS,             /// redis client 连接池
#endif
    SW_CONNPOOL_MYSQL,             /// mysql连接池
    SW_CONNPOOL_TYPE_NUM,          /// 连接池类型总数
    SW_CONNPOOL_HTTP,              /// http 连接池，预留，当前没有做
};

/// 参数校验类型
enum args_check_type{
    OBJ_IS_INSTANCE = 1,               /// 校验参数是否是对应对象
    ARGS_IS_VAILED = 1 << 1 ,      /// 参数字段校验
    ARGC_IS_CONNECTED = (1 << 2 | OBJ_IS_INSTANCE)  /// 对象是否处于连接状态，需要先判断是否是指定类型
};

enum connection_status{
    SW_CONNOBJ_INITED = 0,              ///连接初始状态
    SW_CONNOBJ_CONNING,                 ///连接过程中
    SW_CONNOBJ_OK,                      ///连接成功
    SW_CONNOBJ_ERR,                     ///连接错误
    SW_CONNOBJ_CLOSED,                  ///连接关闭
};

enum connpool_status{
    SW_CONNPOOL_INIT    = 0,                    /// 连接池初始状态
    SW_CONNPOOL_INITED  = 1,                /// 连接池创建成功
    SW_CONNPOOL_RELEASED = 2,           /// 连接池销毁
    SW_CONNPOOLOBJ      = 10,           /// 连接对象的初始状态
    SW_CONNPOOLOBJ_DEFER_CONNECT = 11,  /// 连接对象延迟连接状态
    SW_CONNPOOLOBJ_WAIT_CONNECT = 12,   /// 连接对象等待连接结果回调
    SW_CONNPOOLOBJ_WAIT_HB = 13,            /// 连接对象等待心跳开始
    SW_CONNPOOLOBJ_HB = 14,             /// 连接对象心跳过程中
    SW_CONNPOOLOBJ_CONNECTED = 15,      /// 连接对象处于空闲状态
    SW_CONNPOOLOBJ_WAIT_CB = 16,            /// 连接对象获取，等待回调至业务层
    SW_CONNPOOLOBJ_REALEASED = 17       /// 连接关联对象已经销毁，但连接对象处于延迟回调中，延迟回调中需要销毁连接对象
};

#define DEFAULT_CONNECT_TIMEOUT   200
#define DEFAULT_RECVMSG_TIMEOUT   500
#define DEFAULT_GETCONN_TIMEOUT   200

#define DEFAULT_RECONNECT_TIMES   5
#define MAX_RECONNECT_TIMES      15

/// 用于产生重连间隔随机数
#define MAX_RECONNECT_INTERVAL    10
#define MIN_RECONNECT_INTERVAL    1
#define MAX_CONNECT_INTERVAL      2000
#define MIN_CONNECT_INTERVAL      1000

typedef struct _tag_connpool connpool;

typedef struct _tag_connobj{
    uint8_t     connStatus;
    uint8_t     connTimes;
    uint8_t     currStatus;
    connpool*   pool;
    uint64_t    clientId;
    uint64_t    timeId;
    zval*       client;
#if PHP_MAJOR_VERSION >= 7
    zval        _client;
#endif
}connobj;

typedef struct _tag_connobj_arg{
    int         type;               /// 调用方式
    uint64_t    tmpId;
    uint64_t    clientId;
    zval*       user_callback;
    void*       pool;
    connobj*    obj;
#if PHP_MAJOR_VERSION >= 7
    zval        _user_callback;
#endif
}connobj_arg;

typedef struct _tag_connpool_property{
    int              maxConnTimes;
    int          maxConnIntvl;
    int          connIntvl;
    long         connpoolType;
    long         connpoolMinNum;
    long         connpoolMaxNum;
    long             connectTimeout;
    long             hbTimeout;
    long         hbIntervalTime;
    zval*        onHBMsgConstruct;
    zval*        onHBMsgCheck;
    zval*        cfg;
#if PHP_MAJOR_VERSION >= 7
    zval         _onHBMsgConstruct;
    zval         _onHBMsgCheck;
    zval             _cfg;
#endif
}connpool_property;

typedef struct _tag_connpoolMap{
    swHashMap       *hash_map;
    swLinkedList    *list;

    void* (*release)(struct _tag_connpoolMap*, uint64_t id);
    void* (*pop)(struct _tag_connpoolMap*);
    int   (*push)(struct _tag_connpoolMap* map,uint64_t id,void* data);
    int   (*getNums)(struct _tag_connpoolMap* map);
    int   (*destroyMap)(struct _tag_connpoolMap* map);
}connpoolMap;

struct _tag_connpool{
    int          connpoolStatus;
    int          refCount;
    connpoolMap* waitConnobjPool;
    connpoolMap* idlePool;
    connpoolMap* connObjMap;
    int          (*create)(connpool_property* poolpro,connobj* connobj TSRMLS_DC);
    int          (*argsCheck)(zval* value,int type TSRMLS_DC);
    int          (*connect)(connpool_property* poolpro,connobj* connobj TSRMLS_DC);
    int          (*send)(connpool_property* poolpro,connobj* connobj TSRMLS_DC);
    int          (*close)(connobj* connobj TSRMLS_DC);
    zval*        zobject;
#if PHP_MAJOR_VERSION >= 7
    zval         _zobject;
#endif
};

static uint64_t swoole_connpool_id = 0;

ZEND_METHOD(swoole_connpool,__construct);
ZEND_METHOD(swoole_connpool,__destruct);
ZEND_METHOD(swoole_connpool,createConnPool);
ZEND_METHOD(swoole_connpool,getStatInfo);
ZEND_METHOD(swoole_connpool,destroy);
ZEND_METHOD(swoole_connpool,setConfig);
ZEND_METHOD(swoole_connpool,on);
ZEND_METHOD(swoole_connpool,get);
ZEND_METHOD(swoole_connpool,release);


static connpoolMap* createPoolMap(swDestructor dtor);
static int destroyPoolMap(connpoolMap* map);
static void* map_release_node(connpoolMap* map, uint64_t id);
static void* map_pop_node(connpoolMap* map);
static int map_node_nums(connpoolMap* map);
static int map_push_node(connpoolMap* map,uint64_t id,void* data);


static int initConnpool(int type, connpool* pool);
static void onDefer_handler(void* args);
static int createConnobj(connpool* pool,connpool_property* proptr,connobj* con_obj);
static void defer_create_connobj(connpool* pool,connpool_property* proptr,int connTimes);
static void callback_connobj(connobj_arg* cbArgs TSRMLS_DC);
static long getConnobjFromPool(connpool* pool,long timeout,zval* callback);
static void connpool_onTimeout(swTimer* timer,swTimer_node* node);
static int handler_new_connobj(connpool* pool,connpool_property* proptr,connobj* connClient);
static int client_close(int type,connobj* connClient TSRMLS_DC);
static void close_handler(zval* client);
static void clean_conobj_resource(connobj* con_obj,int reconnect);
static void connpool_onHBSend(swTimer* timer,swTimer_node* node);
static void destroy_resource(connpool* pool,connpool_property* proptr);

void releaseConnobj(zval* client)
{
    connobj* connClient = client? swoole_get_property(client,swoole_connpool_object):NULL;
    if (!connClient)
    {
        return ;
    }

    swoole_set_property(client,swoole_connpool_object,NULL);
    connpool* pool = connClient->pool;
    connClient->pool = NULL;
    if (pool && pool->connObjMap)
    {
        pool->connObjMap->release(pool->connObjMap,connClient->clientId);
    }

    if (pool && 1 == pool->refCount--)
    {
        swoole_efree(pool);
    }

    /// 对象在等待回调时，不能立即释放，需要在延迟回调中处理
    if (connClient->currStatus == SW_CONNPOOLOBJ_WAIT_CB)
    {
        connClient->currStatus = SW_CONNPOOLOBJ_REALEASED;
        return ;
    }

    swoole_efree(connClient);
}

static sw_inline connobj* newConnobj(connpool* pool)
{
    connobj* con_obj = emalloc(sizeof(connobj));
    memset(con_obj,0x00,sizeof(connobj));
    con_obj->clientId = ++swoole_connpool_id;
    con_obj->timeId = 0;
    con_obj->connStatus = SW_CONNOBJ_INITED;
    con_obj->currStatus = SW_CONNPOOLOBJ;
    con_obj->connTimes = 0;
    con_obj->pool = pool;
    pool->refCount++;
    pool->connObjMap->push(pool->connObjMap,con_obj->clientId,con_obj);
    return con_obj;
}

static sw_inline void free_data(void *data)
{
    connobj_arg* args = (connobj_arg*)data;
    if (args->user_callback)
    {
        sw_zval_ptr_dtor(&(args->user_callback));
        args->user_callback = NULL;
    }

    swoole_efree(args);
}

static int createConnobj(connpool* pool,connpool_property* proptr,connobj* con_obj)
{
    con_obj->currStatus = SW_CONNPOOLOBJ_WAIT_CONNECT;
    con_obj->connStatus = SW_CONNOBJ_CONNING;
    con_obj->timeId = 0;
    SWOOLE_FETCH_TSRMLS;
    if (pool->create(proptr,con_obj TSRMLS_CC) < 0 || pool->connect(proptr,con_obj TSRMLS_CC) < 0)
    {
        pool->close(con_obj TSRMLS_CC);
    }

    return SW_OK;
}

static void defer_create_connobj(connpool* pool,connpool_property* proptr,int connTimes)
{
    /// 根据重连次数决定延迟连接时间
    double after = 0;
    if (connTimes >= proptr->maxConnTimes)
    {
        /// 对于断网情况，可以在此释放连接.
        after = (1 << connTimes)*(proptr->connIntvl);
        after = after < proptr->maxConnIntvl? proptr->maxConnIntvl:after;
    }
    else
    {
        after = (1 << (connTimes++))*(proptr->connIntvl);
    }

    connobj_arg* args = emalloc(sizeof(connobj_arg));
    memset(args,0x00,sizeof(connobj_arg));
    args->type = SW_CONNINTERVAL_CALL;

    connobj* con_obj = newConnobj(pool);
    con_obj->connTimes = connTimes;
    con_obj->currStatus = SW_CONNPOOLOBJ_DEFER_CONNECT;

    args->obj = con_obj;
    args->clientId = con_obj->clientId;
    con_obj->timeId = args->tmpId = swTimer_add(&ServerG.timer,after,0,args,CONNPOOL_USED);

    return;
}

static sw_inline void connpool_onConnInter(swTimer* timer,swTimer_node* node)
{
    connobj_arg* args = (connobj_arg*)(node->data);
    connobj* conn_obj = args->obj;
    connpool* pool = conn_obj->pool;
    conn_obj->timeId = args->tmpId = 0;
    connpool_property* proptr = swoole_get_property(pool->zobject,swoole_property_common);
    createConnobj(pool,proptr,conn_obj);
    return;
}

static void connpool_onHBSend(swTimer* timer,swTimer_node* node)
{
    connobj_arg* args = (connobj_arg*)(node->data);
    connpool* pool = (connpool*)(args->pool);
    args->tmpId = 0;
    /// 从空闲池中出栈
    connobj* obj = pool->idlePool->release(pool->idlePool,args->clientId);
    if (!obj){
        return;
    }

    /// 发送心跳数据,使用带超时接口
    zval* zobject = pool->zobject;
    connpool_property* proptr = swoole_get_property(zobject,swoole_property_common);
    obj->currStatus = SW_CONNPOOLOBJ_HB;
    obj->timeId = 0;
    SWOOLE_FETCH_TSRMLS;
    if (pool->send(proptr,obj TSRMLS_CC) < 0)
    {
        pool->close(obj TSRMLS_CC);
    }
}

static sw_inline void connpool_onGetObj(swTimer* timer,swTimer_node* node TSRMLS_DC)
{
    connobj_arg* args = (connobj_arg*)(node->data);
    connpool* pool = (connpool*)args->pool;
    pool->waitConnobjPool->release(pool->waitConnobjPool,args->tmpId);
    args->obj = NULL;
    args->tmpId = 0;

    callback_connobj(args TSRMLS_CC);
    return;
}

//check the php method para
ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_construct, 0, 0, 1)
    ZEND_ARG_INFO(0,type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_init, 0, 0, 2)
    ZEND_ARG_INFO(0,min_num)
    ZEND_ARG_INFO(0,max_num)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_setcfg, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0,cfg,0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_on, 0, 0, 2)
    ZEND_ARG_INFO(0,namestr)
    ZEND_ARG_INFO(0,callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_get, 0, 0, 2)
    ZEND_ARG_INFO(0,timeout)
    ZEND_ARG_INFO(0,callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_connpool_release, 0, 0, 1)
    ZEND_ARG_INFO(0,obj)
    ZEND_ARG_INFO(0,status)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_connpool_methods[] =
{
    ZEND_ME(swoole_connpool,__construct,arginfo_swoole_connpool_construct,ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    ZEND_ME(swoole_connpool,__destruct,arginfo_swoole_void,ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    ZEND_ME(swoole_connpool,createConnPool,arginfo_swoole_connpool_init,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,destroy,arginfo_swoole_void,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,setConfig,arginfo_swoole_connpool_setcfg,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,on,arginfo_swoole_connpool_on,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,get,arginfo_swoole_connpool_get,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,getStatInfo,arginfo_swoole_void,ZEND_ACC_PUBLIC)
    ZEND_ME(swoole_connpool,release,arginfo_swoole_connpool_release,ZEND_ACC_PUBLIC)
    ZEND_FE_END
};

void swoole_connpool_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_connpool_ce, "swoole_connpool", "Swoole\\Connection\\Pool", swoole_connpool_methods);
    swoole_connpool_class_entry_ptr = zend_register_internal_class(&swoole_connpool_ce TSRMLS_CC);

    /// declare property
//  zend_declare_property_long(swoole_connpool_class_entry_ptr, SW_STRL("errCode")-1, 0, ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNPOOL_TCP")-1,SW_CONNPOOL_TCP TSRMLS_CC);
#ifdef SW_USE_REDIS
    zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNPOOL_REDIS")-1,SW_CONNPOOL_REDIS TSRMLS_CC);
#endif
    zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNPOOL_MYSQL")-1,SW_CONNPOOL_MYSQL TSRMLS_CC);
//  zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNPOOL_HTTP")-1,SW_CONNPOOL_HTTP TSRMLS_CC);
    zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNNECT_OK")-1,SW_CONNOBJ_OK TSRMLS_CC);
    zend_declare_class_constant_long(swoole_connpool_class_entry_ptr, SW_STRL("SWOOLE_CONNNECT_ERR")-1,SW_CONNOBJ_ERR TSRMLS_CC);
}

static sw_inline int tcpclient_args_check(zval* args,int type TSRMLS_DC)
{
    if (!args)
    {
        return SW_ERR;
    }

    if (type & OBJ_IS_INSTANCE)
    {
        if (!instanceof_function(Z_OBJCE_P(args), swoole_client_class_entry_ptr TSRMLS_CC))
        {
            return SW_ERR;
        }
    }

    if (type & ARGS_IS_VAILED)
    {
        zval* connection_cfg = args;
        php_swoole_array_separate(connection_cfg);
        HashTable *_ht = Z_ARRVAL_P(connection_cfg);
        zval *value = NULL;
        if (!php_swoole_array_get_value(_ht, "host", value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        value = NULL;
        if (!php_swoole_array_get_value(_ht,"port",value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        sw_zval_ptr_dtor(&connection_cfg);
    }

    if (type & ARGC_IS_CONNECTED)
    {
        zval* retval = NULL;
        sw_zend_call_method_with_0_params(&args,swoole_client_class_entry_ptr,NULL,"isconnected",&retval);
        if (retval && !Z_BVAL_P(retval))
        {
            return SW_CONNOBJ_ERR;
        }

        return SW_CONNOBJ_OK;
    }

    return SW_OK;
}

static sw_inline int tcpclient_create(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (connClient->client)
    {
        return SW_OK;
    }

    zval *client = NULL;
    SW_ALLOC_INIT_THE_ZVAL(client,connClient->_client);

    if (object_init_ex(client, swoole_client_class_entry_ptr) != SUCCESS) {
        return SW_ERR;
    }

    zval* retval = NULL;
    {
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv1);
        ZVAL_LONG(argv1,SW_SOCK_TCP);
        zval* argv2;
        SW_MAKE_STD_ZVAL(argv2);
        ZVAL_LONG(argv2,SW_SOCK_ASYNC);
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"__construct",&retval,argv1,argv2);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv1);
        sw_zval_ptr_dtor(&argv2);
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"close",1);
        SW_ZVAL_STRING(argv1,"onClientClose",1);
        retval = NULL;
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"connect",1);
        SW_ZVAL_STRING(argv1,"onClientConnect",1);
        retval = NULL;
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"error",1);
        SW_ZVAL_STRING(argv1,"onClientClose",1);
        retval = NULL;
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    {
        retval = NULL;
        sw_zend_call_method_with_1_params(&client,swoole_client_class_entry_ptr,NULL,"set",&retval,poolproper->cfg);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
    }

    connClient->client = client;
    swoole_set_property(client,swoole_connpool_object,connClient);
    return SW_OK;
}

static sw_inline int tcpclient_connect(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    zval* client = connClient->client;
    zval* connection_cfg = poolproper->cfg;
    php_swoole_array_separate(connection_cfg);
    HashTable *_ht = Z_ARRVAL_P(connection_cfg);

    zval *host = NULL;
    if (!php_swoole_array_get_value(_ht, "host", host))
    {
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    if (sw_convert_to_string(host) < 0)
    {
        zanWarn("convert to string failed.");
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    zval* port = NULL;
    if (!php_swoole_array_get_value(_ht,"port",port))
    {
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    convert_to_long(port);

    zval* retval = NULL;
    zend_update_property_long(swoole_client_class_entry_ptr, client, ZEND_STRL("connectTimeout"), poolproper->connectTimeout TSRMLS_CC);

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval)  {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    zval* flag = NULL;
    SW_MAKE_STD_ZVAL(flag);
    ZVAL_LONG(flag, 0);

    zval** args[3];
    args[0] = &host;
    args[1] = &port;
    args[2] = &flag;

    zval* function = NULL;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function,"connect",1);

    int ret = SW_OK;
    if (sw_call_user_function_ex(NULL,&client,function,&retval,3,args,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call tcpclient connect error.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_client_class_entry_ptr, client, ZEND_STRL("connectTimeout"), 0 TSRMLS_CC);

    if (retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
    {
        zanDebug("tcpclient connect return false.");
        ret = SW_ERR;
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&flag);
    sw_zval_ptr_dtor(&function);
    sw_zval_ptr_dtor(&connection_cfg);
    return ret;
}

static sw_inline int tcpclient_send(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (!poolproper || !poolproper->onHBMsgConstruct || !connClient || !connClient->client){
        return SW_ERR;
    }

    zval* client = connClient->client;

    zval* retval = NULL;
/// 获取心跳信息.
    zval* php_callback = poolproper->onHBMsgConstruct;
    sw_call_user_function_ex(EG(function_table),NULL,php_callback,&retval,0,NULL,0,NULL TSRMLS_CC);
    if (!retval || ZVAL_IS_NULL(retval) || Z_TYPE_P(retval) != IS_ARRAY)
    {
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        return SW_ERR;
    }

    zval* return_value = retval;
    php_swoole_array_separate(retval);
    sw_zval_ptr_dtor(&return_value);

    HashTable *_ht = Z_ARRVAL_P(retval);
    zval *data = NULL;
    if (!php_swoole_array_get_value(_ht, "args", data))
    {
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        return SW_ERR;
    }

    zval* result = NULL;
    zend_update_property_long(swoole_client_class_entry_ptr, client, ZEND_STRL("sendTimeout"), poolproper->hbTimeout TSRMLS_CC);

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&result,argv0,argv1);
        if (result)  {sw_zval_ptr_dtor(&result);result = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"receive",1);
        SW_ZVAL_STRING(argv1,"onClientRecieve",1);
        sw_zend_call_method_with_2_params(&client,swoole_client_class_entry_ptr,NULL,"on",&result,argv0,argv1);
        if (result)  {sw_zval_ptr_dtor(&result);result = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    zval* function = NULL;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function,"send",1);

    int ret = SW_OK;
    zval** args[1];
    args[0] = &data;

    if (sw_call_user_function_ex(NULL,&client,function,&result,1,args,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call tcp send error.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_client_class_entry_ptr, client, ZEND_STRL("sendTimeout"), 0 TSRMLS_CC);

    if (result && !ZVAL_IS_NULL(result) && !Z_BVAL_P(result))
    {
        ret = SW_ERR;
    }

    if (result) sw_zval_ptr_dtor(&result);
    if (retval) sw_zval_ptr_dtor(&retval);
    sw_zval_ptr_dtor(&function);
    return ret;
}

#ifdef SW_USE_REDIS
static sw_inline int redisclient_args_check(zval* args,int type TSRMLS_DC)
{
    if (!args)
    {
        return SW_ERR;
    }

    if (type & OBJ_IS_INSTANCE)
    {
        if (!instanceof_function(Z_OBJCE_P(args), swoole_redis_class_entry_ptr TSRMLS_CC))
        {
            return SW_ERR;
        }
    }

    if (type & ARGS_IS_VAILED)
    {
        zval* connection_cfg = args;
        php_swoole_array_separate(connection_cfg);
        HashTable *_ht = Z_ARRVAL_P(connection_cfg);
        zval *value = NULL;
        if (!php_swoole_array_get_value(_ht, "host", value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        value = NULL;
        if (!php_swoole_array_get_value(_ht,"port",value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        sw_zval_ptr_dtor(&connection_cfg);
    }

    if (type & ARGC_IS_CONNECTED)
    {
        zval* retval = NULL;
        sw_zend_call_method_with_0_params(&args,swoole_redis_class_entry_ptr,NULL,"isconnected",&retval);
        if (retval && !Z_BVAL_P(retval))
        {
            return SW_CONNOBJ_ERR;
        }

        return SW_CONNOBJ_OK;
    }

    return SW_OK;
}

static sw_inline int redisclient_create(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (connClient->client)
    {
        return SW_ERR;
    }

    zval *client = NULL;
    SW_ALLOC_INIT_THE_ZVAL(client,connClient->_client);

    if (object_init_ex(client, swoole_redis_class_entry_ptr) != SUCCESS) {
        return SW_ERR;
    }

    zval* retval = NULL;

    {
        sw_zend_call_method_with_0_params(&client,swoole_redis_class_entry_ptr,NULL,"__construct",&retval);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"close",1);
        SW_ZVAL_STRING(argv1,"onClientClose",1);
        sw_zend_call_method_with_2_params(&client,swoole_redis_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval)  {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    connClient->client = client;
    swoole_set_property(client,swoole_connpool_object,connClient);
    return SW_OK;
}

static sw_inline int redisclient_connect(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    zval* connection_cfg = poolproper->cfg;
    php_swoole_array_separate(connection_cfg);
    HashTable *_ht = Z_ARRVAL_P(connection_cfg);

    zval *host = NULL;
    if (!php_swoole_array_get_value(_ht, "host", host))
    {
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    if (sw_convert_to_string(host) < 0)
    {
        zanWarn("convert to string failed.");
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    zval* port = NULL;
    if (!php_swoole_array_get_value(_ht,"port",port))
    {
        sw_zval_ptr_dtor(&connection_cfg);
        return SW_ERR;
    }

    convert_to_long(port);

    int ret = SW_OK;
    zval* client = connClient->client;
    zval* retval = NULL;

    zend_update_property_long(swoole_redis_class_entry_ptr, client, ZEND_STRL("connectTimeout"), poolproper->connectTimeout TSRMLS_CC);

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_redis_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval)  {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    zval* callback = NULL;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback,"onSubClientConnect",1);

    zval** argvs[3];
    argvs[0] = &host;
    argvs[1] = &port;
    argvs[2] = &callback;

    zval* function = NULL;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function,"connect",1);
    if (sw_call_user_function_ex(NULL,&client,function,&retval,3,argvs,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call redis connect error.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_redis_class_entry_ptr, client, ZEND_STRL("connectTimeout"), 0 TSRMLS_CC);
    if (retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
    {
        zanDebug("redisclient connect return false.");
        ret = SW_ERR;
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&callback);
    sw_zval_ptr_dtor(&function);
    sw_zval_ptr_dtor(&connection_cfg);
    return ret;
}

static sw_inline int redisclient_send(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (!poolproper || !poolproper->onHBMsgConstruct || !connClient || !connClient->client){
        return SW_ERR;
    }

    zval* client = connClient->client;
    zval* retval = NULL;

    /// 获取心跳信息.
    zval* php_callback = poolproper->onHBMsgConstruct;
    sw_call_user_function_ex(EG(function_table),NULL,php_callback,&retval,0,NULL,0,NULL TSRMLS_CC);
    if (!retval || ZVAL_IS_NULL(retval) || Z_TYPE_P(retval) != IS_ARRAY)
    {
        if (retval) sw_zval_ptr_dtor(&retval);
        return SW_ERR;
    }

    zval* return_value = retval;
    php_swoole_array_separate(retval);
    sw_zval_ptr_dtor(&return_value);
    HashTable *_ht = Z_ARRVAL_P(retval);
    zval* method = NULL;
    if (!php_swoole_array_get_value(_ht, "method", method))
    {
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        return SW_ERR;
    }

    zval* result = NULL;
    zend_update_property_long(swoole_redis_class_entry_ptr, client, ZEND_STRL("queryTimeout"), poolproper->hbTimeout TSRMLS_CC);

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_redis_class_entry_ptr,NULL,"on",&result,argv0,argv1);
        if (result)  {sw_zval_ptr_dtor(&result);result = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    if (sw_convert_to_string(method) < 0)
    {
        zanWarn("convert to string failed.");
        sw_zval_ptr_dtor(&retval);
        return SW_ERR;
    }

    zval* callback;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback,"onClientRecieve",1);
    zval** argvs[2];
    int argc = 0;
    zval *data = NULL;
    if (php_swoole_array_get_value(_ht, "args", data) && data && !ZVAL_IS_NULL(data))
    {
        argvs[argc++] = &data;
    }

    argvs[argc++] = &callback;

    int ret = SW_OK;
    if (sw_call_user_function_ex(NULL,&client,method,&result,argc,argvs,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call redis __call failed.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_redis_class_entry_ptr, client, ZEND_STRL("queryTimeout"), 0 TSRMLS_CC);
    if (result && !ZVAL_IS_NULL(result) && !Z_BVAL_P(result))
    {
        zanDebug("redisclient __call return false.");
        ret = SW_ERR;
    }

    if (result) sw_zval_ptr_dtor(&result);
    if (retval) sw_zval_ptr_dtor(&retval);

    sw_zval_ptr_dtor(&callback);

    return ret;
}
#endif

static sw_inline int mysqlclient_args_check(zval* args,int type TSRMLS_DC)
{
    if (!args)
    {
        return SW_ERR;
    }

    if (type & OBJ_IS_INSTANCE)
    {
        if (!instanceof_function(Z_OBJCE_P(args), swoole_mysql_class_entry_ptr TSRMLS_CC))
        {
            return SW_ERR;
        }
    }

    if (type & ARGS_IS_VAILED)
    {
        zval* connection_cfg = args;
        php_swoole_array_separate(connection_cfg);
        HashTable *_ht = Z_ARRVAL_P(connection_cfg);
        zval *value = NULL;
        if (!php_swoole_array_get_value(_ht, "host", value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        value = NULL;
        if (!php_swoole_array_get_value(_ht,"user",value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        value = NULL;
        if (!php_swoole_array_get_value(_ht,"database",value))
        {
            sw_zval_ptr_dtor(&connection_cfg);
            return SW_ERR;
        }

        sw_zval_ptr_dtor(&connection_cfg);
    }
    else if (type & ARGC_IS_CONNECTED)
    {
        zval* retval = NULL;
        sw_zend_call_method_with_0_params(&args,swoole_mysql_class_entry_ptr,NULL,"isconnected",&retval);
        if (retval && !Z_BVAL_P(retval))
        {
            return SW_CONNOBJ_ERR;
        }

        return SW_CONNOBJ_OK;
    }

    return SW_OK;
}

static sw_inline int mysqlclient_create(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (connClient->client)
    {
        return SW_ERR;
    }

    zval *client = NULL;
    SW_ALLOC_INIT_THE_ZVAL(client,connClient->_client);

    if (object_init_ex(client, swoole_mysql_class_entry_ptr) != SUCCESS) {
        return SW_ERR;
    }

    zval* retval = NULL;
    {
        sw_zend_call_method_with_0_params(&client,swoole_mysql_class_entry_ptr,NULL,"__construct",&retval);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
    }

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"close",1);
        SW_ZVAL_STRING(argv1,"onClientClose",1);
        sw_zend_call_method_with_2_params(&client,swoole_mysql_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    connClient->client = client;
    swoole_set_property(client,swoole_connpool_object,connClient);
    return SW_OK;
}

static sw_inline int mysqlclient_connect(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    zval* connection_cfg = poolproper->cfg;

    zval* client = connClient->client;
    zval* retval = NULL;

    zend_update_property_long(swoole_mysql_class_entry_ptr, client, ZEND_STRL("connectTimeout"), poolproper->connectTimeout TSRMLS_CC);

    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_mysql_class_entry_ptr,NULL,"on",&retval,argv0,argv1);
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    zval* callback = NULL;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback,"onSubClientConnect",1);

    zval** argvs[2];
    argvs[0] = &connection_cfg;
    argvs[1] = &callback;

    int ret = SW_OK;
    zval* function = NULL;
    SW_MAKE_STD_ZVAL(function);
    SW_ZVAL_STRING(function,"connect",1);
    if (sw_call_user_function_ex(NULL,&client,function,&retval,2,argvs,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call mysql connect failed.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_mysql_class_entry_ptr, client, ZEND_STRL("connectTimeout"), 0 TSRMLS_CC);

    if (retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
    {
        zanDebug("mysqlclient connect return false.");
        ret = SW_ERR;
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&callback);
    sw_zval_ptr_dtor(&function);

    return ret;
}

static sw_inline int mysqlclient_send(connpool_property* poolproper,connobj* connClient TSRMLS_DC)
{
    if (!poolproper || !poolproper->onHBMsgConstruct || !connClient || !connClient->client){
        return SW_ERR;
    }

    zval* client = connClient->client;
    zval* retval = NULL;

    /// 获取心跳信息.
    zval* php_callback = poolproper->onHBMsgConstruct;
    sw_call_user_function_ex(EG(function_table),NULL,php_callback,&retval,0,NULL,0,NULL TSRMLS_CC);

    if (!retval || ZVAL_IS_NULL(retval) || Z_TYPE_P(retval) != IS_ARRAY)
    {
        if (retval) sw_zval_ptr_dtor(&retval);
        return SW_ERR;
    }

    zval* return_value = retval;
    php_swoole_array_separate(retval);
    sw_zval_ptr_dtor(&return_value);

    HashTable *_ht = Z_ARRVAL_P(retval);

    zval *data = NULL;
    if (!php_swoole_array_get_value(_ht, "args", data))
    {
        if (retval) {sw_zval_ptr_dtor(&retval);retval = NULL;}
        return SW_ERR;
    }

    zval* result = NULL;
    zend_update_property_long(swoole_mysql_class_entry_ptr, client, ZEND_STRL("queryTimeout"), poolproper->hbTimeout TSRMLS_CC);

    ///设置超时回调
    {
        zval* argv0;
        zval* argv1;
        SW_MAKE_STD_ZVAL(argv0);
        SW_MAKE_STD_ZVAL(argv1);
        SW_ZVAL_STRING(argv0,"timeout",1);
        SW_ZVAL_STRING(argv1,"onClientTimeout",1);
        sw_zend_call_method_with_2_params(&client,swoole_mysql_class_entry_ptr,NULL,"on",&result,argv0,argv1);
        if (result) {sw_zval_ptr_dtor(&result);result = NULL;}
        sw_zval_ptr_dtor(&argv0);
        sw_zval_ptr_dtor(&argv1);
    }

    zval* method = NULL;
    SW_MAKE_STD_ZVAL(method);
    SW_ZVAL_STRING(method,"query",1);

    zval* callback;
    SW_MAKE_STD_ZVAL(callback);
    SW_ZVAL_STRING(callback,"onClientRecieve",1);

    zval** argvs[2];
    argvs[0] = &data;
    argvs[1] = &callback;

    int ret = SW_OK;
    if (sw_call_user_function_ex(NULL,&client,method,&result,2,argvs,0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("call mysql query failed.");
        ret = SW_ERR;
    }

    zend_update_property_long(swoole_mysql_class_entry_ptr, client, ZEND_STRL("queryTimeout"), 0 TSRMLS_CC);

    if (result && !ZVAL_IS_NULL(result) && !Z_BVAL_P(result))
    {
        zanDebug("mysql connect return false.");
        ret = SW_ERR;
    }

    if (result) sw_zval_ptr_dtor(&result);
    if (retval) sw_zval_ptr_dtor(&retval);

    sw_zval_ptr_dtor(&callback);
    sw_zval_ptr_dtor(&method);

    return ret;
}

static sw_inline int tcpclient_close(connobj* connClient TSRMLS_DC)
{
    return client_close(SW_CONNPOOL_TCP,connClient TSRMLS_CC);
}

#ifdef SW_USE_REDIS
static sw_inline int redisclient_close(connobj* connClient TSRMLS_DC)
{
    return client_close(SW_CONNPOOL_REDIS,connClient TSRMLS_CC);
}
#endif

static sw_inline int mysqlclient_close(connobj* connClient TSRMLS_DC)
{
    return client_close(SW_CONNPOOL_MYSQL,connClient TSRMLS_CC);
}

static int client_close(int type,connobj* connClient TSRMLS_DC)
{
    if (!connClient){
        return SW_ERR;
    }

    /// 防二次调用
    if (SW_CONNOBJ_CLOSED != connClient->connStatus)
    {
        clean_conobj_resource(connClient,connClient->client != NULL? 1:0);
        if (!connClient->client)
        {
            connpool* pool = connClient->pool;
            connClient->pool = NULL;
            if (pool && 1 == pool->refCount--)
            {
                swoole_efree(pool);
            }

            swoole_efree(connClient);
            return SW_OK;
        }
    } else if (!connClient->client){
        return SW_OK;
    }

    zend_class_entry* client_class_entry_ptr = NULL;
    switch (type)
    {
    case SW_CONNPOOL_TCP:
        client_class_entry_ptr = swoole_client_class_entry_ptr;
        break;
#ifdef SW_USE_REDIS
    case SW_CONNPOOL_REDIS:
        client_class_entry_ptr = swoole_redis_class_entry_ptr;
        break;
#endif
    case SW_CONNPOOL_MYSQL:
        client_class_entry_ptr = swoole_mysql_class_entry_ptr;
        break;
    default:
        break;
    }

    if (!client_class_entry_ptr)
    {
        return SW_ERR;
    }

    zval* retval = NULL;
    zval* client = connClient->client;
    sw_zval_add_ref(&client);
    zend_update_property_bool(client_class_entry_ptr, client, ZEND_STRL("internal_user"), 0 TSRMLS_CC);
    sw_zend_call_method_with_0_params(&client,client_class_entry_ptr,NULL,"close",&retval);
    zend_update_property_bool(client_class_entry_ptr, client, ZEND_STRL("internal_user"), 1 TSRMLS_CC);

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&client);
    return SW_OK;
}

ZEND_METHOD(swoole_connpool,__construct)
{
    long connpoolType = SW_CONNPOOL_TYPE_INVAIL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l",&connpoolType)){
        return ;
    }

    if (connpoolType <= SW_CONNPOOL_TYPE_INVAIL || connpoolType >= SW_CONNPOOL_TYPE_NUM)
    {
        zend_throw_exception(zend_exception_get_default(TSRMLS_C), "construct swoole_connpool type invailed", 0 TSRMLS_CC);
        return;
    }

    php_swoole_check_reactor();
    zval* zobject = getThis();

    connpool_property* proptr = emalloc(sizeof(connpool_property));
    bzero(proptr,sizeof(connpool_property));
    proptr->connpoolType = connpoolType;
    proptr->hbIntervalTime = 0;
    proptr->hbTimeout = DEFAULT_RECVMSG_TIMEOUT;
    proptr->connectTimeout = DEFAULT_CONNECT_TIMEOUT;
    proptr->connIntvl = rand()%(MAX_RECONNECT_INTERVAL - MIN_RECONNECT_INTERVAL) + MIN_RECONNECT_INTERVAL;
    proptr->maxConnIntvl = rand()%(MAX_CONNECT_INTERVAL - MIN_CONNECT_INTERVAL) + MIN_CONNECT_INTERVAL;
    proptr->maxConnTimes = DEFAULT_RECONNECT_TIMES;
    swoole_set_property(zobject,swoole_property_common,proptr);

//  RETURN_TRUE;
}

ZEND_METHOD(swoole_connpool,__destruct)
{
    connpool_property* proptr = swoole_get_property(getThis(),swoole_property_common);
    connpool* pool = swoole_get_object(getThis());
    destroy_resource(pool,proptr);

    swoole_set_property(getThis(),swoole_property_common,NULL);
    swoole_efree(proptr);
}

ZEND_METHOD(swoole_connpool,createConnPool)
{
    zval* zobject = getThis();
    connpool_property* proptr = swoole_get_property(zobject,swoole_property_common);
    if (!proptr) {
        RETURN_FALSE;
    }

    long minNum = -1;
    long maxNum = -1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"ll",&minNum,&maxNum)) {
        RETURN_FALSE;
    }

    if (minNum < 0 || maxNum <= 0 || minNum > maxNum)
    {
        RETURN_FALSE;
    }

    /// create connect object.
    /// adapt tcp client\httpclient\mysql\redis
    connpool* pool = swoole_get_object(zobject);
    if (!pool)
    {
        pool = emalloc(sizeof(connpool));
        bzero(pool,sizeof(connpool));
        pool->zobject = zobject;
        sw_zval_add_ref(&zobject);
        sw_copy_to_stack(pool->zobject,pool->_zobject);
        swoole_set_object(zobject,pool);
        pool->refCount = 1;
        if (initConnpool(proptr->connpoolType,pool) < 0)
        {
            RETURN_FALSE;
        }
    }

    if (SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        RETURN_FALSE;
    }

    proptr->connpoolMinNum = minNum;
    proptr->connpoolMaxNum = maxNum;
    if (SW_CONNPOOL_INITED == pool->connpoolStatus)
    {
        RETURN_TRUE;
    }

    /// 校验连接参数
    if (pool->argsCheck(proptr->cfg,ARGS_IS_VAILED TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    swTimer_init(&ServerG.timer,100);
    register_after_cb(&ServerG.timer,CONNPOOL_USED,connpool_onTimeout);
    register_dict_cb(&ServerG.timer,CONNPOOL_USED,free_data);

    pool->connpoolStatus = SW_CONNPOOL_INITED;
    /// 创建连接对象
    for (int index = 0;index < minNum;index++)
    {
        connobj* con_obj = newConnobj(pool);
        createConnobj(pool,proptr,con_obj);
    }

    RETURN_TRUE;
}

ZEND_METHOD(swoole_connpool,destroy)
{
    connpool_property* proptr = swoole_get_property(getThis(),swoole_property_common);
    connpool* pool = swoole_get_object(getThis());

    destroy_resource(pool,proptr);

    return ;
}

ZEND_METHOD(swoole_connpool,setConfig)
{
    zval* zobject = getThis();
    connpool_property* proptr = swoole_get_property(zobject,swoole_property_common);
    if (!proptr || proptr->connpoolType == SW_CONNPOOL_TYPE_INVAIL)
    {
        RETURN_FALSE;
    }

    zval* args = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"a",&args)){
        RETURN_FALSE;
    }

    php_swoole_array_separate(args);
    HashTable *_ht = Z_ARRVAL_P(args);
    zval *value = NULL;
    if (php_swoole_array_get_value(_ht, "hbTimeout", value))
    {
        convert_to_long(value);
        proptr->hbTimeout = Z_LVAL_P(value);
        proptr->hbTimeout = proptr->hbTimeout <=0 ?
                            DEFAULT_RECVMSG_TIMEOUT:proptr->hbTimeout;
        value = NULL;
    }

    if (php_swoole_array_get_value(_ht, "hbIntervalTime", value))
    {
        convert_to_long(value);
        proptr->hbIntervalTime = Z_LVAL_P(value);
        proptr->hbIntervalTime = proptr->hbIntervalTime <= 0?
                                 0:proptr->hbIntervalTime;
        value = NULL;
    }

    if (php_swoole_array_get_value(_ht, "connectTimeout", value))
    {
        convert_to_long(value);
        proptr->connectTimeout = Z_LVAL_P(value);
        proptr->connectTimeout = proptr->connectTimeout <= 0?
                                        DEFAULT_CONNECT_TIMEOUT:
                                        (proptr->connectTimeout < 10? 10:proptr->connectTimeout);
        value = NULL;
    }

    if (php_swoole_array_get_value(_ht, "connectInterval", value))
    {
        convert_to_long(value);
        int curConnIntvl = proptr->connIntvl;
        proptr->connIntvl = Z_LVAL_P(value);
        proptr->connIntvl = proptr->connIntvl <= 0?
                            curConnIntvl:proptr->connIntvl;
    }

    if (php_swoole_array_get_value(_ht, "maxConnectInterval", value))
    {
        convert_to_long(value);
        int curConnectIntvl = proptr->maxConnIntvl;
        proptr->maxConnIntvl = Z_LVAL_P(value);
        proptr->maxConnIntvl = proptr->maxConnIntvl <= 0?
                               curConnectIntvl:proptr->maxConnIntvl;
    }

    if (php_swoole_array_get_value(_ht, "maxConnectTimes", value))
    {
        convert_to_long(value);
        int defConnectTimes =  proptr->maxConnIntvl;
        proptr->maxConnTimes = Z_LVAL_P(value);
        proptr->maxConnTimes = proptr->maxConnTimes <= 0? defConnectTimes:
                                 (proptr->maxConnTimes > defConnectTimes?
                                             MAX_RECONNECT_TIMES: proptr->maxConnTimes);
    }

    zend_update_property(swoole_connpool_class_entry_ptr, getThis(), ZEND_STRL("config"), args TSRMLS_CC);
    sw_zval_ptr_dtor(&args);
    proptr->cfg = sw_zend_read_property(swoole_connpool_class_entry_ptr, getThis(), ZEND_STRL("config"), 1 TSRMLS_CC);
    sw_copy_to_stack(proptr->cfg, proptr->_cfg);
    RETURN_TRUE;
}

ZEND_METHOD(swoole_connpool,on)
{
    connpool_property* proptr = swoole_get_property(getThis(),swoole_property_common);
    if (!proptr || SW_CONNPOOL_TYPE_INVAIL == proptr->connpoolType)
    {
        RETURN_FALSE
    }

    char *cb_name = NULL;
    zend_size_t cb_name_len = 0;
    zval *zcallback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz", &cb_name, &cb_name_len, &zcallback))
    {
        zanError("parse user set parameters error.");
        RETURN_FALSE
    }

    if (cb_name_len <= 0 || !cb_name || swoole_check_callable(zcallback TSRMLS_CC) < 0){
        RETURN_FALSE
    }

    if (cb_name_len == strlen("hbConstruct") && strncasecmp(cb_name,"hbConstruct",cb_name_len) == 0){
        proptr->onHBMsgConstruct = zcallback;
        sw_copy_to_stack(proptr->onHBMsgConstruct,proptr->_onHBMsgConstruct);
    }
    else if (cb_name_len == strlen("hbCheck") && strncasecmp(cb_name,"hbCheck",cb_name_len) == 0){
        proptr->onHBMsgCheck = zcallback;
        sw_copy_to_stack(proptr->onHBMsgCheck,proptr->_onHBMsgCheck);
    }
    else {
        RETURN_FALSE;
    }

    sw_zval_add_ref(&zcallback);
    RETURN_TRUE;
}

ZEND_METHOD(swoole_connpool,getStatInfo)
{
    connpool* pool = swoole_get_object(getThis());
    if (!pool || SW_CONNPOOL_INITED != pool->connpoolStatus) {
        RETURN_FALSE
    }

    int idle_nums = pool->idlePool->getNums(pool->idlePool);
    int all_obj_nums = pool->connObjMap->getNums(pool->connObjMap);
    array_init(return_value);
    sw_add_assoc_long_ex(return_value,ZEND_STRS("all_conn_obj"),all_obj_nums);
    sw_add_assoc_long_ex(return_value,ZEND_STRS("idle_conn_obj"),idle_nums);
}

ZEND_METHOD(swoole_connpool,get)
{
    connpool* pool = swoole_get_object(getThis());
    if (!pool || SW_CONNPOOL_INITED != pool->connpoolStatus) {
        RETURN_FALSE
    }

    long timeout = DEFAULT_GETCONN_TIMEOUT;
    zval* callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"lz",&timeout,&callback))
    {
        RETURN_FALSE
    }

    if (timeout <= 0 ) {
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    long connId = getConnobjFromPool(pool,timeout,callback);
    if (connId < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

ZEND_METHOD(swoole_connpool,release)
{
    connpool* pool = swoole_get_object(getThis());
    if (!pool) {
        RETURN_FALSE;
    }

    long status = SW_CONNOBJ_OK;
    zval* client = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC,"z|l",&client,&status)) {
        RETURN_FALSE;
    }

    if (!client || Z_TYPE_P(client) != IS_OBJECT){
        RETURN_FALSE;
    }

    int result = pool->argsCheck(client,status == SW_CONNOBJ_ERR? OBJ_IS_INSTANCE:ARGC_IS_CONNECTED TSRMLS_CC);
    if (result < 0)
    {
        RETURN_FALSE;
    }

    status = (status == SW_CONNOBJ_OK)? result:status;
    connobj* connClient = swoole_get_property(client,swoole_connpool_object);
    /// 连接对象不存在
    if (!connClient || SW_CONNOBJ_CLOSED == connClient->connStatus)
    {
        return;
    }

    /// 连接池销毁，需要关闭连接
    if (SW_CONNPOOL_RELEASED == pool->connpoolStatus) {
        pool->close(connClient TSRMLS_CC);
        RETURN_TRUE;
    }

    if (status != SW_CONNOBJ_OK)
    {
        /// 关闭连接
        pool->close(connClient TSRMLS_CC);
        RETURN_TRUE;
    }

    /// 连接正常，需要先检测是否存在等待获取连接的对象，不需要直接收回到空闲池子中
    connpool_property* proptr = swoole_get_property(getThis(),swoole_property_common);
    if (handler_new_connobj(pool,proptr,connClient) < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

ZEND_FUNCTION(onClientConnect)
{
    zval* client = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &client))
    {
        return;
    }

    connobj* con_obj = swoole_get_property(client,swoole_connpool_object);
    con_obj->connStatus = SW_CONNOBJ_OK;
    con_obj->connTimes = 0;
    connpool* pool = con_obj->pool;
    if (SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        pool->close(con_obj TSRMLS_CC);
        return;
    }

    zend_update_property_bool(swoole_client_class_entry_ptr, client, ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    connpool_property* proptr = swoole_get_property(pool->zobject,swoole_property_common);
    handler_new_connobj(pool,proptr,con_obj);
    return;
}

ZEND_FUNCTION(onClientClose)
{
    zval* client = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &client))
    {
        return;
    }

    close_handler(client);
    return;
}

ZEND_FUNCTION(onClientTimeout)
{
    zval* client = NULL;
    long eventType = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|l", &client,&eventType))
    {
        return;
    }

    connobj* con_obj = swoole_get_property(client,swoole_connpool_object);
    connpool* pool = con_obj->pool;
    pool->close(con_obj TSRMLS_CC);
    return;
}

ZEND_FUNCTION(onSubClientConnect)
{
    zval* client = NULL;
    zval* result = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &client,&result))
    {
        return;
    }

    connobj* con_obj = swoole_get_property(client,swoole_connpool_object);
    connpool* pool = con_obj->pool;
    if (SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        pool->close(con_obj TSRMLS_CC);
        return;
    }

    /// 连接不成功
    if (result && !ZVAL_IS_NULL(result) && !Z_BVAL_P(result))
    {
        /// 和close 的处理方式一样.
        pool->close(con_obj TSRMLS_CC);
        return;
    }

    con_obj->connTimes = 0;
    con_obj->connStatus = SW_CONNOBJ_OK;
    connpool_property* proptr = swoole_get_property(pool->zobject,swoole_property_common);
    zend_class_entry *class_entry_ptr = (SW_CONNPOOL_MYSQL == proptr->connpoolType)?
                                        swoole_mysql_class_entry_ptr:
#ifdef SW_USE_REDIS
                                        (SW_CONNPOOL_REDIS == proptr->connpoolType? swoole_redis_class_entry_ptr:NULL);
#else
                                        NULL;
#endif

    if (class_entry_ptr)
    {
        zend_update_property_bool(class_entry_ptr, client, ZEND_STRL("internal_user"), 1 TSRMLS_CC);
    }

    handler_new_connobj(pool,proptr,con_obj);
}

ZEND_FUNCTION(onClientRecieve)
{
    zval* client = NULL;
    zval* data = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz", &client,&data))
    {
        return;
    }

    connobj* con_obj = swoole_get_property(client,swoole_connpool_object);
    /// get pool
    connpool* pool = con_obj->pool;
    if (SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        pool->close(con_obj TSRMLS_CC);
        return;
    }

    zval* pool_object = pool->zobject;
    connpool_property* proper = swoole_get_property(pool_object,swoole_property_common);

    zval** argvs[3];
    argvs[0] = &pool_object;
    argvs[1] = &client;
    argvs[2] = &data;
    zval* zcallback = proper->onHBMsgCheck;
    zval* retval = NULL;
    if (zcallback &&
            sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 3, argvs, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("onReactorCallback handler error");
    }

    /// 心跳校验失败，需要释放连接对象
    if (retval && !ZVAL_IS_NULL(retval) && !Z_BVAL_P(retval))
    {
        pool->close(con_obj TSRMLS_CC);
    }
    else
    {
        handler_new_connobj(pool,proper,con_obj);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }
}

static connpoolMap* createPoolMap(swDestructor dtor)
{
    connpoolMap* map = emalloc(sizeof(connpoolMap));
    if (!map)
    {
        return NULL;
    }

    memset(map,0x00,sizeof(connpoolMap));
    map->list = swLinkedList_create(0,dtor);
    if (!map->list)
    {
        swoole_efree(map);
        return NULL;
    }

    map->hash_map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    if (!map->hash_map)
    {
        swLinkedList_free(map->list);
        map->list = NULL;
        swoole_efree(map);
        return NULL;
    }

    map->pop = map_pop_node;
    map->push = map_push_node;
    map->getNums = map_node_nums;
    map->release = map_release_node;
    map->destroyMap = destroyPoolMap;
    return map;
}

static int destroyPoolMap(connpoolMap* map)
{
    if (map && map->hash_map)
    {
        swHashMap_free(map->hash_map);
        map->hash_map = NULL;
    }

    if (map && map->list)
    {
        swLinkedList_free(map->list);
        map->list = NULL;
    }

    swoole_efree(map);
    return SW_OK;
}

static void* map_release_node(connpoolMap* map, uint64_t id)
{
    if (!map || !map->list || !map->hash_map)
    {
        return NULL;
    }

    swLinkedList_node * node = (swLinkedList_node *)swHashMap_find_int(map->hash_map,id);
    if (!node)
    {
        return NULL;
    }

    void *data = node->data;
    swHashMap_del_int(map->hash_map,id);
    swLinkedList_remove_node(map->list,node);
    return data;
}

static void* map_pop_node(connpoolMap* map)
{
    if (!map || !map->list || !map->hash_map)
    {
        return NULL;
    }

    swLinkedList_node* node = swLinkedList_get_head_node(map->list);
    if (!node)
    {
        return NULL;
    }

    uint64_t id = node->priority;
    swHashMap_del_int(map->hash_map,id);
    void* data = node->data;
    swLinkedList_remove_node(map->list,node);
    return data;
}

static int map_node_nums(connpoolMap* map)
{
    if (!map || !map->list)
    {
        return 0;
    }

    return map->list->num;
}

static int map_push_node(connpoolMap* map,uint64_t id,void* data)
{
    if (!map || !map->list || !map->hash_map)
    {
        return SW_ERR;
    }

    /// 防止hash节点重入
    swLinkedList_node* node = swHashMap_find_int(map->hash_map,id);
    if (node)
    {
        swHashMap_del_int(map->hash_map,id);
        swLinkedList_remove_node(map->list,node);
    }

    swLinkedList_node* listnode = swLinkedList_append(map->list,data,id);
    if (!listnode)
    {
        return SW_ERR;
    }

    swHashMap_add_int(map->hash_map,id,listnode);
    return SW_OK;
}

static int initConnpool(int type, connpool* pool)
{
    switch (type){
        case SW_CONNPOOL_TCP:
            pool->create = tcpclient_create;
            pool->connect = tcpclient_connect;
            pool->close = tcpclient_close;
            pool->send = tcpclient_send;
            pool->argsCheck = tcpclient_args_check;
            break;
#ifdef SW_USE_REDIS
        case SW_CONNPOOL_REDIS:
            pool->create = redisclient_create;
            pool->connect = redisclient_connect;
            pool->close = redisclient_close;
            pool->send = redisclient_send;
            pool->argsCheck = redisclient_args_check;
            break;
#endif
        case SW_CONNPOOL_MYSQL:
            pool->create = mysqlclient_create;
            pool->connect = mysqlclient_connect;
            pool->close = mysqlclient_close;
            pool->send = mysqlclient_send;
            pool->argsCheck = mysqlclient_args_check;
            break;
        default:
            return SW_ERR;
    }

    pool->connpoolStatus = SW_CONNPOOL_INIT;
    if (!pool->waitConnobjPool)
    {
        pool->waitConnobjPool = createPoolMap(NULL);
        if (!pool->waitConnobjPool)
        {
            return SW_ERR;
        }
    }

    if (!pool->idlePool)
    {
        pool->idlePool = createPoolMap(NULL);
        if (!pool->idlePool)
        {
            return SW_ERR;
        }
    }

    if (!pool->connObjMap)
    {
        pool->connObjMap = createPoolMap(NULL);
        if (!pool->connObjMap)
        {
            return SW_ERR;
        }
    }

    return SW_OK;
}

static void onDefer_handler(void* data)
{
    if (!data) {
        return ;
    }

    SWOOLE_FETCH_TSRMLS;
    connobj_arg* cbArgs = (connobj_arg*)data;
    connpool* pool = (connpool*)cbArgs->pool;
    if (cbArgs->obj)
    {
        connobj* connClient = cbArgs->obj;
        uint8_t curStatus = connClient->currStatus;
        uint8_t connStatus = connClient->connStatus;
        connClient->currStatus = SW_CONNPOOLOBJ_CONNECTED;
        if (SW_CONNPOOL_RELEASED == pool->connpoolStatus)
        {
            if (SW_CONNPOOLOBJ_REALEASED == curStatus)
            {
                swoole_efree(connClient);
            }

            goto free_args;
        }
        else if (SW_CONNPOOLOBJ_REALEASED == curStatus)
        {
            cbArgs->obj = (pool->idlePool)? pool->idlePool->pop(pool->idlePool):NULL;
            connClient->pool = NULL;
            swoole_efree(connClient);
        }
        else if (SW_CONNOBJ_OK != connStatus)
        {
            cbArgs->obj = (pool->idlePool)? pool->idlePool->pop(pool->idlePool):NULL;
        }
    }

    callback_connobj(cbArgs TSRMLS_CC);

free_args:
    if (pool && 1 == pool->refCount--)
    {
        swoole_efree(pool);
    }

    free_data(cbArgs);
}

static void callback_connobj(connobj_arg* cbArgs TSRMLS_DC)
{
    zval *retval = NULL;
    zval* client = (!cbArgs->obj || !cbArgs->obj->client)? NULL:cbArgs->obj->client;
    int free_client = 0;
    connpool* pool = (connpool*)(cbArgs->pool);
    zval** argvs[2];
    argvs[0] = &(pool->zobject);
    if (!client)
    {
        free_client = 1;
        SW_ALLOC_INIT_ZVAL(client);
        ZVAL_BOOL(client,0);
    }

    argvs[1] = &client;

    if (sw_call_user_function_ex(EG(function_table), NULL, cbArgs->user_callback, &retval, 2, argvs, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanError("get connected obj call callback  error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (free_client)
    {
        sw_zval_free(client);
    }
}

static long getConnobjFromPool(connpool* pool,long timeout,zval* callback)
{
    long id = -1;
    connobj_arg* deferArgs = emalloc(sizeof(connobj_arg));
    bzero(deferArgs,sizeof(connobj_arg));
    deferArgs->user_callback = callback;
    deferArgs->pool = pool;
    sw_zval_add_ref(&callback);
    sw_copy_to_stack(deferArgs->user_callback,deferArgs->_user_callback);

    connobj* obj = pool->idlePool->pop(pool->idlePool);
    if (obj)
    {
        if (obj->timeId > 0)
        {
            /// del hb start timer
            swTimer_del(&ServerG.timer,obj->timeId);
            obj->timeId = 0;
        }

        deferArgs->obj = obj;
        obj->currStatus = SW_CONNPOOLOBJ_WAIT_CB;
        pool->refCount++;
        ServerG.main_reactor->defer(ServerG.main_reactor,onDefer_handler,deferArgs);
    }
    else
    {
        connpool_property* proptr = swoole_get_property(pool->zobject,swoole_property_common);
        int objNums = pool->connObjMap->getNums(pool->connObjMap);
        if (objNums < proptr->connpoolMaxNum)
        {
            connobj* con_obj = newConnobj(pool);
            createConnobj(pool,proptr,con_obj);
        }

        /// 添加进超时定时器,id 需要保存好，后续有重要用处
        deferArgs->type = SW_PHP_USER_CALL;
        id = swTimer_add(&ServerG.timer, timeout, 0,deferArgs,CONNPOOL_USED);
        if (id <= 0)
        {
            sw_zval_ptr_dtor(&callback);
            swoole_efree(deferArgs);
            return SW_ERR;
        }

        deferArgs->tmpId = id;
        deferArgs->clientId = 0;
        pool->waitConnobjPool->push(pool->waitConnobjPool,id,deferArgs);
    }

    return SW_OK;
}

static int handler_new_connobj(connpool* pool,connpool_property* proptr,connobj* connClient)
{
    connClient->currStatus = SW_CONNPOOLOBJ_CONNECTED;
    connClient->timeId = 0;
    connobj_arg* arg = (connobj_arg*)pool->waitConnobjPool->pop(pool->waitConnobjPool);
    if (arg) {
        connobj_arg* deferArgs = emalloc(sizeof(connobj_arg));
        memset(deferArgs,0x00,sizeof(connobj_arg));
        deferArgs->obj = connClient;
        deferArgs->pool = pool;
        pool->refCount++;
        zval* callback = arg->user_callback;
        deferArgs->user_callback = callback;
        sw_zval_add_ref(&callback);
        sw_copy_to_stack(deferArgs->user_callback,deferArgs->_user_callback);
        connClient->currStatus = SW_CONNPOOLOBJ_WAIT_CB;
        ServerG.main_reactor->defer(ServerG.main_reactor,onDefer_handler,deferArgs);
        /// del get con_obj timeout timer
        swTimer_del(&ServerG.timer,arg->tmpId);
    } else {
        /// 检测是否需要心跳
        if (proptr->hbIntervalTime > 0 && proptr->onHBMsgConstruct && proptr->onHBMsgCheck)
        {
            arg = emalloc(sizeof(connobj_arg));
            memset(arg,0x00,sizeof(connobj_arg));
            arg->pool = pool;
            arg->type = SW_HBINTERVAL_CALL;
            long id = swTimer_add(&ServerG.timer,proptr->hbIntervalTime,0,arg,CONNPOOL_USED);
            if (id > 0) {
                connClient->currStatus = SW_CONNPOOLOBJ_WAIT_HB;
                arg->tmpId = connClient->timeId = id;
                arg->clientId = connClient->clientId;
            }
            else
            {
                swoole_efree(arg);
            }
        }

        pool->idlePool->push(pool->idlePool,connClient->clientId,connClient);
    }

    return SW_OK;
}

static void connpool_onTimeout(swTimer* timer,swTimer_node* node)
{
    if (!node || !node->data) {
        return ;
    }

    SWOOLE_FETCH_TSRMLS;
    connobj_arg* cbArgs = (connobj_arg*)(node->data);
    switch (cbArgs->type){
        case  SW_PHP_USER_CALL:
            connpool_onGetObj(timer,node TSRMLS_CC);
            break;
        case SW_CONNINTERVAL_CALL:
            connpool_onConnInter(timer,node);
            break;
        case SW_HBINTERVAL_CALL:
            connpool_onHBSend(timer,node);
            break;
        default:
            break;
    }

    swTimer_del(timer,node->id);
    return;
}

static void close_handler(zval* client)
{
    connobj* con_obj = swoole_get_property(client,swoole_connpool_object);
    if (!con_obj || !con_obj->client)
    {
        return;
    }

    connpool* pool = con_obj->pool;
    if (pool && SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        goto release_client;
    }

    if (SW_CONNOBJ_CLOSED != con_obj->connStatus)
    {
        clean_conobj_resource(con_obj,1);
    }

release_client:
    con_obj->client = NULL;
    sw_zval_ptr_dtor(&client);
}

static void clean_conobj_resource(connobj* con_obj,int reconnect)
{
    if (!con_obj)
    {
        return;
    }

    if (con_obj->timeId > 0)
    {
        swTimer_del(&ServerG.timer,con_obj->timeId);
        con_obj->timeId = 0;
    }

    con_obj->connStatus = SW_CONNOBJ_CLOSED;
    connpool* pool = con_obj->pool;
    if (pool && SW_CONNPOOL_RELEASED == pool->connpoolStatus)
    {
        return;
    }

    int all_obj_nums = pool->connObjMap->getNums(pool->connObjMap);
    connpool_property* proptr = swoole_get_property(pool->zobject,swoole_property_common);
    int max_obj_nums = proptr->connpoolMaxNum;
    int connTimes = con_obj->connTimes;
    pool->idlePool->release(pool->idlePool,con_obj->clientId);
    pool->connObjMap->release(pool->connObjMap,con_obj->clientId);
    if (all_obj_nums > max_obj_nums)
    {
        return;
    }

    /// 延迟创建连接对象
    if (reconnect)
    {
        defer_create_connobj(pool,proptr,connTimes);
    }
}

static void destroy_resource(connpool* pool,connpool_property* proptr)
{
    SWOOLE_FETCH_TSRMLS;
    zval* object = pool? pool->zobject:NULL;
    if (pool)
    {
        pool->zobject = NULL;
        pool->connpoolStatus = SW_CONNPOOL_RELEASED;
        connobj_arg* args = pool->waitConnobjPool? pool->waitConnobjPool->pop(pool->waitConnobjPool):NULL;
        while (args)
        {
            swTimer_del(&ServerG.timer,args->tmpId);
            args = pool->waitConnobjPool->pop(pool->waitConnobjPool);
        }

        if (pool->waitConnobjPool)
        {
            pool->waitConnobjPool->destroyMap(pool->waitConnobjPool);
            pool->waitConnobjPool = NULL;
        }

        if (pool->idlePool)
        {
            pool->idlePool->destroyMap(pool->idlePool);
            pool->idlePool = NULL;
        }

        connobj* con_obj = pool->connObjMap? pool->connObjMap->pop(pool->connObjMap):NULL;
        while (con_obj)
        {
            pool->close(con_obj TSRMLS_CC);
            con_obj = pool->connObjMap->pop(pool->connObjMap);
        }

        if (pool->connObjMap)
        {
            pool->connObjMap->destroyMap(pool->connObjMap);
            pool->connObjMap = NULL;
        }
    }

    if (proptr) proptr->connpoolType = SW_CONNPOOL_TYPE_INVAIL;
    if (proptr && proptr->cfg)
    {
        proptr->cfg = NULL;
    }

    if (proptr && proptr->onHBMsgConstruct)
    {
        sw_zval_ptr_dtor(&(proptr->onHBMsgConstruct));
        proptr->onHBMsgConstruct = NULL;
    }

    if (proptr && proptr->onHBMsgCheck)
    {
        sw_zval_ptr_dtor(&(proptr->onHBMsgCheck));
        proptr->onHBMsgCheck = NULL;
    }

    if (pool && 1 == pool->refCount--)
    {
        swoole_efree(pool);
    }

    if (object)
    {
        swoole_set_object(object,NULL);
        sw_zval_ptr_dtor(&object);
    }
}
