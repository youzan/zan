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

#ifndef PHP_SWOOLE_H
#define PHP_SWOOLE_H

#include "php.h"
#include "php_ini.h"
#include "php_globals.h"
#include "php_main.h"

#include "php_streams.h"
#include "php_network.h"

#include "zend_interfaces.h"
#include "zend_exceptions.h"
#include "zend_variables.h"
#include <ext/date/php_date.h>
#include <ext/standard/sha1.h>
#include <ext/standard/url.h>
#include <ext/standard/info.h>
#include <ext/standard/php_array.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "swoole.h"
#include "swClient.h"

#include "zanGlobalVar.h"
#include "php7_wrapper.h"

/**
 * PHP5.2
 */
#ifndef PHP_FE_END
#define PHP_FE_END {NULL,NULL,NULL}
#endif

#ifndef ZEND_MOD_END
#define ZEND_MOD_END {NULL,NULL,NULL}
#endif

#ifdef PHP_WIN32
#   define PHP_SWOOLE_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_SWOOLE_API __attribute__ ((visibility("default")))
#else
#   define PHP_SWOOLE_API
#endif


typedef struct
{
    uint16_t port;
    uint16_t from_fd;
} php_swoole_udp_t;

extern zend_module_entry zan_module_entry;

enum obj_swoole_property
{
    swoole_property_common = 0,
    swoole_property_socket = 1,
    swoole_connpool_object = 2,
    swoole_property_nums
};

typedef struct
{
    void **array;                                   /// object 数组
    uint32_t size;                                  /// object 数组长度
    void **property[swoole_property_nums];          /// object 属性数组
    uint32_t property_size[swoole_property_nums];
} swoole_object_array;

#define PHP_SWOOLE_VERSION  "3.1.0"
#define SW_HOST_SIZE  128
#define SWOOLE_PROPERTY_MAX     32
#define SWOOLE_OBJECT_MAX       10000000
#define phpext_swoole_ptr &zan_module_entry


#ifdef ZTS
#include "TSRM.h"
extern void ***sw_thread_ctx;
extern __thread swoole_object_array swoole_objects;
#else
extern swoole_object_array swoole_objects;
#endif


//#define SW_USE_PHP        1
#define SW_CHECK_RETURN(s)         if(s<0){RETURN_FALSE;}else{RETURN_TRUE;}return
#define SW_LOCK_CHECK_RETURN(s)    if(s==0){RETURN_TRUE;}else{RETURN_FALSE;}return

#define swoole_php_error(level, fmt_str, ...)   if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_fatal_error(level, fmt_str, ...)   php_error_docref(NULL TSRMLS_CC, level, fmt_str, ##__VA_ARGS__)
#define swoole_php_sys_error(level, fmt_str, ...)  if (SWOOLE_G(display_errors)) php_error_docref(NULL TSRMLS_CC, level, fmt_str" Error: %s[%d].", ##__VA_ARGS__, strerror(errno), errno)
#define swoole_efree(p)  do{if (p) efree(p); p=NULL;}while(0)

#ifdef SW_USE_OPENSSL
#ifndef HAVE_OPENSSL
#error "Enable openssl support, require openssl library."
#endif
#else
#ifdef SW_USE_HTTP2
#error "Enable http2 support, require --enable-openssl."
#endif
#endif

#if SW_USE_SOCKETS && PHP_VERSION_ID >= 50301
#include "ext/sockets/php_sockets.h"
#endif

#ifdef SW_USE_HTTP2
#if !defined(HAVE_NGHTTP2)
#error "Enable http2 support, require nghttp2 library."
#endif
#if !defined(HAVE_OPENSSL)
#error "Enable http2 support, require openssl library."
#endif
#endif

#define PHP_CLIENT_CALLBACK_NUM             4
//--------------------------------------------------------
#define SW_MAX_FIND_COUNT                   100    //for swoole_server::connection_list
#define SW_PHP_CLIENT_BUFFER_SIZE           65535
//--------------------------------------------------------
enum php_swoole_client_callback_type
{
    SW_CLIENT_CB_onConnect = 1,
    SW_CLIENT_CB_onReceive,
    SW_CLIENT_CB_onClose,
    SW_CLIENT_CB_onError,
};
//--------------------------------------------------------
enum php_swoole_server_callback_type
{
    SW_SERVER_CB_onConnect,        //worker(event)
    SW_SERVER_CB_onReceive,        //worker(event)
    SW_SERVER_CB_onClose,          //worker(event)
    SW_SERVER_CB_onPacket,         //worker(event)

    SW_SERVER_CB_onStart,          //master
    SW_SERVER_CB_onShutdown,       //master
    SW_SERVER_CB_onWorkerStart,    //worker(event & task)
    SW_SERVER_CB_onWorkerStop,     //worker(event & task)
    SW_SERVER_CB_onTask,           //worker(task)
    SW_SERVER_CB_onFinish,         //worker(event & task)
    SW_SERVER_CB_onWorkerError,    //manager-->master
    SW_SERVER_CB_onNetWorkerStart, //networker start
    //SW_SERVER_CB_onManagerStart,   //manager
    //SW_SERVER_CB_onManagerStop,    //manager
    SW_SERVER_CB_onPipeMessage,    //worker(evnet & task)

    //--------------------------Swoole\Http\Server----------------------
    SW_SERVER_CB_onRequest,        //http server
    //--------------------------Swoole\WebSocket\Server-----------------
    SW_SERVER_CB_onHandShake,      //worker(event)
    SW_SERVER_CB_onOpen,           //worker(event)
    SW_SERVER_CB_onMessage,        //worker(event)
    //-------------------------------END--------------------------------
};

#define PHP_SERVER_CALLBACK_NUM             (SW_SERVER_CB_onMessage+1)
#define PHP_SERVER_PORT_CALLBACK_NUM        (SW_SERVER_CB_onPacket+1)

typedef struct
{
    zval *callbacks[PHP_SERVER_PORT_CALLBACK_NUM];
#if PHP_MAJOR_VERSION >= 7
    zval _callbacks[PHP_SERVER_PORT_CALLBACK_NUM];
#endif
    zval *setting;
} swoole_server_port_property;


//---------------------------------------------------------
#define SW_FLAG_ASYNC                       (1u << 10)
#define SW_FLAG_SYNC                        (1u << 11)
//---------------------------------------------------------
enum php_swoole_fd_type
{
    PHP_SWOOLE_FD_STREAM_CLIENT = SW_FD_STREAM_CLIENT,
    PHP_SWOOLE_FD_DGRAM_CLIENT = SW_FD_DGRAM_CLIENT,
    PHP_SWOOLE_FD_MYSQL,
    PHP_SWOOLE_FD_REDIS,
    PHP_SWOOLE_FD_HTTPCLIENT,
};
//---------------------------------------------------------

#define php_swoole_socktype(type)           (type & (~SW_FLAG_SYNC) & (~SW_FLAG_ASYNC) & (~SW_SOCK_SSL))
#define php_swoole_array_length(array)      (Z_ARRVAL_P(array)->nNumOfElements)

#define php_swoole_array_separate(arr)       zval *_new_##arr;\
    SW_MAKE_STD_ZVAL(_new_##arr);\
    array_init(_new_##arr);\
    sw_php_array_merge(Z_ARRVAL_P(_new_##arr), Z_ARRVAL_P(arr));\
    arr = _new_##arr;

#define SW_LONG_CONNECTION_KEY_LEN          64

extern zend_class_entry *swoole_process_class_entry_ptr;
extern zend_class_entry *swoole_client_class_entry_ptr;
extern zend_class_entry *swoole_http_server_class_entry_ptr;
extern zend_class_entry *swoole_http_response_class_entry_ptr;
extern zend_class_entry *swoole_http_request_class_entry_ptr;
extern zend_class_entry *swoole_http_client_class_entry_ptr;
extern zend_class_entry *swoole_server_class_entry_ptr;

#ifdef HAVE_PCRE
extern zend_class_entry *swoole_connection_iterator_class_entry_ptr;
#endif

extern zend_class_entry *swoole_timer_class_entry_ptr;
extern zend_class_entry *swoole_buffer_class_entry_ptr;
extern zend_class_entry *swoole_websocket_server_class_entry_ptr;
extern zend_class_entry *swoole_websocket_frame_class_entry_ptr;
extern zend_class_entry *swoole_server_port_class_entry_ptr;
extern zend_class_entry *swoole_mysql_class_entry_ptr;
extern zend_class_entry *swoole_redis_class_entry_ptr;

extern void releaseConnobj(zval* client);

PHP_MINIT_FUNCTION(zan);
PHP_RINIT_FUNCTION(zan);
PHP_RSHUTDOWN_FUNCTION(zan);
PHP_MINFO_FUNCTION(zan);

PHP_FUNCTION(swoole_version);
PHP_FUNCTION(swoole_cpu_num);
PHP_FUNCTION(swoole_set_process_name);
PHP_FUNCTION(swoole_get_local_ip);

//For YouZan Nova
PHP_FUNCTION(nova_encode);
PHP_FUNCTION(nova_decode);
PHP_FUNCTION(nova_encode_new);
PHP_FUNCTION(nova_decode_new);
PHP_FUNCTION(is_nova_packet);
PHP_FUNCTION(nova_get_sequence);
PHP_FUNCTION(nova_get_time);
PHP_FUNCTION(nova_get_ip);

//---------------------------------------------------------
//                  swoole_server
//---------------------------------------------------------
PHP_METHOD(swoole_server, __construct);
PHP_METHOD(swoole_server, set);
PHP_METHOD(swoole_server, on);
PHP_METHOD(swoole_server, listen);
PHP_METHOD(swoole_server, sendMessage);
PHP_METHOD(swoole_server, addProcess);
PHP_METHOD(swoole_server, start);
PHP_METHOD(swoole_server, stop);
PHP_METHOD(swoole_server, send);
PHP_METHOD(swoole_server, sendfile);
PHP_METHOD(swoole_server, stats);
PHP_METHOD(swoole_server, bind);
PHP_METHOD(swoole_server, sendto);
PHP_METHOD(swoole_server, sendwait);
PHP_METHOD(swoole_server, exist);
PHP_METHOD(swoole_server, protect);
PHP_METHOD(swoole_server, close);
PHP_METHOD(swoole_server, task);
PHP_METHOD(swoole_server, taskwait);
PHP_METHOD(swoole_server, finish);
PHP_METHOD(swoole_server, reload);
PHP_METHOD(swoole_server, shutdown);
PHP_METHOD(swoole_server, getLastError);
PHP_METHOD(swoole_server, stop);
PHP_METHOD(swoole_server, heartbeat);

PHP_METHOD(swoole_server, getClientList);
PHP_METHOD(swoole_server, getClientInfo);

//For YouZan
PHP_METHOD(swoole_server, denyRequest);
PHP_METHOD(swoole_server, exit);

//test
PHP_METHOD(swoole_server, getWorkerId);
PHP_METHOD(swoole_server, getWorkerType);
PHP_METHOD(swoole_server, getWorkerPid);

#ifdef HAVE_PCRE
PHP_METHOD(swoole_connection_iterator, count);
PHP_METHOD(swoole_connection_iterator, rewind);
PHP_METHOD(swoole_connection_iterator, next);
PHP_METHOD(swoole_connection_iterator, current);
PHP_METHOD(swoole_connection_iterator, key);
PHP_METHOD(swoole_connection_iterator, valid);
#endif

PHP_METHOD(swoole_server, getSocket);

//---------------------------------------------------------
//                  swoole_event
//---------------------------------------------------------
PHP_FUNCTION(swoole_event_add);
PHP_FUNCTION(swoole_event_set);
PHP_FUNCTION(swoole_event_del);
PHP_FUNCTION(swoole_event_write);
PHP_FUNCTION(swoole_event_wait);
PHP_FUNCTION(swoole_event_exit);
PHP_FUNCTION(swoole_event_defer);
//---------------------------------------------------------
//                  swoole_async
//---------------------------------------------------------
PHP_FUNCTION(swoole_async_read);
PHP_FUNCTION(swoole_async_write);
PHP_FUNCTION(swoole_async_close);
PHP_FUNCTION(swoole_async_dns_lookup);
PHP_FUNCTION(swoole_clean_dns_cache);
PHP_FUNCTION(swoole_async_set);

//---------------------------------------------------------
//                  swoole_timer
//---------------------------------------------------------
PHP_FUNCTION(swoole_timer_after);
PHP_FUNCTION(swoole_timer_tick);
PHP_FUNCTION(swoole_timer_clear);
PHP_FUNCTION(swoole_timer_set);
PHP_FUNCTION(swoole_timer_exists);

//---------------------------------------------------------
//                  swoole_client api
//---------------------------------------------------------
PHP_FUNCTION(swoole_client_select);


//---------------------------------------------------------
//                  swoole_connpool callback api
//---------------------------------------------------------
#ifndef PHP_WIN32
ZEND_FUNCTION(onClientConnect);
ZEND_FUNCTION(onClientClose);
ZEND_FUNCTION(onClientTimeout);
ZEND_FUNCTION(onClientRecieve);
ZEND_FUNCTION(onSubClientConnect);
#endif
//---------------------------------------------------------
//                 others global api
//---------------------------------------------------------
PHP_FUNCTION(swoole_strerror);
PHP_FUNCTION(swoole_errno);

//---------------------------------------------------------
//                          end
//---------------------------------------------------------

extern zval *php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
#if PHP_MAJOR_VERSION >= 7
extern zval _php_sw_server_callbacks[PHP_SERVER_CALLBACK_NUM];
#endif

//extern zval *php_swoole_server_get_callback(zanServer *serv, int server_fd, int event_type);
zval* php_swoole_server_get_callback(zanServer *serv, int server_fd, int net_worker_id, int event_type);

void swoole_destroy_table(zend_resource *rsrc TSRMLS_DC);

void swoole_server_port_init(int module_number TSRMLS_DC);
void swoole_aio_init(int module_number TSRMLS_DC);
void swoole_client_init(int module_number TSRMLS_DC);
void swoole_connpool_init(int module_number TSRMLS_DC);
void swoole_timer_init(int module_number TSRMLS_DC);
void swoole_mysql_init(int module_number TSRMLS_DC);

void swoole_http_client_init(int module_number TSRMLS_DC);

#ifdef SW_USE_REDIS
void swoole_redis_init(int module_number TSRMLS_DC);
#endif

void swoole_process_init(int module_number TSRMLS_DC);
void swoole_server_init(int module_number TSRMLS_DC);
void swoole_http_server_init(int module_number TSRMLS_DC);
void swoole_websocket_init(int module_number TSRMLS_DC);
void swoole_buffer_init(int module_number TSRMLS_DC);


int php_swoole_process_start(zanWorker *process, zval *object TSRMLS_DC);
void php_swoole_check_reactor();
void swoole_thread_clean();
void php_swoole_at_shutdown(char *function);

void php_swoole_event_init();
void php_swoole_event_wait();

//void php_swoole_register_callback(swServer *serv);
void php_swoole_register_callback(zanServer *serv);
void php_swoole_client_free(zval *object, swClient *cli TSRMLS_DC);
swClient* php_swoole_client_new(zval *object, char *host, int host_len, int port,swClient** cli);
zval* php_swoole_websocket_unpack(swString *data TSRMLS_DC);

void php_swoole_sha1(const char *str, int _len, unsigned char *digest);
int swoole_check_callable(zval *callback TSRMLS_DC);

void swoole_set_object(zval *object, void *ptr);
void swoole_set_property(zval *object, int property_id, void *ptr);

void* swoole_get_object(zval *object);
void* swoole_get_property(zval *object, int property_id);

#ifdef SW_USE_SOCKETS
php_socket *swoole_convert_to_socket(int sock);
#endif

void php_swoole_server_before_start(zanServer *serv, zval *zobject TSRMLS_DC);
int php_swoole_get_send_data(zval *zdata, char **str TSRMLS_DC);
void php_swoole_get_recv_data(zval *zdata, swEventData *req, char *header, uint32_t header_length TSRMLS_DC);
void php_swoole_onConnect(zanServer *serv, swDataHead *);
int php_swoole_onReceive(zanServer *serv, swEventData *req);
void php_swoole_onClose(zanServer *, swDataHead *);

#define php_swoole_array_get_value(ht, str, v)     (sw_zend_hash_find(ht, str, sizeof(str), (void **) &v) == SUCCESS && !ZVAL_IS_NULL(v))
#define php_swoole_array_get_ptr_value(ht, str, v)     (sw_zend_hash_find(ht, str, strlen(str)+1, (void **) &v) == SUCCESS && !ZVAL_IS_NULL(v))

ZEND_BEGIN_MODULE_GLOBALS(swoole)
    long aio_thread_num;
    long log_level;
    zend_bool display_errors;
    zend_bool cli;
    zend_bool use_namespace;
    key_t message_queue_key;
    uint32_t socket_buffer_size;
ZEND_END_MODULE_GLOBALS(swoole)

extern ZEND_DECLARE_MODULE_GLOBALS(swoole);

#ifdef ZTS
#define SWOOLE_G(v) TSRMG(swoole_globals_id, zend_swoole_globals *, v)
#else
#define SWOOLE_G(v) (swoole_globals.v)
#endif


#define SWOOLE_INIT_CLASS_ENTRY(ce, name, name_ns, methods) \
    if (SWOOLE_G(use_namespace)) { \
        INIT_CLASS_ENTRY(ce, name_ns, methods); \
    } else { \
        INIT_CLASS_ENTRY(ce, name, methods); \
    }

#endif  /* PHP_SWOOLE_H */
