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
#ifndef _SW_GLOBAL_H_
#define _SW_GLOBAL_H_


#include "swTimer.h"
#include "swLock.h"
#include "swPort.h"
#include "swConnection.h"
#include "swFactory.h"
#include "swBaseData.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _swServer swServer;

struct _swServer
{
    /**
     * reactor thread/process num
     */
    uint16_t reactor_num;
    /**
     * worker process num
     */
    uint16_t worker_num;
    /**
     * The number of pipe per reactor maintenance
     */
    /// 每个reactor 所拥有的管道数量
    uint16_t reactor_pipe_num;

    uint8_t factory_mode;

    uint8_t dgram_port_num;

    /**
     * package dispatch mode
     */
    uint8_t dispatch_mode; //分配模式，1平均分配，2按FD取摸固定分配，3,使用抢占式队列(IPC消息队列)分配

    /**
     * max connection num
     */
    uint32_t max_connection;

    /**
     * worker process max request
     */
    uint32_t max_request;

    int timeout_sec;
    int timeout_usec;

    int sock_client_buffer_size; //client的socket缓存区设置
    int sock_server_buffer_size; //server的socket缓存区设置

    int signal_fd;

    int udp_socket_ipv4;
    int udp_socket_ipv6;

    int ringbuffer_size;

    /*----------------------------Reactor schedule--------------------------------*/
    //uint16_t reactor_round_i; //轮询调度
    uint16_t reactor_next_i; //平均算法调度

    sw_atomic_t worker_round_id;

    /**
     * run as a daemon process
     */
    uint32_t daemonize :1;
    /**
     * have udp listen socket
     */
    uint32_t have_udp_sock :1;
    /**
     * have tcp listen socket
     */
    uint32_t have_tcp_sock :1;
    /**
     * oepn cpu affinity setting
     */
    uint32_t open_cpu_affinity :1;
    /**
     * Udisable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
     */
    uint32_t disable_notify :1;
    /**
     * discard the timeout request
     */
    uint32_t discard_timeout_request :1;
    /**
     * parse x-www-form-urlencoded data
     */
    uint32_t http_parse_post :1;
    /**
     * enable onConnect/onClose event when use dispatch_mode=1/3
     */
    uint32_t enable_unsafe_event :1;
    /**
     * packet mode
     */
    uint32_t packet_mode :1;
    /**
     * run as a daemon process
     */
    uint32_t reload_async :1;

    /* heartbeat check time*/
    uint16_t heartbeat_idle_time; //心跳存活时间
    uint16_t heartbeat_check_interval; //心跳定时侦测时间, 必需小于heartbeat_idle_time

    int *cpu_affinity_available;
    int cpu_affinity_available_num;

    uint8_t listen_port_num;
    time_t reload_time;

    /* buffer output/input setting*/
    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

    uint32_t pipe_buffer_size;

    void *ptr2;

    swReactor reactor;
    swFactory factory;

    swListenPort *listen_list;

    uint16_t user_worker_num;
    swUserWorker_node *user_worker_list;
    swHashMap *user_worker_map;
    swWorker **user_workers;

    swReactorThread *reactor_threads;
    swWorker *workers;

#ifdef HAVE_PTHREAD_BARRIER
    pthread_barrier_t barrier;
#endif

    swConnection *connection_list;  //连接列表
    swSession *session_list;

    /**
     * message queue key
     */
    uint64_t message_queue_key;


    void (*onStart)(swServer *serv);
    void (*onManagerStart)(swServer *serv);
    void (*onManagerStop)(swServer *serv);
    void (*onShutdown)(swServer *serv);
    void (*onPipeMessage)(swServer *, swEventData *);
    void (*onWorkerStart)(swServer *serv, int worker_id);
    void (*onWorkerStop)(swServer *serv, int worker_id);
    void (*onWorkerError)(swServer *serv, int worker_id, pid_t worker_pid, int exit_code, int signo);
    void (*onUserWorkerStart)(swServer *serv, swWorker *worker);
    /**
     * Client
     */
    int (*onReceive)(swServer *, swEventData *);
    int (*onPacket)(swServer *, swEventData *);
    void (*onClose)(swServer *serv, swDataHead *);
    void (*onConnect)(swServer *serv, swDataHead *);
    /**
     * Task Worker
     */
    int (*onTask)(swServer *serv, swEventData *data);
    int (*onFinish)(swServer *serv, swEventData *data);

    int (*send)(swServer *, swSendData *);

};

typedef struct _swServerGS
{
    pid_t master_pid;
    pid_t manager_pid;

    uint32_t session_round :24;
    uint8_t start;  //after swServer_start will set start=1

    time_t now;

    sw_atomic_t spinlock;
    swLock lock;     /// server master internal lock
    swLock log_lock;  /// log lock
    uint8_t log_level; /// log level

    swProcessPool task_workers;
    swProcessPool event_workers;
} swServerGS;

//Worker process global Variable
typedef struct
{
    /**
     * Always run
     */
    uint8_t run_always;

    /**
     * Current Proccess Worker's id
     */
    uint32_t id;

    /**
     * pipe_worker
     */
    int pipe_used;

    uint32_t reactor_wait_onexit :1;
    uint32_t reactor_init :1;
    uint32_t reactor_ready :1;
    uint32_t in_client :1;
    uint32_t shutdown :1;
    uint32_t reload;
    uint32_t reload_count;   //reload计数

    uint32_t request_count;

    int max_request;

    swString **buffer_input;
    swString **buffer_output;
    swWorker *worker;

    uint8_t fatal_error;
} swWorkerG;

typedef struct
{
    uint16_t id;
    uint8_t type;
    uint8_t update_time;
    uint8_t factory_lock_target;
    int16_t factory_target_worker;
} swThreadG;

typedef struct
{
    swTimer timer;
    uint8_t running :1;
    uint8_t use_timerfd :1;
    uint8_t use_signalfd :1;
    uint8_t reuse_port :1;
    uint8_t socket_dontwait :1;
    uint8_t disable_dns_cache :1;
    uint8_t dns_lookup_random: 1;

    /**
     * Timer used pipe
     */
    uint8_t use_timer_pipe :1;

    int error;
    int process_type;
    pid_t pid;

    int signal_alarm;  //for timer with message queue
    int signal_fd;
    int log_fd;
    int null_fd;

    /**
     * worker(worker and task_worker) process chroot / user / group
     */
    char *chroot;
    char *user;
    char *group;

    char *log_addr;     /// host addr or file
    int   log_port;

    /**
     *  task worker process num
     */
    uint16_t task_worker_num;
    /**
     *  task worker process max
     */
    uint8_t task_recycle_num;
    char *task_tmpdir;
    uint16_t task_tmpdir_len;
    uint8_t task_ipc_mode;
    uint16_t task_max_request;

    uint16_t cpu_num;

    uint32_t pagesize;
    uint32_t max_sockets;
    struct utsname uname;

    /**
     * Unix socket default buffer size
     */
    uint32_t socket_buffer_size;

    swServer *serv;
    swFactory *factory;

    swMemoryPool *memory_pool;
    swReactor *main_reactor;

    swPipe *task_notify;
    swEventData *task_result;

    pthread_t heartbeat_pidt;

    swString *module_stack;
    int call_php_func_argc;
    int (*call_php_func)(const char *name);

    swHashMap *functions;
} swServerG;

#ifdef __cplusplus
}
#endif

#endif
