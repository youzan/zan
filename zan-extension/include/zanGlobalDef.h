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
  |         Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#ifndef _ZAN_ZANGLOBAL_H_
#define _ZAN_ZANGLOBAL_H_

#include "swBaseOperator.h"
#include "swTimer.h"
#include "swPort.h"
#include "swConnection.h"

#include "zanMemory/zanShmPool.h"
#include "zanWorkers.h"
#include "zanThread.h"

#ifdef __cplusplus
extern "C" {
#endif

//1. zanServerSet 中的所有属性都是通过 serv->set 设置的
//2. 不在 zanServerSet 中的属性，在 swListenPort 中

//todo::: 将全局的相关的变量都放到 zanServerG 中

typedef struct _zanServer
{
    sw_atomic_t worker_round_id;

    uint8_t dgram_port_num;
    uint8_t listen_port_num;

    uint32_t have_tcp_sock :1;

    uint32_t have_udp_sock :1;
    uint32_t udp_socket_ipv4;
    uint32_t udp_socket_ipv6;

    //Udisable notice when use ZAN_DISPATCH_ROUND and ZAN_DISPATCH_QUEUE
    uint32_t disable_notify :1;

    //packet mode
    uint32_t packet_mode :1;

    uint32_t *cpu_affinity_available;
    uint32_t  cpu_affinity_available_num;


    zanFactory factory;

    swListenPort *listen_list;

    uint32_t      user_worker_num;
    zanWorker   **user_workers;
    swHashMap    *user_worker_map;
    zanUserWorker_node *user_worker_list;

    zanSession     *session_list;
    swConnection   **connection_list;

    void *ptr2;

    /*callback*/
    void (*onStart)(struct _zanServer *);
    void (*onShutdown)(struct _zanServer *);
    void (*onWorkerStart)(struct _zanServer *, int worker_id);
    void (*onWorkerStop)(struct _zanServer *, int worker_id);
    void (*onNetWorkerStart)(struct _zanServer *, int worker_id);
    void (*onWorkerError)(struct _zanServer *, int worker_id, pid_t worker_pid, int exit_code, int signo);
    void (*onUserWorkerStart)(struct _zanServer *, zanWorker *);
    void (*onPipeMessage)(struct _zanServer *, swEventData *);    /*worker/task_worker pipe read*/

    /* Task Worker event */
    int (*onTask)(struct _zanServer *serv, swEventData *data);
    int (*onFinish)(struct _zanServer *serv, swEventData *data);

    /* Client event */
    int (*onReceive)(struct _zanServer *, swEventData *);
    int (*onPacket)(struct _zanServer *, swEventData *);
    void (*onClose)(struct _zanServer *, swDataHead *);
    void (*onConnect)(struct _zanServer *, swDataHead *);

    int (*send)(struct _zanServer *, swSendData *);
} zanServer;

typedef struct _zanServerGS
{
    uint8_t      started;
    time_t       server_time;
    zan_pid_t    master_pid;

    zanLock      lock;
    zanLock      log_lock;
    zanLock      accept_lock;
    uint8_t      log_level;
    sw_atomic_t spinlock;

    uint32_t     session_round;

    zanProcessPool event_workers;
    zanProcessPool task_workers;
    zanProcessPool net_workers;
} zanServerGS;

//Worker process global Variable
typedef struct _zanWorkerG
{
    uint32_t worker_id;      /* Current Proccess Worker's id */
    uint32_t reload;         //
    uint32_t reload_count;   //reload计数
    uint32_t request_count;
    uint32_t max_request;

    uint8_t run_always :1;
    uint8_t reactor_init :1;
    uint8_t reactor_ready :1;
    uint8_t in_client :1;
    uint8_t shutdown :1;

    swString **buffer_input;

    uint8_t fatal_error;

} zanWorkerG;

typedef struct _zanServerSet
{
    uint32_t worker_num;
    uint32_t net_worker_num;

    uint32_t max_connection;
    uint32_t max_request;

    uint8_t  dispatch_mode;

    uint8_t   task_ipc_mode;
    uint32_t  task_max_request;
    uint32_t  task_worker_num;
    uint32_t  task_tmpdir_len;
    uint64_t  message_queue_key;
    char      *task_tmpdir;

    uint8_t   log_level;
    char     *log_file;
    char     *pid_file;

    char     *user;
    char     *chroot;
    char     *group;

    uint16_t heartbeat_idle_time;
    uint16_t heartbeat_check_interval;

    uint32_t buffer_output_size;
    uint32_t buffer_input_size;

    uint32_t socket_buffer_size;
    uint32_t pipe_buffer_size;

    uint16_t daemonize :1;
    uint16_t enable_reuse_port :1;
    uint16_t open_cpu_affinity :1;
    uint16_t cpu_affinity_ignore :1;
    uint16_t enable_unsafe_event :1;
    uint16_t discard_timeout_request :1;
    uint16_t http_parse_post :1;
} zanServerSet;

typedef struct _zanServerG
{
    swTimer timer;
    uint16_t running :1;
    uint16_t use_timerfd :1;
    uint16_t use_signalfd :1;
    uint16_t enable_signalfd :1;
    uint16_t reuse_port :1;
    uint16_t socket_dontwait :1;
    uint16_t disable_dns_cache :1;
    uint16_t dns_lookup_random: 1;
    uint16_t use_timer_pipe :1;

    uint8_t   factory_mode;
    uint8_t   process_type;
    zan_pid_t process_pid;

    uint32_t pagesize;
    int max_sockets;
    uint16_t cpu_num;

    int error;
    int signal_alarm;
    int log_fd;
    int null_fd;
    int signal_fd;
#ifndef PHP_WIN32
    struct utsname uname;
#endif

    zan_thread_t heartbeat_tid;

    zanServerSet  servSet;
    zanServer    *serv;
    swReactor    *main_reactor;
    zanFactory   *factory;
    zanShmPool   *g_shm_pool;
} zanServerG;

typedef struct _zanThreadG
{
    uint16_t id;
    uint8_t type;
} zanThreadG;

//==============================================================================
typedef struct _zanWorkerStats
{
    time_t start_time;
    sw_atomic_t total_request_count;
    sw_atomic_t request_count;
    sw_atomic_t start_count;
} zanWorkerStats;

typedef struct _zanServerStats
{
    time_t              start_time;
    time_t              last_reload;
    sw_atomic_t        connection_num;
    sw_atomic_t        accept_count;
    sw_atomic_t        close_count;
    sw_atomic_t        tasking_num;
    sw_atomic_t        request_count;
    sw_atomic_t        active_worker;
    sw_atomic_t        active_task_worker;
    sw_atomic_t        active_networker;
    sw_atomic_t        max_active_worker;
    sw_atomic_t        max_active_task_worker;
    sw_atomic_t        max_active_net_worker;
    sw_atomic_t        worker_normal_exit;
    sw_atomic_t        worker_abnormal_exit;
    sw_atomic_t        task_worker_normal_exit;
    sw_atomic_t        task_worker_abnormal_exit;
    sw_atomic_t        net_worker_normal_exit;
    sw_atomic_t        net_worker_abnormal_exit;
    zanWorkerStats      *workers_state;
    zanLock             lock;
} zanServerStats;

#define zan_stats_incr(val) sw_atomic_fetch_add(val, 1)
#define zan_stats_decr(val) sw_atomic_fetch_sub(val, 1)

#ifdef __cplusplus
}
#endif

#endif
