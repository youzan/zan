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

#include "list.h"
#include "swWork.h"
#include "swError.h"
#include "swSignal.h"
#include "swExecutor.h"
#include "swProtocol/http.h"
#include "swConnection.h"
#include "swBaseOperator.h"

#include <stdlib.h>
#include <time.h>
#include "zanFactory.h"
#include "zanSystem.h"
#include "zanGlobalDef.h"
#include "zanServer.h"
#include "zanWorkers.h"
#include "zanLog.h"

///TODO::: swoole_server

zanServerG   ServerG;              //Local Global Variable
zanServerGS *ServerGS = NULL;      //Share Memory Global Variable
zanWorkerG   ServerWG;             //Worker Global Variable
__thread zanThreadG ServerTG;      //Thread Global Variable
zanServerStats *ServerStatsG = NULL;

static void zan_init_serv_set(void);
static int zan_server_start_check(zanServer *);
//static int zan_server_send1(zanServer *, swSendData *);
static int zan_daemonize(void);

/* initializing server config*/
void zanServer_init(zanServer *serv)
{
    bzero(serv, sizeof(zanServer));

    //init ServerG
    ServerG.factory_mode    = ZAN_MODE_PROCESS;
    ServerG.running         = 1;
    ServerG.log_fd          = STDOUT_FILENO;
    ServerG.cpu_num         = zan_sysconf(_SC_NPROCESSORS_ONLN);
    ServerG.pagesize        = zan_sysconf(_SC_PAGESIZE);
    ServerG.process_pid     = zan_getpid();
    SwooleG.use_timer_pipe  = 1;                 //////////////////////////////

    zan_uname(&ServerG.uname);

    struct rlimit rlmt;
    SwooleG.max_sockets = (zan_getrlimit(RLIMIT_NOFILE, &rlmt) < 0) ?
                           1024:(uint32_t) rlmt.rlim_cur;

#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    if (swoole_version_compare(ServerG.uname.release, "3.9.0") >= 0)
    {
        ServerG.reuse_port = 1;
    }
#endif

    //init ServerG.servSet
    zan_init_serv_set();

    ServerG.serv = serv;
}

//init server:set
void zan_init_serv_set(void)
{
    zanServerSet *servSet = &ServerG.servSet;

    servSet->reactor_num        = ZAN_REACTOR_NUM;    //todo:::delete or replaced with networker_num
    servSet->worker_num         = 1; //ZAN_CPU_NUM;
    servSet->net_worker_num     = 1; //ZAN_CPU_NUM;
    servSet->dispatch_mode      = SW_DISPATCH_FDMOD;
    servSet->max_connection     = SwooleG.max_sockets;

    //just for test
    servSet->task_worker_num    = 1;

    servSet->log_level          = 5;
    servSet->task_ipc_mode      = ZAN_IPC_UNSOCK;
    servSet->task_tmpdir        = strndup(SW_TASK_TMP_FILE, sizeof (SW_TASK_TMP_FILE));
    servSet->task_tmpdir_len    = sizeof (SW_TASK_TMP_FILE);

    servSet->buffer_input_size  = SW_BUFFER_INPUT_SIZE;
    servSet->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;
    servSet->pipe_buffer_size   = SW_PIPE_BUFFER_SIZE;
    servSet->socket_buffer_size = SW_SOCKET_BUFFER_SIZE;

    servSet->heartbeat_idle_time      = SW_HEARTBEAT_IDLE;
    servSet->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    servSet->http_parse_post = 1;
}

//TODO::: zanServer 参数待确定
int zanServer_create(zanServer *serv)
{
    ServerG.factory = &serv->factory;

    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (!serv->session_list)
    {
        zanError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return ZAN_ERR;
    }

    serv->connection_list = sw_shm_calloc(ServerG.servSet.max_connection, sizeof(swConnection));
    if (!serv->connection_list)
    {
        zanError("sw_shm_calloc(%ld) failed for connection_list", ServerG.servSet.max_connection * sizeof(swConnection));
        return ZAN_ERR;
    }

    //create factry object
    int ret = zanFactory_create(&(serv->factory));
    if (ZAN_OK != ret)
    {
        zanError("create factory failed");
    }

    return ret;
}

int zanServer_start(zanServer *serv)
{
    if (zan_server_start_check(serv) < 0)
    {
        return ZAN_ERR;
    }

    zanLog_init(ServerG.servSet.log_file, 0);

    if (ZAN_OK != zan_daemonize())
    {
        zanError("zan_daemonize error.");
        return ZAN_ERR;
    }

    //ServerGS
    ServerGS->master_pid     = zan_getpid();
    ServerGS->started        = 1;
    ServerGS->server_time    = time(NULL);
    ServerStatsG->start_time = ServerGS->server_time;

    ///TODO:::
    //serv->send = zanServer_send1;

    //set listen socket options
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swPort_set_option(ls) < 0)
        {
            return SW_ERR;
        }
    }

    //alloc networker/worker/task_worker resources and fork child process
    zanFactory *factory = &(serv->factory);
    if (!factory || factory->start(factory) < 0)
    {
        zanError("factory start failed");
        return ZAN_ERR;
    }

    //init master process signal, TODO:::
    //

    //master process
    ServerG.process_pid  = ServerGS->master_pid;
    ServerG.process_type = ZAN_PROCESS_MASTER;

    int ret = zan_master_process_loop(serv);

    ///TODO:::
    exit(ret);
    ///swServer_free(serv);

    return SW_OK;
}

//run as daemon
int zan_daemonize(void)
{
    if (!ServerG.servSet.daemonize)
    {
        return ZAN_OK;
    }

    if (ServerG.log_fd > STDOUT_FILENO)
    {
        swoole_redirect_stdout(ServerG.log_fd);
    }
    else
    {
        ServerG.null_fd = open("/dev/null", O_WRONLY);
        if (ServerG.null_fd > 0)
        {
            swoole_redirect_stdout(ServerG.null_fd);
        }
        else
        {
            zanSysError("open(/dev/null) failed.");
        }
    }

    if (swoole_daemon(0, 1) < 0)
    {
        zanError("swoole_daemon return error.");
        return ZAN_ERR;
    }
    return ZAN_OK;
}

//TODO:::
static int zan_server_start_check(zanServer *serv)
{
    return ZAN_OK;
}

uint32_t zan_server_worker_schedule(zanServer *serv, uint32_t conn_fd)
{
    int      index = 0;
    uint32_t target_worker_id = 0;
    zanServerSet *servSet = &ServerG.servSet;
    zanProcessPool *event_pool = &ServerGS->event_workers;

    //轮循或固定
    if (servSet->dispatch_mode == ZAN_DISPATCH_ROUND)
    {
        target_worker_id = zan_atomic_fetch_add(&serv->worker_round_id, 1) % servSet->worker_num;
    }
    else if (servSet->dispatch_mode == ZAN_DISPATCH_FDMOD)
    {
        target_worker_id = conn_fd % servSet->worker_num;
    }
    else if (servSet->dispatch_mode == ZAN_DISPATCH_IPMOD) //Using the IP touch access to hash
    {
        swConnection *conn = zanServer_connection_get(serv, conn_fd);
        if (!conn || SW_SOCK_TCP == conn->socket_type) //UDP or tcp ipv4
        {
            target_worker_id = (!conn)? conn_fd % servSet->worker_num :
                               conn->info.addr.inet_v4.sin_addr.s_addr % servSet->worker_num;
        }
        else  //IPv6
        {
#ifdef HAVE_KQUEUE
            uint32_t ipv6_last_int = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
            target_worker_id = ipv6_last_int % servSet->worker_num;
#else
            target_worker_id = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3] % servSet->worker_num;
#endif
        }
    }
    else if (servSet->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = zanServer_connection_get(serv, conn_fd);
        target_worker_id = (!conn)? (conn_fd % servSet->worker_num):
                           ((conn->uid)? conn->uid % servSet->worker_num:conn_fd % servSet->worker_num);
    }
    else //空闲 worker
    {
        for (index = 0; index < servSet->worker_num + 1; index++)
        {
            target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % servSet->worker_num;
            if (event_pool->workers[target_worker_id].status == SW_WORKER_IDLE)
            {
                break;
            }
        }
        //如果循环一遍无空闲 worker，则随机取一个 worker
        srand((unsigned)time(NULL));
        target_worker_id = rand() % servSet->worker_num;
    }

    /// target worker id 校正
    index = 0;
    while (event_pool->workers[target_worker_id].deny_request)
    {
        zanWarn("worker=%d deny_request, target_work_id increased to %d", target_worker_id, target_worker_id + 1);
        target_worker_id = (target_worker_id + 1) % servSet->worker_num;
        if (++index > servSet->worker_num)
        {
            target_worker_id = 0;
            swDebug("target_work_id is null %d", target_worker_id);
            break;
        }
    }

    return target_worker_id;
}

zanWorker* zanServer_get_worker(zanServer *serv, uint16_t worker_id)
{
    //Event Worker
    if (worker_id < ServerG.servSet.worker_num)
    {
        return &(ServerGS->event_workers.workers[worker_id]);
    }

    //Task Worker
    uint16_t task_worker_max = ServerG.servSet.task_worker_num + ServerG.servSet.worker_num;
    if (worker_id < task_worker_max)
    {
        return &(ServerGS->task_workers.workers[worker_id - ServerG.servSet.worker_num]);
    }

    //net Worker
    uint16_t net_worker_max = task_worker_max + ServerG.servSet.net_worker_num;
    if (worker_id < net_worker_max)
    {
        return &(ServerGS->net_workers.workers[worker_id - task_worker_max]);
    }

    //User Worker
    uint16_t user_worker_max = net_worker_max + serv->user_worker_num;
    if (worker_id < user_worker_max)
    {
        return serv->user_workers[worker_id - net_worker_max];
    }

    //Unkown worker_id
    zanWarn("worker#%d is not exist.", worker_id);
    return NULL;
}

swListenPort* zanServer_add_port(zanServer *serv, int type, char *host, int port)
{
    if (serv->listen_port_num >= SW_MAX_LISTEN_PORT)
    {
        zanWarn("allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return NULL;
    }
    if (!(type == ZAN_SOCK_UNIX_DGRAM || type == ZAN_SOCK_UNIX_STREAM) && (port < 1 || port > 65535))
    {
        zanError("invalid port [%d]", port);
        return NULL;
    }

    swListenPort *ls = ServerG.g_shm_pool->alloc(ServerG.g_shm_pool, sizeof(swListenPort));
    if (ls == NULL)
    {
        zanError("alloc failed");
        return NULL;
    }

    swPort_init(ls);
    ls->type = type;
    ls->port = port;
    bzero(ls->host, SW_HOST_MAXSIZE);
    strncpy(ls->host, host, SW_HOST_MAXSIZE);

    if (type & SW_SOCK_SSL)
    {
        type = type & (~SW_SOCK_SSL);
        if (zanSocket_is_stream(type))
        {
            ls->type = type;
            ls->ssl = 1;
#ifdef SW_USE_OPENSSL
            ls->ssl_config.prefer_server_ciphers = 1;
            ls->ssl_config.session_tickets = 0;
            ls->ssl_config.stapling = 1;
            ls->ssl_config.stapling_verify = 1;
            ls->ssl_config.ciphers = SW_SSL_CIPHER_LIST;
            ls->ssl_config.ecdh_curve = SW_SSL_ECDH_CURVE;
#endif
        }
    }

    //create server socket
    int sock = swSocket_create(ls->type,NULL,NULL);
    if (sock < 0)
    {
        zanError("create socket failed.");
        return NULL;
    }

    //bind address and port
    if (swSocket_bind(sock, ls->type, ls->host, ls->port) < 0)
    {
        close(sock);
        return NULL;
    }

    //stream socket, set nonblock
    ls->sock = sock;
    if (zanSocket_is_stream(ls->type))
    {
        zan_set_nonblocking(sock,1);
        serv->have_tcp_sock = 1;
    }
    else if (zanSocket_is_dgram(ls->type))
    {
        serv->have_udp_sock = 1;
        serv->dgram_port_num++;
        if (ls->type == ZAN_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = sock;
        }
        else if (ls->type == ZAN_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = sock;
        }
    }

    LL_APPEND(serv->listen_list, ls);
    serv->listen_port_num++;
    return ls;
}

int zanServer_tcp_deny_exit(zanServer *serv, long nWorkerId)
{
    zanWarn("swServer_tcp_deny_exit");

    swEventData ev_data;
    ev_data.info.fd = 0;
    ev_data.info.worker_id = nWorkerId;
    ev_data.info.type = SW_EVENT_DENY_EXIT;

    //copy data
    memcpy(ev_data.data, "0", 1);

    ev_data.info.len = 1;
    ev_data.info.from_fd = SW_RESPONSE_SMALL;
    ev_data.info.from_id = 0;
    int sendn = ev_data.info.len + sizeof(swDataHead);

    zanWorker *worker = zanServer_get_worker(serv, nWorkerId);
    if (!worker)
    {
        zanWarn("can't get worker, worker_id=%ld", nWorkerId);
        return ZAN_ERR;
    }

    int ret = //(ServerG.main_reactor)?
              ServerG.main_reactor->write(ServerG.main_reactor, worker->pipe_worker, &ev_data, sendn);
              //swSocket_write_blocking(worker->pipe_worker, &ev_data, sendn);

    return ret;
}
