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

#include <stdlib.h>
#include <time.h>
#include "list.h"
#include "swError.h"
#include "swSignal.h"
#include "swProtocol/http.h"
#include "swConnection.h"
#include "swBaseOperator.h"
#include "zanMemory/zanMemory.h"

#include "zanServer.h"
#include "zanWorkers.h"
#include "zanSocket.h"
#include "zanLog.h"

zanServerG   ServerG;              //Local Global Variable
zanServerGS *ServerGS = NULL;      //Share Memory Global Variable
zanWorkerG   ServerWG;             //Worker Global Variable
__thread zanThreadG ServerTG;      //Thread Global Variable
zanServerStats *ServerStatsG = NULL;

static void zan_server_set_init(void);
static int zanServer_start_check(zanServer *);
static int zan_daemonize(void);
static int get_env_log_level();

/* initializing server config*/
void zanServer_init(zanServer *serv)
{
    bzero(serv, sizeof(zanServer));

    //init ServerG
    ServerG.serv = serv;

    //init ServerG.servSet
    zan_server_set_init();

    uint8_t level = ServerG.servSet.log_level;
    if (get_env_log_level() > 0)
    {
        level = get_env_log_level();
    }
    zan_set_loglevel(level);
}

//init server:set
void zan_server_set_init(void)
{
    zanServerSet *servSet = &ServerG.servSet;

    //servSet->reactor_num        = ZAN_REACTOR_NUM;    //todo:::delete or replaced with networker_num
    servSet->worker_num         = ZAN_CPU_NUM;
    servSet->net_worker_num     = ZAN_CPU_NUM;
    servSet->dispatch_mode      = ZAN_DISPATCH_FDMOD;
    servSet->max_connection     = ServerG.max_sockets;

    //just for test
    servSet->task_worker_num    = 0;

    servSet->log_level          = 5;
    servSet->task_ipc_mode      = ZAN_IPC_UNSOCK;
    servSet->task_tmpdir        = strndup(SW_TASK_TMP_FILE, sizeof (SW_TASK_TMP_FILE));
    servSet->task_tmpdir_len    = sizeof (SW_TASK_TMP_FILE);

    servSet->buffer_input_size  = SW_BUFFER_INPUT_SIZE;
    servSet->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;
    servSet->pipe_buffer_size   = SW_PIPE_BUFFER_SIZE;

    servSet->heartbeat_idle_time      = SW_HEARTBEAT_IDLE;
    servSet->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    servSet->http_parse_post = 1;
}

int zanServer_create(zanServer *serv)
{
    ServerG.factory = &serv->factory;

    serv->session_list = zan_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(zanSession));
    if (!serv->session_list)
    {
        zanError("zan_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(zanSession));
        return ZAN_ERR;
    }

    zanServerSet *servSet = &ServerG.servSet;

    serv->connection_list  = (swConnection**)zan_shm_calloc(servSet->net_worker_num, sizeof(swConnection*));
    for (uint32_t index = 0; index < servSet->net_worker_num; index++)
    {
        zanDebug("calloc connection_list: index=%d, networker_num=%d", index, servSet->net_worker_num);
        serv->connection_list[index] = (swConnection*)zan_shm_calloc(ServerG.servSet.max_connection, sizeof(swConnection));
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
    if (ZAN_OK != zanServer_start_check(serv))
    {
        zanError("zan_server_start_check failed.");
        return ZAN_ERR;
    }

    if (ZAN_OK != zan_daemonize())
    {
        zanError("zan_daemonize failed.");
        return ZAN_ERR;
    }

    //set listen socket options
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        zanDebug("ls->port=%d, ls->host=%s, ls->sock=%d", ls->port, ls->host, ls->sock);
        if (zanPort_set_ListenOption(ls) < 0)
        {
            zanError("setlistion failed: ls->port=%d, ls->host=%s, ls->sock=%d", ls->port, ls->host, ls->sock);
            return ZAN_ERR;
        }
    }

    zanFactory *factory = &(serv->factory);
    if (!factory || factory->start(factory) < 0)
    {
        zanError("factory start failed");
        return ZAN_ERR;
    }

    int ret = zan_master_process_loop(serv);

    exit(ret);
    ///zanServer_free(serv);

    return ZAN_OK;
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

//TODO
static int zanServer_start_check(zanServer *serv)
{
    zanServerSet *servSet = &ServerG.servSet;

    if (serv->have_tcp_sock && serv->onReceive == NULL)
    {
        zanError("Tcp Server: onReceive event callback must be set.");
        return ZAN_ERR;
    }

    //UDP
    if (serv->have_udp_sock && !serv->onPacket)
    {
        zanWarn("Udp Server, no onPacket callback, set to onReceive.");
        serv->onPacket = serv->onReceive;
    }

    ///TODO
    //disable notice when use ZAN_DISPATCH_ROUND and ZAN_DISPATCH_QUEUE
    if (servSet->dispatch_mode == ZAN_DISPATCH_ROUND || servSet->dispatch_mode == ZAN_DISPATCH_QUEUE)
    {
        if (!servSet->enable_unsafe_event)
        {
            serv->onConnect = NULL;
            serv->onClose = NULL;
            serv->disable_notify = 1;
        }
    }

    //AsyncTask
    if (servSet->task_worker_num > 0)
    {
        if (serv->onTask == NULL || serv->onFinish == NULL)
        {
            zanError("task_worker_num=%d, onTask or onFinsh is null", servSet->task_worker_num);
            return ZAN_ERR;
        }
    }

    if (ServerG.max_sockets > 0 && servSet->max_connection > ServerG.max_sockets)
    {
        zanWarn("serv->max_connection is exceed the maximum value[%d].", ServerG.max_sockets);
        servSet->max_connection = ServerG.max_sockets;
    }

    if (servSet->max_connection < (servSet->worker_num + servSet->task_worker_num) * 2 + 32)
    {
        zanWarn("serv->max_connection is too small.");
        servSet->max_connection = ServerG.max_sockets;
    }

    //ServerGS
    ServerGS->master_pid     = getpid();
    ServerGS->started        = 1;
    ServerGS->server_time    = time(NULL);
    ServerGS->session_round = 1;
    ServerStatsG->start_time = ServerGS->server_time;

    //master process
    ServerG.process_pid  = ServerGS->master_pid;
    ServerG.process_type = ZAN_PROCESS_MASTER;

    return ZAN_OK;
}

uint32_t zanServer_worker_schedule(zanServer *serv, uint32_t networker_id, uint32_t conn_fd)
{
    int      index = 0;
    uint32_t target_worker_id = 0;
    zanServerSet *servSet = &ServerG.servSet;
    zanProcessPool *event_pool = &ServerGS->event_workers;

    //轮循: 多个 networker 进程情况下，这种轮循不正确。。。。
    if (servSet->dispatch_mode == ZAN_DISPATCH_ROUND)
    {
        target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % servSet->worker_num;
    }
    else if (servSet->dispatch_mode == ZAN_DISPATCH_FDMOD)
    {
        target_worker_id = conn_fd % servSet->worker_num;
    }
    else if (servSet->dispatch_mode == ZAN_DISPATCH_IPMOD) //Using the IP touch access to hash
    {
        swConnection *conn = zanServer_get_connection(serv, networker_id, conn_fd);
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
    else if (servSet->dispatch_mode == ZAN_DISPATCH_UIDMOD)
    {
        swConnection *conn = zanServer_get_connection(serv, networker_id, conn_fd);
        uint32_t uid = 0;
        if (conn == NULL || conn->uid == 0)
        {
            uid = conn_fd;
        }
        else
        {
            uid = conn->uid;
        }
        target_worker_id = uid % servSet->worker_num;
    }
    else //空闲 worker
    {
        for (index = 0; index < servSet->worker_num + 1; index++)
        {
            target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % servSet->worker_num;
            if (event_pool->workers[target_worker_id].status == ZAN_WORKER_IDLE)
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
            zanDebug("target_work_id is null %d", target_worker_id);
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
    zanError("error, worker#%d is not exist.", worker_id);
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

    swListenPort *ls = zan_shm_calloc(1, sizeof(swListenPort));
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
            ls->ssl_config.ciphers = strdup(SW_SSL_CIPHER_LIST);
            ls->ssl_config.ecdh_curve = strdup(SW_SSL_ECDH_CURVE);
#endif
        }
    }

    //create server socket
    int sock = swSocket_create(ls->type, NULL, NULL);
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
    swEventData ev_data;
    ev_data.info.fd = 0;
    ev_data.info.worker_id = nWorkerId;
    ev_data.info.type = SW_EVENT_DENY_EXIT;

    //copy data
    memcpy(ev_data.data, "0", 1);

    ev_data.info.len = 1;
    ev_data.info.from_fd = ZAN_RESPONSE_SMALL;
    ev_data.info.from_id = 0;
    int sendn = ev_data.info.len + sizeof(swDataHead);

    zanWorker *worker = zanServer_get_worker(serv, nWorkerId);
    if (!worker)
    {
        zanWarn("can't get worker, worker_id=%ld", nWorkerId);
        return ZAN_ERR;
    }

    int ret = (ServerG.main_reactor)?
              ServerG.main_reactor->write(ServerG.main_reactor, worker->pipe_worker, &ev_data, sendn):
              swSocket_write_blocking(worker->pipe_worker, &ev_data, sendn);

    return ret;
}

void zanServer_connection_ready(zanServer *serv, int fd, int reactor_id, int networker_id)
{
    swDataHead connect_event;
    connect_event.type = SW_EVENT_CONNECT;
    connect_event.from_id = reactor_id;
    connect_event.fd = fd;
    connect_event.networker_id = networker_id;

    if (serv->factory.notify(&serv->factory, &connect_event) < 0)
    {
        zanWarn("send notification SW_EVENT_CONNECT, [fd=%d] failed.", fd);
    }
}

int zanServer_send(zanServer *serv, swSendData *resp)
{
    return swWrite(resp->info.fd, resp->data, resp->info.len);
}

int zanServer_tcp_send(zanServer *serv, int session_id, void *data, uint32_t length)
{
    swSendData _send;
    zanFactory   *factory = &(serv->factory);
    zanServerSet *servSet = &ServerG.servSet;

    //More than the output buffer
    if (length >= servSet->buffer_output_size)
    {
        zanWarn("More than the output buffer size[%d], please use the sendfile.", servSet->buffer_output_size);
        return ZAN_ERR;
    }

    //fd: session_id
    memset(&_send, 0, sizeof(swSendData));
    _send.info.fd   = session_id;
    _send.info.type = SW_EVENT_TCP;
    _send.data      = data;
    _send.info.worker_id = ServerWG.worker_id;   //src worker, for test

    if (length >= SW_IPC_MAX_SIZE - sizeof(swDataHead))
    {
        _send.length = length;
    }
    else
    {
        _send.info.len = length;
        _send.length = 0;
    }
    return factory->finish(factory, &_send);
}

void zanServer_store_listen_socket(zanServer *serv, int networker_id)
{
    int index  = -1;
    int sockfd = 0;
    swListenPort *ls = NULL;
    int networker_index = zanServer_get_networker_index(networker_id);

    LL_FOREACH(serv->listen_list, ls)
    {
        index++;
        sockfd = ls->sock;
        if (sockfd <= 0)
        {
            zanError("sockfd=%d, sock_type=%d, port=%d, index=%d", sockfd, ls->type, ls->port, index);
            continue;
        }

        //save server socket to connection_list
        serv->connection_list[networker_index][sockfd].fd = sockfd;
        //socket type
        serv->connection_list[networker_index][sockfd].socket_type = ls->type;
        //save listen_host object
        serv->connection_list[networker_index][sockfd].object = ls;

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[networker_index][sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else if (ls->type == SW_SOCK_UDP6)
            {
                ServerG.serv->udp_socket_ipv6 = sockfd;
                serv->connection_list[networker_index][sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        else
        {
            //IPv4
            if (ls->type == SW_SOCK_TCP)
            {
                serv->connection_list[networker_index][sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            //IPv6
            else if (ls->type == SW_SOCK_TCP6)
            {
                serv->connection_list[networker_index][sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }

        zanServer_set_minfd(serv, networker_index, 0);
        zanServer_set_maxfd(serv, networker_index, 0);
    }
}

swConnection *zanServer_verify_connection(zanServer *serv, int session_id)
{
    zanSession *session = zanServer_get_session(serv, session_id);
    int fd = session->accept_fd;
    int networker_id = session->networker_id;

    swConnection *conn = zanServer_get_connection(serv, networker_id, fd);
    if (!conn || conn->active == 0)
    {
        return NULL;
    }
    if (session->session_id != session_id || conn->session_id != session_id)
    {
        return NULL;
    }
#ifdef SW_USE_OPENSSL
    if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
    {
        zanError("SSL not ready");
        return NULL;
    }
#endif
    return conn;
}

int zanServer_getSocket(zanServer *serv, int port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->port == port || port == 0)
        {
            return ls->sock;
        }
    }

    return ZAN_ERR;
}

swConnection* zanServer_get_connection(zanServer *serv, int networker_id, int fd)
{
    zanServerSet *servSet = &ServerG.servSet;
    int networker_index = zanServer_get_networker_index(networker_id);

    if (fd > servSet->max_connection || fd <= 2 ||
        networker_index >= servSet->net_worker_num || networker_index < 0)
    {
        zanWarn("fd=%d, no connection, networker_index=%d", fd, networker_index);
        return NULL;
    }
    else
    {
        return &serv->connection_list[networker_index][fd];
    }
}

zanSession* zanServer_get_session(zanServer *serv, uint32_t session_id)
{
    return &serv->session_list[session_id % SW_SESSION_LIST_SIZE];
}

int zanServer_getFd_bySession(zanServer *serv, uint32_t session_id)
{
    return serv->session_list[session_id % SW_SESSION_LIST_SIZE].accept_fd;
}

swConnection* zanServer_get_connection_by_sessionId(zanServer *serv, uint32_t session_id)
{
    zanSession* session = zanServer_get_session(serv, session_id);
    uint32_t accept_fd    = session->accept_fd;
    uint32_t networker_id = session->networker_id;

    return zanServer_get_connection(serv, networker_id, accept_fd);
}

swListenPort* zanServer_get_port(zanServer *serv, int networker_id, int fd)
{
    int network_index = zanServer_get_networker_index(networker_id);

    sw_atomic_t server_fd = 0;
    int index = 0;
    for (index = 0;index < 128;index++)
    {
        server_fd = serv->connection_list[network_index][fd].from_fd;

        if (server_fd > 0)
        {
            break;
        }

        swYield();
    }

#if defined(__GNUC__)
    if (index > 0)
    {
        zanWarn("get port failed, count=%d. gcc version=%d.%d", index, __GNUC__, __GNUC_MINOR__);
    }
#endif

    return serv->connection_list[network_index][server_fd].object;
}

void zanServer_free_connection_buffer(zanServer *serv, int networker_id, int fd)
{
    int network_index = zanServer_get_networker_index(networker_id);
    swString *buffer = serv->connection_list[network_index][fd].object;
    if (buffer)
    {
        swString_free(buffer);
        serv->connection_list[network_index][fd].object = NULL;
    }
}

int zanServer_get_networker_index(int net_worker_id)
{
    int index = net_worker_id - ServerG.servSet.worker_num - ServerG.servSet.task_worker_num;
    return index;
}

uint32_t zanServer_get_connection_num(zanServer *serv)
{
    int index = 0;
    int sum   = 0;
    zanServerSet *servSet = &ServerG.servSet;

    for (index = 0; index < servSet->net_worker_num; index++)
    {
        int minfd = zanServer_get_minfd(serv, index);
        int maxfd = zanServer_get_maxfd(serv, index);
        if (0 != maxfd)
        {
            sum += maxfd - minfd + 1;
        }
        zanDebug("networker_index=%d, minfd=%d, max_fd=%d, sum=%d", index, minfd, maxfd, sum);
    }

    return sum;
}

int zanServer_tcp_sendfile(zanServer *serv, int fd, char *filename, uint32_t len)
{
#ifdef SW_USE_OPENSSL
    swConnection *conn = zanServer_verify_connection(serv, fd);
    if (conn && conn->ssl)
    {
        zanError("SSL session#%d cannot use sendfile().", fd);
        return ZAN_ERR;
    }
#endif

    swSendData send_data;
    send_data.info.len = len;
    char buffer[SW_BUFFER_SIZE] = {0};

    //file name size
    if (send_data.info.len > SW_BUFFER_SIZE - 1)
    {
        zanWarn("sendfile name too long. [MAX_LENGTH=%d]",(int) SW_BUFFER_SIZE - 1);
        return ZAN_ERR;
    }

    //check file exists
    if (access(filename, R_OK) < 0)
    {
        zanError("file[%s] not found.", filename);
        return ZAN_ERR;
    }

    send_data.info.fd = fd;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, filename, send_data.info.len);
    buffer[send_data.info.len] = 0;
    ++send_data.info.len;
    send_data.length = 0;
    send_data.data = buffer;

    return serv->factory.finish(&serv->factory, &send_data);
}

swString *zanServer_get_buffer(zanServer *serv, int networker_id, int fd)
{
    int networker_index = zanServer_get_networker_index(networker_id);
    swString *buffer = serv->connection_list[networker_index][fd].object;

    if (buffer == NULL)
    {
        buffer = swString_new(SW_BUFFER_SIZE);
        //alloc memory failed.
        if (!buffer)
        {
            return NULL;
        }
        serv->connection_list[networker_index][fd].object = buffer;
    }
    return buffer;
}

int zanServer_adduserworker(zanServer *serv, zanWorker *worker)
{
    zanUserWorker_node *user_worker = sw_malloc(sizeof(zanUserWorker_node));
    if (!user_worker)
    {
        return ZAN_ERR;
    }

    serv->user_worker_num++;
    user_worker->worker = worker;

    LL_APPEND(serv->user_worker_list, user_worker);
    if (!serv->user_worker_map)
    {
        serv->user_worker_map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    }

    return worker->worker_id;
}

int zanServer_tcp_deny_request(zanServer *serv, long nWorkerId)
{
    zanTrace("deny_request: dstworker_id=%ld", nWorkerId);
    if (nWorkerId < 0 || nWorkerId >= ServerG.servSet.worker_num)
    {
        zanError("workerid=%ld is error, worker_num=%d", nWorkerId, ServerG.servSet.worker_num);
        return ZAN_ERR;
    }

    if (nWorkerId == ServerWG.worker_id)
    {
        ServerGS->event_workers.workers[nWorkerId].deny_request = 1;
        zanDebug("set self worker deny_request, [dst_work_id=%ld], src_worker_id=%d", nWorkerId, ServerWG.worker_id);
        return ZAN_OK;
    }

    swEventData ev_data;
    ev_data.info.fd = 0;
    ev_data.info.worker_id = nWorkerId;
    ev_data.info.type = SW_EVENT_DENY_REQUEST;
    //copy data
    memcpy(ev_data.data, "0", 1);

    ev_data.info.len = 1;
    ev_data.info.from_fd = ZAN_RESPONSE_SMALL;
    ev_data.info.from_id = 0;
    int sendn = ev_data.info.len + sizeof(swDataHead);

    zanWorker *worker = zanServer_get_worker(serv, nWorkerId);
    int ret = 0;
    if (ServerG.main_reactor)
    {
        ret = ServerG.main_reactor->write(ServerG.main_reactor, worker->pipe_worker, &ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(worker->pipe_worker, &ev_data, sendn);
    }
    return ret;
}

int zanServer_get_first_sessionId(zanServer *serv)
{
    zanServerSet *servSet = &ServerG.servSet;
    for (int index = 0; index < servSet->net_worker_num; index++)
    {
        int minfd = zanServer_get_minfd(serv, index);
        int maxfd = zanServer_get_maxfd(serv, index);
        for (int fd = minfd; fd <= maxfd && fd >= 2 ; fd++)
        {
            swConnection *conn = &serv->connection_list[index][fd];
            if (conn && conn->active && !conn->closed)
            {
                return conn->session_id;
            }
        }
    }
    return 0;
}

int get_env_log_level()
{
    int level = ZAN_LOG_LEVEL_UNKNOW;
    char* tmp = getenv("ZANEXT_DEBUG_LOG_LEVEL");
    if (tmp)
    {
        level = strtol(tmp,NULL,0);
    }

    return level;
}

void swoole_cpu_setAffinity(int threadid, zanServer *serv)
{
#ifdef HAVE_CPU_AFFINITY
    if (!serv){
        return ;
    }

    //cpu affinity setting
    if (ServerG.servSet.open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[threadid % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(threadid % ZAN_CPU_NUM, &cpu_set);
        }

        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
        {
            zanError("pthread_setaffinity_np() failed");
        }
    }
#endif
}
