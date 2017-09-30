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


#include "list.h"
#include "swServer.h"
#include "swWork.h"
#include "swError.h"
#include "swSignal.h"
#include "swLog.h"
#include "swExecutor.h"
#include "swProtocol/http.h"
#include "swConnection.h"
#include "swBaseOperator.h"
#include "swGlobalVars.h"


swServerG SwooleG;              /// 超全局本地变量，此全局变量子进程中修改，其它进程不感知
swServerGS *SwooleGS = NULL;        /// 超全局共享变量，此全局变量是基于共享内存的，修改字段，其它进程可感知
swWorkerG SwooleWG;             /// 进程内全局变量，此全局变量在worker进程内初始化
swServerStats *SwooleStats = NULL;
__thread swThreadG SwooleTG;   /// 线程独立变量


#if SW_REACTOR_SCHEDULE == 3
static sw_inline void swServer_reactor_schedule(swServer *serv)
{
    //以第1个为基准进行排序，取出最小值
    int index = 0, event_num = serv->reactor_threads[0].reactor.event_num;
    serv->reactor_next_i = 0;
    for (index = 1; index < serv->reactor_num; index++)
    {
        if (serv->reactor_threads[index].reactor.event_num < event_num)
        {
            serv->reactor_next_i = index;
            event_num = serv->reactor_threads[index].reactor.event_num;
        }
    }
}

#endif

static int swServer_start_check(swServer *serv);

static void swServer_signal_init(void);
static void swServer_signal_hanlder(int sig);

static int swServer_send1(swServer *serv, swSendData *resp);
static int swServer_send2(swServer *serv, swSendData *resp);

static void (*onConnect_callback)(swServer *, int, int);
static int (*onReceive_callback)(swServer *, char *, int, int, int);
static void (*onClose_callback)(swServer *, int, int);

static int swServer_start_check(swServer *serv)
{
    if (serv->onReceive == NULL && serv->onPacket == NULL)
    {
        swWarn("onReceive and onPacket event callback must be set.");
        return SW_ERR;
    }

    if (serv->have_tcp_sock && serv->onReceive == NULL)
    {
        swWarn("onReceive event callback must be set.");
        return SW_ERR;
    }

    //UDP
    if (!serv->onPacket)
    {
        serv->onPacket = serv->onReceive;
    }

    //disable notice when use SW_DISPATCH_ROUND and SW_DISPATCH_QUEUE
    if (serv->factory_mode == SW_MODE_PROCESS)
    {
        if (serv->dispatch_mode == SW_DISPATCH_ROUND || serv->dispatch_mode == SW_DISPATCH_QUEUE)
        {
            if (!serv->enable_unsafe_event)
            {
                serv->onConnect = NULL;
                serv->onClose = NULL;
                serv->disable_notify = 1;
            }
        }
    }
    //AsyncTask
    if (SwooleG.task_worker_num > 0)
    {
        if (serv->onTask == NULL || serv->onFinish == NULL)
        {
            swWarn("onTask or onFinsh is null");
            return SW_ERR;
        }
    }

    //check thread num
    serv->reactor_num  = (serv->reactor_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)?
                            (SW_CPU_NUM * SW_MAX_THREAD_NCPU):serv->reactor_num;

    serv->worker_num  = (serv->worker_num > SW_CPU_NUM * SW_MAX_THREAD_NCPU)?
                            (SW_CPU_NUM * SW_MAX_THREAD_NCPU):serv->worker_num;

    serv->reactor_num = (serv->worker_num < serv->reactor_num)? serv->worker_num:
                                serv->reactor_num;

    if (SwooleG.max_sockets > 0 && serv->max_connection > SwooleG.max_sockets)
    {
        swWarn("serv->max_connection is exceed the maximum value[%d].", SwooleG.max_sockets);
        serv->max_connection = SwooleG.max_sockets;
    }

    if (serv->max_connection < (serv->worker_num + SwooleG.task_worker_num) * 2 + 32)
    {
        swWarn("serv->max_connection is too small.");
        serv->max_connection = SwooleG.max_sockets;
    }

    SwooleGS->session_round = 1;
    return SW_OK;
}

static void swServer_signal_init(void)
{
    swSignal_add(SIGPIPE, NULL);
    swSignal_add(SIGHUP, NULL);
    swSignal_add(SIGCHLD, swServer_signal_hanlder);
    swSignal_add(SIGUSR1, swServer_signal_hanlder);
    swSignal_add(SIGUSR2, swServer_signal_hanlder);
    swSignal_add(SIGTERM, swServer_signal_hanlder);
#ifdef SIGRTMIN
    swSignal_add(SIGRTMIN, swServer_signal_hanlder);
#endif
    swSignal_add(SIGALRM, swSystemTimer_signal_handler);
    //for test
    swSignal_add(SIGVTALRM, swServer_signal_hanlder);
    swServer_set_minfd(SwooleG.serv, SwooleG.signal_fd);
}

static void swServer_signal_hanlder(int sig)
{
    int status;
    switch (sig)
    {
    case SIGTERM:
        if (SwooleG.main_reactor)
        {
            SwooleG.main_reactor->running = 0;
        }
        else
        {
            SwooleG.running = 0;
        }
        swNotice("Server is shutdown now.");
        break;
    case SIGALRM:
        swSystemTimer_signal_handler(SIGALRM);
        break;
    case SIGCHLD:
        /// 需要看看在信号处理函数中 调用swWaitpid；若有问题还是要调用原始接口swWaitpid
        if (swWaitpid(SwooleGS->manager_pid, &status, WNOHANG) > 0 && SwooleG.running > 0)
        {
            swWarn("Fatal Error: manager process exit. status=%d, signal=%d.", WEXITSTATUS(status), WTERMSIG(status));
        }
        break;
        /**
         * for test
         */
    case SIGVTALRM:
        swWarn("SIGVTALRM coming");
        break;
        /**
         * proxy the restart signal
         */
    case SIGUSR1:
    case SIGUSR2:
        if (SwooleG.serv->factory_mode == SW_MODE_SINGLE)
        {
            SwooleGS->event_workers.reloading = 1;
            SwooleGS->event_workers.reload_flag = 0;
        }
        else
        {
            /// 需要看看在信号处理函数中 调用swKill；若有问题还是要调用原始接口kill
            swKill(SwooleGS->manager_pid, sig);
        }
        break;
    default:
#ifdef SIGRTMIN
        if (sig == SIGRTMIN)
        {
            int index;
            swWorker *worker = NULL;
            for (index = 0; index < SwooleG.serv->worker_num + SwooleG.task_worker_num +
                                                SwooleG.serv->user_worker_num; index++)
            {
                worker = swServer_get_worker(SwooleG.serv, index);
                swKill(worker->pid, SIGRTMIN);
            }

            if (SwooleG.serv->factory_mode == SW_MODE_PROCESS)
            {
                swKill(SwooleGS->manager_pid, SIGRTMIN);
            }

            swServer_reopen_log_file(SwooleG.serv);
        }
#endif
        break;
    }
}

/**
 * only tcp
 */
static int swServer_send1(swServer *serv, swSendData *resp)
{
    return swWrite(resp->info.fd, resp->data, resp->info.len);
}

/**
 * for udp + tcp
 */
static int swServer_send2(swServer *serv, swSendData *resp)
{
    int ret = (resp->info.from_id >= serv->reactor_num)? swServer_udp_send(serv, resp):
                                    swWrite(resp->info.fd, resp->data, resp->info.len);

    if (ret < 0)
    {
        swWarn("[Writer]sendto client failed. errno=%d", errno);
    }

    return ret;
}

void swServer_store_listen_socket(swServer *serv)
{
    swListenPort *ls = NULL;
    int sockfd;
    LL_FOREACH(serv->listen_list, ls)
    {
        sockfd = ls->sock;
        //save server socket to connection_list
        serv->connection_list[sockfd].fd = sockfd;
        //socket type
        serv->connection_list[sockfd].socket_type = ls->type;
        //save listen_host object
        serv->connection_list[sockfd].object = ls;

        if (swSocket_is_dgram(ls->type))
        {
            if (ls->type == SW_SOCK_UDP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            else if (ls->type == SW_SOCK_UDP6)
            {
                SwooleG.serv->udp_socket_ipv6 = sockfd;
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        else
        {
            //IPv4
            if (ls->type == SW_SOCK_TCP)
            {
                serv->connection_list[sockfd].info.addr.inet_v4.sin_port = htons(ls->port);
            }
            //IPv6
            else if (ls->type == SW_SOCK_TCP6)
            {
                serv->connection_list[sockfd].info.addr.inet_v6.sin6_port = htons(ls->port);
            }
        }
        if (sockfd >= 0)
        {
            swServer_set_minfd(serv, sockfd);
            swServer_set_maxfd(serv, sockfd);
        }
    }
}

int swServer_worker_init(swServer *serv, swWorker *worker)
{
    /// 设置cpu 亲和性
    swoole_cpu_setAffinity(SwooleWG.id,serv);

    int buffer_input_size = (serv->listen_list->open_eof_check ||
                                serv->listen_list->open_length_check ||
                                serv->listen_list->open_http_protocol)?
                                serv->listen_list->protocol.package_max_length:
                                SW_BUFFER_SIZE_BIG;

    int buffer_num = (serv->factory_mode != SW_MODE_PROCESS)? 1:
                    serv->reactor_num + serv->dgram_port_num;

    SwooleWG.buffer_input = sw_malloc(sizeof(swString*) * buffer_num);
    if (!SwooleWG.buffer_input)
    {
        swError("malloc for SwooleWG.buffer_input failed.");
        return SW_ERR;
    }

    int index = 0;
    for (index = 0; index < buffer_num; index++)
    {
        SwooleWG.buffer_input[index] = swString_new(buffer_input_size);
        if (!SwooleWG.buffer_input[index])
        {
            swError("buffer_input init failed.");
            return SW_ERR;
        }
    }

    if (serv->max_request < 1)
    {
        SwooleWG.run_always = 1;
    }
    else
    {
        SwooleWG.max_request = serv->max_request;
        if (SwooleWG.max_request > 10)
        {
            SwooleWG.max_request += swoole_system_random(1, 100);
        }
    }

    return SW_OK;
}

/**
 * initializing server config, set default
 */
void swServer_init(swServer *serv)
{
    bzero(serv, sizeof(swServer));

    swoole_init();
    serv->factory_mode = SW_MODE_BASE;

    serv->reactor_num = SW_REACTOR_NUM > SW_REACTOR_MAX_THREAD ? SW_REACTOR_MAX_THREAD : SW_REACTOR_NUM;

    serv->dispatch_mode = SW_DISPATCH_FDMOD;
    serv->ringbuffer_size = SW_QUEUE_SIZE;

    serv->timeout_sec = SW_REACTOR_TIMEO_SEC;
    serv->timeout_usec = SW_REACTOR_TIMEO_USEC;  //300ms;

    serv->worker_num = SW_CPU_NUM;
    serv->max_connection = SwooleG.max_sockets;
    serv->max_request = 0;

    serv->http_parse_post = 1;

    //heartbeat check
    serv->heartbeat_idle_time = SW_HEARTBEAT_IDLE;
    serv->heartbeat_check_interval = SW_HEARTBEAT_CHECK;

    serv->buffer_input_size = SW_BUFFER_INPUT_SIZE;
    serv->buffer_output_size = SW_BUFFER_OUTPUT_SIZE;

    serv->pipe_buffer_size = SW_PIPE_BUFFER_SIZE;

    SwooleG.serv = serv;
}

int swServer_create(swServer *serv)
{
    if (SwooleG.main_reactor)
    {
        swError("The swoole_server must create before client");
        return SW_ERR;
    }

    SwooleG.factory = &serv->factory;
    serv->factory.ptr = serv;

#ifdef SW_REACTOR_USE_SESSION
    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (!serv->session_list)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return SW_ERR;
    }
#endif

    return (serv->factory_mode == SW_MODE_SINGLE)?
                swReactorProcess_create(serv):
                swReactorThread_create(serv);
}

int swServer_start(swServer *serv)
{
    if (swServer_start_check(serv) < 0)
    {
        return SW_ERR;
    }

    if (serv->message_queue_key == 0)
    {
        char path_buf[128] = {0};
        char *path_ptr = getcwd(path_buf, 128);
        serv->message_queue_key = ftok(path_ptr, 1);
    }

    //init loggger
    if (SwooleG.log_addr)
    {
        swLog_init(SwooleG.log_addr,SwooleG.log_port);
    }

    //run as daemon
    if (serv->daemonize){
        /**
            * redirect STDOUT to log file
        */
        if (SwooleG.log_fd > STDOUT_FILENO)
        {
            swoole_redirect_stdout(SwooleG.log_fd);
        }
        /**
         * redirect STDOUT_FILENO/STDERR_FILENO to /dev/null
         */
        else
        {
            SwooleG.null_fd = open("/dev/null", O_WRONLY);
            if (SwooleG.null_fd > 0)
            {
                swoole_redirect_stdout(SwooleG.null_fd);
            }
            else
            {
                swSysError("open(/dev/null) failed.");
            }
        }

        if (swoole_daemon(0, 1) < 0)
        {
            return SW_ERR;
        }
    }

    //master pid
    SwooleGS->master_pid = getpid();
    SwooleGS->start = 1;
    SwooleGS->now = SwooleStats->start_time = time(NULL);

    serv->send = (serv->have_udp_sock == 1 && serv->factory_mode != SW_MODE_PROCESS)?
                    swServer_send2:swServer_send1;

    serv->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool, serv->worker_num * sizeof(swWorker));
    if (!serv->workers)
    {
        swFatalError("gmalloc[object->workers] failed");
        return SW_ERR;
    }

    /**
     * Alloc shared memory for worker stats
     */
    SwooleStats->workers = SwooleG.memory_pool->alloc(SwooleG.memory_pool,
            (serv->worker_num + SwooleG.task_worker_num) * sizeof(swWorkerStats));
    if (!SwooleStats->workers) {
        swFatalError("gmalloc[SwooleStats->workers] failed");
        return SW_ERR;
    }

    /**
     * store to swProcessPool object
     */
    SwooleGS->event_workers.workers = serv->workers;
    SwooleGS->event_workers.worker_num = serv->worker_num;
    SwooleGS->event_workers.use_msgqueue = 0;

    int index = 0;
    for (index = 0; index < serv->worker_num; index++)
    {
        SwooleGS->event_workers.workers[index].pool = &SwooleGS->event_workers;
    }

#ifdef SW_USE_RINGBUFFER
    for (index = 0; index < serv->reactor_num; index++)
    {
        serv->reactor_threads[index].buffer_input = swRingBuffer_new(SwooleG.serv->buffer_input_size, 1);
        if (!serv->reactor_threads[index].buffer_input)
        {
            return SW_ERR;
        }
    }
#endif

    /*
     * For swoole_server->taskwait, create notify pipe and result shared memory.
     */
    if (SwooleG.task_worker_num > 0 && serv->worker_num > 0)
    {
        SwooleG.task_result = sw_shm_calloc(serv->worker_num, sizeof(swEventData));
        SwooleG.task_notify = sw_calloc(serv->worker_num, sizeof(swPipe));
        for (index = 0; index < serv->worker_num; index++)
        {
            if (swPipeNotify_auto(&SwooleG.task_notify[index], 1, 0))
            {
                return SW_ERR;
            }
        }
    }

    /**
     * user worker process
     */
    if (serv->user_worker_list)
    {
        swUserWorker_node *user_worker = NULL;
        index = 0;
        LL_FOREACH(serv->user_worker_list, user_worker)
        {
            user_worker->worker->id = serv->worker_num + SwooleG.task_worker_num + (index++);
        }
    }

    //set listen socket options
    swListenPort *ls = NULL;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swPort_set_option(ls) < 0)
        {
            return SW_ERR;
        }
    }

    //factory start
    swFactory *factory = &serv->factory;
    if (!factory || factory->start(factory) < 0)
    {
        return SW_ERR;
    }

    //signal Init
    swServer_signal_init();

    int ret = (serv->factory_mode == SW_MODE_SINGLE)?
                swReactorProcess_start(serv):swReactorThread_start(serv);

    if (ret < 0)
    {
        SwooleGS->start = 0;
    }

    swServer_free(serv);
    return SW_OK;
}

void swServer_reopen_log_file(swServer *serv)
{
    if (!SwooleG.log_addr)
    {
        return;
    }
    /**
     * reopen log file
     */
    close(SwooleG.log_fd);
    swLog_init(SwooleG.log_addr,SwooleG.log_port);
    /**
     * redirect STDOUT & STDERR to log file
     */
    if (serv->daemonize)
    {
        swoole_redirect_stdout(SwooleG.log_fd);
    }
}

swWorker* swServer_get_worker(swServer *serv, uint16_t worker_id)
{
    //Event Worker
    if (worker_id < serv->worker_num)
    {
        return &(SwooleGS->event_workers.workers[worker_id]);
    }

    //Task Worker
    uint16_t task_worker_max = SwooleG.task_worker_num + serv->worker_num;
    if (worker_id < task_worker_max)
    {
        return &(SwooleGS->task_workers.workers[worker_id - serv->worker_num]);
    }

    //User Worker
    uint16_t user_worker_max = task_worker_max + serv->user_worker_num;
    if (worker_id < user_worker_max)
    {
        return serv->user_workers[worker_id - task_worker_max];
    }

    //Unkown worker_id
    swWarn("worker#%d is not exist.", worker_id);
    return NULL;
}

uint32_t swServer_worker_schedule(swServer *serv, uint32_t schedule_key)
{
    uint32_t target_worker_id = 0;

    //polling mode or fd touch access to hash
    if (serv->dispatch_mode == SW_DISPATCH_ROUND || serv->dispatch_mode == SW_DISPATCH_FDMOD)
    {
        target_worker_id = (serv->dispatch_mode == SW_DISPATCH_ROUND )?
                                    sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num:
                                    schedule_key % serv->worker_num;
    }
    //Using the IP touch access to hash
    else if (serv->dispatch_mode == SW_DISPATCH_IPMOD)
    {
        swConnection *conn = swServer_connection_get(serv, schedule_key);
        //UDP or tcp ipv4
        if (!conn || SW_SOCK_TCP == conn->socket_type)
        {
            target_worker_id = (!conn)? schedule_key % serv->worker_num :
                            conn->info.addr.inet_v4.sin_addr.s_addr % serv->worker_num;
        }
        //IPv6
        else
        {
#ifdef HAVE_KQUEUE
            uint32_t ipv6_last_int = *(((uint32_t *) &conn->info.addr.inet_v6.sin6_addr) + 3);
            target_worker_id = ipv6_last_int % serv->worker_num;
#else
            target_worker_id = conn->info.addr.inet_v6.sin6_addr.s6_addr32[3] % serv->worker_num;
#endif
        }
    }
    else if (serv->dispatch_mode == SW_DISPATCH_UIDMOD)
    {
        swConnection *conn = swServer_connection_get(serv, schedule_key);
        target_worker_id = (!conn)? (schedule_key % serv->worker_num):
                            ((conn->uid)? conn->uid % serv->worker_num:schedule_key % serv->worker_num);
    }
    //Preemptive distribution
    else
    {
        int index = 0;
        for (index = 0; index < serv->worker_num + 1; index++)
        {
            target_worker_id = sw_atomic_fetch_add(&serv->worker_round_id, 1) % serv->worker_num;
            if (serv->workers[target_worker_id].status == SW_WORKER_IDLE)
            {
                break;
            }
        }
    }

    /// target worker id 校正
    int index = 0;
    while (serv->workers[target_worker_id].deny_request) {
        target_worker_id = (target_worker_id + 1) % serv->worker_num;
        swDebug("target_work_id increased %d", target_worker_id);
        if (++index > serv->worker_num) {
            target_worker_id = 0;
            swDebug("target_work_id is null %d", target_worker_id);
            break;
        }
    }

    return target_worker_id;
}

int swServer_shutdown(swServer *serv)
{
    //stop all thread
    SwooleG.main_reactor->running = 0;
    return SW_OK;
}

int swServer_free(swServer *serv)
{
    /**
     * shutdown workers
     */
    if (serv->factory.shutdown != NULL)
    {
        serv->factory.shutdown(&(serv->factory));
    }

    /**
     * Shutdown heartbeat thread
     */
    if (SwooleG.heartbeat_pidt)
    {
        pthread_cancel(SwooleG.heartbeat_pidt);
        pthread_join(SwooleG.heartbeat_pidt, NULL);
    }

    if (serv->factory_mode == SW_MODE_SINGLE)
    {
        if (SwooleG.task_worker_num > 0)
        {
            swProcessPool_shutdown(&SwooleGS->task_workers);
        }
    }
    else
    {
        /**
         * Wait until all the end of the thread
         */
        swReactorThread_free(serv);
    }

    swListenPort *port;
    LL_FOREACH(serv->listen_list, port)
    {
        swPort_free(port);
    }
    //reactor free
    if (serv->reactor.free != NULL)
    {
        serv->reactor.free(&(serv->reactor));
    }
    //close log file
    if (SwooleG.log_addr != 0)
    {
        swLog_free();
    }

    if (SwooleG.null_fd > 0)
    {
        close(SwooleG.null_fd);
        SwooleG.null_fd = 0;
    }

    if (SwooleGS->start > 0 && serv->onShutdown != NULL)
    {
        serv->onShutdown(serv);
    }

    swoole_clean();
    return SW_OK;
}

int swServer_udp_send(swServer *serv, swSendData *resp)
{
    struct sockaddr_in addr_in;
    int sock = resp->info.from_fd;

    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons((uint16_t) resp->info.from_id); //from_id is remote port
    addr_in.sin_addr.s_addr = (uint32_t) resp->info.fd; //fd is remote ip address

    int ret = swSocket_sendto_blocking(sock, resp->data, resp->info.len, 0, (struct sockaddr*) &addr_in, sizeof(addr_in));
    if (ret < 0)
    {
        swSysError("sendto to client[%s:%d] failed.", inet_ntoa(addr_in.sin_addr), resp->info.from_id);
    }
    return ret;
}

void swServer_store_pipe_fd(swServer *serv, swPipe *p)
{
    int master_fd = p->getFd(p, SW_PIPE_MASTER);

    serv->connection_list[p->getFd(p, SW_PIPE_WORKER)].object = p;
    serv->connection_list[master_fd].object = p;

    if (master_fd > swServer_get_minfd(serv))
    {
        swServer_set_minfd(serv, master_fd);
    }
}

void swServer_close_listen_port(swServer *serv)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (swSocket_is_stream(ls->type))
        {
            close(ls->sock);
        }
    }
}

swPipe * swServer_get_pipe_object(swServer *serv, int pipe_fd)
{
    return (swPipe *) serv->connection_list[pipe_fd].object;
}

int swServer_tcp_send(swServer *serv, int fd, void *data, uint32_t length)
{
    swSendData _send;
    swFactory *factory = &(serv->factory);
    /**
     * More than the output buffer
     */
    if (length >= serv->buffer_output_size)
    {
        swWarn("More than the output buffer size[%d], please use the sendfile.", serv->buffer_output_size);
        return SW_ERR;
    }
    else
    {
        _send.info.fd = fd;
        _send.info.type = SW_EVENT_TCP;
        _send.data = data;

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
    return SW_OK;
}

int swServer_tcp_deny_request(swServer *serv, long nWorkerId)
{
    swNotice("swServer_tcp_deny_request");
    swEventData ev_data;
    ev_data.info.fd = 0;
    ev_data.info.worker_id = nWorkerId;
    ev_data.info.type = SW_EVENT_DENY_REQUEST;
    //copy data
    memcpy(ev_data.data, "0", 1);

    ev_data.info.len = 1;
    ev_data.info.from_fd = SW_RESPONSE_SMALL;
    ev_data.info.from_id = 0;
    int sendn = ev_data.info.len + sizeof(swDataHead);

    swWorker *worker = swServer_get_worker(serv, nWorkerId);
    int ret = 0;
    if (SwooleG.main_reactor)
    {
        ret = SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_worker, &ev_data, sendn);
    }
    else
    {
        ret = swSocket_write_blocking(worker->pipe_worker, &ev_data, sendn);
    }
    return ret;
}

int swServer_tcp_deny_exit(swServer *serv, long nWorkerId)
{
    swTrace("swServer_tcp_deny_exit");

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

    swWorker *worker = swServer_get_worker(serv, nWorkerId);
    if (!worker){
        return SW_ERR;
    }

    int ret = (SwooleG.main_reactor)?
                SwooleG.main_reactor->write(SwooleG.main_reactor, worker->pipe_worker, &ev_data, sendn):
                swSocket_write_blocking(worker->pipe_worker, &ev_data, sendn);

    return ret;
}

int swServer_tcp_sendfile(swServer *serv, int fd, char *filename, uint32_t len)
{
#ifdef SW_USE_OPENSSL
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (conn && conn->ssl)
    {
        swError("SSL session#%d cannot use sendfile().", fd);
        return SW_ERR;
    }
#endif

    swSendData send_data;
    send_data.info.len = len;
    char buffer[SW_BUFFER_SIZE] = {0};

    //file name size
    if (send_data.info.len > SW_BUFFER_SIZE - 1)
    {
        swWarn("sendfile name too long. [MAX_LENGTH=%d]",(int) SW_BUFFER_SIZE - 1);
        return SW_ERR;
    }

    //check file exists
    if (access(filename, R_OK) < 0)
    {
        swError("file[%s] not found.", filename);
        return SW_ERR;
    }

    send_data.info.fd = fd;
    send_data.info.type = SW_EVENT_SENDFILE;
    memcpy(buffer, filename, send_data.info.len);
    buffer[send_data.info.len] = 0;
    send_data.info.len++;
    send_data.length = 0;
    send_data.data = buffer;

    return serv->factory.finish(&serv->factory, &send_data);
}

int swServer_tcp_sendwait(swServer *serv, int fd, void *data, uint32_t length)
{
    swConnection *conn = swServer_connection_verify(serv, fd);
    if (!conn)
    {
        swNotice("send %d byte failed, because session#%d is closed.", length, fd);
        return SW_ERR;
    }
    return swSocket_write_blocking(conn->fd, data, length);
}

int swServer_add_worker(swServer *serv, swWorker *worker)
{
    swUserWorker_node *user_worker = sw_malloc(sizeof(swUserWorker_node));
    if (!user_worker)
    {
        return SW_ERR;
    }

    serv->user_worker_num++;
    user_worker->worker = worker;

    LL_APPEND(serv->user_worker_list, user_worker);
    if (!serv->user_worker_map)
    {
        serv->user_worker_map = swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, NULL);
    }

    return worker->id;
}

swListenPort* swServer_add_port(swServer *serv, int type, char *host, int port)
{
    if (serv->listen_port_num >= SW_MAX_LISTEN_PORT)
    {
        swWarn("allows up to %d ports to listen", SW_MAX_LISTEN_PORT);
        return NULL;
    }
    if (!(type == SW_SOCK_UNIX_DGRAM || type == SW_SOCK_UNIX_STREAM) && (port < 1 || port > 65535))
    {
        swError("invalid port [%d]", port);
        return NULL;
    }

    swListenPort *ls = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swListenPort));
    if (ls == NULL)
    {
        swFatalError("alloc failed");
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
        if (swSocket_is_stream(type))
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
        swError("create socket failed.");

create_error:
        SwooleG.memory_pool->free(SwooleG.memory_pool,ls);
        return NULL;
    }
    //bind address and port
    if (swSocket_bind(sock, ls->type, ls->host, ls->port) < 0)
    {
        close(sock);
        goto create_error;
    }

    //stream socket, set nonblock
    if (swSocket_is_stream(ls->type))
    {
        swSetNonBlock(sock,1);
    }

    ls->sock = sock;

    if (swSocket_is_dgram(ls->type))
    {
        serv->have_udp_sock = 1;
        serv->dgram_port_num++;
        if (ls->type == SW_SOCK_UDP)
        {
            serv->udp_socket_ipv4 = sock;
        }
        else if (ls->type == SW_SOCK_UDP6)
        {
            serv->udp_socket_ipv6 = sock;
        }
    }
    else
    {
        serv->have_tcp_sock = 1;
    }

    LL_APPEND(serv->listen_list, ls);
    serv->listen_port_num++;
    return ls;
}

int swServer_get_manager_pid(swServer *serv)
{
    if (SW_MODE_PROCESS != serv->factory_mode)
    {
        return SW_ERR;
    }
    return SwooleGS->manager_pid;
}

int swServer_get_socket(swServer *serv, int port)
{
    swListenPort *ls;
    LL_FOREACH(serv->listen_list, ls)
    {
        if (ls->port == port || port == 0)
        {
            return ls->sock;
        }
    }

    return SW_ERR;
}

void swServer_set_callback(swServer *serv, int type, void *callback)
{
    switch(type)
    {
    case SW_SERVER_CALLBACK_onConnect:
        serv->onConnect = callback;
        break;
    case SW_SERVER_CALLBACK_onReceive:
        serv->onReceive = callback;
        break;
    case SW_SERVER_CALLBACK_onClose:
        serv->onClose = callback;
        break;
    default:
        swError("unkown callback type.");
        break;
    }
}

static void swServer_scalar_onConnect_callback(swServer *serv, swDataHead *info)
{
    onConnect_callback(serv, info->fd, info->from_id);
}

static int swServer_scalar_onReceive_callback(swServer *serv, swEventData *req)
{
    return onReceive_callback(serv, req->data, req->info.len, req->info.fd, req->info.from_id);
}

static void swServer_scalar_onClose_callback(swServer *serv, swDataHead *info)
{
    onClose_callback(serv, info->fd, info->from_id);
}

void swServer_set_callback_onConnect(swServer *serv, void (*callback)(swServer *, int, int))
{
    onConnect_callback = callback;
    serv->onConnect = swServer_scalar_onConnect_callback;
}

void swServer_set_callback_onReceive(swServer *serv, int (*callback)(swServer *, char *, int, int, int))
{
    onReceive_callback = callback;
    serv->onReceive = swServer_scalar_onReceive_callback;
}

void swServer_set_callback_onClose(swServer *serv, void (*callback)(swServer *, int, int))
{
    onClose_callback = callback;
    serv->onClose = swServer_scalar_onClose_callback;
}


//---------

swConnection *swWorker_get_connection(swServer *serv, int session_id)
{
    int real_fd = swServer_get_fd(serv, session_id);
    swConnection *conn = swServer_connection_get(serv, real_fd);
    return conn;
}

swString *swWorker_get_buffer(swServer *serv, int worker_id)
{
    //input buffer
    return (serv->factory_mode != SW_MODE_PROCESS)?
           SwooleWG.buffer_input[0]:SwooleWG.buffer_input[worker_id];
}

swConnection *swServer_connection_verify(swServer *serv, int session_id)
{
    swSession *session = swServer_get_session(serv, session_id);
    int fd = session->fd;
    swConnection *conn = swServer_connection_get(serv, fd);
    if (!conn || conn->active == 0)
    {
        return NULL;
    }
    if (session->id != session_id || conn->session_id != session_id)
    {
        return NULL;
    }
#ifdef SW_USE_OPENSSL
    if (conn->ssl && conn->ssl_state != SW_SSL_STATE_READY)
    {
        //swNotice("SSL not ready");
        return NULL;
    }
#endif
    return conn;
}

void swServer_connection_ready(swServer *serv, int fd, int reactor_id)
{
    swDataHead connect_event;
    connect_event.type = SW_EVENT_CONNECT;
    connect_event.from_id = reactor_id;
    connect_event.fd = fd;

    if (serv->factory.notify(&serv->factory, &connect_event) < 0)
    {
        //swWarn("send notification [fd=%d] failed.", fd);
    }
}
