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
static int zan_server_send1(zanServer *, swSendData *);
static int zan_daemonize(void);

/* initializing server config*/
void zanServer_init(zanServer *serv)
{
    bzero(serv, sizeof(zanServer));

    //init serv, TODO:::
    serv->http_parse_post = 1;

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

    //init ServerG.serverSet
    zan_init_serv_set();

    ServerG.serv = serv;
}

//init server:set
void zan_init_serv_set(void)
{
    zanServerSet *servSet = &ServerG.serverSet;

    servSet->reactor_num        = ZAN_REACTOR_NUM;
    servSet->worker_num         = ZAN_CPU_NUM;
    servSet->dispatch_mode      = SW_DISPATCH_FDMOD;
    servSet->max_connection     = SwooleG.max_sockets;

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
}

//TODO::: zanServer 参数待确定
int zanServer_create(zanServer *serv)
{
    ServerG.factory   = &serv->factory;
    serv->factory.ptr = serv;

    serv->session_list = sw_shm_calloc(SW_SESSION_LIST_SIZE, sizeof(swSession));
    if (!serv->session_list)
    {
        swError("sw_shm_calloc(%ld) for session_list failed", SW_SESSION_LIST_SIZE * sizeof(swSession));
        return ZAN_ERR;
    }

    serv->connection_list = sw_shm_calloc(ServerG.serverSet.max_connection, sizeof(swConnection));
    if (!serv->connection_list)
    {
        swError("sw_shm_calloc(%ld) failed for connection_list", ServerG.serverSet.max_connection * sizeof(swConnection));
        return ZAN_ERR;
    }

    //create factry object
    int ret = zanFactory_create(&(serv->factory));
    if (ZAN_OK != ret)
    {
        swError("create factory failed");
    }

    return ret;
}

int zanServer_start(zanServer *serv)
{
    if (zan_server_start_check(serv) < 0)
    {
        return ZAN_ERR;
    }

    zanLog_init(ServerG.serverSet.log_file, 0);

    if (ZAN_OK != zan_daemonize())
    {
        zanError("zan_daemonize error.");
        return ZAN_ERR;
    }

    //ServerGS
    ServerGS->master_pid     = zan_getpid();
    ServerGS->started        = 1;
    ServerGS->now            = time(NULL);
    ServerStatsG->start_time = ServerGS->now;

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
    zanFactory *factory = &serv->factory;
    if (!factory || factory->start(factory) < 0)
    {
        zanError("factory start failed");
        return ZAN_ERR;
    }

    //master process signal, TODO:::
    //

    //master process
    ServerG.process_pid  = ServerGS->master_pid;
    ServerG.process_type = ZAN_PROCESS_MASTER;

    int ret = zanMaster_loop(serv);

    ///TODO:::
    exit(ret);
    ///swServer_free(serv);

    return SW_OK;
}

//run as daemon
int zan_daemonize(void)
{
    if (!ServerG.serverSet.daemonize)
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

static int zan_server_send(zanServer *serv, swSendData *resp)
{
    return ZAN_OK;
}
