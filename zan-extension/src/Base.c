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

#ifdef PHP_WIN32
#else
#include <sys/resource.h>
#endif
#include "swSignal.h"
#include "zanGlobalVar.h"
#include "zanLog.h"
#include "zanSystem.h"

void zan_init(void)
{
    if (ServerG.running)
    {
        printf("ServerG is running, can't init");
        return;
    }

    bzero(&ServerG, sizeof(zanServerG));
    bzero(&ServerWG, sizeof(zanWorkerG));
    bzero(&ZanAIO, sizeof(zanAsyncIO));

    //init global shared memory, 初始化内存池
    ServerG.g_shm_pool = zanShmGlobal_new(ZAN_GLOBAL_MEMORY_PAGESIZE, 1);
    if (NULL == ServerG.g_shm_pool)
    {
        printf("[Master] Fatal Error: create global shm memory failed.");
        exit(1);
    }

    ServerGS = ServerG.g_shm_pool->alloc(ServerG.g_shm_pool, sizeof(zanServerGS));
    if (NULL == ServerGS)
    {
        printf("[Master] Fatal Error: alloc memory for ServerGS failed.");
        exit(2);
    }

    //init global lock
    if (ZAN_OK != zanLock_create(&ServerGS->lock, ZAN_MUTEX, 1))
    {
        printf("[Master] Fatal Error: zanLock_create ServerGS->lock failed.");
        exit(3);
    }

    if (ZAN_OK !=  zanLock_create(&ServerGS->log_lock, ZAN_MUTEX, 1))
    {
        printf("[Master] Fatal Error: zanLock_create ServerGS->log_lock failed.");
        exit(3);
    }

    if (ZAN_OK !=  zanLock_create(&ServerGS->accept_lock, ZAN_MUTEX, 1))
    {
        printf("[Master] Fatal Error: zanLock_create ServerGS->accept_lock failed.");
        exit(3);
    }

    /// 统计信息
    ServerStatsG = ServerG.g_shm_pool->alloc(ServerG.g_shm_pool, sizeof(zanServerStats));
    if (NULL == ServerStatsG)
    {
        exit(2);
        printf("[Master] Fatal Error: alloc memory for SwooleStats failed.");
    }

    if (ZAN_OK != zanLock_create(&ServerStatsG->lock, ZAN_ATOMLOCK, 1))
    {
        printf("[Master] Fatal Error: zanLock_create  ServerStats->lock failed.");
        exit(3);
    }

    ServerG.factory_mode    = ZAN_MODE_PROCESS;
    ServerG.running         = 1;
    ServerG.log_fd          = STDOUT_FILENO;
    ServerG.cpu_num         = zan_get_cpu_num();
    ServerG.pagesize        = zan_get_pagesize();
    ServerG.process_pid     = getpid();

#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    ServerG.use_signalfd = 1;
    ServerG.enable_signalfd = 1;
#endif

#ifdef HAVE_TIMERFD
    ServerG.use_timerfd = 1;
#endif
    ServerG.use_timer_pipe = 1;

#ifndef PHP_WIN32
    uname(&ServerG.uname);
#endif

#ifdef PHP_WIN32
    // todo
    ServerG.max_sockets = 512;
#else
    struct rlimit rlmt;
    ServerG.max_sockets = (getrlimit(RLIMIT_NOFILE, &rlmt) < 0) ?
                          1024:(int) rlmt.rlim_cur;
#endif

#ifdef __MACH__
    ServerG.servSet.socket_buffer_size = 256 * 1024;
#else
    ServerG.servSet.socket_buffer_size = SW_SOCKET_BUFFER_SIZE;
#endif

#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL) && !defined(PHP_WIN32)
    if (swoole_version_compare(ServerG.uname.release, "3.9.0") >= 0)
    {
        ServerG.reuse_port = 1;
    }
#endif

    zan_update_time();
    zan_set_loglevel(ZAN_LOG_WARNING);
}

void zan_clean(void)
{
    if (NULL != ServerG.g_shm_pool){
        //free the global shm memory
        ServerG.g_shm_pool->destroy(ServerG.g_shm_pool);
        ServerG.g_shm_pool = NULL;
    }

    if (ServerG.timer.fd > 0)
    {
        swTimer_free(&ServerG.timer);
    }

    if (ServerG.main_reactor)
    {
        ServerG.main_reactor->free(ServerG.main_reactor);
    }

    bzero(&ServerG, sizeof(zanServerG));
}

void zan_update_time(void)
{
    time_t now = time(NULL);
    if (now < 0)
    {
        zanError("get time failed, errno=%d:%s", errno, strerror(errno));
    }
    else
    {
        ServerGS->server_time = now;
    }
}

double get_microtime(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double) t.tv_sec + ((double) t.tv_usec / 1000000);
}

void zan_set_loglevel(uint8_t level)
{
    if (!ServerGS)
    {
        printf("set_log_level, ServerGS is null");
        return ;
    }

    if (level < ZAN_LOG_DEBUG || level > ZAN_LOG_FATAL_ERROR)
    {
        printf("set_log_level, log_level=%d", level);
        return ;
    }
    ServerGS->log_level = level;
}

