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


#include "swoole.h"
#include "swSignal.h"
#include "swError.h"
#include "swAtomic.h"
#include "swClient.h"
#include "swBaseOperator.h"
#include <sys/resource.h>

void swoole_init(void)
{
    if (SwooleG.running)
    {
        return;
    }

    bzero(&SwooleG, sizeof(SwooleG));
    bzero(&SwooleWG, sizeof(SwooleWG));
    bzero(sw_error, SW_ERROR_MSG_SIZE);

    SwooleG.running = 1;
    SwooleG.error = sw_errno = 0;

    SwooleG.log_fd = STDOUT_FILENO;
    SwooleG.cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    SwooleG.pagesize = getpagesize();
    SwooleG.pid = getpid();
    SwooleG.socket_buffer_size = SW_SOCKET_BUFFER_SIZE;

    //get system uname
    uname(&SwooleG.uname);

#if defined(HAVE_REUSEPORT) && defined(HAVE_EPOLL)
    if (swoole_version_compare(SwooleG.uname.release, "3.9.0") >= 0)
    {
        SwooleG.reuse_port = 1;
    }
#endif

    //random seed
    srandom(time(NULL));

    //init global shared memory, 初始化内存池
    SwooleG.memory_pool = swMemoryGlobal_new(SW_GLOBAL_MEMORY_PAGESIZE, 1);
    if (SwooleG.memory_pool == NULL)
    {
        printf("[Master] Fatal Error: create global memory failed.");
        exit(1);
    }
    SwooleGS = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerGS));
    if (SwooleGS == NULL)
    {
        printf("[Master] Fatal Error: alloc memory for SwooleGS failed.");
        exit(2);
    }

    //init global lock
    if (swMutex_create(&SwooleGS->lock, 1) < 0){
    	exit(3);
    }

    if (swMutex_create(&SwooleGS->log_lock,1) < 0){
    	exit(3);
    }

    /// 获取进程支持的最大文件描述符数
    struct rlimit rlmt;
    SwooleG.max_sockets = (getrlimit(RLIMIT_NOFILE, &rlmt) < 0)? 1024:(uint32_t) rlmt.rlim_cur;

    //init signalfd
#ifdef HAVE_SIGNALFD
    swSignalfd_init();
    SwooleG.use_signalfd = 1;
#endif
    //timerfd
#ifdef HAVE_TIMERFD
    SwooleG.use_timerfd = 1;
#endif

    SwooleG.use_timer_pipe = 1;

    /// 统计信息
    SwooleStats = SwooleG.memory_pool->alloc(SwooleG.memory_pool, sizeof(swServerStats));
    if (SwooleStats == NULL)
    {
        printf("[Master] Fatal Error: alloc memory for SwooleStats failed.");
    }
    else
    {
        swAtomicLock_create(&SwooleStats->lock, 1);
    }

    swoole_update_time();
}

void swoole_clean(void)
{
	if (SwooleG.memory_pool == NULL){
		return ;
	}

    //free the global memory
	SwooleG.memory_pool->destroy(SwooleG.memory_pool);
	SwooleG.memory_pool = NULL;
	if (SwooleG.timer.fd > 0)
	{
		swTimer_free(&SwooleG.timer);
	}

	if (SwooleG.main_reactor)
	{
		SwooleG.main_reactor->free(SwooleG.main_reactor);
	}

	bzero(&SwooleG, sizeof(SwooleG));
}

void swoole_update_time(void)
{
    time_t now = time(NULL);
    if (now < 0)
    {
        swSysError("get time failed.");
    }
    else
    {
        SwooleGS->now = now;
    }
}

double swoole_microtime(void)
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return (double) t.tv_sec + ((double) t.tv_usec / 1000000);
}

void set_log_level(int level)
{
	if (!SwooleGS)
	{
		return ;
	}

	if (level < SW_LOG_DEBUG || level > SW_LOG_FATAL_ERROR)
	{
		return ;
	}

	SwooleGS->log_lock.lock(&SwooleGS->log_lock);
	SwooleGS->log_level = level;
	SwooleGS->log_lock.unlock(&SwooleGS->log_lock);
}

