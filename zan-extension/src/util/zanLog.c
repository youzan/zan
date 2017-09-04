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

#include "zanLog.h"
#include "swWork.h"
#include "swBaseOperator.h"

#define ZAN_LOG_BUFFER_SIZE 1024
#define ZAN_LOG_DATE_STRLEN  64

char zan_log_buffer[ZAN_MSG_SIZE] = {0};

void zanLog_init(char *logfile,int port)
{
    if (!logfile)
    {
        return;
    }

#ifdef SW_DEBUG_REMOTE_OPEN
    swClient log_client;
    swClient_create(&log_client, SW_SOCK_UDP, 0);

    if (log_client.connect(&log_client, logfile, port, -1, 1) < 0)
    {
        SwooleG.log_fd = STDOUT_FILENO;
        printf("connect to remote log server[%s:%d] failed.", logfile, port);
    }
    else
    {
        SwooleG.log_fd = log_client.socket->fd;
    }
#else
    SwooleG.log_fd = open(logfile, O_APPEND| O_RDWR | O_CREAT, 0666);
#endif
    if (SwooleG.log_fd < 0)
    {
        printf("open(%s) failed. Error: %s[%d]", logfile, strerror(errno), errno);
    }
}

void zanLog_free(void)
{
    if (SwooleG.log_fd > STDOUT_FILENO)
    {
        close(SwooleG.log_fd);
        SwooleG.log_fd = 0;
    }

    sw_free(SwooleG.log_addr);
}

void zanLog_put(int level, char *cnt)
{
    const char *level_str = NULL;
    char date_str[ZAN_LOG_DATE_STRLEN] = {0};
    char log_str[ZAN_LOG_BUFFER_SIZE] = {0};

    switch (level)
    {
    case ZAN_LOG_DEBUG:
        level_str = "DEBUG";
        break;
    case ZAN_LOG_TRACE:
        level_str = "TRACE";
        break;
    case ZAN_LOG_WARNING:
        level_str = "WARNING";
        break;
    case ZAN_LOG_ERROR:
        level_str = "ERROR";
        break;
    case ZAN_LOG_FATAL_ERROR:
        level_str = "FATAL";
        break;
    default:
        level_str = "INFO";
        break;
    }

    time_t t = time(NULL);
    struct tm *p = localtime(&t);
    snprintf(date_str, ZAN_LOG_DATE_STRLEN, "%d-%02d-%02d %02d:%02d:%02d",
            p->tm_year + 1900, p->tm_mon + 1, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);

    char process_flag = '@';
    int process_id = 0;

    switch(SwooleG.process_type)
    {
    case SW_PROCESS_MASTER:        ///TODO:::
        process_flag = '#';
        process_id = SwooleTG.id;
        break;
    case SW_PROCESS_MANAGER:
        process_flag = '$';
        break;
    case SW_PROCESS_WORKER:
        process_flag = '*';
        process_id = SwooleWG.id;
        break;
    case SW_PROCESS_TASKWORKER:
        process_flag = '^';
        process_id = SwooleWG.id;
        break;
    default:
        break;
    }

    int n = snprintf(log_str, ZAN_LOG_BUFFER_SIZE,
            "[%s %c%d.%d]\t%s\t%s\n", date_str, process_flag, SwooleG.pid, process_id, level_str, cnt);
    if (write(SwooleG.log_fd, log_str, n) < 0)
    {
        return;
    }
}
