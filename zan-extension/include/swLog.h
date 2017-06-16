/*
  +----------------------------------------------------------------------+
  | Zan                                                                  |
  +----------------------------------------------------------------------+
  | Copyright (c) 2016-2017 Zan Group                                    |
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
#ifndef _SW_SWLOG_H_
#define _SW_SWLOG_H_

#include "swoole.h"
#include "swGlobalVars.h"

#ifdef __cplusplus
extern "C" {
#endif

void swPrintf_dump_bin(char *data, char type, int size);
void swPrintf_dump_hex(char *data, int outlen);
void swPrintf_dump_ascii(char *data, int size);

#define SW_ERROR_MSG_SIZE      512
extern int16_t sw_errno;
extern char sw_error[SW_ERROR_MSG_SIZE];

int swLog_init(char *logfile);
void swLog_put(int level, char *cnt);
void swLog_free(void);
#define sw_log(str,...)       {snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
							    swLog_put(SW_LOG_INFO, sw_error);}


#define swWarn(str,...)        SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARNING, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock)

#define swInfo(str,...)        SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_INFO, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock)


#define swNotice(str,...)        SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
swLog_put(SW_LOG_NOTICE, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock)

#define swError(str,...)       SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, str, ##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);\
exit(1)

#define swSysError(str,...) SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s(:%d): "str" Error: %s[%d].",__func__,__LINE__,##__VA_ARGS__,strerror(errno),errno);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock)

#define swoole_error_log(level, errno, str, ...)      do{SwooleG.error=errno;\
    if (level >= SwooleG.log_level){\
    snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s (ERROR %d): "str,__func__,errno,##__VA_ARGS__);\
    SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
    swLog_put( SW_LOG_ERROR, sw_error);\
    SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#ifdef SW_DEBUG_REMOTE_OPEN
#define swDebug(str,...) int __debug_log_n = snprintf(sw_error,SW_ERROR_MSG_SIZE,str,##__VA_ARGS__);\
write(SwooleG.debug_fd, sw_error, __debug_log_n);
#else
#define swDebug(str,...)
#endif

#ifdef SW_DEBUG
#define swTrace(str,...)       {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
//#define swWarn(str,...)        {printf("[%s:%d@%s]"str"\n",__FILE__,__LINE__,__func__,##__VA_ARGS__);}
#else
#define swTrace(str,...)
//#define swWarn(str,...)        {printf(sw_error);}
#endif

enum swLog_level
{
    SW_LOG_DEBUG = 0,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARNING,
    SW_LOG_ERROR,

};

enum swTraceType
{
    SW_TRACE_SERVER  = 1,
    SW_TRACE_CLIENT  = 2,
    SW_TRACE_BUFFER  = 3,
    SW_TRACE_CONN    = 4,
    SW_TRACE_EVENT   = 5,
    SW_TRACE_WORKER,
    SW_TRACE_MEMORY,
    SW_TRACE_REACTOR,
    SW_TRACE_PHP,
    SW_TRACE_HTTP2,
};

#if SW_LOG_TRACE_OPEN == 1
#define swTraceLog(id,str,...)      SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock)
#elif SW_LOG_TRACE_OPEN == 0
#define swTraceLog(id,str,...)
#else
#define swTraceLog(id,str,...)      if (id==SW_LOG_TRACE_OPEN) {SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}
#endif


#ifdef __cplusplus
}
#endif

#endif
