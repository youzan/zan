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
#ifndef _SW_SWLOG_H_
#define _SW_SWLOG_H_

#include "swoole.h"
#include "swGlobalVars.h"

#ifdef __cplusplus
extern "C" {
#endif

enum swLog_level
{
	SW_LOG_LEVEL_UNKNOW = 0,
    SW_LOG_DEBUG = 1,
    SW_LOG_TRACE,
    SW_LOG_INFO,
    SW_LOG_NOTICE,
    SW_LOG_WARNING,
    SW_LOG_ERROR,
	SW_LOG_FATAL_ERROR,
};

#define SW_ERROR_MSG_SIZE      512
extern int16_t sw_errno;
extern char sw_error[SW_ERROR_MSG_SIZE];

void swPrintf_dump_bin(char *data, char type, int size);
void swPrintf_dump_hex(char *data, int outlen);
void swPrintf_dump_ascii(char *data, int size);

int swLog_init(char *logfile,int port);
void swLog_put(int level, char *cnt);
void swLog_free(void);

#define swDebug(str,...)		  do {if (SwooleGS && SwooleGS->log_level <= SW_LOG_DEBUG)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_DEBUG, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swTrace(str,...)		do {if (SwooleGS && SwooleGS->log_level <= SW_LOG_TRACE)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_TRACE, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swInfo(str,...)        do{ if(SwooleGS && SwooleGS->log_level <= SW_LOG_INFO)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_INFO, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swNotice(str,...)       do{ if(SwooleGS && SwooleGS->log_level <= SW_LOG_NOTICE)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_NOTICE, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swWarn(str,...)        do { if (SwooleGS && SwooleGS->log_level <= SW_LOG_WARNING) {\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_WARNING, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swError(str,...)       do{ if(SwooleGS && SwooleGS->log_level <= SW_LOG_ERROR)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE,"%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swSysError(str,...)    do{ if(SwooleGS && SwooleGS->log_level <= SW_LOG_ERROR)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error,SW_ERROR_MSG_SIZE,"%s: "str" Error: %s[%d].",__func__,##__VA_ARGS__,strerror(errno),errno);\
swLog_put(SW_LOG_ERROR, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);}}while(0)

#define swFatalError(str,...)	do{ if(SwooleGS && SwooleGS->log_level <= SW_LOG_FATAL_ERROR)	{\
SwooleGS->log_lock.lock(&SwooleGS->log_lock);\
snprintf(sw_error, SW_ERROR_MSG_SIZE, "%s: "str,__func__,##__VA_ARGS__);\
swLog_put(SW_LOG_FATAL_ERROR, sw_error);\
SwooleGS->log_lock.unlock(&SwooleGS->log_lock);exit(1);}}while(0)

#ifdef __cplusplus
}
#endif

#endif
