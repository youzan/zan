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
  | Author: Zan Group   <zan@zanphp.io>                                  |
  +----------------------------------------------------------------------+
*/

#ifndef _ZAN_ZANLOG_H_
#define _ZAN_ZANLOG_H_

#include "swoole.h"
#include "zanGlobalVar.h"

#ifdef __cplusplus
extern "C" {
#endif

enum zanLog_level
{
    ZAN_LOG_LEVEL_UNKNOW = 0,
    ZAN_LOG_DEBUG = 1,
    ZAN_LOG_TRACE,
    ZAN_LOG_INFO,
    ZAN_LOG_NOTICE,
    ZAN_LOG_WARNING,
    ZAN_LOG_ERROR,
    ZAN_LOG_FATAL_ERROR,
};
#ifndef PHP_WIN32
#define ZAN_MSG_SIZE      512
extern char zan_log_buffer[ZAN_MSG_SIZE];
extern void zanLog_put(int level, char *cnt);
void zanLog_init(char *logfile,int port);


#define zanDebug(str,...)          do {if (ServerGS && ServerGS->log_level <= ZAN_LOG_DEBUG)  {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer,ZAN_MSG_SIZE,"%s(:%d): "str,__func__,__LINE__,##__VA_ARGS__);\
zanLog_put(ZAN_LOG_DEBUG, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);}}while(0)

#define zanTrace(str,...)        do {if (ServerGS && ServerGS->log_level <= ZAN_LOG_TRACE)    {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer,ZAN_MSG_SIZE,"%s(:%d): "str,__func__,__LINE__,##__VA_ARGS__);\
zanLog_put(ZAN_LOG_TRACE, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);}}while(0)

#define zanWarn(str,...)        do { if (ServerGS && ServerGS->log_level <= ZAN_LOG_WARNING) {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer,ZAN_MSG_SIZE,"%s(:%d): "str,__func__,__LINE__,##__VA_ARGS__);\
zanLog_put(ZAN_LOG_WARNING, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);}}while(0)

#define zanError(str,...)       do{ if(ServerGS && ServerGS->log_level <= ZAN_LOG_ERROR)  {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer, ZAN_MSG_SIZE,"%s(:%d): "str,__func__,__LINE__,##__VA_ARGS__);\
zanLog_put(ZAN_LOG_ERROR, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);}}while(0)

#define zanSysError(str,...)    do{ if(ServerGS && ServerGS->log_level <= ZAN_LOG_ERROR)  {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer,ZAN_MSG_SIZE,"%s(:%d): "str" Error: %s[%d].",__func__,__LINE__,##__VA_ARGS__,strerror(errno),errno);\
zanLog_put(ZAN_LOG_ERROR, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);}}while(0)

#define zanFatalError(str,...)   do{ if(ServerGS && ServerGS->log_level <= ZAN_LOG_FATAL_ERROR)   {\
ServerGS->log_lock.lock(&ServerGS->log_lock);\
snprintf(zan_log_buffer, ZAN_MSG_SIZE, "%s(:%d): "str,__func__,__LINE__,##__VA_ARGS__);\
zanLog_put(ZAN_LOG_FATAL_ERROR, zan_log_buffer);\
ServerGS->log_lock.unlock(&ServerGS->log_lock);exit(1);}}while(0)

#endif
#ifdef __cplusplus
}
#endif

#endif
