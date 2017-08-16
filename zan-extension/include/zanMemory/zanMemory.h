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

#ifndef _ZAN_MEMORY_H_
#define _ZAN_MEMORY_H_

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

void* malloc_debug(const char* file,int line,const char* func,int __size);
void free_debug(const char* file,int line,const char* func,void* ptr);

#ifdef ZAN_MALLOC_DEBUG
#define zan_malloc(__size)      malloc_debug(__FILE__, __LINE__,__func__,__size)
#define zan_free(ptr)           if(ptr){free_debug(__FILE__, __LINE__,__func__,ptr);ptr=NULL;}
#else
#define zan_malloc              malloc
#define zan_free(ptr)           if(ptr){free(ptr);ptr=NULL;}
#endif

#define zan_calloc              calloc
#define zan_realloc             realloc

#ifdef __cplusplus
}
#endif

#endif //_ZAN_MEMORY_H_
