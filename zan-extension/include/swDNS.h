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
#ifndef _SW_DNS_H_
#define _SW_DNS_H_

#include "swoole.h"
#include "swBaseData.h"

#ifdef __cplusplus
extern "C"
{
#endif

enum swDNSLookup_cache_type
{
    SW_DNS_LOOKUP_CACHE_ONLY =  (1u << 10),
    SW_DNS_LOOKUP_RANDOM  = (1u << 11),
    SW_DNS_LOOKUP_NOCACHE = (1u << 12)
};

typedef struct
{
    int number;
    int host_length;
    union
    {
        char host[SW_IP_MAX_LENGTH];
    } addr[SW_DNS_LOOKUP_CACHE_SIZE];
} swDNS_cache;

typedef struct
{
    void (*callback)(void *addrs);
    void *object;
    char *domain;
} swDNS_request;

int swoole_gethostbyReactor(swDNS_request *request);
int swoole_gethostbyname(int flags, char *name, char *addr);
void swoole_clear_dns_cache(void);
int swoole_getHostbyAIO(int flags,void *hostname, void *ip_addr, size_t size);
void dns_lookup_init();


#ifdef __cplusplus
}
#endif


#endif
