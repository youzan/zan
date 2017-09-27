/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
 +----------------------------------------------------------------------+
 | This source file is subject to version 2.0 of the Apache license,    |
 | that is bundled with this package in the file LICENSE, and is        |
 | available through the world-wide-web at the following url:           |
 | http://www.apache.org/licenses/LICENSE-2.0.html                      |
 | If you did not receive a copy of the Apache2.0 license and are unable|
 | to obtain it through the world-wide-web, please send a note to       |
 | license@swoole.com so we can mail you a copy immediately.            |
 +----------------------------------------------------------------------+
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 +----------------------------------------------------------------------+
 */

#include "swDNS.h"
#include "swClient.h"
#include "swReactor.h"

//#include "swAsyncIO.h"
//#include "swGlobalVars.h"
//#include "swLog.h"

#include "zanAsyncIo.h"
#include "zanLog.h"

#define SW_DNS_SERVER_CONF   "/etc/resolv.conf"
#define SW_DNS_SERVER_NUM    2
#define SW_DNS_SERVER_PORT   53

static swHashMap *swoole_dns_cache_v4 = NULL;
static swHashMap *swoole_dns_cache_v6 = NULL;
static swLock    *dns_cache_v4_lock = NULL;
static swLock    *dns_cache_v6_lock = NULL;
static int       dns_inited = 0;

enum swDNS_type
{
    SW_DNS_A_RECORD = 0x01, //Lookup IP address
    SW_DNS_AAAA_RECORD = 0x1c, //Lookup IPv6 address
    SW_DNS_MX_RECORD = 0x0f //Lookup mail server for domain
};

enum swDNS_error
{
    SW_DNS_NOT_EXIST, //Error: adress does not exist
    SW_DNS_TIMEOUT, //Lookup time expired
    SW_DNS_ERROR //No memory or other error
};

typedef struct
{
    int id;
    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } ipaddr;
} swDNS_server;

/* Struct for the DNS Header */
typedef struct
{
    uint16_t id;
    uchar rd :1;
    uchar tc :1;
    uchar aa :1;
    uchar opcode :4;
    uchar qr :1;
    uchar rcode :4;
    uchar z :3;
    uchar ra :1;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} swDNSResolver_header;

/* Struct for the flags for the DNS Question */
typedef struct q_flags
{
    uint16_t qtype;
    uint16_t qclass;
} swDNSQ_FLAGS;

/* Struct for the flags for the DNS RRs */
typedef struct rr_flags
{
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
} swDNSRR_FLAGS;

static int swoole_dns_server_num = 0;
static int swoole_dns_request_id = 1;
static void* swoole_dns_request_ptr[1024] = {0};
static swDNS_server swoole_dns_servers[SW_DNS_SERVER_NUM];

static void swDNSResolver_domain_encode(char *src, char *dest);
static void swDNSResolver_domain_decode(char *str);
static int swDNSResolver_get_servers(swDNS_server *dns_server);
static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event);
//static int get_host_by_syscall(int af,char* name,swDNS_cache* cache);

static int swDNSResolver_get_servers(swDNS_server *dns_server)
{
    FILE *fp = NULL;
    char line[100] = {0};
    swoole_dns_server_num = 0;

    if ((fp = fopen(SW_DNS_SERVER_CONF, "rt")) == NULL)
    {
        zanError("fopen("SW_DNS_SERVER_CONF") failed.");
        return ZAN_ERR;
    }

    while (fgets(line, 100, fp))
    {
        if (strncmp(line, "nameserver", 10) == 0)
        {
            strcpy(dns_server[swoole_dns_server_num].ipaddr.v4, strtok(line, " "));
            strcpy(dns_server[swoole_dns_server_num].ipaddr.v4, strtok(NULL, "\n"));
            swoole_dns_server_num++;
        }
        if (swoole_dns_server_num >= SW_DNS_SERVER_NUM)
        {
            break;
        }
    }

    fclose(fp);

    if (swoole_dns_server_num == 0)
    {
        return ZAN_ERR;
    }

    return ZAN_OK;
}

static int swDNSResolver_onReceive(swReactor *reactor, swEvent *event)
{
    swDNSResolver_header *header = NULL;
    swClient *cli = NULL;
    //swDNSQ_FLAGS *qflags = NULL;
    swDNSRR_FLAGS *rrflags = NULL;

    char packet[SW_BUFFER_SIZE_UDP] = {0};
    char rdata[10][254];
    uint32_t type[10] = {0};

    char *temp = NULL;
    uint16_t steps = 0;

    char *_domain_name = NULL;
    char name[10][254];
    int index = 0, j;

    if (recv(event->fd, packet, 65536, 0) <= 0)
    {
        return ZAN_ERR;
    }

    header = (swDNSResolver_header *) &packet[steps];
    steps = sizeof(swDNSResolver_header);
    int requestID = ntohs(header->id);
    cli = swoole_dns_request_ptr[requestID%1024];
    if (!cli){
        return ZAN_ERR;
    }

    _domain_name = &packet[steps];
    swDNSResolver_domain_decode(_domain_name);
    steps = steps + (strlen(_domain_name) + 2);

    //qflags = (swDNSQ_FLAGS *) &packet[steps];
    steps = steps + sizeof(swDNSQ_FLAGS);

    //printf("ancount=%d, nscount=%d, qdcount=%d, arcount=%d\n", ntohs(header->ancount), ntohs(header->nscount), ntohs(header->qdcount), ntohs(header->arcount));

    /* Parsing the RRs from the reply packet */
    int anCount = ntohs(header->ancount);
    for (index = 0; index < anCount; ++index)
    {
        /* Parsing the NAME portion of the RR */
        temp = &packet[steps];
        j = 0;
        while (*temp != 0)
        {
            if ((uchar) (*temp) == 0xc0)
            {
                ++temp;
                temp = &packet[(int)(*temp)];
            }
            else
            {
                name[index][j] = *temp;
                ++j;
                ++temp;
            }
        }

        name[index][j] = '\0';

        swDNSResolver_domain_decode(name[index]);
        steps = steps + 2;

        /* Parsing the RR flags of the RR */
        rrflags = (swDNSRR_FLAGS *) &packet[steps];
        steps = steps + sizeof(swDNSRR_FLAGS) - 2;

        /* Parsing the IPv4 address in the RR */
        if (ntohs(rrflags->type) == 1)
        {
            int rdLength = ntohs(rrflags->rdlength);
            for (j = 0; j < rdLength; ++j)
                rdata[index][j] = (uchar) packet[steps + j];
            type[index] = ntohs(rrflags->type);
        }

        /* Parsing the canonical name in the RR */
        if (ntohs(rrflags->type) == 5)
        {
            temp = &packet[steps];
            j = 0;
            while (*temp != 0)
            {
                if ((uchar)(*temp) == 0xc0)
                {
                    ++temp;
                    temp = &packet[(int)(*temp)];
                }
                else
                {
                    rdata[index][j] = *temp;
                    ++j;
                    ++temp;
                }
            }

            rdata[index][j] = '\0';
            swDNSResolver_domain_decode(rdata[index]);
            type[index] = ntohs(rrflags->type);
        }
        steps = steps + ntohs(rrflags->rdlength);
    }

    /* Printing the output */
    printf("QNAME: %s\n", _domain_name);
    printf("ANCOUNT: %d\n", ntohs(header->ancount));
    printf("\nRDATA:");

    for (index = 0; index < anCount; ++index)
    {
        printf("\nNAME: %s\n\t", name[index]);
        if (type[index] == 5)
            printf("CNAME: %s", rdata[index]);
        else if (type[index] == 1)
        {
            printf("IPv4: ");
            for (j = 0; j < ntohs(rrflags->rdlength); ++j)
                printf("%d.", rdata[index][j]);
            printf("\b ");
        }
    }
    putchar('\n');

    ((swDNS_request*)(cli->ptr))->callback(NULL);
    return ZAN_OK;
}

int swDNSResolver_request(swDNS_request *request)
{
    char *_domain_name = NULL;
    swDNSQ_FLAGS *qflags = NULL;
    char packet[SW_BUFFER_SIZE_UDP] = {0};
    swDNSResolver_header *header = NULL;
    int steps = 0;

    if (swoole_dns_server_num == 0)
    {
        if (swDNSResolver_get_servers(swoole_dns_servers) < 0)
        {
            return ZAN_ERR;
        }

        ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_DNS_RESOLVER, swDNSResolver_onReceive);
    }

//    header = (swDNSResolver_header *) &packet;
    header = (swDNSResolver_header*)&packet[steps];
    header->id = (uint16_t) htons(swoole_dns_request_id);
    header->qr = 0;
    header->opcode = 0;
    header->aa = 0;
    header->tc = 0;
    header->rd = 1;
    header->ra = 0;
    header->z = 0;
    header->rcode = 0;
    header->qdcount = htons(1);
    header->ancount = 0x0000;
    header->nscount = 0x0000;
    header->arcount = 0x0000;

    steps = sizeof(swDNSResolver_header);

    _domain_name = &packet[steps];
    swDNSResolver_domain_encode(request->domain, _domain_name);

    steps += (strlen((const char *) _domain_name) + 1);

    qflags = (swDNSQ_FLAGS *) &packet[steps];
    qflags->qtype = htons(SW_DNS_A_RECORD);
    qflags->qclass = htons(0x0001);
    steps += sizeof(swDNSQ_FLAGS);

    swClient *cli = sw_malloc(sizeof(swClient));
    if (cli == NULL)
    {
        zanWarn("malloc failed.");
        return ZAN_ERR;
    }

    if (swClient_create(cli, SW_SOCK_UDP, 0) < 0)
    {
        sw_free(cli);
        return ZAN_ERR;
    }

    if (cli->connect(cli, swoole_dns_servers[0].ipaddr.v4, SW_DNS_SERVER_PORT, 1, 0) < 0)
    {
        cli->close(cli);
        sw_free(cli);
        return ZAN_ERR;
    }

    if (cli->send(cli, (char *) packet, steps, 0) < 0)
    {
        cli->close(cli);
        sw_free(cli);
        return ZAN_ERR;
    }

    if (ServerG.main_reactor->add(ServerG.main_reactor, cli->socket->fd, SW_FD_DNS_RESOLVER))
    {
        cli->close(cli);
        sw_free(cli);
        return ZAN_ERR;
    }

    cli->ptr = request;
    /// 不安全
    swoole_dns_request_ptr[(swoole_dns_request_id++)%1024] = cli;
    return ZAN_OK;
}

/**
 * The function converts the dot-based hostname into the DNS format
 * (i.e. www.apple.com into 3www5apple3com0)
 */
static void swDNSResolver_domain_encode(char *src, char *dest)
{
    int pos = 0;
    int len = 0;
    int n = strlen(src);
    int index = 0;
    strcat(src, ".");

    for (index = 0; index < n; ++index)
    {
        if (src[index] == '.')
        {
            dest[pos] = index - len;
            ++pos;
            for (; len < index; ++len)
            {
                dest[pos] = src[len];
                ++pos;
            }
            len++;
        }
    }
    dest[pos] = '\0';
}

/**
 * This function converts a DNS-based hostname into dot-based format
 * (i.e. 3www5apple3com0 into www.apple.com)
 */
static void swDNSResolver_domain_decode(char *str)
{
    int index = 0, j = 0;
    uint32_t strLen = strlen((const char*) str);
    for (index = 0; index < strLen; ++index)
    {
        unsigned int len = str[index];
        for (j = 0; j < len; ++j)
        {
            str[index] = str[index + 1];
            ++index;
        }
        str[index] = '.';
    }

    str[index - 1] = '\0';
}

#if 0
/// get host by system call
int swoole_gethostbyname(int flags, char *name, int name_length, char *addr,uint32_t addrLen)
{
    if (name_length <= 0){
        return ZAN_ERR;
    }

    int __af = flags & (~SW_DNS_LOOKUP_CACHE_ONLY) & (~SW_DNS_LOOKUP_RANDOM) & (~SW_DNS_LOOKUP_NOCACHE);

    swHashMap *cache_table = NULL;
    swLock    *cache_lock = NULL;
    swDNS_cache *cache = NULL;
    int disable_cache = (flags & SW_DNS_LOOKUP_NOCACHE);
    if (!disable_cache)
    {
        if (__af == AF_INET)
        {
            cache_lock = dns_cache_v4_lock;
            cache_lock->lock(cache_lock);
            cache_table = (!swoole_dns_cache_v4)? (swoole_dns_cache_v4 =
                                            swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, free)):swoole_dns_cache_v4;
        }
        else if (__af == AF_INET6)
        {
            cache_lock = dns_cache_v6_lock;
            cache_lock->lock(cache_lock);
            cache_table = (!swoole_dns_cache_v6)? (swoole_dns_cache_v6 =
                                    swHashMap_create(SW_HASHMAP_INIT_BUCKET_N, free)):swoole_dns_cache_v6;
        }
        else
        {
            return ZAN_ERR;
        }

        cache = swHashMap_find(cache_table, name, name_length);
        if (!cache && (flags & SW_DNS_LOOKUP_CACHE_ONLY))
        {
            cache_lock->unlock(cache_lock);
            return ZAN_ERR;
        }

        cache_lock->unlock(cache_lock);
    }

    swDNS_cache tmp_info;
    swDNS_cache* tmp_cache = cache;
    memset(&tmp_info,0x00,sizeof(swDNS_cache));
    int cacheisNull = (cache == NULL)? 1:0;
    if (cacheisNull)
    {
        if (get_host_by_syscall(__af,name,&tmp_info) < 0)
        {
            return ZAN_ERR;
        }

        tmp_cache = &tmp_info;
        if (!disable_cache)
        {
            cache = sw_malloc(sizeof(swDNS_cache));
            memcpy(cache,&tmp_info,sizeof(swDNS_cache));
        }
    }

    int index = (flags & SW_DNS_LOOKUP_RANDOM)? (rand() % tmp_cache->number):0;
    bzero(addr,addrLen);
    memcpy(addr, tmp_cache->addr[index].host, addrLen);

    /// 允许缓冲，并且缓冲没有当前节点数据.
    if (!disable_cache && cacheisNull && cache)
    {
        cache_table = NULL;
        /// 设置缓冲，先判断是否当前查询的key是否存在，避免并发时造成hash 冲突,引起hash表膨胀(多线程模式下)
        cache_lock->lock(cache_lock);
        /// 防止cache_table被清空
        cache_table = (__af == AF_INET)? swoole_dns_cache_v4:((__af == AF_INET6)? swoole_dns_cache_v6:NULL);
        int ret = ZAN_ERR;
        if (cache_table)
        {
            ret = (!swHashMap_find(cache_table, name, name_length))?
                        swHashMap_add(cache_table, name, name_length, cache): ZAN_ERR;
        }

        cache_lock->unlock(cache_lock);
        if (ret < 0) sw_free(cache);
    }

    return ZAN_OK;
}
#endif

int swoole_gethostbyname(int flags, char *name, char *addr)
{
    int __af = flags & (~SW_DNS_LOOKUP_RANDOM);
    int index = 0;

    struct hostent *host_entry;
    if (!(host_entry = gethostbyname2(name, __af)))
    {
        return ZAN_ERR;
    }

    union
    {
        char v4[INET_ADDRSTRLEN];
        char v6[INET6_ADDRSTRLEN];
    } addr_list[SW_DNS_HOST_BUFFER_SIZE];

    int i = 0;
    for (i = 0; i < SW_DNS_HOST_BUFFER_SIZE; i++)
    {
        if (host_entry->h_addr_list[i] == NULL)
        {
            break;
        }
        if (__af == AF_INET)
        {
            memcpy(addr_list[i].v4, host_entry->h_addr_list[i], host_entry->h_length);
        }
        else
        {
            memcpy(addr_list[i].v6, host_entry->h_addr_list[i], host_entry->h_length);
        }
    }
    if (__af == AF_INET)
    {
        memcpy(addr, addr_list[index].v4, host_entry->h_length);
    }
    else
    {
        memcpy(addr, addr_list[index].v6, host_entry->h_length);
    }
    return ZAN_OK;
}

void swoole_clear_dns_cache(void)
{
    dns_cache_v4_lock->lock(dns_cache_v4_lock);
    if (swoole_dns_cache_v4)
    {
        swHashMap_free(swoole_dns_cache_v4);
        swoole_dns_cache_v4 = NULL;
    }

    dns_cache_v4_lock->unlock(dns_cache_v4_lock);

    dns_cache_v6_lock->lock(dns_cache_v6_lock);
    if (swoole_dns_cache_v6)
    {
        swHashMap_free(swoole_dns_cache_v6);
        swoole_dns_cache_v6 = NULL;
    }

    dns_cache_v6_lock->unlock(dns_cache_v6_lock);
}

void dns_lookup_init()
{
    if (dns_inited)
    {
        return ;
    }

    dns_inited = 1;

    if (!dns_cache_v4_lock)
    {
        dns_cache_v4_lock = sw_malloc(sizeof(swLock));
        swMutex_create(dns_cache_v4_lock,0);
    }

    if (!dns_cache_v6_lock)
    {
        dns_cache_v6_lock = sw_malloc(sizeof(swLock));
        swMutex_create(dns_cache_v6_lock,0);
    }
}

int swoole_getHostbyAIO(int type,void *hostname, void *ip_addr, size_t size)
{
    //return swAio_dns_lookup(type,hostname,ip_addr,size);
    return zanAio_dns_lookup(type,hostname,ip_addr,size);
}

#if 0
static int get_host_by_syscall(int af,char* name,swDNS_cache* cache)
{
    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;
    bzero(&hints,sizeof(struct addrinfo));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(name,NULL,&hints,&result) != 0 || !result){
        zanWarn("get address info error.");
        if (result) freeaddrinfo(result);
        return ZAN_ERR;
    }

    int icount = 0;
    for (icount = 0,ptr = result; icount < SW_DNS_LOOKUP_CACHE_SIZE && ptr!= NULL;
            ptr = ptr->ai_next)
    {
        if (ptr->ai_family != af){
            continue;
        }

        void* srcptr = (AF_INET == af)? (void*)(&((struct sockaddr_in*)ptr->ai_addr)->sin_addr):
                                            (void*)(&((struct sockaddr_in6*)ptr->ai_addr)->sin6_addr);

        inet_ntop(af,srcptr,cache->addr[icount++].host,SW_IP_MAX_LENGTH);
    }

    cache->number = icount;
    cache->host_length = SW_IP_MAX_LENGTH;
    freeaddrinfo(result);

    return icount <= 0? ZAN_ERR:ZAN_OK;
}
#endif
