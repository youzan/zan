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
#ifndef _SW_BASE_OPERATOR_H_
#define _SW_BASE_OPERATOR_H_

#include "swoole.h"
#include "swLog.h"
#include "swBaseData.h"
#include "swGlobalDef.h"
#include "swAtomic.h"

///
#include "zanAtomic.h"


#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/stat.h>

static sw_inline size_t get_filelen(int filefd)
{
    struct stat file_stat;
    if (fstat(filefd, &file_stat) < 0)
    {
        swWarn("fstat() failed. Error: %s[%d]", strerror(errno), errno);
        return 0;
    }

    return file_stat.st_size;
}

static sw_inline size_t get_filelen_byname(const char* filename)
{
    struct stat file_stat;
    if (stat(filename, &file_stat) < 0)
    {
        swWarn("stat(%s) failed.", filename);
        return 0;
    }

    return file_stat.st_size;
}

static sw_inline void sw_spinlock(sw_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }

        if (SW_CPU_NUM > 1)
        {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1)
            {
                for (i = 0; i < n; i++)
                {
                    sw_atomic_cpu_pause();
                }

                if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
                {
                    return;
                }
            }
        }

        swYield();
    }
}

static sw_inline int swWaitpid(pid_t __pid, int *__stat_loc, int __options)
{
    int ret;
    do
    {
        ret = waitpid(__pid, __stat_loc, __options);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while(1);
    return ret;
}

static sw_inline int swKill(pid_t __pid, int __sig)
{
    int ret = -1;
    do
    {
        ret = kill(__pid, __sig);
        if (ret < 0 && errno == EINTR)
        {
            continue;
        }
        break;
    } while (1);

    return ret;
}

static sw_inline uint64_t swoole_hton64(uint64_t host)
{
    uint64_t ret = 0;
    uint32_t high, low;

    low = host & 0xFFFFFFFF;
    high = (host >> 32) & 0xFFFFFFFF;
    low = htonl(low);
    high = htonl(high);

    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

static sw_inline uint64_t swoole_ntoh64(uint64_t net)
{
    uint64_t ret = 0;
    uint32_t high = 0, low = 0;

    low = net & 0xFFFFFFFF;
    high = (net >> 32) & 0xFFFFFFFF;
    low = ntohl(low);
    high = ntohl(high);
    ret = low;
    ret <<= 32;
    ret |= high;
    return ret;
}

static sw_inline uint16_t swoole_swap_endian16(uint16_t x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x)
{
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

static sw_inline int32_t swoole_unpack(char type, void *data)
{
    switch(type)
    {
    /*-------------------------16bit-----------------------------*/
    /**
     * signed short (always 16 bit, machine byte order)
     */
    case 's':
        return *((int16_t *) data);
    /**
     * unsigned short (always 16 bit, machine byte order)
     */
    case 'S':
        return *((uint16_t *) data);
    /**
     * unsigned short (always 16 bit, big endian byte order)
     */
    case 'n':
        return ntohs(*((uint16_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'v':
        return swoole_swap_endian16(ntohs(*((uint16_t *) data)));

    /*-------------------------32bit-----------------------------*/
    /**
     * unsigned long (always 32 bit, machine byte order)
     */
    case 'L':
        return *((uint32_t *) data);
    /**
     * signed long (always 32 bit, machine byte order)
     */
    case 'l':
        return *((int *) data);
    /**
     * unsigned long (always 32 bit, big endian byte order)
     */
    case 'N':
        return ntohl(*((uint32_t *) data));
    /**
     * unsigned short (always 32 bit, little endian byte order)
     */
    case 'V':
        return swoole_swap_endian32(ntohl(*((uint32_t *) data)));

    default:
        return *((uint32_t *) data);
    }
}

static inline char* swoole_strnstr(char *haystack, char *needle, uint32_t length)
{
    int i;
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);

    for (i = 0; i < (int) (length - needle_length + 1); i++)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return (char *) haystack;
        }
        haystack++;
    }

    return NULL;
}

static inline int swoole_strnpos(char *haystack, uint32_t haystack_length, char *needle, uint32_t needle_length)
{
    assert(needle_length > 0);
    uint32_t index = 0;

    for (index = 0; index < (int) (haystack_length - needle_length + 1); index++)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return index;
        }

        haystack++;
    }

    return SW_ERR;
}

static inline int swoole_strrnpos(char *haystack, char *needle, uint32_t length)
{
    uint32_t needle_length = strlen(needle);
    assert(needle_length > 0);
    uint32_t i;
    haystack += (length - needle_length);

    for (i = length - needle_length; i > 0; i--)
    {
        if ((haystack[0] == needle[0]) && (0 == memcmp(haystack, needle, needle_length)))
        {
            return i;
        }
        haystack--;
    }

    return -1;
}

static inline void swoole_strtolower(char *str, int length)
{
    char *c, *e;

    c = str;
    e = c + length;

    while (c < e)
    {
        *c = tolower(*c);
        c++;
    }
}

void swBreakPoint(void);

void swoole_cpu_setAffinity(int threadid,swServer *serv);

uint64_t swoole_hash_key(char *str, int str_len);
uint32_t swoole_common_multiple(uint32_t u, uint32_t v);
uint32_t swoole_common_divisor(uint32_t u, uint32_t v);

int swoole_itoa(char *buf, long value);

void swoole_rtrim(char *str, int len);

int swoole_type_size(char type);
int swoole_mkdir_recursive(const char *dir);
char* swoole_dirname(char *file);

int get_env_log_level();
void swoole_redirect_stdout(int new_fd);

long swoole_file_get_size(FILE *fp);
int swoole_tmpfile(char *filename);
swString* swoole_file_get_contents(char *filename);

int swoole_rand(int min, int max);
int swoole_system_random(int min, int max);

char *swoole_dec2hex(int value, int base);
void replaceChar(char* str,int length,char srcCh,char dstCh);
int swoole_version_compare(char *version1, char *version2);

#ifdef HAVE_EXECINFO
void swoole_print_trace(void);
#endif


int swoole_daemon(int nochdir, int noclose);


#ifdef __MACH__
#include <mach/clock.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>

#define ORWL_NANO (+1.0E-9)
#define ORWL_GIGA UINT64_C(1000000000)

static double orwl_timebase = 0.0;
static uint64_t orwl_timestart = 0;

#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clock_id_t which_clock, struct timespec *t);
#endif
#endif


//==============================================================================
static sw_inline void zan_spinlock(zan_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && zan_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }

        if (SW_CPU_NUM > 1)
        {
            for (n = 1; n < SW_SPINLOCK_LOOP_N; n <<= 1)
            {
                for (i = 0; i < n; i++)
                {
                    zan_atomic_cpu_pause();
                }

                if (*lock == 0 && zan_atomic_cmp_set(lock, 0, 1))
                {
                    return;
                }
            }
        }

        swYield();
    }
}



#ifdef __cplusplus
}
#endif

#endif
