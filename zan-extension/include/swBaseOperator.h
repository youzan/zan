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
#include "swBaseData.h"
#include "swAtomic.h"

#include "zanAtomic.h"
#include "zanGlobalVar.h"

#ifdef __cplusplus
extern "C"
{
#endif

#include <sys/stat.h>

size_t get_filelen(int filefd);
size_t get_filelen_byname(const char* filename);
void sw_spinlock(sw_atomic_t *lock);
int swWaitpid(pid_t __pid, int *__stat_loc, int __options);
int swKill(pid_t __pid, int __sig);
uint64_t swoole_ntoh64(uint64_t net);


int32_t swoole_unpack(char type, void *data);
int swoole_strnpos(char *haystack, uint32_t haystack_length, char *needle, uint32_t needle_length);

static sw_inline uint16_t swoole_swap_endian16(uint16_t x)
{
    return (((x & 0xff) << 8) | ((x & 0xff00) >> 8));
}

static sw_inline uint32_t swoole_swap_endian32(uint32_t x)
{
    return (((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24));
}

void swoole_strtolower(char *str, int length);


void swBreakPoint(void);

//void swoole_cpu_setAffinity(int threadid, swServer *serv);

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

void zan_spinlock(zan_atomic_t *lock);


#ifdef __cplusplus
}
#endif

#endif
