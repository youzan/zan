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

#if __APPLE__
// Fix warning: 'daemon' is deprecated: first deprecated in macOS 10.5
// - Use posix_spawn APIs instead. [-Wdeprecated-declarations]
#define daemon daemon_is_deprecated_in_os_x_10_5
#endif

#include "swoole.h"
#include "swSignal.h"
#include "swError.h"
#include "swAtomic.h"
#include "swClient.h"
#include "swBaseOperator.h"
#include "zanLog.h"

#include <stdlib.h>
#include <pthread.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#ifdef HAVE_EXECINFO
#include <execinfo.h>
#endif

#if __APPLE__
#undef daemon
extern int daemon(int,int);
#endif

uint64_t swoole_hash_key(char *str, int str_len)
{
    uint64_t hash = 5381;
    int charValue = 0, index = 0;
    for (charValue = *str++; index < str_len; index++)
    {
        hash = (*((hash * 33) + str)) & 0x7fffffff;
        hash = ((hash << 5) + hash) + charValue;
    }

    return hash;
}

/**
 * Recursive directory creation
 */
int swoole_mkdir_recursive(const char *dir)
{
    char tmp[1024] = {0};
    int len = strlen(dir);
    if (len + 1 > 1024)
    {
        zanWarn("mkdir(%s) failed,Path exceeds %d characters limit.",dir,1023);
        return -1;
    }

    strncpy(tmp, dir, len);
    if (dir[len - 1] != '/')
    {
        strcat(tmp, "/");
    }

    len = strlen(tmp);
    int index = 0;
    for (index = 1; index < len; index++)
    {
        if (tmp[index] == '/')
        {
            tmp[index] = 0;
            if (access(tmp, R_OK) != 0)
            {
                if (mkdir(tmp, 0755) == -1)
                {
                    zanError("mkdir(%s) failed.", tmp);
                    return -1;
                }
            }

            tmp[index] = '/';
        }
    }
    return 0;
}

/**
 * get parent dir name
 */
char* swoole_dirname(char *file)
{
    char *dirname = strdup(file);
    if (dirname == NULL)
    {
        zanWarn("strdup() failed.");
        return NULL;
    }

    int len = strlen(dirname);
    len = (dirname[len - 1] == '/')? len -2:len;
    for (; len > 0; len--)
    {
        if ('/' == dirname[len])
        {
            dirname[len] = 0;
            break;
        }
    }

    return dirname;
}

int get_env_log_level()
{
    int level = ZAN_LOG_LEVEL_UNKNOW;
    char* tmp = getenv("ZANEXT_DEBUG_LOG_LEVEL");
    if (tmp)
    {
        level = strtol(tmp,NULL,0);
    }

    return level;
}

int swoole_type_size(char type)
{
    switch (type)
    {
    case 's':
    case 'S':
    case 'n':
    case 'v':
        return 2;
    case 'l':
    case 'L':
    case 'N':
    case 'V':
        return 4;
    default:
        return 0;
    }
}

char* swoole_dec2hex(int value, int base)
{
    assert(base > 1 && base < 37);

    static char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char buf[(sizeof(unsigned long) << 3) + 1];
    char *ptr = NULL, *end = NULL;

    end = ptr = buf + sizeof(buf) - 1;
    *ptr = '\0';

    do
    {
        *--ptr = digits[value % base];
        value /= base;
    } while (ptr > buf && value);

    return strndup(ptr, end - ptr);
}

#ifndef RAND_MAX
#define RAND_MAX   2147483647
#endif

int swoole_rand(int min, int max)
{
    static int _seed = 0;
    assert(max > min);

    if (_seed == 0)
    {
        _seed = time(NULL);
        srand(_seed);
    }

    int _rand = rand();
    _rand = min + (int) ((double) ((double) (max) - (min) + 1.0) * ((_rand) / ((RAND_MAX) + 1.0)));
    return _rand;
}

int swoole_system_random(int min, int max)
{
    static int dev_random_fd = -1;
    char *next_random_byte;
    int bytes_to_read;
    unsigned random_value;

    assert(max > min);

    if (dev_random_fd == -1)
    {
        dev_random_fd = open("/dev/urandom", O_RDONLY);
        if (dev_random_fd < 0)
        {
            return swoole_rand(min, max);
        }
    }

    next_random_byte = (char *) &random_value;
    bytes_to_read = sizeof(random_value);

    if (read(dev_random_fd, next_random_byte, bytes_to_read) < 0)
    {
        zanError("read() failed.");
        return SW_ERR;
    }

    return min + (random_value % (max - min + 1));
}

//replace src char to dst char
void replaceChar(char* str,int length,char srcCh,char dstCh)
{
    int index;
    for (index = 0; index < length; index++)
    {
        if (str[index] == srcCh)
        {
            str[index] = dstCh;
        }
    }
}

int swoole_version_compare(char *version1, char *version2)
{
    int result = 0;

    while (result == 0)
    {
        char* tail1;
        char* tail2;

        unsigned long ver1 = strtoul(version1, &tail1, 10);
        unsigned long ver2 = strtoul(version2, &tail2, 10);

        if (ver1 != ver2){
            result = (ver1 < ver2)? -1:result + 1;
        }
        else
        {
            version1 = tail1;
            version2 = tail2;
            if (*version1 == '\0' && *version2 == '\0')
            {
                break;
            }
            else if (*version1 == '\0')
            {
                result = -1;
            }
            else if (*version2 == '\0')
            {
                result = +1;
            }
            else
            {
                version1++;
                version2++;
            }
        }
    }
    return result;
}

void swoole_rtrim(char *str, int len)
{
    int i;
    for (i = len; i > 0; i--)
    {
        switch (str[i])
        {
        case ' ':
        case '\0':
        case '\n':
        case '\r':
        case '\t':
        case '\v':
            str[i] = 0;
            break;
        default:
            break;
        }
    }
}

int swoole_tmpfile(char *filename)
{
#if defined(HAVE_MKOSTEMP) && defined(HAVE_EPOLL)
    int tmp_fd = mkostemp(filename, O_WRONLY | O_CREAT);
#else
    int tmp_fd = mkstemp(filename);
#endif

    if (tmp_fd < 0)
    {
        zanError("mkstemp/mkostemp(%s) failed.", filename);
        return SW_ERR;
    }
    else
    {
        return tmp_fd;
    }
}

long swoole_file_get_size(FILE *fp)
{
    long pos = ftell(fp);
    fseek(fp, 0L, SEEK_END);
    long size = ftell(fp);
    fseek(fp, pos, SEEK_SET);
    return size;
}

swString* swoole_file_get_contents(char *filename)
{
    struct stat file_stat;
    if (lstat(filename, &file_stat) < 0)
    {
        zanError("lstat(%s) failed.", filename);
        return NULL;
    }
    if (file_stat.st_size > SW_MAX_FILE_CONTENT)
    {
        zanWarn("file is too big");
        return NULL;
    }
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        zanError("open(%s) failed.", filename);
        return NULL;
    }

    swString *content = swString_new(file_stat.st_size);
    if (!content)
    {
        zanWarn("malloc failed");
        close(fd);
        return NULL;
    }

    int readn = 0;
    int n;

    while(readn < file_stat.st_size)
    {
        n = pread(fd, content->str + readn, file_stat.st_size - readn, readn);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else
            {
                zanError("pread() failed.");
                swString_free(content);
                close(fd);
                return NULL;
            }
        }
        readn += n;
    }

    close(fd);
    return content;
}

/**
 * 最大公约数
 */
uint32_t swoole_common_divisor(uint32_t u, uint32_t v)
{
    assert(u > 0 && v > 0);
    uint32_t t = 0;
    while (u > 0)
    {
        if (u < v)
        {
            t = u;
            u = v;
            v = t;
        }
        u = u - v;
    }
    return v;
}

/**
 * 最小公倍数
 */
uint32_t swoole_common_multiple(uint32_t u, uint32_t v)
{
    assert(u > 0 && v > 0);

    uint32_t m_cup = u;
    uint32_t n_cup = v;
    int res = m_cup % n_cup;

    while (res != 0)
    {
        m_cup = n_cup;
        n_cup = res;
        res = m_cup % n_cup;
    }

    return u * v / n_cup;
}

/**
 * for GDB
 */
void swBreakPoint()
{

}

void swoole_redirect_stdout(int new_fd)
{
    if (dup2(new_fd, STDOUT_FILENO) < 0)
    {
        zanError("dup2(STDOUT_FILENO) failed.");
    }
    if (dup2(new_fd, STDERR_FILENO) < 0)
    {
        zanError("dup2(STDERR_FILENO) failed.");
    }
}

static int *swoole_kmp_borders(char *needle, size_t nlen)
{
    if (!needle)
    {
        return NULL;
    }

    int i, j, *borders = sw_malloc((nlen + 1) * sizeof(*borders));
    if (!borders)
    {
        return NULL;
    }

    i = 0;
    j = -1;
    borders[i] = j;
    while ((uint32_t) i < nlen)
    {
        while (j >= 0 && needle[i] != needle[j])
        {
            j = borders[j];
        }
        ++i;
        ++j;
        borders[i] = j;
    }
    return borders;
}

static char *swoole_kmp_search(char *haystack, size_t haylen, char *needle, uint32_t nlen, int *borders)
{
    uint32_t max_index = haylen - nlen, i = 0, j = 0;

    while (i <= max_index)
    {
        while (j < nlen && *haystack && needle[j] == *haystack)
        {
            ++j;
            ++haystack;
        }
        if (j == nlen)
        {
            return haystack - nlen;
        }
        if (!(*haystack))
        {
            return NULL;
        }
        if (j == 0)
        {
            ++haystack;
            ++i;
        }
        else
        {
            do
            {
                i += j - (uint32_t) borders[j];
                j = borders[j];
            } while (j > 0 && needle[j] != *haystack);
        }
    }
    return NULL;
}

int swoole_itoa(char *buf, long value)
{
    long i = 0, j = 0;
    long sign_mask;
    unsigned long nn;

    sign_mask = value >> (sizeof(long) * 8 - 1);
    nn = (value + sign_mask) ^ sign_mask;
    do
    {
        buf[i++] = nn % 10 + '0';
    } while (nn /= 10);

    buf[i] = '-';
    i += sign_mask & 1;
    buf[i] = '\0';

    int s_len = i;
    char swap;

    for (i = 0, j = s_len - 1; i < j; ++i, --j)
    {
        swap = buf[i];
        buf[i] = buf[j];
        buf[j] = swap;
    }

    buf[s_len] = 0;
    return s_len;
}

char *swoole_kmp_strnstr(char *haystack, char *needle, uint32_t length)
{
    if (!haystack || !needle)
    {
        return NULL;
    }
    size_t nlen = strlen(needle);
    if (length < nlen)
    {
        return NULL;
    }
    int *borders = swoole_kmp_borders(needle, nlen);
    if (!borders)
    {
        return NULL;
    }

    char *match = swoole_kmp_search(haystack, length, needle, nlen, borders);
    free(borders);
    return match;
}

#ifdef HAVE_EXECINFO
void swoole_print_trace(void)
{
    int size = 16;
    void* array[16];
    int stack_num = backtrace(array, size);
    char** stacktrace = backtrace_symbols(array, stack_num);
    int i;

    for (i = 0; i < stack_num; ++i)
    {
        printf("%s\n", stacktrace[i]);
    }
    free(stacktrace);
}
#endif

void swoole_cpu_setAffinity(int threadid, zanServer *serv)
{
#ifdef HAVE_CPU_AFFINITY
    if (!serv){
        return ;
    }

    //cpu affinity setting
    if (ServerG.servSet.open_cpu_affinity)
    {
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);

        if (serv->cpu_affinity_available_num)
        {
            CPU_SET(serv->cpu_affinity_available[threadid % serv->cpu_affinity_available_num], &cpu_set);
        }
        else
        {
            CPU_SET(threadid % ZAN_CPU_NUM, &cpu_set);
        }

        if (0 != pthread_setaffinity_np(pthread_self(), sizeof(cpu_set), &cpu_set))
        {
            zanError("pthread_setaffinity_np() failed");
        }
    }
#endif

}


#ifdef __MACH__
#ifndef HAVE_CLOCK_GETTIME
int clock_gettime(clock_id_t which_clock, struct timespec *t)
{
    // be more careful in a multithreaded environement
    if (!orwl_timestart)
    {
        mach_timebase_info_data_t tb =
        {   0};
        mach_timebase_info(&tb);
        orwl_timebase = tb.numer;
        orwl_timebase /= tb.denom;
        orwl_timestart = mach_absolute_time();
    }
    double diff = (mach_absolute_time() - orwl_timestart) * orwl_timebase;
    t->tv_sec = diff * ORWL_NANO;
    t->tv_nsec = diff - (t->tv_sec * ORWL_GIGA);
    return 0;
}
#endif
#endif


int swoole_daemon(int nochdir, int noclose)
{
#ifndef HAVE_DAEMON
    if (!nochdir && chdir("/") != 0)
    {
        zanError("chdir() failed.");
        return -1;
    }

    if (!noclose)
    {
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0)
        {
            zanError("open() failed.");
            return -1;
        }

        if (dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0)
        {
            close(fd);
            zanError("dup2() failed.");
            return -1;
        }

        close(fd);
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        zanError("fork() failed.");
        return -1;
    }
    if (pid > 0)
    {
        _exit(0);
    }
    if (setsid() < 0)
    {
        zanError("setsid() failed.");
        return -1;
    }

    return 0;
#else
    return daemon(nochdir,noclose);
#endif

}

size_t get_filelen(int filefd)
{
    struct stat file_stat;
    if (fstat(filefd, &file_stat) < 0)
    {
        //swWarn("fstat() failed. Error: %s[%d]", strerror(errno), errno);
        return 0;
    }

    return file_stat.st_size;
}

size_t get_filelen_byname(const char* filename)
{
    struct stat file_stat;
    if (stat(filename, &file_stat) < 0)
    {
        //swWarn("stat(%s) failed.", filename);
        return 0;
    }

    return file_stat.st_size;
}

void sw_spinlock(sw_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && sw_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }

        //if (SW_CPU_NUM > 1)
        if (ZAN_CPU_NUM > 1)
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

int swWaitpid(pid_t __pid, int *__stat_loc, int __options)
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

uint64_t swoole_ntoh64(uint64_t net)
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

int swKill(pid_t __pid, int __sig)
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

int32_t swoole_unpack(char type, void *data)
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

int swoole_strnpos(char *haystack, uint32_t haystack_length, char *needle, uint32_t needle_length)
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

void swoole_strtolower(char *str, int length)
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

void zan_spinlock(zan_atomic_t *lock)
{
    uint32_t i, n;
    while (1)
    {
        if (*lock == 0 && zan_atomic_cmp_set(lock, 0, 1))
        {
            return;
        }

        if (ZAN_CPU_NUM > 1)
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
