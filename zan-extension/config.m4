dnl config.m4 for extension zan

dnl  +----------------------------------------------------------------------+
dnl  | Zan                                                                  |
dnl  +----------------------------------------------------------------------+
dnl  | Copyright (c) 2016-2017 Zan Group <https://github.com/youzan/zan>    |
dnl  | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
dnl  +----------------------------------------------------------------------+
dnl  | This source file is subject to version 2.0 of the Apache license,    |
dnl  | that is bundled with this package in the file LICENSE, and is        |
dnl  | available through the world-wide-web at the following url:           |
dnl  | http://www.apache.org/licenses/LICENSE-2.0.html                      |
dnl  | If you did not receive a copy of the Apache2.0 license and are unable|
dnl  | to obtain it through the world-wide-web, please send a note to       |
dnl  | zan@zanphp.io so we can mail you a copy immediately.                 |
dnl  +----------------------------------------------------------------------+
dnl  | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
dnl  |         Zan Group   <zan@zanphp.io>                                  |
dnl  +----------------------------------------------------------------------+

PHP_ARG_ENABLE(zan-debug, whether to enable zan debug,
[  --enable-zan-debug   Enable zan debug], no, no)

PHP_ARG_ENABLE(sockets, enable sockets support,
[  --enable-sockets        Do you have sockets extension?], yes, no)

PHP_ARG_ENABLE(ringbuffer, enable ringbuffer shared memory pool support,
[  --enable-ringbuffer     Use ringbuffer memory pool?], no, no)

PHP_ARG_ENABLE(async_redis, enable async_redis support,
[  --enable-async-redis    Do you have hiredis?], yes, no)

PHP_ARG_ENABLE(openssl, enable openssl support,
[  --enable-openssl        Use openssl?], no, no)

PHP_ARG_ENABLE(http2, enable http2.0 support,
[  --enable-http2        Use http2.0?], no, no)

PHP_ARG_ENABLE(jemalloc, enable jemalloc support,
[  --enable-jemalloc        Use jemalloc?], no, no)

PHP_ARG_ENABLE(tcmalloc, enable tcmalloc support,
[  --enable-tcmalloc        Use tcmalloc?], no, no)

PHP_ARG_WITH(zan, zan support,
[  --with-zan           With zan support])

PHP_ARG_ENABLE(zan, zan support,
[  --enable-zan         Enable zan support], [enable_zan="yes"])

PHP_ARG_WITH(openssl_dir, for OpenSSL support,
[  --with-openssl-dir[=DIR]    Include OpenSSL support (requires OpenSSL >= 0.9.6)], no, no)

PHP_ARG_ENABLE(mysqlnd, enable mysqlnd support,
[  --enable-mysqlnd       Do you have mysqlnd?], no, no)

AC_DEFUN([ZAN_HAVE_PHP_EXT], [
    extname=$1
    haveext=$[PHP_]translit($1,a-z_-,A-Z__)

    AC_MSG_CHECKING([for ext/$extname support])
    if test -x "$PHP_EXECUTABLE"; then
        grepext=`$PHP_EXECUTABLE -m | $EGREP ^$extname\$`
        if test "$grepext" = "$extname"; then
            [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=1
            AC_MSG_RESULT([yes])
            $2
        else
            [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=
            AC_MSG_RESULT([no])
            $3
        fi
    elif test "$haveext" != "no" && test "x$haveext" != "x"; then
        [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=1
        AC_MSG_RESULT([yes])
        $2
    else
        [PHP_HTTP_HAVE_EXT_]translit($1,a-z_-,A-Z__)=
        AC_MSG_RESULT([no])
        $3
    fi
])

AC_DEFUN([AC_ZAN_CPU_AFFINITY],
[
    AC_MSG_CHECKING([for cpu affinity])
    AC_TRY_COMPILE(
    [
        #include <sched.h>
    ], [
        cpu_set_t cpu_set;
        CPU_ZERO(&cpu_set);
    ], [
        AC_DEFINE([HAVE_CPU_AFFINITY], 1, [cpu affinity?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_DEFUN([AC_ZAN_HAVE_REUSEPORT],
[
    AC_MSG_CHECKING([for socket REUSEPORT])
    AC_TRY_COMPILE(
    [
        #include <sys/socket.h>
    ], [
        int val = 1;
        setsockopt(0, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
    ], [
        AC_DEFINE([HAVE_REUSEPORT], 1, [have SO_REUSEPORT?])
        AC_MSG_RESULT([yes])
    ], [
        AC_MSG_RESULT([no])
    ])
])

AC_MSG_CHECKING([if compiling with clang])
AC_COMPILE_IFELSE([
    AC_LANG_PROGRAM([], [[
        #ifndef __clang__
            not clang
        #endif
    ]])],
    [CLANG=yes], [CLANG=no]
)
AC_MSG_RESULT([$CLANG])

if test "$CLANG" = "yes"; then
    CFLAGS="$CFLAGS -std=gnu89 -fsanitize=bounds -fsanitize-undefined-trap-on-error"
else
    CFLAGS="$CFLAGS -std=gnu99 -fbounds-check -pthread"
    LDFLAGS="$LDFLAGS -lpthread"
fi

if test "$PHP_ZAN" != "no"; then

    PHP_ADD_LIBRARY(pthread)
    PHP_SUBST(ZAN_SHARED_LIBADD)

    AC_ARG_ENABLE(debug,
        [--enable-debug,  compile with debug symbols],
        [PHP_DEBUG=$enableval],
        [PHP_DEBUG=0]
    )

    if test "$PHP_ZAN_DEBUG" != "no"; then
        AC_DEFINE(SW_DEBUG, 1, [do we enable zan debug])
    fi

    if test "$PHP_SOCKETS" = "yes"; then
        AC_CHECK_HEADER([${phpincludedir}/ext/sockets/php_sockets.h],
            [AC_DEFINE([HAVE_SOCKETS], 1, [ ])],
            [AC_MSG_ERROR([enable sockets support, sockets extension installed incorrectly])])
        AC_DEFINE(SW_USE_SOCKETS, 1, [enable sockets support])
    fi

    if test "$PHP_RINGBUFFER" = "yes"; then
        AC_DEFINE(SW_USE_RINGBUFFER, 1, [enable ringbuffer support])
    fi

    if test "$PHP_HTTP2" = "yes"; then
        AC_DEFINE(SW_USE_HTTP2, 1, [enable http2.0 support])
    fi

    AC_ZAN_CPU_AFFINITY
    AC_ZAN_HAVE_REUSEPORT

    CFLAGS="-Wall $CFLAGS -fstack-check -fstack-protector -fstack-protector-all -fno-strict-aliasing"

    if test "$PHP_MYSQLND" = "yes"; then
        PHP_ADD_EXTENSION_DEP(mysqli, mysqlnd)
        AC_DEFINE(SW_USE_MYSQLND, 1, [use mysqlnd])
    fi
    AC_CHECK_LIB(c, accept4, AC_DEFINE(HAVE_ACCEPT4, 1, [have accept4]))
    AC_CHECK_LIB(c, signalfd, AC_DEFINE(HAVE_SIGNALFD, 1, [have signalfd]))
    AC_CHECK_LIB(c, timerfd_create, AC_DEFINE(HAVE_TIMERFD, 1, [have timerfd]))
    AC_CHECK_LIB(c, eventfd, AC_DEFINE(HAVE_EVENTFD, 1, [have eventfd]))
    AC_CHECK_LIB(c, epoll_create, AC_DEFINE(HAVE_EPOLL, 1, [have epoll]))
    AC_CHECK_LIB(c, sendfile, AC_DEFINE(HAVE_SENDFILE, 1, [have sendfile]))
    AC_CHECK_LIB(c, kqueue, AC_DEFINE(HAVE_KQUEUE, 1, [have kqueue]))
    AC_CHECK_LIB(c, backtrace, AC_DEFINE(HAVE_EXECINFO, 1, [have execinfo]))
    AC_CHECK_LIB(c, daemon, AC_DEFINE(HAVE_DAEMON, 1, [have daemon]))
    AC_CHECK_LIB(c, mkostemp, AC_DEFINE(HAVE_MKOSTEMP, 1, [have mkostemp]))
    AC_CHECK_LIB(c, inotify_init, AC_DEFINE(HAVE_INOTIFY, 1, [have inotify]))
    AC_CHECK_LIB(c, inotify_init1, AC_DEFINE(HAVE_INOTIFY_INIT1, 1, [have inotify_init1]))
    AC_CHECK_LIB(pthread, pthread_rwlock_init, AC_DEFINE(HAVE_RWLOCK, 1, [have pthread_rwlock_init]))
    AC_CHECK_LIB(pthread, pthread_spin_lock, AC_DEFINE(HAVE_SPINLOCK, 1, [have pthread_spin_lock]))
    AC_CHECK_LIB(pthread, pthread_mutex_timedlock, AC_DEFINE(HAVE_MUTEX_TIMEDLOCK, 1, [have pthread_mutex_timedlock]))
    AC_CHECK_LIB(pthread, pthread_barrier_init, AC_DEFINE(HAVE_PTHREAD_BARRIER, 1, [have pthread_barrier_init]))
    AC_CHECK_LIB(ssl, SSL_connect, AC_DEFINE(HAVE_OPENSSL, 1, [have openssl]))
    AC_CHECK_LIB(pcre, pcre_compile, AC_DEFINE(HAVE_PCRE, 1, [have pcre]))
    AC_CHECK_LIB(hiredis, redisConnect, AC_DEFINE(HAVE_HIREDIS, 1, [have hiredis]))
    AC_CHECK_LIB(nghttp2, nghttp2_hd_inflate_new, AC_DEFINE(HAVE_NGHTTP2, 1, [have nghttp2]))

    AC_CHECK_LIB(z, gzgets, [
        AC_DEFINE(SW_HAVE_ZLIB, 1, [have zlib])
        PHP_ADD_LIBRARY(z, 1, ZAN_SHARED_LIBADD)
    ])

    if test `uname` = "Darwin"; then
        AC_CHECK_LIB(c, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
        AC_CHECK_LIB(c, aio_read, AC_DEFINE(HAVE_GCC_AIO, 1, [have gcc aio]))

        if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
            AC_DEFINE(SW_USE_OPENSSL, 1, [enable openssl support])
        if test "$PHP_OPENSSL_DIR" != "no"; then
                PHP_ADD_INCLUDE("${PHP_OPENSSL_DIR}/include")
                PHP_ADD_LIBRARY_WITH_PATH(ssl, "${PHP_OPENSSL_DIR}/lib")
        PHP_ADD_LIBRARY_WITH_PATH(crypto,"${PHP_OPENSSL_DIR}/lib")
            fi
            PHP_ADD_LIBRARY(ssl, 1, ZAN_SHARED_LIBADD)
            PHP_ADD_LIBRARY_WITH_PATH(crypto, /usr/local/opt/openssl/lib, ZAN_SHARED_LIBADD)
            PHP_ADD_INCLUDE(/usr/local/opt/openssl/include)
        fi
    else
        AC_CHECK_LIB(rt, clock_gettime, AC_DEFINE(HAVE_CLOCK_GETTIME, 1, [have clock_gettime]))
        AC_CHECK_LIB(rt, aio_read, AC_DEFINE(HAVE_GCC_AIO, 1, [have gcc aio]))
        PHP_ADD_LIBRARY(rt, 1, ZAN_SHARED_LIBADD)

        if test "$PHP_OPENSSL" != "no" || test "$PHP_OPENSSL_DIR" != "no"; then
            AC_DEFINE(SW_USE_OPENSSL, 1, [enable openssl support])
        if test "$PHP_OPENSSL_DIR" != "no"; then
                PHP_ADD_INCLUDE("${PHP_OPENSSL_DIR}/include")
                PHP_ADD_LIBRARY_WITH_PATH(ssl, "${PHP_OPENSSL_DIR}/lib")
        PHP_ADD_LIBRARY_WITH_PATH(crypto,"${PHP_OPENSSL_DIR}/lib")
        PHP_ADD_LIBRARY_WITH_PATH(crypt,"${PHP_OPENSSL_DIR}/lib")
            fi

            PHP_ADD_LIBRARY(ssl, 1, ZAN_SHARED_LIBADD)
            PHP_ADD_LIBRARY(crypt, 1, ZAN_SHARED_LIBADD)
            PHP_ADD_LIBRARY(crypto, 1, ZAN_SHARED_LIBADD)
        fi
    fi
    if test "$PHP_CURL" != "no"; then
        for i in /usr /usr/local /usr/local/Cellar/curl/*; do
            if test -f $i/include/curl/curl.h; then
                CURL_DIR=$i
            fi
        done

        if test -z "$CURL_DIR"; then
            AC_MSG_ERROR([libcurl not installed])
        fi

        PHP_ADD_LIBRARY(curl, 1, ZAN_SHARED_LIBADD)
    fi

    PHP_ADD_LIBRARY(pthread, 1, ZAN_SHARED_LIBADD)

    if test "$PHP_ASYNC_REDIS" = "yes"; then
        AC_DEFINE(SW_USE_REDIS, 1, [enable async-redis support])
        os=`uname -s`
        case $os in
            Linux)
                PHP_ADD_LIBRARY_WITH_PATH(hiredis_linux, ../lib, ZAN_SHARED_LIBADD)
            ;;
            Darwin)
                PHP_ADD_LIBRARY_WITH_PATH(hiredis_mac, ../lib, ZAN_SHARED_LIBADD)
            ;;
        esac
    fi

    if test "$PHP_HTTP2" = "yes"; then
        PHP_ADD_LIBRARY(nghttp2, 1, ZAN_SHARED_LIBADD)
    fi

    if test "$PHP_JEMALLOC" = "yes"; then
        PHP_ADD_LIBRARY(jemalloc, 1, ZAN_SHARED_LIBADD)
    elif test "$PHP_TCMALLOC" = "yes"; then
        PHP_ADD_LIBRARY(tcmalloc, 1, ZAN_SHARED_LIBADD)
    fi

    swoole_source_file="swoole.c \
        swoole_server1.c \
        swoole_server_port1.c \
dnl        swoole_connpool.c \
        swoole_client.c \
        swoole_event.c \
        swoole_timer.c \
        swoole_async.c \
        swoole_process.c \
        swoole_buffer.c \
dnl        swoole_http_server.c \
dnl        swoole_http_v2_server.c \
dnl        swoole_websocket_server.c \
dnl        swoole_http_client.c \
dnl        swoole_mysql.c \
dnl        swoole_redis.c \
        swoole_nova.c \
        swoole_stats.c \
        src/Base.c \
        src/core/hashmap.c \
        src/core/RingQueue.c \
        src/core/string.c \
        src/core/array.c \
        src/core/list.c \
        src/core/heap.c \
        src/core/log.c \
        src/core/rbtree.c \
        src/memory/ShareMemory.c \
        src/memory/MemoryGlobal.c \
        src/memory/RingBuffer.c \
        src/memory/FixedPool.c \
        src/memory/Malloc.c \
        src/memory/Table.c \
        src/memory/Buffer.c \
        src/memory/zanShmPool.c \
        src/factory/Factory.c \
        src/factory/FactoryThread.c \
        src/factory/FactoryProcess.c \
        src/factory/ProcessPool.c \
        src/factory/ThreadPool.c \
        src/factory/zanFactory.c \
        src/reactor/ReactorBase.c \
        src/reactor/ReactorSelect.c \
        src/reactor/ReactorPoll.c \
        src/reactor/ReactorEpoll.c \
        src/reactor/ReactorKqueue.c \
        src/pipe/PipeBase.c \
        src/pipe/PipeEventfd.c \
        src/pipe/PipeUnsock.c \
        src/pipe/Channel.c \
        src/pipe/Msgqueue.c \
        src/lock/Semaphore.c \
        src/lock/Mutex.c \
        src/lock/RWLock.c \
        src/lock/SpinLock.c \
        src/lock/FileLock.c \
        src/lock/AtomicLock.c \
        src/lock/Cond.c \
        src/lock/zanSem.c \
        src/lock/zanMutex.c \
        src/lock/zanRWLock.c \
        src/lock/zanSpinLock.c \
        src/lock/zanFileLock.c \
        src/lock/zanAtomicLock.c \
        src/lock/zanLockBase.c \
        src/network/Client.c \
        src/network/Connection.c \
        src/network/Manager.c \
        src/network/Port.c \
        src/network/ReactorAccept.c \
        src/network/ReactorProcess.c \
        src/network/ReactorThread.c \
        src/network/Server.c \
        src/network/Socket.c \
        src/network/TaskWorker.c \
        src/network/Worker.c \
        src/network/zanConnection.c \
        src/network/zanSocket.c \
        src/network/zanServer.c \
        src/protocol/Base.c \
        src/protocol/Base64.c \
        src/protocol/Http.c \
        src/protocol/Http2.c \
        src/protocol/Mqtt.c \
        src/protocol/Nova.c \
        src/protocol/Sha1.c \
        src/protocol/SSL.c \
        src/protocol/WebSocket.c \
        src/util/Baseoperator.c \
        src/util/BinaryData.c \
        src/util/zanBinaryData.c \
        src/util/Sendfile.c \
        src/util/zanLog.c \
        src/util/zanProcess.c \
        src/util/zanThread.c \
        src/util/zanSystem.c \
        src/dns/DNS.c \
        src/signal/Signal.c \
        src/ipc/zanCond.c \
        src/ipc/zanPipe.c \
        src/ipc/zanPipeBase.c \
        src/ipc/zanUnSock.c \
        src/ipc/zanMsgQueue.c \
        src/ipc/zanShm.c \
        src/aio/AsyncIO.c \
        src/aio/zanAio.c \
        src/timer/Timer.c \
        src/workers/zanWorker.c \
        src/workers/zanNetWorker.c \
        src/workers/zanTaskWorker.c \
        src/workers/zanMaster.c"


    swoole_source_file="$swoole_source_file thirdparty/php_http_parser.c"
    swoole_source_file="$swoole_source_file thirdparty/multipart_parser.c"

    PHP_NEW_EXTENSION(zan, $swoole_source_file, $ext_shared)

    PHP_ADD_INCLUDE([$ext_srcdir/include])

    PHP_ADD_BUILD_DIR($ext_builddir/src/core)
    PHP_ADD_BUILD_DIR($ext_builddir/src/memory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/factory)
    PHP_ADD_BUILD_DIR($ext_builddir/src/reactor)
    PHP_ADD_BUILD_DIR($ext_builddir/src/pipe)
    PHP_ADD_BUILD_DIR($ext_builddir/src/util)
    PHP_ADD_BUILD_DIR($ext_builddir/src/lock)
    PHP_ADD_BUILD_DIR($ext_builddir/src/os)
    PHP_ADD_BUILD_DIR($ext_builddir/src/network)
    PHP_ADD_BUILD_DIR($ext_builddir/src/protocol)
    PHP_ADD_BUILD_DIR($ext_builddir/thirdparty)
fi
