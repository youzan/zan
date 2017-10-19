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

#include "php_swoole.h"
#include "php_streams.h"
#include "php_network.h"
#include "swSignal.h"
#include "swBaseOperator.h"
#include "zanWorkers.h"

#include "zanLog.h"

static PHP_METHOD(swoole_process, __construct);
static PHP_METHOD(swoole_process, __destruct);
static PHP_METHOD(swoole_process, useQueue);
static PHP_METHOD(swoole_process, freeQueue);
static PHP_METHOD(swoole_process, pop);
static PHP_METHOD(swoole_process, push);
static PHP_METHOD(swoole_process, kill);
static PHP_METHOD(swoole_process, signal);
static PHP_METHOD(swoole_process, wait);
static PHP_METHOD(swoole_process, daemon);
static PHP_METHOD(swoole_process, setaffinity);
static PHP_METHOD(swoole_process, start);
static PHP_METHOD(swoole_process, write);
static PHP_METHOD(swoole_process, read);
static PHP_METHOD(swoole_process, close);
static PHP_METHOD(swoole_process, exit);
static PHP_METHOD(swoole_process, exec);

static void php_swoole_onSignal(int signo);

static uint32_t php_swoole_worker_round_id = 1;
static zval *signal_callback[SW_SIGNO_MAX];

static zend_class_entry swoole_process_ce;
zend_class_entry *swoole_process_class_entry_ptr;

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_void, 0, 0, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_construct, 0, 0, 1)
    ZEND_ARG_INFO(0, callback)
    ZEND_ARG_INFO(0, redirect_stdin_and_stdout)
    ZEND_ARG_INFO(0, pipe_type)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_wait, 0, 0, 0)
    ZEND_ARG_INFO(0, blocking)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_signal, 0, 0, 2)
    ZEND_ARG_INFO(0, signo)
    ZEND_ARG_INFO(0, callback)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_kill, 0, 0, 1)
    ZEND_ARG_INFO(0, pid)
    ZEND_ARG_INFO(0, sig)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_daemon, 0, 0, 0)
    ZEND_ARG_INFO(0, nochdir)
    ZEND_ARG_INFO(0, noclose)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_setaffinity, 0, 0, 1)
    ZEND_ARG_ARRAY_INFO(0, cpu_set, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_useQueue, 0, 0, 1)
    ZEND_ARG_INFO(0, msgkey)
    ZEND_ARG_INFO(0, mode)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_write, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_read, 0, 0, 0)
    ZEND_ARG_INFO(0, buf_size)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_push, 0, 0, 1)
    ZEND_ARG_INFO(0, data)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_pop, 0, 0, 0)
    ZEND_ARG_INFO(0, maxsize)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exit, 0, 0, 0)
    ZEND_ARG_INFO(0, ret_code)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_exec, 0, 0, 2)
    ZEND_ARG_INFO(0, execfile)
    ZEND_ARG_INFO(0, args)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_swoole_process_name, 0, 0, 1)
    ZEND_ARG_INFO(0, process_name)
ZEND_END_ARG_INFO()

static const zend_function_entry swoole_process_methods[] =
{
    PHP_ME(swoole_process, __construct, arginfo_swoole_process_construct, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
    PHP_ME(swoole_process, __destruct, arginfo_swoole_process_void, ZEND_ACC_PUBLIC | ZEND_ACC_DTOR)
    PHP_ME(swoole_process, wait, arginfo_swoole_process_wait, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, signal, arginfo_swoole_process_signal, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, kill, arginfo_swoole_process_kill, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, daemon, arginfo_swoole_process_daemon, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, setaffinity, arginfo_swoole_process_setaffinity, ZEND_ACC_PUBLIC | ZEND_ACC_STATIC)
    PHP_ME(swoole_process, useQueue, arginfo_swoole_process_useQueue, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, freeQueue, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, start, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, write, arginfo_swoole_process_write, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, close, arginfo_swoole_process_void, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, read, arginfo_swoole_process_read, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, push, arginfo_swoole_process_push, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, pop, arginfo_swoole_process_pop, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exit, arginfo_swoole_process_exit, ZEND_ACC_PUBLIC)
    PHP_ME(swoole_process, exec, arginfo_swoole_process_exec, ZEND_ACC_PUBLIC)
    PHP_FALIAS(name, swoole_set_process_name, arginfo_swoole_process_name)
    PHP_FE_END
};

void swoole_process_init(int module_number TSRMLS_DC)
{
    SWOOLE_INIT_CLASS_ENTRY(swoole_process_ce, "swoole_process", "Swoole\\Process", swoole_process_methods);
    swoole_process_class_entry_ptr = zend_register_internal_class(&swoole_process_ce TSRMLS_CC);

    /// class property declare;
    zend_declare_property_long(swoole_process_class_entry_ptr,ZEND_STRL("pid"),-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_process_class_entry_ptr,ZEND_STRL("pipe"),-1,ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_null(swoole_process_class_entry_ptr,ZEND_STRL("callback"),ZEND_ACC_PUBLIC TSRMLS_CC);
    zend_declare_property_long(swoole_process_class_entry_ptr, ZEND_STRL("id"), 0,ZEND_ACC_PUBLIC TSRMLS_CC);
    /**
     * 31 signal constants
     */
   zval *zpcntl;
   if (sw_zend_hash_find(&module_registry, ZEND_STRS("pcntl"), (void **) &zpcntl) == FAILURE)
   {
       REGISTER_LONG_CONSTANT("SIGHUP", (long) SIGHUP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGINT", (long) SIGINT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGQUIT", (long) SIGQUIT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGILL", (long) SIGILL, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTRAP", (long) SIGTRAP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGABRT", (long) SIGABRT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGBUS", (long) SIGBUS, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGFPE", (long) SIGFPE, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGKILL", (long) SIGKILL, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGUSR1", (long) SIGUSR1, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGSEGV", (long) SIGSEGV, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGUSR2", (long) SIGUSR2, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGPIPE", (long) SIGPIPE, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGALRM", (long) SIGALRM, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTERM", (long) SIGTERM, CONST_CS | CONST_PERSISTENT);
#ifdef SIGSTKFLT
       REGISTER_LONG_CONSTANT("SIGSTKFLT", (long) SIGSTKFLT, CONST_CS | CONST_PERSISTENT);
#endif
       REGISTER_LONG_CONSTANT("SIGCHLD", (long) SIGCHLD, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGCONT", (long) SIGCONT, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGSTOP", (long) SIGSTOP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTSTP", (long) SIGTSTP, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTTIN", (long) SIGTTIN, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGTTOU", (long) SIGTTOU, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGURG", (long) SIGURG, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGXCPU", (long) SIGXCPU, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGXFSZ", (long) SIGXFSZ, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGVTALRM", (long) SIGVTALRM, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGPROF", (long) SIGPROF, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGWINCH", (long) SIGWINCH, CONST_CS | CONST_PERSISTENT);
       REGISTER_LONG_CONSTANT("SIGIO", (long) SIGIO, CONST_CS | CONST_PERSISTENT);
#ifdef SIGPWR
       REGISTER_LONG_CONSTANT("SIGPWR", (long) SIGPWR, CONST_CS | CONST_PERSISTENT);
#endif
#ifdef SIGSYS
       REGISTER_LONG_CONSTANT("SIGSYS", (long) SIGSYS, CONST_CS | CONST_PERSISTENT);
#endif
   }
}

int php_swoole_process_start(zanWorker *process, zval *object TSRMLS_DC)
{
    process->pipe = process->pipe_worker;
    process->worker_pid = getpid();

    if (process->redirect_stdin && dup2(process->pipe, STDIN_FILENO) < 0)
    {
       zanWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
    }

    if (process->redirect_stdout && dup2(process->pipe, STDOUT_FILENO) < 0)
    {
        zanWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
    }

    if (process->redirect_stderr && dup2(process->pipe, STDERR_FILENO) < 0)
    {
        zanWarn("dup2() failed. Error: %s[%d]", strerror(errno), errno);
    }

    /// Close EventLoop
    if (ServerG.main_reactor)
    {
        ServerG.main_reactor->free(ServerG.main_reactor);
        ServerG.main_reactor = NULL;
        zanTrace("destroy reactor");
    }

    bzero(&ServerWG, sizeof(ServerWG));
    ServerG.process_pid = process->worker_pid;
    ServerG.process_type = 0;
    ServerWG.worker_id = process->worker_id;

    if (ServerG.timer.fd)
    {
        swTimer_free(&ServerG.timer);
        bzero(&ServerG.timer, sizeof(ServerG.timer));
    }

    swSignal_clear();

    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pid"), process->worker_pid TSRMLS_CC);
    zend_update_property_long(swoole_process_class_entry_ptr, object, ZEND_STRL("pipe"), process->pipe_worker TSRMLS_CC);

    zval *zcallback = sw_zend_read_property(swoole_process_class_entry_ptr, object, ZEND_STRL("callback"), 0 TSRMLS_CC);

    if (swoole_check_callable(zcallback TSRMLS_CC) < 0)
    {
        swoole_php_fatal_error(E_ERROR, "no callback.");
        return SW_ERR;
    }

    zval **args[1];
    zval *retval = NULL;
    args[0] = &object;

    if (sw_call_user_function_ex(EG(function_table), NULL, zcallback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        swoole_php_fatal_error(E_ERROR, "callback function error");
        return SW_ERR;
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (ServerG.main_reactor)
    {
        php_swoole_event_wait();
    }

    zend_bailout();
    return SW_OK;
}

/// safe signal
static void php_swoole_onSignal(int signo)
{
    SWOOLE_FETCH_TSRMLS;

    zval *callback = signal_callback[signo];
    if (!callback || ZVAL_IS_NULL(callback))
    {
        return;
    }

    zval *zsigno = NULL;
    SW_MAKE_STD_ZVAL(zsigno);
    ZVAL_LONG(zsigno, signo);

    zval **args[1];
    args[0] = &zsigno;
    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, callback, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("user_signal handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    sw_zval_ptr_dtor(&zsigno);
}

static PHP_METHOD(swoole_process, __construct)
{
    ///only cli env
    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process must run at php_cli environment.");
        RETURN_FALSE;
    }

    zanWorker *process = swoole_get_object(getThis());
    if (process)
    {
        swoole_php_fatal_error(E_ERROR, "swoole_process has been constructed.");
        RETURN_FALSE;
    }

    zend_bool redirect_stdin_and_stdout = 0;
    long pipe_type = 2;
    zval *callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|bl", &callback, &redirect_stdin_and_stdout, &pipe_type))
    {
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        RETURN_FALSE;
    }

    process = emalloc(sizeof(zanWorker));
    bzero(process, sizeof(zanWorker));

    process->worker_id = php_swoole_worker_round_id++;
    php_swoole_worker_round_id = (php_swoole_worker_round_id == 0)? 1:php_swoole_worker_round_id;

    if (redirect_stdin_and_stdout)
    {
        process->redirect_stdin = 1;
        process->redirect_stdout = 1;
        process->redirect_stderr = 1;
        pipe_type = 2;
    }

    if (pipe_type > 0)
    {
        zanPipe *_pipe = emalloc(sizeof(zanWorker));
        int socket_type = pipe_type == 1 ? SOCK_STREAM : SOCK_DGRAM;
        //if (swPipeUnsock_create(_pipe, 1, socket_type) < 0)
        if (zanPipe_create(_pipe, ZAN_UNSOCK, 0, socket_type) < 0)
        {
            swoole_efree(_pipe);
            swoole_efree(process);
            RETURN_FALSE;
        }

        process->pipe_object = _pipe;
        process->pipe_master = _pipe->getFd(_pipe, ZAN_PIPE_MASTER);
        process->pipe_worker = _pipe->getFd(_pipe, ZAN_PIPE_WORKER);
        process->pipe = process->pipe_master;

        zend_update_property_long(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("pipe"), process->pipe_master TSRMLS_CC);
    }

    swoole_set_object(getThis(), process);
    zend_update_property(swoole_process_class_entry_ptr, getThis(), ZEND_STRL("callback"), callback TSRMLS_CC);
}

static PHP_METHOD(swoole_process, __destruct)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process)
    {
        return ;
    }

    swoole_set_object(getThis(),NULL);

    zanPipe *_pipe = process->pipe_object;
    if (_pipe)
    {
        _pipe->close(_pipe);
        swoole_efree(_pipe);
    }
    if (process->queue)
    {
        process->queue->close(process->queue);
        swoole_efree(process->queue);
    }

    swoole_efree(process);
}

static PHP_METHOD(swoole_process, wait)
{
    int status;
    zend_bool blocking = 1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|b", &blocking))
    {
        RETURN_FALSE;
    }

    int options = (!blocking)? WNOHANG:0;
    pid_t pid = swWaitpid(-1, &status, options);
    if (pid <= 0)
    {
        RETURN_FALSE;
    }

    array_init(return_value);
    add_assoc_long(return_value, "pid", pid);
    add_assoc_long(return_value, "code", WEXITSTATUS(status));
    add_assoc_long(return_value, "signal", WTERMSIG(status));
}

static PHP_METHOD(swoole_process, useQueue)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process)
    {
        RETURN_FALSE;
    }

    long msgkey = 0;
    long mode = 2;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|ll", &msgkey, &mode))
    {
        RETURN_FALSE;
    }

    if (msgkey <= 0)
    {
#if PHP_MAJOR_VERSION >= 7
        msgkey = ftok(zend_get_executed_filename(), 0);
#else
        msgkey = ftok(zend_get_executed_filename(TSRMLS_C), 0);
#endif
    }

    zanMsgQueue *queue = emalloc(sizeof(zanMsgQueue));
    if (zanMsgQueue_create(queue, 1, msgkey, 0) < 0)
    {
        RETURN_FALSE;
    }

    queue->deleted = 0;
    process->queue = queue;
    process->ipc_mode = mode;
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, freeQueue)
{
    zanWorker *process = swoole_get_object(getThis());
    if (process && process->queue)
    {
        process->queue->deleted = 1;
        process->queue->close(process->queue);
        swoole_efree(process->queue);
        process->queue = NULL;
        RETURN_TRUE;
    }
    else
    {
        RETURN_FALSE;
    }
}

static PHP_METHOD(swoole_process, kill)
{
    long pid;
    long sig = SIGTERM;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l|l", &pid, &sig))
    {
        RETURN_FALSE;
    }

    int ret = swKill((int) pid, (int) sig);
    if (ret < 0)
    {
        if (!(sig == 0 && errno == ESRCH))
        {
            zanWarn("kill(%d, %d) failed. Error: %s[%d]", (int) pid, (int) sig, strerror(errno), errno);
        }
        RETURN_FALSE;
    }
    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, signal)
{
    zval *callback = NULL;
    long signo = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "lz", &signo, &callback))
    {
        return;
    }

    if (!SWOOLE_G(cli))
    {
        swoole_php_fatal_error(E_ERROR, "cannot use swoole_process::signal here.");
        RETURN_FALSE;
    }

    if (ServerGS->started && (signo == SIGTERM || signo == SIGALRM))
    {
        zanWarn("cannot use swoole_process::signal in swoole_server.");
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        callback = signal_callback[signo];
        if (!callback)
        {
            zanWarn("no callback.");
            RETURN_FALSE;

        }

//        sw_zval_ptr_dtor(&callback);
        swSignal_add(signo, NULL);
        RETURN_TRUE;
    }

#if PHP_MAJOR_VERSION >= 7
    zval *tmp = emalloc(sizeof(zval));
    memcpy(tmp, callback, sizeof(zval));
    callback = tmp;
#endif

    sw_zval_add_ref(&callback);
    if (signal_callback[signo])
    {
        zval* _callback = signal_callback[signo];
        sw_zval_ptr_dtor(&_callback);
    }

    signal_callback[signo] = callback;

#if PHP_MAJOR_VERSION >= 7 || (PHP_MAJOR_VERSION >= 5 && PHP_MINOR_VERSION >= 4)
    ServerG.use_signalfd = ServerG.enable_signalfd;
#else
    ServerG.use_signalfd = 0;
#endif

    php_swoole_check_reactor();

    ///  for swSignal fd_setup
    ServerG.main_reactor->check_signalfd = 1;
    swSignal_add(signo, php_swoole_onSignal);

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, start)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || (process->worker_pid > 0 && swKill(process->worker_pid, 0) == 0))
    {
        zanWarn("process is already started.");
        RETURN_FALSE;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        zanWarn("fork() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    else if (pid > 0)
    {
        process->worker_pid = pid;
        process->child_process = 0;
        zend_update_property_long(swoole_server_class_entry_ptr, getThis(), ZEND_STRL("pid"), process->worker_pid TSRMLS_CC);
        RETURN_LONG(pid);
    }
    else
    {
        process->child_process = 1;
        SW_CHECK_RETURN(php_swoole_process_start(process, getThis() TSRMLS_CC));
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, read)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || process->pipe == 0)
    {
        zanWarn("process not exist or not pipe, can not use read");
        RETURN_FALSE;
    }

    long buf_size = 8192;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &buf_size))
    {
        RETURN_FALSE;
    }

    buf_size = (buf_size > 65536)? 65535:buf_size;

    char *buf = emalloc(buf_size + 1);
    int ret = read(process->pipe, buf, buf_size);
    if (ret < 0)
    {
        swoole_efree(buf);
        if (errno != EINTR)
        {
            zanWarn("failed. Error: %s[%d]", strerror(errno), errno);
        }

        RETURN_FALSE;
    }

    buf[ret] = 0;
    SW_ZVAL_STRINGL(return_value, buf, ret, 0);

#if PHP_MAJOR_VERSION >= 7
    swoole_efree(buf);
#endif
}

static PHP_METHOD(swoole_process, write)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || process->pipe == 0)
    {
        zanWarn("process not exist or not pipe, can not use write");
        RETURN_FALSE;
    }

    char *data = NULL;
    zend_size_t data_len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &data_len))
    {
        RETURN_FALSE;
    }

    if (data_len < 1 || !data)
    {
        zanWarn("send data empty.");
        RETURN_FALSE;
    }

    //async write or sync write.
    int ret = ServerG.main_reactor? ServerG.main_reactor->write(ServerG.main_reactor, process->pipe, data, (size_t) data_len):
                    swSocket_write_blocking(process->pipe, data, data_len);

    if (ret < 0)
    {
        zanWarn("write() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    ZVAL_LONG(return_value, ret);
}

static PHP_METHOD(swoole_process, push)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || !process->queue)
    {
        zanWarn("process not exist or have not msgqueue, can not use push.");
        RETURN_FALSE;
    }

    struct
    {
        long type;
        char data[65536];
    } message;

    char *data = NULL;
    zend_size_t length = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &data, &length))
    {
        RETURN_FALSE;
    }

    if (length <= 0 || !data)
    {
        zanWarn("data empty.");
        RETURN_FALSE;
    }

    if (length >= sizeof(message.data))
    {
        zanWarn("data too big.");
        RETURN_FALSE;
    }

    message.type = process->worker_pid;
    memcpy(message.data, data, length);

    //if (swMsgQueue_push(process->queue, (swQueue_data *)&message, length) < 0)
    if (process->queue->push(process->queue, (zanQueue_Data *)&message, length) < 0)
    {
        zanWarn("msgsnd() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, pop)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || !process->queue)
    {
        zanWarn("process not exist or have not msgqueue, can not use push");
        RETURN_FALSE;
    }

    long maxsize = SW_MSGMAX;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &maxsize))
    {
        RETURN_FALSE;
    }

    maxsize = (maxsize > SW_MSGMAX)? SW_MSGMAX:(maxsize <= 0? 8192:maxsize);

    struct
    {
        long type;
        char data[SW_MSGMAX];
    } message;

    message.type = (process->ipc_mode == 2)? 0:process->worker_id;
    //int n = swMsgQueue_pop(process->queue, (swQueue_data *) &message, maxsize);
    int n = process->queue->pop(process->queue, (zanQueue_Data *) &message, maxsize);
    if (n < 0)
    {
        zanWarn("msgrcv() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }

    SW_RETURN_STRINGL(message.data, n, 1);
}

static PHP_METHOD(swoole_process, exec)
{
    char *execfile = NULL;
    zend_size_t execfile_len = 0;
    zval *args = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sa", &execfile, &execfile_len, &args))
    {
        RETURN_FALSE;
    }

    if (execfile_len < 1 || !execfile)
    {
        zanWarn("execfile name empty.");
        RETURN_FALSE;
    }

    int exec_argc = php_swoole_array_length(args);
    char **exec_args = emalloc(sizeof(char*) * (exec_argc + 2));
    exec_args[0] = strdup(execfile);

    int index = 1;
    zval *value = NULL;
    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(args), value)
        if (sw_convert_to_string(value) < 0)
        {
            zanWarn("convert to string failed.");
            RETURN_FALSE;
        }

        sw_zval_add_ref(&value);
        exec_args[index] = Z_STRVAL_P(value);
        index++;
    SW_HASHTABLE_FOREACH_END();
    exec_args[index] = NULL;

    if (execv(execfile, exec_args) < 0)
    {
        zanWarn("execv(%s) failed. Error: %s[%d]", execfile, strerror(errno), errno);
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

static PHP_METHOD(swoole_process, daemon)
{
    zend_bool nochdir = 1;
    zend_bool noclose = 1;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|bb", &nochdir, &noclose))
    {
        RETURN_FALSE;
    }

    RETURN_BOOL(swoole_daemon(nochdir, noclose) == 0);
}

static PHP_METHOD(swoole_process, setaffinity)
{
#ifdef HAVE_CPU_AFFINITY
    zval *array = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "a", &array))
    {
        RETURN_FALSE;
    }

    if (!array || Z_ARRVAL_P(array)->nNumOfElements == 0 || Z_ARRVAL_P(array)->nNumOfElements > ZAN_CPU_NUM)
    {
        zanWarn("array number of CPU between 0 and %d.",ZAN_CPU_NUM);
        RETURN_FALSE;
    }

    zval *value = NULL;
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);

    SW_HASHTABLE_FOREACH_START(Z_ARRVAL_P(array), value)
        convert_to_long(value);
        if (Z_LVAL_P(value) >= ZAN_CPU_NUM)
        {
            zanWarn("invalid cpu id [%d]", (int) Z_LVAL_P(value));
            RETURN_FALSE;
        }
        CPU_SET(Z_LVAL_P(value), &cpu_set);
    SW_HASHTABLE_FOREACH_END();

    if (sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set) < 0)
    {
        swoole_php_sys_error(E_WARNING, "sched_setaffinity() failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
#else
    RETURN_FALSE;
#endif
}

static PHP_METHOD(swoole_process, exit)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || getpid() != process->worker_pid)
    {
        zanWarn("process not exits or not current process.");
        RETURN_FALSE;
    }

    long ret_code = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "|l", &ret_code))
    {
        RETURN_FALSE;
    }

    if (ret_code < 0 || ret_code > 255)
    {
        zanWarn("exit ret_code range is [>0 and <255] ");
        ret_code = 1;
    }

    close(process->pipe);

    if (ServerG.main_reactor != NULL)
    {
        ServerG.running = 0;
    }

    if (ret_code == 0)
    {
        zend_bailout();
    }
    else
    {
        exit(ret_code);
    }
}

static PHP_METHOD(swoole_process, close)
{
    zanWorker *process = swoole_get_object(getThis());
    if (!process || process->pipe == 0)
    {
        zanWarn("process not exist or have not pipe, can not use close");
        RETURN_FALSE;
    }

    int ret = process->pipe_object->close(process->pipe_object);
    if (ret < 0)
    {
        zanWarn("close() failed. Error: %s[%d]", strerror(errno), errno);
        RETURN_FALSE;
    }
    else
    {
        process->pipe = 0;
        swoole_efree(process->pipe_object);
        process->pipe_object = NULL;
    }

    ZVAL_LONG(return_value, ret);
}
