/*
 +----------------------------------------------------------------------+
 | Zan                                                                  |
 +----------------------------------------------------------------------+
 | Copyright (c) 2012-2016 Swoole Team <http://github.com/swoole>       |
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
 | Author: Tianfeng Han  <mikan.tenny@gmail.com>                        |
 |         Zan Group   <zan@zanphp.io>                                  |
 +----------------------------------------------------------------------+
 */

#include "php_swoole.h"
#include "swSignal.h"

#include "zanLog.h"

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _cb_read;
    zval _cb_write;
    zval _socket;
#endif
    zval *cb_read;
    zval *cb_write;
    zval *socket;
} php_reactor_fd;

typedef struct
{
#if PHP_MAJOR_VERSION >= 7
    zval _callback;
#endif
    zval *callback;
} php_defer_callback;

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event);
static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event);
static int php_swoole_event_onError(swReactor *reactor, swEvent *event);
static void php_swoole_event_onDefer(void *_cb);

static int swoole_convert_to_fd(zval *zfd);

static sw_inline void defer_free(void* data)
{
    php_reactor_fd* ev_set = (php_reactor_fd*)data;

    if (ev_set && ev_set->cb_read) {sw_zval_ptr_dtor(&(ev_set->cb_read));ev_set->cb_read = NULL;}
    if (ev_set && ev_set->cb_write)  {sw_zval_ptr_dtor(&(ev_set->cb_write));ev_set->cb_write = NULL;}
    if (ev_set && ev_set->socket) {sw_zval_ptr_dtor(&(ev_set->socket));ev_set->socket = NULL;}
    swoole_efree(ev_set);
}

static int php_swoole_event_onRead(swReactor *reactor, swEvent *event)
{

    SWOOLE_FETCH_TSRMLS;

    php_reactor_fd *fd = event->socket->object;
    if (!fd || !fd->socket || !fd->cb_read)
    {
        zanWarn("read callback is null,user error");
        ServerG.main_reactor->del(ServerG.main_reactor, event->fd);
        return ZAN_OK;
    }

    zval **args[1];
    args[0] = &fd->socket;
    zval *retval = NULL;

    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_read, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_event: onRead handler error.");
        ServerG.main_reactor->del(ServerG.main_reactor, event->fd);
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

static int php_swoole_event_onWrite(swReactor *reactor, swEvent *event)
{

    SWOOLE_FETCH_TSRMLS;

    php_reactor_fd *fd = event->socket->object;
    if (!fd || !fd->socket || !fd->cb_write)
    {
        return swReactor_onWrite(reactor, event);
    }

    zval **args[1];
    args[0] = &fd->socket;
    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, fd->cb_write, &retval, 1, args, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_event: onWrite handler error");
        ServerG.main_reactor->del(ServerG.main_reactor, event->fd);
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    return ZAN_OK;
}

static int php_swoole_event_onError(swReactor *reactor, swEvent *event)
{
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
    {
        zanError("swoole_event->onError[1]: getsockopt[sock=%d] failed.", event->fd);
    }

    if (error != 0)
    {
        zanError("swoole_event->onError[1]: socket error. Error: %s [%d]", strerror(error), error);
    }

    swoole_efree(event->socket->object);
    event->socket->object = NULL;
    event->socket->active = 0;

    ServerG.main_reactor->del(ServerG.main_reactor, event->fd);

    return ZAN_OK;
}

static void php_swoole_event_onDefer(void *_cb)
{
    SWOOLE_FETCH_TSRMLS;

    php_defer_callback *defer = _cb;

    zval *retval = NULL;
    if (sw_call_user_function_ex(EG(function_table), NULL, defer->callback, &retval, 0, NULL, 0, NULL TSRMLS_CC) == FAILURE)
    {
        zanWarn("swoole_event: defer handler error");
    }

    if (EG(exception))
    {
        zend_exception_error(EG(exception), E_ERROR TSRMLS_CC);
    }

    if (retval)
    {
        sw_zval_ptr_dtor(&retval);
    }

    if (defer->callback)
    {
        sw_zval_ptr_dtor(&defer->callback);
        defer->callback = NULL;
    }

    swoole_efree(defer);
}

void php_swoole_event_init(void)
{
    ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_USER | SW_EVENT_READ, php_swoole_event_onRead);
    ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_USER | SW_EVENT_WRITE, php_swoole_event_onWrite);
    ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_USER | SW_EVENT_ERROR, php_swoole_event_onError);
}

void php_swoole_event_wait()
{
    SWOOLE_FETCH_TSRMLS;

    if (ServerWG.in_client == 1 && ServerWG.reactor_ready == 0 && ServerG.running)
    {
        ServerWG.reactor_ready = 1;

#ifdef HAVE_SIGNALFD
        if (ServerG.main_reactor->check_signalfd)
        {
            swSignalfd_setup(ServerG.main_reactor);
        }
#endif
        int ret = ServerG.main_reactor->wait(ServerG.main_reactor, NULL);
        if (ret < 0)
        {
            swoole_php_fatal_error(E_ERROR, "reactor wait failed. Error: %s [%d]", strerror(errno), errno);
        }
    }
}

static int swoole_convert_to_fd(zval *zfd)
{

    SWOOLE_FETCH_TSRMLS;
    if (!zfd || Z_TYPE_P(zfd) == IS_NULL)
    {
        zanWarn("zfd is null.");
        return ZAN_ERR;
    }

    int socket_fd = -1;
    if (SW_Z_TYPE_P(zfd) == IS_RESOURCE)
    {
        php_stream *stream = NULL;
        if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(stream, php_stream*, &zfd, -1, NULL, php_file_le_stream()))
        {
            if (php_stream_cast(stream, PHP_STREAM_AS_FD_FOR_SELECT | PHP_STREAM_CAST_INTERNAL, (void* )&socket_fd, 1) != SUCCESS || socket_fd < 0)
            {
                return ZAN_ERR;
            }
        }
        else
        {
#ifdef SW_USE_SOCKETS
            php_socket *php_sock = NULL;
            if (SW_ZEND_FETCH_RESOURCE_NO_RETURN(php_sock, php_socket*, &zfd, -1, NULL, php_sockets_le_socket()))
            {
                socket_fd = php_sock->bsd_socket;

            }
            else
            {
                zanWarn("fd argument must be either valid PHP stream or valid PHP socket resource");
                return ZAN_ERR;
            }
#else
            zanWarn("fd argument must be valid PHP stream resource");
            return ZAN_ERR;
#endif
        }
    }
    else if (SW_Z_TYPE_P(zfd) == IS_LONG)
    {
        socket_fd = Z_LVAL_P(zfd);
    }

    return socket_fd < 0? SW_ERR:socket_fd;
}

#ifdef SW_USE_SOCKETS
php_socket* swoole_convert_to_socket(int sock)
{
    SWOOLE_FETCH_TSRMLS;
    if (sock < 0)
    {
        return NULL;
    }

    php_socket *socket_object = emalloc(sizeof(php_socket));
    bzero(socket_object, sizeof(php_socket));
    socket_object->bsd_socket = sock;
    socket_object->blocking = 1;

    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(sock, (struct sockaddr*) &addr, &addr_len) == 0)
    {
        socket_object->type = addr.ss_family;
    }
    else
    {
        swoole_php_sys_error(E_WARNING, "unable to obtain socket family");
error:
        swoole_efree(socket_object);
        return NULL;
    }

    int t = fcntl(sock, F_GETFL);
    if (t < 0)
    {
        swoole_php_sys_error(E_WARNING, "unable to obtain blocking state");
        goto error;
    }
    else
    {
        socket_object->blocking = !(t & O_NONBLOCK);
    }

    return socket_object;
}
#endif

PHP_FUNCTION(swoole_event_add)
{
    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd = NULL;
    long event_flag = 0;

    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag))
    {
        RETURN_FALSE;
    }

    int checkRCb = swoole_check_callable(cb_read TSRMLS_CC);
    int checkWCb = swoole_check_callable(cb_write TSRMLS_CC);
    if ((event_flag & SW_EVENT_READ) && checkRCb < 0)
    {
        zanWarn("swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && checkWCb < 0)
    {
        zanWarn("swoole_event: no write callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        zanWarn("unknow type.");
        RETURN_FALSE;
    }

    if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
    {
        zanWarn("socket fd [%d] is std input,but used write event", socket_fd);
        RETURN_FALSE;
    }

    php_swoole_check_reactor();
    swConnection *socket = swReactor_get(ServerG.main_reactor, socket_fd);
    if (!socket || socket->active)
    {
        zanWarn("socket[%d] is not found in the reactor or socket has been actived.", socket_fd);
        RETURN_FALSE;
    }

    php_reactor_fd *reactor_fd = (socket->object)? socket->object:emalloc(sizeof(php_reactor_fd));
    if (!reactor_fd)
    {
        zanWarn("alloc global memory failed");
        RETURN_FALSE;
    }


    reactor_fd->cb_read = (checkRCb < 0)? NULL:cb_read;
    reactor_fd->cb_write = (checkWCb < 0)? NULL:cb_write;
    reactor_fd->socket = zfd;

    sw_zval_add_ref(&zfd);
    sw_copy_to_stack(reactor_fd->socket,reactor_fd->_socket);
    if (checkRCb >= 0)
    {
        sw_zval_add_ref(&cb_read);
        sw_copy_to_stack(reactor_fd->cb_read,reactor_fd->_cb_read);
    }

    if (checkWCb >= 0)
    {
        sw_zval_add_ref(&cb_write);
        sw_copy_to_stack(reactor_fd->cb_write,reactor_fd->_cb_write);
    }

    swSetNonBlock(socket_fd,1); //must be nonblock

    if (ServerG.main_reactor->add(ServerG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        zanWarn("swoole_event_add failed.");
        RETURN_FALSE;
    }

    socket->object = reactor_fd;
    socket->active = 1;

    RETURN_LONG(socket_fd);
}

PHP_FUNCTION(swoole_event_write)
{
    if (!ServerG.main_reactor)
    {
        zanWarn("reactor no ready, cannot swoole_event_write.");
        RETURN_FALSE;
    }

    zval *zfd = NULL;
    char *data = NULL;
    zend_size_t len = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs", &zfd, &data, &len))
    {
        RETURN_FALSE;
    }

    if (!data || len <= 0)
    {
        zanWarn("data empty.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        zanWarn("unknow type.");
        RETURN_FALSE;
    }

    if (ServerG.main_reactor->write(ServerG.main_reactor, socket_fd, data, len) < 0)
    {
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_set)
{
    if (!ServerG.main_reactor)
    {
        zanWarn("reactor no ready, cannot swoole_event_set.");
        RETURN_FALSE;
    }

    zval *cb_read = NULL;
    zval *cb_write = NULL;
    zval *zfd = NULL;
    long event_flag = 0;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z|zzl", &zfd, &cb_read, &cb_write, &event_flag))
    {
        RETURN_FALSE;
    }

    int checkRCb = swoole_check_callable(cb_read TSRMLS_CC);
    int checkWCb = swoole_check_callable(cb_write TSRMLS_CC);
    if ((event_flag & SW_EVENT_READ) && checkRCb < 0)
    {
        zanWarn("swoole_event: no read callback.");
        RETURN_FALSE;
    }

    if ((event_flag & SW_EVENT_WRITE) && checkWCb < 0)
    {
        zanWarn("swoole_event: no write callback.");
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        zanWarn("unknow type.");
        RETURN_FALSE;
    }

    if (socket_fd == 0 && (event_flag & SW_EVENT_WRITE))
    {
        zanWarn("invalid socket fd [%d].", socket_fd);
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(ServerG.main_reactor, socket_fd);
    if (!socket || !socket->active)
    {
        zanWarn("socket[%d] is not found in the reactor or not actice.", socket_fd);
        RETURN_FALSE;
    }

    php_reactor_fd *ev_set = socket->object;
    if (!ev_set)
    {
        zanWarn("socket[%d] has not been set. should set first.",socket_fd);
        RETURN_FALSE;
    }

    if (checkRCb >= 0)
    {
        if (ev_set->cb_read) sw_zval_ptr_dtor(&(ev_set->cb_read));
        ev_set->cb_read = cb_read;
        sw_zval_add_ref(&cb_read);
        sw_copy_to_stack(ev_set->cb_read,ev_set->_cb_read);
    }

    if (checkWCb >= 0)
    {
        if (ev_set->cb_write)  sw_zval_ptr_dtor(&(ev_set->cb_write));
        ev_set->cb_write = cb_write;
        sw_zval_add_ref(&cb_write);
        sw_copy_to_stack(ev_set->cb_write,ev_set->_cb_write);
    }

    if (ServerG.main_reactor->set(ServerG.main_reactor, socket_fd, SW_FD_USER | event_flag) < 0)
    {
        zanWarn("swoole_event_set failed.");
        RETURN_FALSE;
    }

    RETURN_TRUE;
}

PHP_FUNCTION(swoole_event_del)
{
    if (!ServerG.main_reactor)
    {
        zanWarn("reactor no ready, cannot swoole_event_del.");
        RETURN_FALSE;
    }

    zval *zfd = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &zfd))
    {
        RETURN_FALSE;
    }

    int socket_fd = swoole_convert_to_fd(zfd);
    if (socket_fd < 0)
    {
        zanWarn("unknow type.");
        RETURN_FALSE;
    }

    swConnection *socket = swReactor_get(ServerG.main_reactor, socket_fd);
    if (!socket)
    {
        zanWarn("socket[%d] is not found in the reactor",socket_fd);
        RETURN_FALSE;
    }

    php_reactor_fd *ev_set = socket->object;
    socket->object = NULL;
    socket->active = 0;

    if (ev_set)
    {
        ServerG.main_reactor->defer(ServerG.main_reactor,defer_free,ev_set);
    }

    int ret = (socket->fd >= 0)? ServerG.main_reactor->del(ServerG.main_reactor, socket_fd):SW_ERR;
    SW_CHECK_RETURN(ret);
}

PHP_FUNCTION(swoole_event_defer)
{
    if (!ServerG.main_reactor)
    {
        zanWarn("reactor no ready, cannot swoole_event_defer.");
        RETURN_FALSE;
    }

    zval *callback = NULL;
    if (FAILURE == zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "z", &callback))
    {
        RETURN_FALSE;
    }

    if (swoole_check_callable(callback TSRMLS_CC) < 0)
    {
        return;
    }

    php_defer_callback *defer = emalloc(sizeof(php_defer_callback));
    if (!defer)
    {
        zanWarn("alloc global memory failed");
        return;
    }

    defer->callback = callback;
    sw_zval_add_ref(&callback);
    sw_copy_to_stack(defer->callback,defer->_callback);

    SW_CHECK_RETURN(ServerG.main_reactor->defer(ServerG.main_reactor, php_swoole_event_onDefer, defer));
}

PHP_FUNCTION(swoole_event_exit)
{
    /// 只针对client 支持事件循环退出
    if (ServerWG.in_client == 1)
    {
        if (ServerG.main_reactor)
        {
            ServerG.main_reactor->running = 0;
        }

        ServerG.running = 0;
    }
}

PHP_FUNCTION(swoole_event_wait)
{
    if (!ServerG.main_reactor)
    {
        return;
    }

    php_swoole_event_wait();
}
