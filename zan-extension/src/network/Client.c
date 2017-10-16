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


#include "swReactor.h"
#include "swDNS.h"
#include "swClient.h"

#include "zanLog.h"

static int swClient_inet_addr(swClient *cli, char *host, int port);
static int swClient_tcp_connect_sync(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_tcp_connect_async(swClient *cli, char *host, int port, double timeout, int nonblock);

static int swClient_tcp_send_sync(swClient *cli, char *data, int length, int flags);
static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags);
static int swClient_udp_sendto(swClient *cli, char *data, int length, int flags);
static int swClient_udp_send(swClient *cli, char *data, int length, int flags);

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename);
static int swClient_tcp_sendfile_async(swClient *cli, char *filename);
static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flags);
static int swClient_udp_connect(swClient *cli, char *host, int port, double _timeout, int udp_connect);
static int swClient_udp_recv(swClient *cli, char *data, int len, int waitall);
static int swClient_socket_free(swClient *cli);
static int swClient_close(swClient *cli);

static int swClient_onDgramRead(swReactor *reactor, swEvent *event);
static int swClient_onStreamRead(swReactor *reactor, swEvent *event);
static int swClient_onWrite(swReactor *reactor, swEvent *event);
static int swClient_onError(swReactor *reactor, swEvent *event);

static int isset_event_handle = 0;

int swClient_create(swClient *cli, int type, int async)
{
    int _type,_domain;
    int sockfd = swSocket_create(type,&_type,&_domain);
    if (sockfd < 0)
    {
        return ZAN_ERR;
    }

    cli->socket = async? swReactor_get(ServerG.main_reactor, sockfd) : sw_malloc(sizeof(swConnection));
    if (!cli->socket)
    {
        close(sockfd);
        zanError("malloc(%d) failed.", (int ) sizeof(swConnection));
        return ZAN_ERR;
    }

    cli->type = type;
    cli->_sock_type = _type;
    cli->_sock_domain = _domain;

    bzero(cli->socket, sizeof(swConnection));
    cli->socket->fd = sockfd;
    cli->socket->object = cli;
    cli->socket->socket_type = type;

    cli->buffer_input_size = SW_CLIENT_BUFFER_SIZE;
    cli->type = type;
    cli->async = async;

    if (cli->async)
    {
        swSetNonBlock(cli->socket->fd,1);
        if (isset_event_handle == 0)
        {
            ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_READ, swClient_onStreamRead);
            ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_DGRAM_CLIENT | SW_EVENT_READ, swClient_onDgramRead);
            ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_WRITE, swClient_onWrite);
            ServerG.main_reactor->setHandle(ServerG.main_reactor, SW_FD_STREAM_CLIENT | SW_EVENT_ERROR, swClient_onError);
            isset_event_handle = 1;
        }
    }

    if (swSocket_is_stream(cli->type))
    {
        cli->recv = swClient_tcp_recv_no_buffer;
        cli->connect = (cli->async)? swClient_tcp_connect_async : swClient_tcp_connect_sync;
        cli->send = (cli->async)? swClient_tcp_send_async:swClient_tcp_send_sync;
        cli->sendfile = (cli->async)? swClient_tcp_sendfile_async:swClient_tcp_sendfile_sync;
    }
    else
    {
        cli->connect = swClient_udp_connect;
        cli->recv = swClient_udp_recv;
        cli->send = swClient_udp_sendto;
    }

    cli->close = swClient_close;
    return ZAN_OK;
}

int swClient_free(swClient* cli)
{
    if (!cli)
    {
        return ZAN_OK;
    }

    cli->close(cli);

    //clear buffer
    if (cli->buffer)
    {
        swString_free(cli->buffer);
        cli->buffer = NULL;
    }

    return ZAN_OK;
}

#ifdef SW_USE_OPENSSL
int swClient_enable_ssl_encrypt(swClient *cli)
{
    cli->ssl_context = swSSL_get_context(&cli->ssl_option);
    if (cli->ssl_context == NULL)
    {
        return ZAN_ERR;
    }
    cli->socket->ssl_send = 1;
#if defined(SW_USE_HTTP2) && defined(SW_USE_OPENSSL) && OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (cli->http2)
    {
        if (SSL_CTX_set_alpn_protos(cli->ssl_context, (const unsigned char *) "\x02h2", 3) < 0)
        {
            return ZAN_ERR;
        }
    }
#endif
    return ZAN_OK;
}

int swClient_ssl_handshake(swClient *cli)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (!cli->socket->ssl)
    {
        if (swSSL_create(cli->socket, cli->ssl_context, SW_SSL_CLIENT) < 0)
        {
            return ZAN_ERR;
        }
    }
    if (swSSL_connect(cli->socket) < 0)
    {
        return ZAN_ERR;
    }
    return ZAN_OK;
}
#endif

static int swClient_socket_free(swClient *cli)
{
    if (!cli || !cli->socket) {
        return ZAN_OK;
    }

    if (cli->socket->out_buffer)
    {
        swBuffer_free(cli->socket->out_buffer);
        cli->socket->out_buffer = NULL;
    }
    if (cli->socket->in_buffer)
    {
        swBuffer_free(cli->socket->in_buffer);
        cli->socket->in_buffer = NULL;
    }

    bzero(cli->socket, sizeof(swConnection));
    if (cli->async)
    {
        cli->socket->removed = 1;
        cli->socket->closed = 1;
        cli->socket = NULL;
    }
    else
    {
        sw_free(cli->socket);
    }

    return ZAN_OK;
}

static int swClient_close(swClient *cli)
{
    if (!cli || !cli->socket) {
        return ZAN_OK;
    }

    int fd = cli->socket->fd;
    int needClosefd = !cli->socket->closed;
#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->ssl_context)
    {
        if (cli->socket->ssl)
        {
            swSSL_close(cli->socket);
        }
        swSSL_free_context(cli->ssl_context);
        if (cli->ssl_option.cert_file)
        {
            sw_free(cli->ssl_option.cert_file);
        }
        if (cli->ssl_option.key_file)
        {
            sw_free(cli->ssl_option.key_file);
        }
        if (cli->ssl_option.passphrase)
        {
            sw_free(cli->ssl_option.passphrase);
        }
    }
#endif

    if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(cli->socket->info.addr.un.sun_path);
        cli->type = SW_SOCK_UNKNOW;
    }

    cli->socket->closed = 1;
    int needCallback = 0;
    if (cli->async)
    {
        //remove from reactor
        if (!cli->socket->removed && ServerG.main_reactor)
        {
            ServerG.main_reactor->del(ServerG.main_reactor, fd);
        }

        //onClose callback
        if (cli->socket->active && cli->onClose)
        {
            cli->socket->active = 0;
            needCallback = 1;
        }
    }
    else
    {
        cli->socket->active = 0;
    }

    swClient_socket_free(cli);

    if (needCallback)
    {
        cli->onClose(cli);
    }

    if (needClosefd)
    {
        close(fd);
    }

    return ZAN_OK;
}

static int swClient_tcp_connect_sync(swClient *cli, char *host, int port, double timeout, int nonblock)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    int ret = -1;
    cli->timeout = timeout;
    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return ZAN_ERR;
    }

    if (cli->timeout > 0)
    {
        swSocket_set_timeout(cli->socket->fd,cli->timeout);
    }

    if (nonblock || cli->timeout > 0)
    {
        swSetNonBlock(cli->socket->fd,1);
    }

    ret = connect(cli->socket->fd, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
    if (ret < 0 && errno != EINPROGRESS)
    {
        return ret;
    }

    int timeout_set = (cli->timeout > 0 && !nonblock)?cli->timeout*1000:-1;
    if ((ret < 0 && errno == EINPROGRESS) && timeout_set > 0 &&
            swSocket_wait(cli->socket->fd,timeout_set,SW_EVENT_WRITE) >= 0)
    {
        ret = ZAN_OK;
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(cli->socket->fd,SOL_SOCKET,SO_ERROR,&error,&len) < 0 || error != 0)
        {
            zanError("get socket option %s\n",error? strerror(error):"error");
            ret = ZAN_ERR;
        }
    }

    if (ret >= 0)
    {
        if (cli->timeout > 0 && !nonblock)
        {
            swSetNonBlock(cli->socket->fd,0);
        }

#ifdef SW_USE_OPENSSL
        if (cli->open_ssl)
        {
            if (swClient_enable_ssl_encrypt(cli) < 0 || swClient_ssl_handshake(cli) < 0)
            {
                return ZAN_ERR;
            }
        }
#endif
        cli->socket->active = 1;
    }

    return ret;
}

/// 异步方式，需业务去解析域名，同步方式，内部阻塞解析域名
static int swClient_inet_addr(swClient *cli, char *host, int port)
{
    int hostLen = strlen(host);
    if (NULL == host || hostLen <= 0 || port < 0)
    {
        zanWarn("%s:%d invailed host:port.",host,port);
        return ZAN_ERR;
    }

    void *s_addr = NULL;
    int type = -1;
    if (cli->type == SW_SOCK_TCP || cli->type == SW_SOCK_UDP)
    {
        cli->server_addr.addr.inet_v4.sin_family = AF_INET;
        cli->server_addr.addr.inet_v4.sin_port = htons(port);
        cli->server_addr.len = sizeof(cli->server_addr.addr.inet_v4);
        s_addr = &cli->server_addr.addr.inet_v4.sin_addr.s_addr;
        type = AF_INET;
    }
    else if (cli->type == SW_SOCK_TCP6 || cli->type == SW_SOCK_UDP6)
    {
        cli->server_addr.addr.inet_v6.sin6_family = AF_INET6;
        cli->server_addr.addr.inet_v6.sin6_port = htons(port);
        cli->server_addr.len = sizeof(cli->server_addr.addr.inet_v6);
        s_addr = &cli->server_addr.addr.inet_v6.sin6_addr.s6_addr;
        type = AF_INET6;
    }
    else if (cli->type == SW_SOCK_UNIX_STREAM || cli->type == SW_SOCK_UNIX_DGRAM)
    {
        cli->server_addr.addr.un.sun_family = AF_UNIX;
        strncpy(cli->server_addr.addr.un.sun_path, host, sizeof(cli->server_addr.addr.un.sun_path));
        cli->server_addr.len = sizeof(cli->server_addr.addr.un);
        return ZAN_OK;
    }
    else
    {
        return ZAN_ERR;
    }
    ///地址校验
    int checkAddr = inet_pton(type,host, s_addr);
    /// 异步客户端，需要自行解析地址
    if (cli->async && checkAddr != 1)
    {
        zanWarn("DNS lookup will block the process. Please use swoole_async_dns_lookup.");
        return ZAN_ERR;
    }
    else if (!cli->async && checkAddr != 1)
    {
        /// 非异步客户端，阻塞方式域名解析
        int iret = swoole_gethostbyname(type, host, s_addr);
        if (iret < 0)
        {
            zanWarn("gethostbyname failed, iret=%d, errno=%d:%s", iret, errno, strerror(errno));
            return ZAN_ERR;
        }
    }

    return ZAN_OK;
}

static int swClient_tcp_connect_async(swClient *cli, char *host, int port, double timeout, int nonblock)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (!(cli->onConnect && cli->onError && cli->onClose))
    {
        zanError("onConnect/onError/onClose callback have not set.");
        return ZAN_ERR;
    }

    int ret = 0;
    cli->timeout = timeout;

    //alloc input memory buffer
    cli->buffer = swString_new(cli->buffer_input_size);
    if (!cli->buffer)
    {
        return ZAN_ERR;
    }

    /// 地址解析由dns 模块提供，不再自己处理
    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return ZAN_ERR;
    }

    /// 出现返回错误，还需要继续处理; ret == 0时需要，表示连接成了，还是需要继续处理
    ret = connect(cli->socket->fd, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
    if (ret == 0 || (ret < 0 && errno == EINPROGRESS))
    {
        ret = ServerG.main_reactor->add(ServerG.main_reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_WRITE);
    }

    return ret < 0? ZAN_ERR:ZAN_OK;
}

static int swClient_tcp_send_async(swClient *cli, char *data, int length, int flags)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (length <= 0 || !data)
    {
        return ZAN_ERR;
    }

    int iret = ServerG.main_reactor->write(ServerG.main_reactor, cli->socket->fd, data, length);
    return iret < 0? ZAN_ERR:length;
}

static int swClient_tcp_send_sync(swClient *cli, char *data, int length, int flags)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (length <= 0 || !data)
    {
        return ZAN_ERR;
    }

    int written = 0;
    int n = -1;

    while (written < length)
    {
        n = swConnection_send(cli->socket, data, length - written, flags);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN)
            {
                swSocket_wait(cli->socket->fd, 1000, SW_EVENT_WRITE);
                continue;
            }
            else
            {
                return ZAN_ERR;
            }
        }

        written += n;
        data += n;
    }

    return written;
}

static int swClient_tcp_sendfile_sync(swClient *cli, char *filename)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (swSocket_sendfile_sync(cli->socket->fd, filename, cli->timeout) < 0)
    {
        ServerG.error = errno;
        return ZAN_ERR;
    }

    return ZAN_OK;
}

static int swClient_tcp_sendfile_async(swClient *cli, char *filename)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (swConnection_sendfile_async(cli->socket, filename) < 0){
        ServerG.error = errno;
        return ZAN_ERR;
    }

    swConnection *socket = cli->socket;
    if (!(socket->events & SW_EVENT_WRITE))
    {
        if (socket->events & SW_EVENT_READ)
        {
            return ServerG.main_reactor->set(ServerG.main_reactor, socket->fd,
                               socket->fdtype | SW_EVENT_READ | SW_EVENT_WRITE);
        }
        else
        {
            return ServerG.main_reactor->add(ServerG.main_reactor, socket->fd,
                               socket->fdtype | SW_EVENT_WRITE);
        }
    }

    return ZAN_OK;
}

static int swClient_tcp_recv_no_buffer(swClient *cli, char *data, int len, int flag)
{
    if (!cli ||!cli->socket || !data) {
        return ZAN_ERR;
    }

#ifdef SW_CLIENT_SOCKET_WAIT
    if (cli->socket->socket_wait)
    {
        swSocket_wait(cli->socket->fd, cli->timeout_ms, SW_EVENT_READ);
    }
#endif

    int recvLen = 0;
    do{
        int ret = swConnection_recv(cli->socket, data + recvLen, len - recvLen, flag);
        if (ret < 0 && EINTR == errno){
            continue;
        }
        else if(ret < 0){
            return ZAN_ERR;
        }
        else{
            recvLen += ret;
            return recvLen;
        }

    }while(1);
}

static int swClient_udp_connect(swClient *cli, char *host, int port, double timeout, int udp_connect)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    if (swClient_inet_addr(cli, host, port) < 0)
    {
        return ZAN_ERR;
    }

    cli->timeout = timeout;
    int bufsize = ServerG.servSet.socket_buffer_size;

    if (cli->timeout > 0)
    {
        swSocket_set_timeout(cli->socket->fd, cli->timeout);
    }

    if (cli->type == SW_SOCK_UNIX_DGRAM)
    {
        struct sockaddr_un* client_addr = &cli->socket->info.addr.un;
        sprintf(client_addr->sun_path, "/tmp/swoole-client.%d.%d.sock", getpid(), cli->socket->fd);
        client_addr->sun_family = AF_UNIX;
        unlink(client_addr->sun_path);

        if (bind(cli->socket->fd, (struct sockaddr *) client_addr, sizeof(cli->socket->info.addr.un)) < 0)
        {
            zanError("bind(%s) failed.", client_addr->sun_path);
            return ZAN_ERR;
        }
    }
    else if (!udp_connect)
    {
        goto connect_ok;
    }

    if (connect(cli->socket->fd, (struct sockaddr *) (&cli->server_addr), cli->server_addr.len) >= 0)
    {
        swSocket_clean(cli->socket->fd);
        cli->send = swClient_udp_send;

connect_ok:
        setsockopt(cli->socket->fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(cli->socket->fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        cli->socket->active = 1;
        if (cli->async)
        {
            if (ServerG.main_reactor->add(ServerG.main_reactor, cli->socket->fd, cli->reactor_fdtype | SW_EVENT_READ) < 0)
            {
                return ZAN_ERR;
            }

            if (cli->onConnect) cli->onConnect(cli);
        }

        return ZAN_OK;
    }
    else
    {
        zanError("connect() failed.");
        cli->socket->active = 0;
        return ZAN_ERR;
    }
}

static int swClient_udp_sendto(swClient *cli, char *data, int len, int flags)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    int n = -1;

    n = cli->async? send(cli->socket->fd,data,len,flags):
            sendto(cli->socket->fd, data, len, 0, (struct sockaddr *) &cli->server_addr.addr, cli->server_addr.len);
    if (n < 0 || n < len)
    {
        return ZAN_ERR;
    }
    else
    {
        return n;
    }
}

static int swClient_udp_send(swClient *cli, char *data, int len, int flags)
{
    if (!cli || !cli->socket) {
            return ZAN_ERR;
    }

    int n = -1;

    n = send(cli->socket->fd,data,len,flags);
    if (n < 0 || n < len)
    {
        return ZAN_ERR;
    }
    else
    {
        return n;
    }
}

static int swClient_udp_recv(swClient *cli, char *data, int length, int flags)
{
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    cli->remote_addr.len = sizeof(cli->remote_addr.addr);

    do{
        int ret = recvfrom(cli->socket->fd, data, length, flags, (struct sockaddr *) &cli->remote_addr.addr, &cli->remote_addr.len);
        if (ret < 0 && EINTR == errno){
            continue;
        }
        else if (ret < 0){
            return ZAN_ERR;
        }
        else{
            return ret;
        }

    }while(1);
}

static int swClient_onStreamRead(swReactor *reactor, swEvent *event)
{
    int n;
    swClient *cli = event->socket->object;
    if (NULL == cli || !cli->socket) {
        return ZAN_ERR;
    }

    long buf_size = cli->buffer->size;

#ifdef SW_USE_OPENSSL
    if (cli->open_ssl && cli->socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
    {
        if (swClient_ssl_handshake(cli) < 0)
        {
            return cli->close(cli);
        }
        if (cli->socket->ssl_state != SW_SSL_STATE_READY)
        {
            return ZAN_OK;
        }
        //ssl handshake sucess
        else if (cli->onConnect)
        {
            cli->onConnect(cli);
        }
    }
#endif

    if (cli->open_eof_check || cli->open_length_check)
    {
        swConnection *conn = cli->socket;
        swProtocol *protocol = &cli->protocol;

        n = (cli->open_eof_check)? swProtocol_recv_check_eof(protocol, conn, cli->buffer):
                swProtocol_recv_check_length(protocol, conn, cli->buffer);
        return (n < 0)? cli->close(cli):ZAN_OK;
    }
    //packet mode
    else if (cli->packet_mode == 1)
    {
        uint32_t len_tmp = 0;
        n = swConnection_recv(event->socket, &len_tmp, 4, 0);
        if (n <= 0)
        {
            return cli->close(cli);
        }
        else
        {
            buf_size = ntohl(len_tmp);
            int needExtentBuf = buf_size > cli->buffer->size;
            if (needExtentBuf && swString_extend(cli->buffer, buf_size) < 0)
            {
                return cli->close(cli);
            }
        }
    }

#ifdef SW_CLIENT_RECV_AGAIN
    recv_again:
#endif
    n = swConnection_recv(event->socket, cli->buffer->str, buf_size, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            zanError("Read from socket[%d] failed.", event->fd);
            return ZAN_OK;
        case SW_CLOSE:
            goto close_fd;
        case SW_WAIT:
            return ZAN_OK;
        default:
            return ZAN_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
        return  cli->close(cli);
    }
    else
    {
        cli->onReceive(cli, cli->buffer->str, n);
#ifdef SW_CLIENT_RECV_AGAIN
        if (n == buf_size)
        {
            goto recv_again;
        }
#endif
        return ZAN_OK;
    }
    return ZAN_OK;
}

static int swClient_onDgramRead(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    if (!cli || !cli->socket) {
        return ZAN_ERR;
    }

    char buffer[SW_BUFFER_SIZE_UDP] = {0};
    int n = swClient_udp_recv(cli, buffer, sizeof(buffer), 0);
    if (n < 0)
    {
        return ZAN_ERR;
    }
    else
    {
        cli->onReceive(cli, buffer, n);
    }

    return ZAN_OK;
}

static int swClient_onError(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    if (cli == NULL || cli->socket == NULL) {
        return ZAN_ERR;
    }

    uint32_t fd_active = cli->socket->active;
    cli->close(cli);
    if (!fd_active && cli->onError)
    {
        cli->onError(cli);
    }

    return ZAN_OK;
}

static int swClient_onWrite(swReactor *reactor, swEvent *event)
{
    swClient *cli = event->socket->object;
    if (cli == NULL || !cli->socket) {
        return ZAN_ERR;
    }

    if (cli->socket->active)
    {
#ifdef SW_USE_OPENSSL
        if (cli->open_ssl && cli->socket->ssl_state == SW_SSL_STATE_WAIT_STREAM)
        {
            if (swClient_ssl_handshake(cli) < 0)
            {
                goto connect_fail;
            }
            else if (cli->socket->ssl_state == SW_SSL_STATE_READY)
            {
                goto connect_success;
            }
            else
            {
                return ZAN_OK;
            }
        }
#endif
        if (swReactor_onWrite(ServerG.main_reactor, event) != ZAN_OK)
        {
            cli->close(cli);
            if (cli->onError)
            {
                cli->onError(cli);
            }
        }

        return ZAN_OK;
    }

    socklen_t len = sizeof(ServerG.error);
    if (getsockopt(event->fd, SOL_SOCKET, SO_ERROR, &ServerG.error, &len) < 0)
    {
        zanError("getsockopt(%d) failed.", event->fd);
        return ZAN_ERR;
    }

    //success,连接成功，表示可写
    if (ServerG.error == 0)
    {
        //listen read event,设置可读事件
        ServerG.main_reactor->set(ServerG.main_reactor, event->fd, SW_FD_STREAM_CLIENT | SW_EVENT_READ);
        //connected
        cli->socket->active = 1;

#ifdef SW_USE_OPENSSL
        if (cli->open_ssl)
        {
            if (swClient_enable_ssl_encrypt(cli) < 0)
            {
                goto connect_fail;
            }
            if (swClient_ssl_handshake(cli) < 0)
            {
                goto connect_fail;
            }
            else
            {
                cli->socket->ssl_state = SW_SSL_STATE_WAIT_STREAM;
            }

            return ZAN_OK;
        }
        connect_success:
#endif
        if (cli->onConnect)
        {
            cli->onConnect(cli);
        }
    }
    else
    {
#ifdef SW_USE_OPENSSL
        connect_fail:
#endif
        /// close 不会回调给外部，只有onError会回调
//        cli->close(cli);
//        if (cli->onError)
//        {
//            cli->onError(cli);
//        }

        swClient_onError(reactor,event);
    }

    return ZAN_OK;
}

