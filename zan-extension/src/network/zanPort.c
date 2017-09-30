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

#include "swProtocol/http.h"
#include "swProtocol/http2.h"
#include "swProtocol/websocket.h"
#include "swProtocol/mqtt.h"
#include "swPort.h"

#include "zanGlobalVar.h"
#include "zanServer.h"
#include "zanConnection.h"
#include "zanLog.h"

static int swPort_onRead_raw(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_check_length(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_check_eof(swReactor *reactor, swListenPort *lp, swEvent *event);
static int swPort_onRead_http(swReactor *reactor, swListenPort *lp, swEvent *event);

void swPort_init(swListenPort *port)
{
    port->sock = 0;
    port->ssl = 0;

    //listen backlog
    port->backlog = SW_BACKLOG;
    //tcp keepalive
    port->tcp_keepcount = SW_TCP_KEEPCOUNT;
    port->tcp_keepinterval = SW_TCP_KEEPINTERVAL;
    port->tcp_keepidle = SW_TCP_KEEPIDLE;
    port->open_tcp_nopush = 1;

    port->protocol.package_length_type = 'N';
    port->protocol.package_length_size = 4;
    port->protocol.package_body_offset = 0;
    port->protocol.package_max_length = SW_BUFFER_INPUT_SIZE;

    char eof[] = SW_DATA_EOF;
    port->protocol.package_eof_len = sizeof(SW_DATA_EOF) - 1;
    memcpy(port->protocol.package_eof, eof, port->protocol.package_eof_len);
}

static int swPort_websocket_onPackage(swConnection *conn, char *data, uint32_t length)
{
    swString frame;
    bzero(&frame, sizeof(frame));
    frame.str = data;
    frame.length = length;

    swString send_frame;
    bzero(&send_frame, sizeof(send_frame));
    char buf[128] = {0};
    send_frame.str = buf;
    send_frame.size = sizeof(buf);

    swWebSocket_frame ws;
    swWebSocket_decode(&ws, &frame);

    size_t offset;
    switch (ws.header.OPCODE)
    {
    case WEBSOCKET_OPCODE_CONTINUATION_FRAME:
    case WEBSOCKET_OPCODE_TEXT_FRAME:
    case WEBSOCKET_OPCODE_BINARY_FRAME:
        offset = length - ws.payload_length - 2;
        data[offset] = ws.header.FIN;
        data[offset + 1] = ws.header.OPCODE;
        zanNetworker_dispatch(conn, data + offset, length - offset);
        break;

    case WEBSOCKET_OPCODE_PING:
        if (length == 2 || length >= (sizeof(buf) - 2))
        {
            return ZAN_ERR;
        }
        swWebSocket_encode(&send_frame, data += 2, length - 2, WEBSOCKET_OPCODE_PONG, 1, 0);
        swConnection_send(conn, send_frame.str, send_frame.length, 0);
        break;

    case WEBSOCKET_OPCODE_PONG:
        return ZAN_ERR;

    case WEBSOCKET_OPCODE_CONNECTION_CLOSE:
        if (0x7d < (length - 2))
        {
            return ZAN_ERR;
        }
        send_frame.str[0] = 0x88;
        send_frame.str[1] = 0x00;
        send_frame.length = 2;
        swConnection_send(conn, send_frame.str, 2, 0);
        return ZAN_ERR;
    }
    return ZAN_OK;
}

void swPort_set_protocol(swListenPort *ls)
{
    //Thread mode must copy the data.
    //will free after onFinish
    if (ls->open_eof_check)
    {
        if (ls->protocol.package_eof_len > sizeof(ls->protocol.package_eof))
        {
            ls->protocol.package_eof_len = sizeof(ls->protocol.package_eof);
        }
        ls->protocol.onPackage = zanNetworker_dispatch;
        ls->onRead = swPort_onRead_check_eof;
    }
    else if (ls->open_length_check)
    {
        ls->protocol.get_package_length = swProtocol_get_package_length;
        ls->protocol.onPackage = zanNetworker_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else if (ls->open_http_protocol)
    {
        if (ls->open_websocket_protocol)
        {
            ls->protocol.get_package_length = swWebSocket_get_package_length;
            ls->protocol.onPackage = swPort_websocket_onPackage;
            ls->protocol.package_length_size = SW_WEBSOCKET_HEADER_LEN;
        }
#ifdef SW_USE_HTTP2
        else if (ls->open_http2_protocol)
        {
            ls->protocol.get_package_length = swHttp2_get_frame_length;
            ls->protocol.package_length_size = SW_HTTP2_FRAME_HEADER_SIZE;
            ls->protocol.onPackage = zanNetworker_dispatch;
        }
#endif
        ls->onRead = swPort_onRead_http;
    }
    else if (ls->open_mqtt_protocol)
    {
        ls->protocol.get_package_length = swMqtt_get_package_length;
        ls->protocol.onPackage = zanNetworker_dispatch;
        ls->onRead = swPort_onRead_check_length;
    }
    else
    {
        ls->onRead = swPort_onRead_raw;
    }
}

static int swPort_onRead_raw(swReactor *reactor, swListenPort *port, swEvent *event)
{
    int ret = 0;
    swDispatchData task;
    zanServer *serv = ServerG.serv;
    swConnection *conn =  event->socket;

    memset(&task, 0, sizeof(task));

    int n = swConnection_recv(conn, task.data.data, SW_BUFFER_SIZE, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            zanError("recv from connection#%d failed.", event->fd);
            return ZAN_OK;
        case SW_CLOSE:
            zanWarn("onRead_raw error, recv_ret=%d, errno=%d:%s", n, errno, strerror(errno));
            goto close_fd;
        default:
            return ZAN_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
            zanNetworker_onClose(reactor, event);
        return ZAN_OK;
    }
    else
    {
        task.data.info.fd = event->fd;
        task.data.info.from_id = event->from_id;
        task.data.info.networker_id = ServerWG.worker_id;
        task.data.info.len = n;
        task.data.info.type = SW_EVENT_TCP;
        task.target_worker_id = -1;

        zanDebug("dispatch: fd=%d, from_id=%d, reactor_id=%d, networker_id=%d", event->fd, event->from_id, reactor->id, ServerWG.worker_id);
        ret = serv->factory.dispatch(&serv->factory, &task);
        return ret;
    }

    return ZAN_OK;
}

///TODO:::
static int swPort_onRead_check_length(swReactor *reactor, swListenPort *port, swEvent *event)
{
    zanServer *serv = ServerG.serv;
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;

    swString *buffer = zanServer_get_buffer(serv, ServerWG.worker_id, event->fd);
    if (!buffer)
    {
        return ZAN_ERR;
    }

    if (swProtocol_recv_check_length(protocol, conn, buffer) < 0)
    {
        zanTrace("Close Event.FD=%d|From=%d", event->fd, event->from_id);
        zanNetworker_onClose(reactor, event);
    }

    return ZAN_OK;
}

/**
 * For Http Protocol
 */
static int swPort_onRead_http(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    if (conn->websocket_status >= WEBSOCKET_STATUS_HANDSHAKE)
    {
        if (conn->http_upgrade == 0)
        {
            swHttpRequest_free(conn);
            conn->websocket_status = WEBSOCKET_STATUS_ACTIVE;
            conn->http_upgrade = 1;
        }

        return swPort_onRead_check_length(reactor, port, event);
    }

#ifdef SW_USE_HTTP2
    if (conn->http2_stream)
    {
        return swPort_onRead_check_length(reactor, port, event);
    }
#endif

    char *buf = NULL;
    int buf_len = 0;
    int n = 0;
    swHttpRequest *request = NULL;
    swProtocol *protocol = &port->protocol;

    //new http request
    if (conn->object == NULL)
    {
        request = sw_malloc(sizeof(swHttpRequest));
        bzero(request, sizeof(swHttpRequest));
        conn->object = request;
    }
    else
    {
        request = (swHttpRequest *) conn->object;
    }

    if (!request->buffer)
    {
     //alloc memory failed.
        request->buffer = swString_new(SW_HTTP_HEADER_MAX_SIZE);
        if (!request->buffer)
        {
            zanNetworker_onClose(reactor, event);
            return ZAN_ERR;
        }
    }

    swString *buffer = request->buffer;

recv_data:
    buf = buffer->str + buffer->length;
    buf_len = buffer->size - buffer->length;

    n = swConnection_recv(conn, buf, buf_len, 0);
    if (n < 0)
    {
        switch (swConnection_error(errno))
        {
        case SW_ERROR:
            zanError("recv from connection#%d failed.", event->fd);
            return ZAN_OK;
        case SW_CLOSE:
            goto close_fd;
        default:
            return ZAN_OK;
        }
    }
    else if (n == 0)
    {
        close_fd:
        swHttpRequest_free(conn);
        zanNetworker_onClose(reactor, event);
        return ZAN_OK;
    }
    else
    {
        buffer->length += n;
        if (request->method == 0 && swHttpRequest_get_protocol(request) < 0)
        {
            /// 数据没有接收全，继续接收
            if (request->buffer->length < SW_HTTP_HEADER_MAX_SIZE)
            {
                return SW_OK;
            }

            zanWarn("get protocol failed.");
#ifdef SW_HTTP_BAD_REQUEST
            if (swConnection_send(conn, SW_STRL(SW_HTTP_BAD_REQUEST) - 1, 0) < 0)
            {
                zanError("send() failed.");
            }
#endif
            goto close_fd;
        }

        //support method:get post put delete patch head options
        if ((request->method > 0 && request->method <= HTTP_PATCH) || request->method == HTTP_OPTIONS)
        {
            //receive data of http header
            if (request->header_length == 0)
            {
                if (swHttpRequest_get_header_length(request) < 0)
                {
                    if (buffer->size == buffer->length)
                    {
                        zanWarn("http header is too long.");
                        goto close_fd;
                    }
                    else
                    {
                        goto recv_data;
                    }
                }
            }
            //handle http body
            if (request->content_length == 0)
            {
                //http_no_entity
                if (swHttpRequest_get_content_length(request) < 0)
                {
                    if (memcmp(buffer->str + buffer->length - 4, "\r\n\r\n", 4) == 0)
                    {
                        zanNetworker_dispatch(conn, buffer->str, buffer->length);
                        swHttpRequest_free(conn);
                        return SW_OK;
                    }
                    else if (buffer->size == buffer->length)
                    {
                        zanWarn("http header is too long.");
                        goto close_fd;
                    }
                    else
                    {
                        goto recv_data;
                    }
                }
                //content_length overflow
                else if (request->content_length > (protocol->package_max_length - SW_HTTP_HEADER_MAX_SIZE))
                {
                    zanWarn("Content-Length more than the package_max_length[%d].", protocol->package_max_length - SW_HTTP_HEADER_MAX_SIZE);
                    goto close_fd;
                }
            }
            //http_entity
            uint32_t request_size = request->content_length + request->header_length;
            int needExtentBuf = request_size > buffer->size;
            if (needExtentBuf && swString_extend(buffer, request_size) < 0)
            {
                goto close_fd;
            }

            //discard the redundant data
            buffer->length = (buffer->length > request_size)? request_size:buffer->length;
            if (buffer->length == request_size)
            {
                zanNetworker_dispatch(conn, buffer->str, buffer->length);
                swHttpRequest_free(conn);
            }
            else
            {
#ifdef SW_HTTP_100_CONTINUE
                //Expect: 100-continue
                if (swHttpRequest_has_expect_header(request))
                {
                    swSendData _send;
                    _send.data = "HTTP/1.1 100 Continue\r\n\r\n";
                    _send.length = strlen(_send.data);

                    int send_times = 0;
                    direct_send:
                    n = swConnection_send(conn, _send.data, _send.length, 0);
                    if (n < _send.length)
                    {
                        _send.data += n;
                        _send.length -= n;
                        send_times++;
                        if (send_times < 10)
                        {
                            goto direct_send;
                        }
                        else
                        {
                            zanWarn("send http header failed");
                        }
                    }
                }
                else
                {
                    zanTrace("PostWait: request->content_length=%d, buffer->length=%zd, request->header_length=%d\n",
                            request->content_length, buffer->length, request->header_length);
                }
#endif
                goto recv_data;
            }
        }
#ifdef SW_USE_HTTP2
        else if (request->method == HTTP_PRI)
        {
            conn->http2_stream = 1;
            swHttp2_send_setting_frame(protocol, conn);
            if (n == sizeof(SW_HTTP2_PRI_STRING) - 1)
            {
                swHttpRequest_free(conn);
                return SW_OK;
            }

            swHttp2_parse_frame(protocol, conn, buf + (sizeof(SW_HTTP2_PRI_STRING) - 1), n - (sizeof(SW_HTTP2_PRI_STRING) - 1));
            swHttpRequest_free(conn);
            return SW_OK;
        }
#endif
        else
        {
            zanWarn("method no support");
            goto close_fd;
        }
    }

    return ZAN_OK;
}

static int swPort_onRead_check_eof(swReactor *reactor, swListenPort *port, swEvent *event)
{
    swConnection *conn = event->socket;
    swProtocol *protocol = &port->protocol;
    zanServer *serv = ServerG.serv;

    swString *buffer = zanServer_get_buffer(serv, ServerWG.worker_id, event->fd);
    if (!buffer)
    {
        zanWarn("get buffer error, fd=%d, from_id=%d", event->fd, event->from_id);
        return ZAN_ERR;
    }

    if (swProtocol_recv_check_eof(protocol, conn, buffer) < 0)
    {
        zanNetworker_onClose(reactor, event);
    }

    return ZAN_OK;
}

void swPort_free(swListenPort *port)
{
#ifdef SW_USE_OPENSSL
    if (port->ssl)
    {
        swSSL_free_context(port->ssl_context);
        free(port->ssl_cert_file);
        free(port->ssl_key_file);
    }
#endif

    close(port->sock);

    //remove unix socket file
    if (port->type == SW_SOCK_UNIX_STREAM || port->type == SW_SOCK_UNIX_DGRAM)
    {
        unlink(port->host);
    }
}

/******************************************************************************/
int zanPort_set_ListenOption(swListenPort *ls)
{
    int sock = ls->sock;

    //reuse address
    int option = 1;

    //reuse port
#ifdef HAVE_REUSEPORT
    if (ServerG.reuse_port && setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &option, sizeof(int)) < 0)
    {
        zanError("setsockopt(SO_REUSEPORT) failed.");
        ServerG.reuse_port = 0;
    }
#endif

    if (swSocket_is_dgram(ls->type))
    {
        int bufsize = ServerG.servSet.socket_buffer_size;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
        return ZAN_OK;
    }

#ifdef SW_USE_OPENSSL
    if (ls->open_ssl_encrypt)
    {
        if (ls->ssl_cert_file == NULL || ls->ssl_key_file == NULL)
        {
            zanError("SSL error, require ssl_cert_file and ssl_key_file.");
            return ZAN_ERR;
        }
        ls->ssl_context = swSSL_get_context(ls->ssl_method, ls->ssl_cert_file, ls->ssl_key_file);
        if (ls->ssl_context == NULL)
        {
            zanError("swSSL_get_context() error.");
            return ZAN_ERR;
        }
        if (ls->ssl_client_cert_file && swSSL_set_client_certificate(ls->ssl_context, ls->ssl_client_cert_file, ls->ssl_verify_depth) == SW_ERR)
        {
            zanError("swSSL_set_client_certificate() error.");
            return ZAN_ERR;
        }
        if (ls->open_http_protocol)
        {
            ls->ssl_config.http = 1;
        }
        if (ls->open_http2_protocol)
        {
            ls->ssl_config.http_v2 = 1;
            swSSL_server_http_advise(ls->ssl_context, &ls->ssl_config);
        }
        if (swSSL_server_set_cipher(ls->ssl_context, &ls->ssl_config) < 0)
        {
            zanError("swSSL_server_set_cipher() error.");
            return ZAN_ERR;
        }
    }

    if (ls->ssl && (!ls->ssl_cert_file || !ls->ssl_key_file))
    {
        zanWarn("need to set [ssl_cert_file] or [ssl_key_file] option.");
        return ZAN_ERR;
    }
#endif

    //listen stream socket
    if (listen(sock, ls->backlog) < 0)
    {
        zanError("listen(%s:%d, %d) failed", ls->host, ls->port, ls->backlog);
        return ZAN_ERR;
    }

#ifdef TCP_DEFER_ACCEPT
    if (ls->tcp_defer_accept && setsockopt(sock, IPPROTO_TCP, TCP_DEFER_ACCEPT,
                                           (const void*) &ls->tcp_defer_accept, sizeof(int)) < 0)
    {
        zanError("setsockopt(TCP_DEFER_ACCEPT) failed.");
    }
#endif

#ifdef TCP_FASTOPEN
    if (ls->tcp_fastopen && setsockopt(sock, IPPROTO_TCP, TCP_FASTOPEN,
                                       (const void*) &ls->tcp_fastopen, sizeof(int)) < 0)
    {
        zanError("setsockopt(TCP_FASTOPEN) failed.");
        return ZAN_ERR;
    }
#endif

#ifdef SO_KEEPALIVE
    if (ls->open_tcp_keepalive == 1)
    {
        option = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (void *) &option, sizeof(option)) < 0)
        {
            zanError("setsockopt(SO_KEEPALIVE) failed.");
            return ZAN_ERR;
        }
#ifdef TCP_KEEPIDLE
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (void*) &ls->tcp_keepidle, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (void *) &ls->tcp_keepinterval, sizeof(int));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (void *) &ls->tcp_keepcount, sizeof(int));
#endif
    }
#endif
    return ZAN_OK;
}
