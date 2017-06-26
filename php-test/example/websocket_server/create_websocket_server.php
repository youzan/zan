<?php

function onOpen(\swoole_websocket_server $server,\swoole_http_request $resquest)
{
	echo "websocket server, fd:$resquest->fd handshake success\n";
}

function onMessage(\swoole_websocket_server $server,\swoole_websocket_frame $frame)
{
	echo "websocket server,receive message from: $frame->fd\n";
	echo "websocket server,receive message with opcode:$frame->opcode\n";
	echo "websocket server,receive message with fin:$frame->finish\n";
	echo "websocket server,receive message with data:$frame->data\n";
	/// 发送数据
	$server->push($frame->fd,"websocket server example");
}

/// websokcet server 继承http server
function onRequest(\swoole_http_request $request,\swoole_http_response $response)
{
	$response->end("<h1>Zan WebSocket Server Test!!</h1>");
}

function onClose(\swoole_websocket_server $server,$fd)
{
	echo "websocket server,fd:$fd closed\n";
}

$websocket_server = new \swoole_websocket_server("127.0.0.1",9001);

$websocket_server->on("open","onOpen");
$websocket_server->on("message","onMessage");
$websocket_server->on("close","onClose");
$websocket_server->on("requests","onRequest");

$websocket_server->start();