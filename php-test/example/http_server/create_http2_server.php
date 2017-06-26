<?php

function onRequest(\swoole_http_request $request,\swoole_http_response $response)
{
	$response->end("<h1>Zan Https Server Test!!</h1>");
}

$http2_server = new \swoole_http_server("127.0.0.1",9002,SWOOLE_PROCESS, SWOOLE_SOCK_TCP|SWOOLE_SSL);

$http2_server->set([
		"ssl_cert_file"=> '../../apitest/swoole_http_server/localhost-ssl/server.crt',
		"ssl_key_file"=> '../../apitest/swoole_http_server/localhost-ssl/server.key',
		"open_http2_protocol" => true
]);

$http2_server->on("request","onRequest");
$http2_server->start();