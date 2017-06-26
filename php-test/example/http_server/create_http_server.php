<?php

function onRequest(\swoole_http_request $request,\swoole_http_response $response)
{
	$response->end("<h1>Zan Http Server Test!!</h1>");
}

$http_server = new \swoole_http_server("127.0.0.1",9003);
$http_server->on("request","onRequest");
$http_server->start();