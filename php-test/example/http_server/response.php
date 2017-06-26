<?php

function onRequest(\swoole_http_request $request,\swoole_http_response $response)
{
	$uri = $request->server["request_uri"];
	
	if ($uri === "/rawcookie") {
		$name = "name";
		$value = "value";
		$expire = 0;
		$path = "/";
		$domain = "";
		$secure = false;
		$httpOnly = true;
		$response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
		$response->rawcookie("rawcontent", $request->rawcontent());
		$response->end("Hello World!");
		return;
	}
	
	if ($uri === "/gzip")  {
		$level = 9;
		$response->gzip($level);
		$response->end(RandStr::gen(1024 * 1024 * 2, RandStr::ALL));
		return;
	}
	
	if ($uri === "/file") {
		$response->header("Content-Type", "text");
		$response->header("Content-Disposition", "attachment; filename=\"test.php\"");
		$response->sendfile("http_response_test.txt");
	}
	
	$response->end("hello world!");
}

$http_server = new \swoole_http_server("127.0.0.1",9003);
$http_server->on("request","onRequest");
$http_server->start();
