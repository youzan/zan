<?php

function onRequest(\swoole_http_request $request,\swoole_http_response $response)
{
	/// 获取request 的server属性 
	$send_str1 = "<h1>Zan Http Server Request Server Property Test!!</h1>";
	
	/// http 请求相关的服务信息，类似于PHP $_SERVER
	echo "output request msg header:\n";
	var_dump($request->server);
	
	$sub_send_str2 = "<h2>request property request_method:". $request->server['request_method']."</h2>";
	$sub_send_str3 ="<h2>request property request_uri:". $request->server['request_uri']."</h2>";
	$sub_send_str4 = "<h2>request property path_info:". $request->server['path_info']."</h2>";
	$sub_send_str5 = "<h2>request property request_time:". $request->server['request_time']."</h2>";
	$sub_send_str6 = "<h2>request property request_time_float:". $request->server['request_time_float']."</h2>";
	$sub_send_str7 = "<h2>request property server_port:". $request->server['server_port']."</h2>";
	$sub_send_str8 = "<h2>request property remote_port:". $request->server['remote_port']."</h2>";
	$sub_send_str9 = "<h2>request property server_protocol:". $request->server['server_protocol']."</h2>";
	$sub_send_str10 = "<h2>request property server_software:". $request->server['server_software']."</h2>";

	/// http 请求消息的头部信息，数组类型，key均转换为小写
	echo "\noutput request msg header:\n";
	var_dump($request->header);

	/// http请求的GET 参数，数组类型,类似于PHP $_GET
	echo "\noutput get parameter:\n";
	var_dump($request->get);
	
	/// http请求的POST参数
	echo "\noutput post parameter:\n";
	var_dump($request->post);
	
	/// http请求消息中携带的COOKIE信息，数组类型，类似于PHP $_COOKIE
	echo "\noutput request msg cookie:\n";
	var_dump($request->cookie);
	
	/// http请求的文件上传信息，类似于PHP $_FILES 
	echo "\noutput request upload file info:\n";
	var_dump($request->files);

	/// http POST消息的原始body
	echo "\noutput request message cookie:\n";
	echo $request->rawContent() ."\n";

	$response->end($send_str1.$sub_send_str2 . $sub_send_str3 . $sub_send_str4 . $sub_send_str5.
			$sub_send_str6 .$sub_send_str7 .$sub_send_str8 . $sub_send_str9 . $sub_send_str10);
}

$http_server = new \swoole_http_server("127.0.0.1",9003);
$http_server->on("request","onRequest");
$http_server->start();