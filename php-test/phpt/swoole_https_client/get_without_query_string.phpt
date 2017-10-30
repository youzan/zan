--TEST--
swoole_https_client: get_without_query_string
--SKIPIF--
<?php require __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

require_once __DIR__ . "/../inc/zan.inc";

/*
require_once __DIR__ . "/../../apitest/swoole_http_client/simple_https_client.php";

$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/simple_https_server.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());


testGet(HTTP_SERVER_HOST, $port, [], function() use($closeServer) {
    echo "SUCCESS";$closeServer();
});

suicide(1000, SIGTERM, $closeServer);
*/


$host = HTTP_SERVER_HOST;
$port = HTTP_SERVER_PORT;

$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(500000);


    $httpClient = new \swoole_http_client($host, $port, true);

    $httpClient->set([
        "socket_buffer_size" => 1024 * 1024 * 2,
        'ssl_cert_file' => __DIR__ . '/../../apitest/swoole_http_server/localhost-ssl/server.crt',
        'ssl_key_file' => __DIR__ . '/../../apitest/swoole_http_server/localhost-ssl/server.key',
    ]);


    $httpClient->on("connect", function(\swoole_http_client $httpClient) {
        assert($httpClient->isConnected() === true);
        // debug_log("connect");
    });

    $httpClient->on("error", function(\swoole_http_client $httpClient) {
        // debug_log("error");
    });

    $httpClient->on("close", function(\swoole_http_client $httpClient) {
        // debug_log("close");
    });

    
    $query = [];
    $queryStr = http_build_query($query);
    $ok = $httpClient->get("/get?$queryStr", function(\swoole_http_client $httpClient) use($query, $queryStr) {
        assert($httpClient->statusCode === 200);
        assert($httpClient->errCode === 0);
        // $httpClient->headers;
        if ($queryStr === "") {
            echo "querStr == NULL\n";
            assert($httpClient->body === "null");
            $httpClient->close();
        } else {
            $ret = json_decode($httpClient->body, true);
            assert(arrayEqual($ret, $query, false));
            echo "querStr != NULL\n";
        }

    });
    assert($ok);


} else {

    $httpServ = new \swoole_http_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
        
    $httpServ->set([
        // 输出限制
        'user' => 'www-data',
        'group' => 'www-data',
        // 'log_file' => __DIR__.'/swoole.log',
        'worker_num' => 1,
        'net_worker_num' => 1,
        'ssl_cert_file' => __DIR__ . '/../../apitest/swoole_http_server/localhost-ssl/server.crt',
        'ssl_key_file' => __DIR__ . '/../../apitest/swoole_http_server/localhost-ssl/server.key',
        ]);


    $httpServ->on('WorkerStart', function (\swoole_http_server $httpServ, $workerId) {
        //echo "onWorkerStart! worker_id=$workerId\n";
    });

    $httpServ->on('WorkerStop', function (\swoole_http_server $httpServ, $workerId) {
        //echo "onWorkerStop! worker_id=$workerId\n";
    });

    $httpServ->on('connect', function ($httpServ, $fd) {
        //echo "HttpServer: onConnected, client_fd=$fd\n";
        //$httpServ->send($fd, "Hello Client!");
    });

    $httpServ->on('receive', function (\swoole_http_server $swooleServer, $fd, $fromId, $data) {
        $recv_len = strlen($data);
        echo "receive: len $recv_len\n";
        //$httpServ->send($fd, "HelloHttpClient!");
        $httpServ->shutdown();
    });


    $httpServ->on('request', function (\swoole_http_request $request, \swoole_http_response $response) use($httpServ) {
        $uri = $request->server["request_uri"];
        if ($uri === "/favicon.ico")  {
            $response->status(404);
            $response->end();
            $httpServ->shutdown();
            return;
        }

        testSetCookie:
        {
            $name = "name";
            $value = "value";
            $expire = 0;
            $path = "/";
            $domain = "";
            $secure = false;
            $httpOnly = true;
            $response->cookie($name, $value, $expire, $path, $domain, $secure, $httpOnly);
            $expect = "name=value; path=/; httponly";
            assert(in_array($expect, $response->cookie, true));
        }

        if ($uri === "/rawcontent") {
            echo "onRequest/rawcontent\n";
            $response->end($request->rawcontent());
            $httpServ->shutdown();
            return;
        }

        if ($uri === "/get") {
            if (property_exists($request, "get")) {
                $response->end(json_encode($request->get));
            } else {
                $response->end("{}");
            }
            $httpServ->shutdown();
            return;
        }

    });

    $httpServ->start();
}


?>
--EXPECT--
querStr == NULL
