--TEST--
swoole_http_client: send timeout

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

/*
require_once __DIR__ . "/../../apitest/swoole_http_client/http_request_send_timeout.php";

$simple_http_server = __DIR__ . "/../../apitest/swoole_http_server/http_server_without_response.php";
$closeServer = start_server($simple_http_server, HTTP_SERVER_HOST, $port = get_one_free_port());

request_send_timeout(HTTP_SERVER_HOST, $port);
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
    
    $httpClient = new swoole_http_client($host, $port);
    $httpClient->on("timeout", function(swoole_http_client $httpClient) {
        echo "timeout\n";
        $httpClient->close();
    });

    $httpClient->setReqTimeout(1);
    $httpClient->get("/", function ($client)  {
        assert(false);
    });

} else {

    $httpServ = new \swoole_http_server($host, $port, SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
        
    $httpServ->set([
        // 输出限制
        'user' => 'www-data',
        'group' => 'www-data',
        'log_file' => __DIR__.'/swoole.log',
        'worker_num' => 1,
        'net_worker_num' => 1,
        ]);

    $httpServ->on("request", function ($request, $response) use ($httpServ) {
       // echo "onRequest\n";
        $httpServ->shutdown();
    });

    $httpServ->start();
}

?>

--EXPECT--
timeout