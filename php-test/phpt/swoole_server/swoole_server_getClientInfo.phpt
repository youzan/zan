--TEST--
swoole_server: getClientInfo
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

$host = TCP_SERVER_HOST1;
$port = TCP_SERVER_PORT1;


$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(500000);

    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client->on("connect", function($cli) {
        //$cli->send("Hello Server!");
    });

    $client->on("receive", function($cli, $data){
        echo "Client Received: $data";
        sleep(1);
        $cli->close();
    });
    $client->on("error", function($cli){
        echo "Clinet Error.";
    });
    $client->on("close", function($cli){
        //echo "Client Close.";
    });
    //发起网络连接
    $client->connect($host, $port, 0.5);

} else {

    $serv = new swoole_server($host, $port);
    $serv->set([
        'worker_num' => 1,
        'net_worker_num' => 1,
        'log_file' => '/tmp/test_log.log',
    ]);

    $serv->on('Connect', function ($serv, $fd){
        //echo "Server: onConnected, client_fd=$fd\n";
        $data= $serv->getClientInfo($fd);

        var_dump($data['server_port']);
        var_dump($data['socket_type']);
        var_dump($data['remote_ip']);
        var_dump($data['from_networker_id']);

        $serv->shutdown();

    });

    $serv->on('Receive', function ($serv, $fd, $from_id, $data) use($pid) {
        echo "Server: Receive data: $data\n";
    });
    $serv->start();
}


?>
--EXPECT--
int(9011)
int(1)
string(9) "127.0.0.1"
int(1)