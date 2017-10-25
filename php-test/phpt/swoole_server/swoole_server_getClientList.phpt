--TEST--
swoole_server: getClientList
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
    usleep(500);

    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client->on("connect", function($cli) {
        //echo "Client1 onConnected!\n";
    });

    $client->on("receive", function($cli, $data){
        //echo "Client1 onReceive: $data\n";
        $cli->send("From Client!");
        //sleep(1);
        //$cli->close();
    });
    $client->on("error", function($cli){
        echo "Clinet1 Error.";
    });
    $client->on("close", function($cli){
    });
    $client->connect($host, $port, 0.5);

    ////////////////////////////////////////////////////////////////////
    usleep(500);
    $client1 = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client1->on("connect", function($client1) {
        //echo "Client2 onConnected!\n";
    });
    $client1->on("receive", function($client1, $data){
        //echo "Client2 onReceive: $data\n";
        $client1->send("From Client!");
        //sleep(1);
        //$client1->close();
    });
    $client1->on("error", function($client1){
        echo "Clinet2 Error.";
    });
    $client1->on("close", function($client1){
    });

    $client1->connect($host, $port, 0.5);

} else {

    $serv = new swoole_server($host, $port);
    $serv->set([
        'worker_num' => 1,
        'net_worker_num' => 1,
        'log_file' => '/tmp/test_log.log',
    ]);

    $serv->on('Connect', function ($serv, $fd){
        //echo "Server: onConnected, client_fd=$fd\n";
        $serv->send($fd, "Hello Client!");
    });

    $serv->on('Receive', function ($serv, $fd, $from_id, $data) {
        echo "Server: Receive data: $data\n";
        if ($fd == 2) {
            //echo "fd=$fd\n";
            $data= $serv->getClientList();
            echo "count:" . count($data) . "\n";
            //var_dump($data);
            $serv->shutdown();
        }
    });
    $serv->start();
}


?>
--EXPECT--
Server: Receive data: From Client!
Server: Receive data: From Client!
count:2