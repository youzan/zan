--TEST--
swoole_server: addListener
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
$port2 = 9502;

$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(1000);

    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client->on("connect", function($client) {
        echo "Client onConnected!\n";
    });
    $client->on("receive", function($client, $data){
        echo "Client onReceive data: $data\n";
        $client->send("Hello Server, From Client!");
        $client->close();
    });
    $client->on("error", function($client){
        echo "Clinet Error.";
    });
    $client->on("close", function($client){
        //echo "Client Close.";
    });
    $client->connect($host, $port, 0.5);

    ////////////////////////////////////////////////////////////////////
    $client1 = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    
    //设置事件回调函数
    $client1->on("connect", function($client1) {
        echo "Client1 onConnected!\n";
    });
    $client1->on("receive", function($client1, $data){
        echo "Client1 onReceive data: $data\n";
        $client1->send("Hello Server, From Client1!");
        $client1->close();
    });
    $client1->on("error", function($client1){
        echo "Clinet1 Error.";
    });
    $client1->on("close", function($client1){
        //echo "Client Close.";
    });

    ////////port2
    $client1->connect($host, $port2, 0.5);


} else {

    $serv = new swoole_server($host, $port);
    $serv->set([
        'worker_num' => 1,
        'net_worker_num' => 1,
        'log_file' => '/tmp/test_log.log',
    ]);
    $serv->addlistener(TCP_SERVER_HOST, $port2, SWOOLE_SOCK_TCP);

    $serv->on('Connect', function ($serv, $fd){
        $serv->send($fd, "Hello Client!");
    });

    $serv->on('Receive', function ($serv, $fd, $from_id, $data) use($pid) {
        echo "Server: Receive data: $data\n";
        $serv->shutdown();
    });


    $serv->start();
}



?>
--EXPECT--
Client1 onConnected!
Client onConnected!
Client1 onReceive data: Hello Client!
Client onReceive data: Hello Client!
Server: Receive data: Hello Server, From Client1!
Server: Receive data: Hello Server, From Client!