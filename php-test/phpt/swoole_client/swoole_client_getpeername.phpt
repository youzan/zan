--TEST--
swoole_client: swoole_client getsockpeername

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

$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(500000);

    $client = new swoole_client(SWOOLE_SOCK_UDP);
    $client->connect('127.0.0.1', 9503);

    $ret = $client->sendto("127.0.0.1", 9503, "Hello UdpServer!");
    
    $message2 = $client->recv();
    echo "From Server:{$message2}\n";

    $peer = $client->getpeername();
    echo "ip: " . $peer["host"] . "\n";
    echo "port: " . $peer["port"] . "\n";

} else {

    $serv = new swoole_server("127.0.0.1", 9503, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

    $serv->set(array(
        'worker_num' => 1,
        'net_worker_num' => 1,
        'log_file' => '/tmp/test_log.log',
    ));

    $serv->on('Packet', function ($serv, $data, $clientInfo) {
        echo ("onPacket: $data\n");
        $serv->sendto($clientInfo['address'], $clientInfo['port'], "Hello UdpClient!");
        $serv->shutdown();
    });


    $serv->on('connect', function ($serv, $fd){
        echo "onConnect, fd=%d\n";
    });

    //启动服务器
    $serv->start();
}

?>

--EXPECT--
onPacket: Hello UdpServer!
From Server:Hello UdpClient!
ip: 127.0.0.1
port: 9503