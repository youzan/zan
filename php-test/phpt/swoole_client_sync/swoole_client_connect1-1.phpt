--TEST--
swoole_client sync: connect 1 - 1

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

$host = TCP_SERVER_HOST1;
$port = TCP_SERVER_PORT1;

$pid = pcntl_fork();
if ($pid < 0) {
    exit;
}

if ($pid === 0) {
    usleep(500000);

    $client = new swoole_client(SWOOLE_TCP, SWOOLE_SOCK_SYNC);
    $client->connect("127.0.0.1", 9501);

    
	$data = "TcpSendto";
	$client->send($data);

	$message = $client->recv();


} else {

    $serv = new swoole_server("127.0.0.1", 9501);
    $serv->set([
        'worker_num' => 1,
        'net_worker_num' => 1,
        'task_worker_num' => 1,
        'log_file' => '/tmp/test_log.log',
    ]);

    $serv->on('Connect', function ($serv, $fd){
        //echo "Server: onConnected, client_fd=$fd\n";
    });

    $serv->on('Receive', function ($serv, $fd, $from_id, $data) use($pid) {
        echo "Server: Receive data: $data";
        $serv->task($data);
    });

    $serv->on('Task', function (swoole_server $serv, $task_id, $fromId, $data){
        echo "Server: Task data: $data";
        $serv->shutdown();
    });

    $serv->on('Finish', function (swoole_server $serv, $worker_task_id, $data){
        //echo "Server: Finish data: $data";
        //$serv->shutdown();
    });

    $serv->start();
}

?>

--EXPECT--
Server: Receive data: TcpSendtoServer: Task data: TcpSendto
