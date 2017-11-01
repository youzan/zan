--TEST--
swoole_server: sendMessage
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

$serv = new swoole_server($host, $port);
$serv->set([
    'worker_num' => 2,
    'net_worker_num' => 1,
    'log_file' => '/tmp/test_log.log',
]);

$serv->on('Connect', function ($serv, $fd){
    //echo "Server: onConnected, client_fd=$fd\n";
});

$serv->on('Receive', function ($serv, $fd, $from_id, $data) {
    echo "Server: Receive data: $data";
});

$serv->on('PipeMessage', function (swoole_server $serv, $from_worker_id, $message) {
    echo "PipeMessage from worker_id=$from_worker_id: $message";
    $serv->shutdown();
});

$serv->on('WorkerStart', function ($serv, $worker_id) {
    if (0 == $worker_id) {
        swoole_timer_after(1000, function() use($serv) {
            $serv->sendMessage("Hello Worker1", 1);
        });
    }
});


$serv->start();


?>
--EXPECT--
PipeMessage from worker_id=0: Hello Worker1