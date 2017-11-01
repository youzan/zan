--TEST--
swoole_server: stop
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
    'worker_num' => 1,
    'net_worker_num' => 1,
    'log_file' => '/tmp/test_log.log',
]);

$process = new swoole_process(function($process) use ($serv) {
    echo "addProcess!\n";
    static $count = 0;
    while (true) {
        $count++;
        echo "sleep, count=$count\n";
        if (intval($count) >= 3) 
        {
            $serv->shutdown();
            sleep(3);
        }
    }
});
$serv->addProcess($process);

$serv->on('Connect', function ($serv, $fd){
    //echo "Server: onConnected, client_fd=$fd\n";
});

$serv->on('Receive', function ($serv, $fd, $from_id, $data) {
    echo "Server: Receive data: $data";
});

$serv->on('WorkerStart', function ($serv, $worker_id) {
    //echo "onWorkerStart!\n";
    swoole_timer_after(1000, function() use($serv) {
        //$serv->shutdown();
    });
});


$serv->start();


$serv->start();


?>
--EXPECT--
addProcess!
sleep, count=1
sleep, count=2
sleep, count=3