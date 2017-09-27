<?php
$server = new swoole_server('127.0.0.1', 9501);

$serv->set(array(
    'worker_num' => 2,   //工作进程数量
    //'task_worker_num' =>1,
    'daemonize' => false, //是否作为守护进程
    'networker_num' => 2,
    'heartbeat_idle_time' => 10,
    'heartbeat_check_interval' =>5,
));

$process = new swoole_process(function($process) use ($server) {
    while (true) {
        $msg = $process->read();
        foreach($server->connections as $conn) {
            $server->send($conn, $msg);
        }
    }
});

$server->addProcess($process);

$server->on('receive', function ($serv, $fd, $from_id, $data) use ($process) {
    //群发收到的消息
    $process->write($data);
});

$server->start();
