<?php

require __DIR__ . "/BaseTcpServer.php";

$param = array (
    'reactor_num' => 4,
    'worker_num' => 8,
    'process_name' => 'BaseTcpServer1',    //mac 不支持 cli_set_process_title，无法设置进程名
    'daemonize'  => true,                  //后台运行
    'log_file'   => '/tmp/zan_server.log',
);

$server = BaseTcpServer::createServer("0.0.0.0", 9505);
$server->setParam($param);
$server->serve();
