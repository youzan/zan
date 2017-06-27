<?php

require __DIR__ . "/EofSplitTcpServer.php";

/*
 * 示例：这里要处理的 TCP 流格式如下：'*CMD|key=value|key=value|key=value$'
 *      即客户端发送的每个完整的数据包格式都是以 * 开关，$ 符结尾
 *      中间每个字段都是以 '|' 分割的 key=value 形式
 */

//分割符，
$package_sof = '*';    //数据包开头符
$package_eof = '$';    //数据包结尾符

$param = array (
    //mac 不支持 cli_set_process_title，无法设置进程名
    'process_name'  => 'EofSplitTcpServer',
    'worker_num'      => 4,
    'task_worker_num' => 8,
    'package_eof'     => $package_eof,
    'daemonize'       => true,                 //后台运行
    'log_file'        => '/tmp/zan_server.log',
);

$server = EofSplitTcpServer::createServer("0.0.0.0", 9506, $package_sof, $package_eof);
$server->setParam($param);
$server->serve();
