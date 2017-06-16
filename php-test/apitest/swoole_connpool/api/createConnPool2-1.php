<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接池数量

$tcpConf = [
    "host" => "180.97.33.107", // baidu
    "port" => 80,
];

$tcpTest = makeConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_TCP, $tcpConf);
$tcpTest();

