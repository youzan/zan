<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接池数量

// TODO coredump
$mysqlConf = [
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",
];

$tcpTest = makeConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL, $mysqlConf);
$tcpTest();

