<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接创建数量

$test = makeGroupConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL, [
    [
        "host" => "127.0.0.1",
        "port" => 3306,
        'user' => 'root',
        "password" => '',
        "database" => '',
        "charset" => "utf8mb4",
    ],
    [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => '',
        'database' => '',
        'port' => '3008',
    ],
    [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => '',
        'database' => '',
        'port' => '3307',
    ],
    [
        'host' => '127.0.0.1',
        'user' => 'root',
        'password' => '',
        'database' => '',
        'port' => '3008',
    ]

]);
$test();
