<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接创建数量

$test = makeGroupConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_TCP, [
    [
        "host" => "180.97.33.107", //baidu
        "port" => 80,
    ],
    [
        "host" => "180.150.190.136", // youan
        "port" => 80,
    ],
    [
        "host" => "204.79.197.200", // bing
        "port" => 80,
    ],
    [
        "host" => "180.163.251.85", // so
        "port" => 80,
    ],
]);

$test();
