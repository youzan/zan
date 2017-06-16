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
swoole_async_dns_lookup("127.0.0.1", function($_, $ip) {
    $redisConf = [
        "host" => $ip,
        "port" => 6379,
    ];
    $tcpTest = makeConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_REDIS, $redisConf);
    $tcpTest();
});

