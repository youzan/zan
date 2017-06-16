<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:15
 */


require_once __DIR__ . "/connSizeTest.php";

// 测试连接创建数量

/*
测试环境（qa）
127.0.0.1
6602

性能测试环境（perf）
127.0.0.1
6602

开发环境（dev）
127.0.0.1
6602

daily环境（daily）
127.0.0.1
6602
*/

$configGroup = [
    [
        "host" => "127.0.0.1",
        "port" => 6602,
    ],
    [
        "host" => "127.0.0.1",
        "port" => 6602,
    ],
    [
        "host" => "127.0.0.1",
        "port" => 6602,
    ],
    [
        "host" => "127.0.0.1",
        "port" => 6602,
    ]
];

function dns_lookup_group(array $configGroup, callable $callback, $i = 0)
{
    $c = count($configGroup);
    if ($i < $c) {
        swoole_async_dns_lookup($configGroup[$i]["host"], function($_, $ip) use($i, $configGroup, $callback) {
            $configGroup[$i]["host"] = $ip;
            dns_lookup_group($configGroup, $callback, $i + 1);
        });
    } else {
        $callback($configGroup);
    }
}

dns_lookup_group($configGroup, function(array $configGroup) {
    $test = makeGroupConnSizeTest(\swoole_connpool::SWOOLE_CONNPOOL_REDIS, $configGroup);
    $test();
});