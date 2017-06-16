<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午6:11
 */


$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);

$r = $tcp_pool->on("\0", "printf");
assert($r === false);

// TODO 感觉这里应该返回true
$r = $tcp_pool->on("hbConstruct", [$tcp_pool, "on"]);
assert($r === null);
$r = $tcp_pool->on("hbCheck", [$tcp_pool, "on"]);
assert($r === null);


// zval string 本身是类型安全的，但是字符串比较函数是非二进制安全的
$r = $tcp_pool->on("hbCheck\0λ", [$tcp_pool, "on"]);
assert($r === null);

$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
]);

// TODO
$cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
$cli->on("connect\0@@@@@@@@@", function() { });
$cli->on("close\0########", function() { });
$cli->on("receive\0*********", function() { });
$cli->connect("180.97.33.107", 80);

//swoole_event_exit();