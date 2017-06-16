<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午7:54
 */

// TODO 一个连接跑一段时间 可能 CORE DUMP
// 1000 个连接可能概率高一些

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
    // 可能跟这里有关系
    "connectTimeout" => 1,
]);
assert($r === true);

$r = $tcp_pool->createConnPool(1, 1);
assert($r > 0);

//swoole_timer_after(1, function() {
//    swoole_event_exit();
//});