<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午7:54
 */

$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 6379,
    "connectTimeout" => 1,
]);
assert($r === true);
$r = $redis_pool->createConnPool(1, 1);
assert($r > 0);

//swoole_timer_after(1, function() {
//    swoole_event_exit();
//});