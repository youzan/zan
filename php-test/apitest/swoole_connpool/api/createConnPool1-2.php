<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:14
 */

$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 6379,
]);
assert($r === true);
$r = $redis_pool->createConnPool(0, 0);
assert($r === false);
$r = $redis_pool->createConnPool(2, 1);
assert($r === false);
$r = $redis_pool->createConnPool(1, 1);
assert($r > 0);

// TODO 没有限制 max_limit
//$r = $redis_pool->createConnPool(PHP_INT_MAX, PHP_INT_MAX);
//assert($r === false);

swoole_timer_after(1, function() {
    swoole_event_exit();
});