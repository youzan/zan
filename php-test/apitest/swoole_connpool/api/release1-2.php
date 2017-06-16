<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:12
 */


require_once __DIR__ . "/../tcpstat.php";

// WARNING	swTimer_del: timer#0 is not found.
// TODO coredump

$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
]);
assert($r === true);
$r = $redis_pool->createConnPool(1, 1);
assert($r === true);


$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$connId = $redis_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
    swoole_timer_clear($timerId);

    if ($cli instanceof \swoole_redis) {
        $r = $pool->release($cli);
        assert($r === true);


        // 释放之后重新获取该连接
        $timeout = 1000;
        $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
            assert(false);
            swoole_event_exit();
        });


        $connId = $pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
            swoole_timer_clear($timerId);
            if ($cli instanceof \swoole_redis) {

            } else {
                assert(false);
            }
            swoole_event_exit();
        });

        if ($connId === false) {
            assert(false);
        }
        swoole_event_exit();
    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId > 0);

