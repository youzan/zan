<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/23
 * Time: 上午11:57
 */


$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 6379,
]);
$r = $redis_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$redis_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId) {
    swoole_timer_clear($timerId);

    if ($cli instanceof \swoole_redis) {
        $pool->destroy();
        $pool->destroy();

        $r = $pool->setConfig([
            "host" => "127.0.0.1",
            "port" => 6379,
        ]);
        assert($r === false);
        $r = $pool->createConnPool(1, 1);
        assert($r === false);
    } else {
        assert(false);
    }

    swoole_event_exit();
});