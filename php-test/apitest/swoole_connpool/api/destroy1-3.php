<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:14
 */

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $tcp_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",
]);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$tcp_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId) {
    swoole_timer_clear($timerId);

    if ($cli instanceof \swoole_mysql) {
        $pool->destroy();
        $pool->destroy();

        $r = $pool->get(function() {}, 1);
        assert($r === false);

        $r = $pool->release($cli);
        assert($r === false);

    } else {
        assert(false);
    }
    swoole_event_exit();
});