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

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",
]);
assert($r === true);
$r = $mysql_pool->createConnPool(1, 1);
assert($r === true);


$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$connId = $mysql_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
    swoole_timer_clear($timerId);

    if ($cli instanceof \swoole_mysql) {
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
            if ($cli instanceof \swoole_mysql) {

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

