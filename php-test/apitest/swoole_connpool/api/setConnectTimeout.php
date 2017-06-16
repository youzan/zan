<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/23
 * Time: 下午12:02
 */


$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
    // TODO
    "connectTimeout" => "",
    "queryTimeout" => "",
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;
//
//$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
//    assert(false);
//    swoole_event_exit();
//});
//
//$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
//    swoole_timer_clear($timerId);
//    if ($cli instanceof \swoole_client) {
//        assert($cli->isConnected());
//
//    } else {
//        assert(false);
//    }
//    swoole_event_exit();
//});
//assert($connId > 0);