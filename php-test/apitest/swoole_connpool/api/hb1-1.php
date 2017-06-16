<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/23
 * Time: 下午12:03
 */



$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.150.190.136", // baidu
    "port" => 80,
    "hbIntervalTime" => 1,
//    hbTimeout
//    connectTimeout
]);
assert($r === true);

$tcp_pool->on("hbConstruct", function() {
    return [
        "method" => "send",
        "args" => "GET / HTTP 1.1\r\n\r\n\r\n",
    ];
});
$tcp_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) {
    echo $data;
    swoole_event_exit();
    return true;
});


$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;

$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});

$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_client) {
        assert($cli->isConnected());
        $pool->release($cli);

    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId > 0);