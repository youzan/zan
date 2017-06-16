<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午3:10
 */

/** @var \swoole_client $test_cli */
$test_cli = null;


$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$tcp_pool->get($timeout, function(\swoole_connpool $pool, $cli) use($timerId) {
    global $test_cli;
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_client) {
        $test_cli = $cli;
        $pool->destroy();
        $pool->destroy();
    } else {
        assert(false);
        swoole_event_exit();
    }
});

// 预期引用计数为0
unset($tcp_pool);

//if (function_exists("xdebug_debug_zval")) {
//    xdebug_debug_zval("tcp_pool");
//};


// 连接池销毁后，持有连接池内连接
swoole_timer_after(200, function() {
    global $test_cli;
    assert($test_cli->isConnected() === false);
    $test_cli->connect("180.150.190.136", 80);
    swoole_timer_after(200, function() use($test_cli) {
        assert($test_cli->isConnected() === false);
        swoole_event_exit();
    });
});