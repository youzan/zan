--TEST--
swoole_conn_pool: release 1 - 1

--SKIPIF--
<?php require  __DIR__ . "/../inc/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../inc/zan.inc";

/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:12
 */


// WARNING	swTimer_del: timer#0 is not found.
// TODO coredump

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
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
$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
    swoole_timer_clear($timerId);

    if ($cli instanceof \swoole_client) {
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
            if ($cli instanceof \swoole_client) {
                assert($cli->isConnected());
            } else {
                assert(false);
            }
            swoole_event_exit();
        });

        if ($connId === false) {
            assert(false);
        }
        swoole_event_exit();
        echo "SUCCESS";
    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId !== false);

?>

--EXPECT--
SUCCESS