--TEST--
swoole_conn_pool: release 2

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



$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;


// get 回调可能同步也可能异步
// 默认不解决，自行使用defer函数处理
// 处理release3， 使用defer后coredump

// [2017-05-22 22:13:30 @75667.0]	WARNING	swTimer_del: timer#0 is not found.
// xdebug: Fatal error: Maximum function nesting level of '256' reached, aborting!

function getAndRelease()
{
    global $tcp_pool, $timeout;

    $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
        assert(false);
        swoole_event_exit();
    });


    // TODO 这里应该同步执行了
    $connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
        if (swoole_timer_exists($timerId)) {
            swoole_timer_clear($timerId);
        }

        if ($cli instanceof \swoole_client) {
            assert($cli->isConnected());
            $r = $pool->release($cli);
            assert($r == true);

            // TODO  处理defer bug
            swoole_timer_after(1, function() {
                getAndRelease();
            });

        } else {
            assert(false);
        }
    });

    if ($connId === false) {
        assert(false);
        swoole_event_exit();
        exit(1);
    }
    assert($connId !== false);
}



swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

getAndRelease();

?>

--EXPECT--
SUCCESS