--TEST--
swoole_conn_pool: tcp send with callback

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
 * Time: 下午6:10
 */

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 10);
assert($r !== false);

$timeout = 1000;
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});

$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_client) {
        $timeout = 1000;
        $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
            assert(false);
            swoole_event_exit();
        });

        $cli->setSendTimeout($timeout);
        $cb = function($cli, $r) use($timerId) {
            if (is_int($r)) {
                // on timeout
                assert(false);
            } else {
                // on recv
                swoole_timer_clear($timerId);
                // var_dump($r);
                echo "SUCCESS";
            }
            swoole_event_exit();
        };
        $cli->on("timeout", $cb);
        $cli->on("receive", $cb);

        $str = "GET / HTTP/1.1\r\n\r\n";
        $r = $cli->send($str);
        assert(strlen($str) === $r);

    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId !== false);

?>

--EXPECT--
SUCCESS