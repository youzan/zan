--TEST--
swoole_conn_pool: get -release

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
 * Date: 17/5/24
 * Time: 下午9:02
 */


$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);



function get_release($tcp_pool)
{
    $timeout = 1000;

    $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
        assert(false);
        swoole_event_exit();
    });

    $connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
        swoole_timer_clear($timerId);
        if ($cli instanceof \swoole_client) {
            assert($cli->isConnected());
            $r = $pool->release($cli, \swoole_connpool::SWOOLE_CONNNECT_ERR);
            assert($r);
            get_release($pool);
        } else {
            assert(false);
            swoole_event_exit();
        }
    });

    // echo $connId, "\t" , microtime(true), "\n";

    if ($connId === false) {
        assert(false);
        swoole_event_exit();
    }
}

get_release($tcp_pool);

swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS