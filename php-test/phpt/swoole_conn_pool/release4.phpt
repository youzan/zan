--TEST--
swoole_conn_pool: release 4

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
 * Date: 17/5/23
 * Time: 上午11:35
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
$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});
$connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_client) {
        assert($cli->isConnected());


        // TODO COREDUMP
        $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
        $cli->on("error", function() {});
        $cli->on("close", function() {});
        $cli->on("connect", function(\swoole_client $cli) use($pool) {
            $pool->release($cli);

            $timeout = 1000;
            $timerId = swoole_timer_after($timeout + 100, function() use(&$got){
                assert(false);
                swoole_event_exit();
            });

            $connId = $pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/ $cli) use($timerId) {
                swoole_timer_clear($timerId);
                if ($cli instanceof \swoole_client) {
                    assert(false);
                    swoole_event_exit();
                } else {
                	echo "SUCCESS";
		}
                swoole_event_exit();
            });
            assert($connId !== false);

            if ($connId === false) {
                swoole_event_exit();
            }
        });
        $cli->connect(IP_BAIDU, 80);


    } else {
        assert(false);
    }

});
assert($connId !== false);
?>

--EXPECT--
SUCCESS
