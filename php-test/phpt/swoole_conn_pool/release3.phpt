--TEST--
swoole_conn_pool: release 3

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

// TODO COREDUMP

function getAndRelease()
{
    global $tcp_pool, $timeout;

    // TODO 这里应该同步执行了
    $connId = $tcp_pool->get($timeout, function(\swoole_connpool $pool, $cli) {
        swoole_event_defer(function() use($cli, $pool) {
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
    });

    assert($connId !== false);
}

getAndRelease();


swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS
