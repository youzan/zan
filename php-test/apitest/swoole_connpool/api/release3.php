<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午9:12
 */

require_once __DIR__ . "/../tcpstat.php";

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => "180.97.33.107", // baidu
    "port" => 80,
]);
assert($r === true);
$r = $tcp_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;

// TODO COREDUMP

function getAndRelease()
{
    global $redis_pool, $timeout;

    $connId = $redis_pool->get($timeout, function(\swoole_connpool $pool, $cli) {
        swoole_event_defer(function() use($cli, $pool) {
            if ($cli instanceof \swoole_client) {
                assert($cli->isConnected());
                $r = $pool->release($cli);
                assert($r == true);
                getAndRelease();
            } else {
                assert(false);
            }
            swoole_event_exit();
        });
    });

    assert($connId > 0);
}

getAndRelease();
