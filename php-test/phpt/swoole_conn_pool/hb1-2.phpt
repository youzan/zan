--TEST--
swoole_conn_pool: hb 1 - 2

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
 * Time: 下午12:03
 */



$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);
$r = $redis_pool->setConfig([
    "host" => REDIS_SERVER_HOST,
    "port" => REDIS_SERVER_PORT,
    "hbIntervalTime" => 1,
//    hbTimeout
//    connectTimeout
]);
assert($r === true);

$redis_pool->on("hbConstruct", function() {
    return [
        "method" => "ping",
        "args" => null,
    ];
});
$redis_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) {
    return true;
});


$r = $redis_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;

$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});

$connId = $redis_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_redis) {
        assert($cli->isConnected());
        $pool->release($cli);

    } else {
        assert(false);
        swoole_event_exit();
    }
});
assert($connId !== false);

swoole_timer_after(5000, function() {
    swoole_event_exit();
    echo "SUCCESS";
});


?>

--EXPECT--
SUCCESS