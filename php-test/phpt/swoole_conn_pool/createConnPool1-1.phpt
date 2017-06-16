--TEST--
swoole_conn_pool: create conn pool 1 - 1

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
 * Time: 下午9:14
 */

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$r = $tcp_pool->setConfig([
    "host" => IP_BAIDU, // baidu
    "port" => 80,
]);
assert($r === true);

$r = $tcp_pool->createConnPool(0, 0);
assert($r === false);
$r = $tcp_pool->createConnPool(2, 1);
assert($r === false);
$r = $tcp_pool->createConnPool(1, 1);
assert($r > 0);

// TODO 没有限制 max_limit
//$r = $tcp_pool->createConnPool(PHP_INT_MAX, PHP_INT_MAX);
//assert($r === false);

swoole_timer_after(1, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS