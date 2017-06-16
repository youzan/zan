--TEST--
swoole_conn_pool: create conn pool 1 - 3

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

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
]);
assert($r === true);
$r = $mysql_pool->createConnPool(0, 0);
assert($r === false);
$r = $mysql_pool->createConnPool(2, 1);
assert($r === false);
$r = $mysql_pool->createConnPool(1, 1);
assert($r > 0);

// TODO 没有限制 max_limit
//$r = $mysql_pool->createConnPool(PHP_INT_MAX, PHP_INT_MAX);
//assert($r === false);

swoole_timer_after(1, function() {
    swoole_event_exit();
    echo "SUCCESS";
});

?>

--EXPECT--
SUCCESS