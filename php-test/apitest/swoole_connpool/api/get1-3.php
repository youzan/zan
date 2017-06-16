<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/22
 * Time: 下午8:56
 */

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",
]);
assert($r === true);
$r = $mysql_pool->createConnPool(1, 1);
assert($r === true);

$timeout = 1000;

$timerId = swoole_timer_after($timeout + 100, function() use(&$got){
    assert(false);
    swoole_event_exit();
});

$connId = $mysql_pool->get($timeout, function(\swoole_connpool $pool, /*\swoole_client*/$cli) use($timerId) {
    swoole_timer_clear($timerId);
    if ($cli instanceof \swoole_mysql) {
        assert($cli->isConnected());
        $cli->query("select 1", function($_, $r) {
//            var_dump($r[0][1] === "1");
        });
    } else {
        assert(false);
    }
    swoole_event_exit();
});
assert($connId > 0);

