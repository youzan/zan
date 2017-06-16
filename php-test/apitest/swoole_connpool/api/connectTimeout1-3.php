<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/5/24
 * Time: 下午7:54
 */


$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$r = $mysql_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 3306,
    "user" => "root",
    "password" => "",
    "database" => "test",
    "charset" => "utf8mb4",
    "connectTimeout" => 1,
]);
assert($r === true);
$r = $mysql_pool->createConnPool(1, 1);
assert($r > 0);

//swoole_timer_after(1, function() {
//    swoole_event_exit();
//});