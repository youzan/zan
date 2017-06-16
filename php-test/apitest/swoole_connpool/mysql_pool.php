<?php

// `nc -lk 9001`

define("MYSQL_SERVER_HOST", "127.0.0.1");
define("MYSQL_SERVER_PORT", 3306);
define("MYSQL_SERVER_USER", "test_database");
define("MYSQL_SERVER_PWD", "test_database");
define("MYSQL_SERVER_DB", "test_database");

$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$mysql_pool->on("hbConstruct", function() {
    return "select 1";
});
$mysql_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) {
    var_dump($data);
});

$mysql_pool->setConfig([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
]);
$mysql_pool->createConnPool(20, 50);

$connId = $mysql_pool->get(function(\swoole_connpool $pool, \swoole_mysql $client) {
    var_dump($client);
    $pool->release($client);
}, 100);
