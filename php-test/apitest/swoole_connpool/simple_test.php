<?php

require_once __DIR__ . "/tcpstat.php";

define("MYSQL_SERVER_HOST", "127.0.0.1");
define("MYSQL_SERVER_PORT", 3306);
define("MYSQL_SERVER_USER", "test_database");
define("MYSQL_SERVER_PWD", "test_database");
define("MYSQL_SERVER_DB", "test_database");
define("MYSQL_CONN_MIN", 20);
define("MYSQL_CONN_MAX", 50);

define("TCP_SERVER_HOST", "127.0.0.1");
define("TCP_SERVER_PORT", "9001");
define("TCP_CONN_MIN", 20);
define("TCP_CONN_MAX", 50);

define("REDIS_SERVER_HOST", "127.0.0.1");
define("REDIS_SERVER_PORT", 6379);
define("REDIS_CONN_MIN", 20);
define("REDIS_CONN_MAX", 50);

$tcp_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_TCP);
$mysql_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_MYSQL);
$redis_pool = new \swoole_connpool(\swoole_connpool::SWOOLE_CONNPOOL_REDIS);


$tcp_pool->on("hbConstruct", function() { return "PING"; });
$tcp_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) { var_dump($data); });
$mysql_pool->on("hbConstruct", function() {
    return "select 1";
});
$mysql_pool->on("hbCheck", function(\swoole_connpool $pool, $conn, $data) {
    var_dump($data);
});
$redis_pool->on("hbConstruct", function() {
    return [
        "method" => "PING"
    ];
});
$redis_pool->on("hbCheck", function(\swoole_connpool $pool, $connobj, $data) {
    return true;
});



$tcp_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 9001,
]);
$mysql_pool->setConfig([
    "host" => MYSQL_SERVER_HOST,
    "port" => MYSQL_SERVER_PORT,
    "user" => MYSQL_SERVER_USER,
    "password" => MYSQL_SERVER_PWD,
    "database" => MYSQL_SERVER_DB,
    "charset" => "utf8mb4",
]);
$redis_pool->setConfig([
    "host" => "127.0.0.1",
    "port" => 6379,
]);

$tcp_pool->createConnPool(TCP_CONN_MIN, TCP_CONN_MAX);
$redis_pool->createConnPool(REDIS_CONN_MIN, REDIS_CONN_MAX);
$mysql_pool->createConnPool(MYSQL_CONN_MIN, MYSQL_CONN_MAX);



swoole_timer_after(2000, function() {
    $tcpStat = TcpStat::count(TCP_SERVER_HOST, TCP_SERVER_PORT);
    $mysqlStat = TcpStat::count(MYSQL_SERVER_HOST, MYSQL_SERVER_PORT);
    $redisStat = TcpStat::count(REDIS_SERVER_HOST, REDIS_SERVER_PORT);

    assert($tcpStat["established"] === TCP_CONN_MIN);
    assert($mysqlStat["established"] === MYSQL_CONN_MIN);
    assert($redisStat["established"] === REDIS_CONN_MIN);
});



$connId = $tcp_pool->get(function(\swoole_connpool $pool, \swoole_client $client) {
    $pool->release($client);
}, 100);


